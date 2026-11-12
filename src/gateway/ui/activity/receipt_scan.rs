// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The receipt's forward scan from a call: its delivery record, every record
//! with its trace, and the continuity of the chain across the window it read.

use std::io;
use std::path::Path;

use serde_json::{Value, json};

use super::answer::{Delivery, Effect, Findings, Joined, RECEIPT_SCAN, Searched, Why};
use super::joiner::{Joiner, Seen};
use super::reader::{Line, Which};
use super::rows::Check;
use super::seek::{Found, segments};
use super::strict_scan::{Forward, Next};
use crate::security::transparency_log::pager::open_segment;
use crate::security::transparency_log::recompute_entry_hash;

/// What one forward scan found.
pub(super) struct Scanned {
    pub(super) joined: Joined,
    /// The first two delivery records of the call's trace, summarised.
    pub(super) records: Vec<Value>,
    /// Records of the trace beyond those listed.
    pub(super) more: usize,
    pub(super) bytes: u64,
    pub(super) lines: usize,
    /// Which limit ended the scan.
    pub(super) stopped: &'static str,
    /// The window (256 KiB or the log head) was read to its end.
    pub(super) finished: bool,
    /// A consecutive pair in the window broke the chain.
    pub(super) chain_broken: bool,
}

/// Whether `entry` follows `prev`: the next counter, and `prev`'s own hash.
fn follows(prev: &Value, entry: &Value) -> bool {
    let counter = |e: &Value| e.get("counter").and_then(Value::as_u64);
    counter(entry) == counter(prev).map(|c| c + 1)
        && entry.get("prev_entry_hash").and_then(Value::as_str)
            == recompute_entry_hash(prev).ok().as_deref()
}

fn summary(entry: &Value) -> Value {
    json!({
        "counter": entry.get("counter"),
        "effect": entry.get("response_effect"),
        "findings_listed": entry.get("response_findings").and_then(Value::as_array).map(Vec::len),
    })
}

fn is_delivery(entry: &Value, trace: &str) -> bool {
    let text = |k: &str| entry.get(k).and_then(Value::as_str);
    text("trace_id") == Some(trace)
        && text("event") == Some("response_delivery_attempt")
        && text("response_stage") == Some("transport_finalized")
}

/// Read forward from `found`, up to [`RECEIPT_SCAN`] bytes, crossing at most
/// one segment boundary. The byte bound governs alone: a valid chained record
/// is over 131 bytes, so no line cap could fire before it (design I1).
pub(super) fn scan(
    log: &Path,
    found: &Found,
    call: &Line,
    check: &Check<'_>,
) -> io::Result<Scanned> {
    let trace = call
        .entry
        .get("trace_id")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty());
    let mut joiner = Joiner::new(check);
    // The call is judged first, as the list judges it: a call whose own line was
    // tampered with poisons its trace here too.
    joiner.observe(call);
    let mut out = Scanned {
        joined: Joined::NoRecord(Searched::Finished),
        records: Vec::new(),
        more: 0,
        bytes: 0,
        lines: 0,
        stopped: "end of log",
        finished: true,
        chain_broken: false,
    };
    let mut prev = found.entry.clone();
    let (mut seq, mut offset, mut crossed) = (found.segment, found.end, false);
    let mut total = 0_usize;
    loop {
        let Some(file) = open_segment(log, seq, || {})? else {
            (out.stopped, out.finished) = ("missing segment", false);
            break;
        };
        let mut forward = Forward::open(file, offset, RECEIPT_SCAN - out.bytes)?;
        let mut at = offset;
        let ended = loop {
            let bytes = match forward.next_line()? {
                Next::Line(bytes) => bytes,
                other => break other,
            };
            let span = Some((at, bytes.len() as u64));
            at += bytes.len() as u64 + 1;
            out.lines += 1;
            let Ok(entry @ Value::Object(_)) = serde_json::from_slice::<Value>(&bytes) else {
                // A complete line that is no record is a break, never a skip.
                out.chain_broken = true;
                continue;
            };
            out.chain_broken |= !follows(&prev, &entry);
            if trace.is_some_and(|t| is_delivery(&entry, t)) {
                total += 1;
                if out.records.len() < 2 {
                    out.records.push(summary(&entry));
                }
            }
            // Continuity covers every record; the join takes only this call's
            // trace, so other traces cannot evict its record.
            // A line with no usable trace is fed too: if it fails its integrity
            // check, no call can be told apart from the delivery it may have been.
            let untraced = entry
                .get("trace_id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty);
            if untraced || entry.get("trace_id").and_then(Value::as_str) == trace {
                let line = Line {
                    log: Which::Invocation,
                    entry: entry.clone(),
                    segment: seq,
                    span,
                };
                joiner.observe(&line);
            }
            prev = entry;
        };
        out.bytes += forward.pulled();
        if ended == Next::Budget {
            out.stopped = "byte limit";
            break;
        }
        match segments(log)?.into_iter().find(|s| *s > seq) {
            None => break,
            // Segment numbers are contiguous: a gap is an unread segment.
            Some(next) if next != seq + 1 => {
                (out.stopped, out.finished) = ("missing segment", false);
                break;
            }
            Some(_) if crossed => {
                (out.stopped, out.finished) = ("end of the next segment", false);
                break;
            }
            Some(next) => (seq, offset, crossed) = (next, 0, true),
        }
    }
    out.more = total.saturating_sub(out.records.len());
    let seen = Seen {
        above: out.bytes,
        head_covered: out.finished,
    };
    out.joined = joiner.join(call, seen);
    // A found record in a window whose chain broke is not vouched for.
    if out.chain_broken && matches!(out.joined, Joined::Found(_)) {
        out.joined = Joined::Incomplete(Why::Chain);
    }
    Ok(out)
}

const UNVERIFIABLE: &str =
    "this gateway cannot verify the delivery record's signature, so it cannot vouch for the record";

fn found_line(d: &Delivery) -> String {
    let effect = d.effect.as_str();
    let line = match (&d.findings, d.effect) {
        (Findings::Scanned { list, .. }, _) => format!("effect: {effect}; findings: {} listed", list.len()),
        (Findings::NotScanned, _) => format!("effect: {effect}; the answer was not scanned"),
        (Findings::NotRecorded, Effect::Refused) => "effect: refused; the gateway did not vouch for this answer, so no findings are recorded for it".into(),
        (Findings::NotRecorded, Effect::Rewritten) => "effect: rewritten (the gateway removed an injected value from something this backend sent during the call); findings not recorded for this answer".into(),
        (Findings::NotRecorded, _) => "effect not known: the record states none (an answer the gateway did not vouch for, or a gateway version before response effects)".into(),
    };
    if d.unverifiable {
        format!("{line}; {UNVERIFIABLE}")
    } else {
        line
    }
}

fn incomplete_line(why: Why) -> String {
    match why {
        Why::Invalid | Why::Unsigned => format!(
            "a record carrying this call's trace failed its integrity check ({}); effect not stated",
            if why == Why::Invalid { "invalid" } else { "unsigned under the configured secret" }
        ),
        Why::Duplicate => "more than one delivery record for this trace: the writer writes one; treated as tampering".into(),
        Why::Chain => "the log chain broke inside the delivery window, so the delivery record cannot be vouched for; effect not stated".into(),
        Why::Unattributed => "a line after this call failed its integrity check and names no trace, so a delivery record for this call cannot be ruled out; effect not stated".into(),
        Why::Evicted | Why::Overflow => "the join was incomplete".into(),
    }
}

/// The receipt's `answer` block: the joined record's effect, a plain line
/// saying what is and is not known, the first records, and the search.
pub(super) fn answer_block(call: &Line, s: &Scanned) -> Value {
    let trace = call.entry.get("trace_id").and_then(Value::as_str);
    let (line, searched) = match &s.joined {
        Joined::Found(d) => (found_line(d), false),
        Joined::Incomplete(why) => (incomplete_line(*why), false),
        Joined::NoRecord(Searched::NoTrace) => (
            "this call has no trace to join a delivery record on".to_string(),
            false,
        ),
        Joined::NoRecord(_) => (
            format!(
                "no delivery record for trace {} in the {} bytes and {} lines after the call; the search stopped at: {}",
                trace.unwrap_or_default(),
                s.bytes,
                s.lines,
                s.stopped
            ),
            true,
        ),
    };
    let mut block = json!({
        "effect": s.joined.effect().as_str(),
        "line": line,
        "records": s.records,
        "more": s.more,
    });
    if searched {
        block["search"] = json!({"bytes": s.bytes, "lines": s.lines, "stopped": s.stopped});
    }
    block
}
