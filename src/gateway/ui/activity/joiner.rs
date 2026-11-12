// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The join of delivery records to calls, held for one read (a page, or all
//! the passes of one export).
//!
//! A delivery sits newer than its call, so a newest-first scan meets it first
//! and holds it in a bounded map until the call arrives. Nothing the map
//! forgets is ever restored: an evicted trace keeps a tombstone with the
//! reason, and a read that outgrows the tombstones says so for every call
//! after it. A record that has been joined to a call row moves to a separate
//! set, so completed traces do not use up the bounds meant for the unresolved
//! ones; a second record for a joined trace reopens it as a duplicate.

use std::collections::{HashMap, VecDeque};

use serde_json::{Map, Value, json};

use super::answer::{
    DELIVERY_WINDOW, Delivery, Effect, Findings, Joined, MAX_EVICTED, MAX_JOINED, MAX_PENDING,
    Searched, Why,
};
use super::reader::{Line, Which};
use super::rows::{Check, kind_of};
use crate::security::transparency_log::signature::SignatureState;

pub(super) use super::reader::Seen;

/// What is held for one trace.
/// Where the line that failed integrity and names no trace sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Position {
    segment: u64,
    offset: Option<u64>,
}

impl Position {
    /// The manifest and list field: the log, segment and byte offset (null for
    /// a record the writer just announced).
    pub(super) fn to_json(self) -> Value {
        json!({"log": "invocation", "segment": self.segment, "offset": self.offset})
    }
}

enum Held {
    One(Delivery),
    Bad(Why),
}

/// The join state of one read.
pub(super) struct Joiner<'a, 's> {
    check: &'a Check<'s>,
    pending: HashMap<String, Held>,
    /// Insertion order of `pending`, oldest first. An entry that left `pending`
    /// (joined) stays until it reaches the front or the queue is compacted.
    order: VecDeque<String>,
    /// Records already joined to a call row, by trace.
    joined: HashMap<String, Delivery>,
    evicted: HashMap<String, Why>,
    overflowed: bool,
    /// The first line seen that failed its integrity check and names no usable
    /// trace: older calls left without a delivery cannot rule it out.
    unattributed: Option<Position>,
    /// Admitted calls joined incomplete, or unfinished with no record.
    pub(super) join_incomplete: usize,
    /// Calls whose record failed the trust rule or was duplicated.
    pub(super) answer_integrity_failed: usize,
}

fn str_of<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
}

/// The line's trace id, when it is a non-empty string.
fn usable_trace(line: &Line) -> Option<&str> {
    str_of(&line.entry, "trace_id").filter(|t| !t.is_empty())
}

/// The longest a finding's text field is kept: the writer's kinds and parts
/// are short closed sets, so a longer value is not one of them.
const FINDING_FIELD_MAX: usize = 128;

/// One finding as the writer shapes it, and no more: `kind`, `severity` and
/// `where`, each only when it is a string, so a record carrying anything else
/// (a payload, a nested object) never reaches a row or a manifest.
fn project_finding(finding: &Value) -> Option<Value> {
    let object = finding.as_object()?;
    let kept: Map<String, Value> = ["kind", "severity", "where"]
        .into_iter()
        .filter_map(|key| {
            let text = object.get(key)?.as_str()?;
            let capped: String = text.chars().take(FINDING_FIELD_MAX).collect();
            Some((key.to_string(), Value::String(capped)))
        })
        .collect();
    Some(Value::Object(kept))
}

/// The bounded projection of a delivery record.
fn project(entry: &Value, unverifiable: bool) -> Delivery {
    let effect = match str_of(entry, "response_effect").and_then(Effect::parse) {
        Some(e @ (Effect::Delivered | Effect::Annotated | Effect::Rewritten | Effect::Refused)) => {
            e
        }
        _ => Effect::Unknown,
    };
    let findings = match entry.get("response_findings") {
        Some(Value::Array(list)) => Findings::Scanned {
            list: list.iter().take(32).filter_map(project_finding).collect(),
            total: entry.get("response_findings_total").and_then(Value::as_u64),
        },
        Some(Value::Null) => Findings::NotScanned,
        _ => Findings::NotRecorded,
    };
    Delivery {
        effect,
        findings,
        unverifiable,
    }
}

/// Why a line was edited: a failed hash or signature, or a missing signature
/// after signing began. A plain unsigned line, one written before signing, is
/// not tampering: legacy rows carry trace ids too.
fn why_edited(state: SignatureState, integrity: Option<&str>) -> Option<Why> {
    match state {
        SignatureState::Invalid if integrity == Some("sig_missing") => Some(Why::Unsigned),
        SignatureState::Invalid => Some(Why::Invalid),
        _ => None,
    }
}

impl<'a, 's> Joiner<'a, 's> {
    pub(super) fn new(check: &'a Check<'s>) -> Self {
        Self {
            check,
            pending: HashMap::new(),
            order: VecDeque::new(),
            joined: HashMap::new(),
            evicted: HashMap::new(),
            overflowed: false,
            unattributed: None,
            join_incomplete: 0,
            answer_integrity_failed: 0,
        }
    }

    /// The trust rule: `Err` is why the record cannot be believed; `Ok(true)`
    /// is a record whose signature cannot be verified by this gateway, which
    /// holds no log secret. With a secret, an unsigned record is never
    /// believed, even one written before signing began.
    fn trust(&self, line: &Line) -> Result<bool, Why> {
        let judged = self.check.judge(line);
        if let Some(why) = why_edited(judged.state, judged.integrity) {
            return Err(why);
        }
        match judged.state {
            SignatureState::Valid => Ok(false),
            SignatureState::Unsigned if self.check.has_secret() => Err(Why::Unsigned),
            SignatureState::Unsigned | SignatureState::SignedUnverifiable => Ok(true),
            // `why_edited` has returned for this already; failing closed regardless.
            SignatureState::Invalid => Err(Why::Invalid),
        }
    }

    /// Why a line was edited, for a line that is not a delivery record's own
    /// kind: see [`why_edited`].
    fn tampered(&self, line: &Line) -> Option<Why> {
        let judged = self.check.judge(line);
        why_edited(judged.state, judged.integrity)
    }

    /// Fold a scanned invocation-log line that is not a listed row. `true`
    /// when the line carried a trace and was routed here: the caller drops it.
    pub(super) fn observe(&mut self, line: &Line) -> bool {
        if line.log != Which::Invocation {
            return false;
        }
        if kind_of(line).is_some() {
            // A delivery record edited to look like a listed row would drop out
            // of the join unseen, so a tampered line still poisons its trace.
            match usable_trace(line) {
                Some(trace) => {
                    if let Some(why) = self.tampered(line) {
                        self.hold_bad(trace, why);
                    }
                }
                None => self.note_unattributed(line),
            }
            return false;
        }
        let Some(trace) = usable_trace(line) else {
            self.note_unattributed(line);
            return false;
        };
        match self.trust(line) {
            Err(why) => self.hold_bad(trace, why),
            Ok(unverifiable) => {
                let is_delivery = str_of(&line.entry, "event") == Some("response_delivery_attempt")
                    && str_of(&line.entry, "response_stage") == Some("transport_finalized");
                if is_delivery {
                    self.hold_record(trace, project(&line.entry, unverifiable));
                }
            }
        }
        true
    }
}

impl Joiner<'_, '_> {
    /// A line with no usable trace that fails its integrity check cannot be
    /// tied to a call; the first one seen is kept.
    fn note_unattributed(&mut self, line: &Line) {
        if self.unattributed.is_none() && self.tampered(line).is_some() {
            self.unattributed = Some(Position {
                segment: line.segment,
                offset: line.span.map(|(offset, _)| offset),
            });
        }
    }

    /// The position for the list's and export's `answer_integrity_unattributed`.
    pub(super) fn unattributed(&self) -> Value {
        self.unattributed.map_or(Value::Null, Position::to_json)
    }

    /// A record that cannot be believed poisons its trace.
    fn hold_bad(&mut self, trace: &str, why: Why) {
        if self.joined.remove(trace).is_some() {
            self.insert(trace, Held::Bad(why));
            return;
        }
        if let Some(reason) = self.evicted.get_mut(trace) {
            // The first integrity reason stays; an evicted record is upgraded.
            if reason.integrity().is_none() {
                *reason = why;
            }
            return;
        }
        match self.pending.get_mut(trace) {
            Some(held @ Held::One(_)) => *held = Held::Bad(why),
            Some(Held::Bad(_)) => {}
            None => self.insert(trace, Held::Bad(why)),
        }
    }

    /// A believed `transport_finalized` record: a second one for a trace is
    /// tamper, whether the first is held or was evicted.
    fn hold_record(&mut self, trace: &str, delivery: Delivery) {
        if self.joined.remove(trace).is_some() {
            self.insert(trace, Held::Bad(Why::Duplicate));
            return;
        }
        if let Some(reason) = self.evicted.get_mut(trace) {
            if *reason == Why::Evicted {
                *reason = Why::Duplicate;
            }
            return;
        }
        match self.pending.get_mut(trace) {
            Some(held @ Held::One(_)) => *held = Held::Bad(Why::Duplicate),
            Some(Held::Bad(_)) => {}
            None => self.insert(trace, Held::One(delivery)),
        }
    }

    fn insert(&mut self, trace: &str, held: Held) {
        if self.pending.len() >= MAX_PENDING {
            self.evict_oldest();
        }
        if self.order.len() >= 2 * MAX_PENDING {
            let pending = &self.pending;
            self.order.retain(|t| pending.contains_key(t));
        }
        self.order.push_back(trace.to_string());
        self.pending.insert(trace.to_string(), held);
    }

    /// The oldest-inserted entry leaves; its tombstone keeps the reason.
    fn evict_oldest(&mut self) {
        // Skip entries that already left `pending` (joined).
        let (oldest, held) = loop {
            let Some(oldest) = self.order.pop_front() else {
                return;
            };
            if let Some(held) = self.pending.remove(&oldest) {
                break (oldest, held);
            }
        };
        let reason = match held {
            Held::Bad(why) => why,
            Held::One(_) => Why::Evicted,
        };
        if self.evicted.len() < MAX_EVICTED {
            self.evicted.insert(oldest, reason);
        } else {
            self.overflowed = true;
        }
    }

    /// A joined record leaves `pending`, so completed traces stop using the
    /// bounds meant for unresolved ones. When `joined` is full it stays in
    /// `pending`, as before.
    fn retire(&mut self, trace: &str) {
        if self.joined.len() >= MAX_JOINED {
            return;
        }
        if let Some(Held::One(d)) = self.pending.remove(trace) {
            self.joined.insert(trace.to_string(), d);
        }
    }

    /// The join for a call line. Does not count: see [`Self::count`].
    pub(super) fn join(&mut self, line: &Line, seen: Seen) -> Joined {
        let Some(trace) = str_of(&line.entry, "trace_id") else {
            return Joined::NoRecord(Searched::NoTrace);
        };
        if self.overflowed {
            return Joined::Incomplete(Why::Overflow);
        }
        if let Some(why) = self.evicted.get(trace) {
            return Joined::Incomplete(*why);
        }
        if let Some(d) = self.joined.get(trace) {
            return Joined::Found(d.clone());
        }
        match self.pending.get(trace) {
            Some(Held::One(d)) => {
                let found = d.clone();
                self.retire(trace);
                Joined::Found(found)
            }
            Some(Held::Bad(why)) => Joined::Incomplete(*why),
            None if self.unattributed.is_some() => Joined::Incomplete(Why::Unattributed),
            None if seen.head_covered || seen.above >= DELIVERY_WINDOW => {
                Joined::NoRecord(Searched::Finished)
            }
            None => Joined::NoRecord(Searched::Unfinished),
        }
    }

    /// Count an admitted call's join.
    pub(super) fn count(&mut self, joined: &Joined) {
        match joined {
            Joined::Incomplete(why) => {
                self.join_incomplete += 1;
                if why.integrity().is_some() {
                    self.answer_integrity_failed += 1;
                }
            }
            Joined::NoRecord(Searched::Unfinished) => self.join_incomplete += 1,
            Joined::Found(_) | Joined::NoRecord(_) => {}
        }
    }
}
