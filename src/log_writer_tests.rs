// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The lossy stderr writer: drops are counted and reported, never waited for.

use std::time::{Duration, Instant};

use tracing_subscriber::layer::SubscriberExt;

use super::test_sinks::{Step, flush, line, notices, parked, parked_on, scripted, scripted_with};
use super::{LOG_FLUSH_DEADLINE, NoticeFormat, Sent, flush_until, notice_line};

/// A failed write counts its line and the writer goes on (L1b).
#[test]
fn l1b_a_failed_write_counts_its_line_and_the_writer_goes_on() {
    let (w, _f, out) = scripted(vec![Step::Accept, Step::Accept, Step::Fail]);
    for n in 1..=6 {
        line(&w, &format!("line-{n}"));
    }
    assert!(
        out.wait_for(|t| t.contains("line-6\n")),
        "the writer stopped: {}",
        out.text()
    );
    let kept: Vec<String> = out.lines().into_iter().filter(|l| !l.is_empty()).collect();
    assert_eq!(kept[..3], ["line-1", "line-2", "line-4"], "{kept:?}");
    assert_eq!(
        notices(&kept[3..4]),
        [1],
        "the notice follows the next good line: {kept:?}"
    );
    assert_eq!(kept[4..], ["line-5", "line-6"], "{kept:?}");
    assert_eq!(w.dropped_lines(), 1);
}

/// After a write that stopped part-way, the next record starts on a line of its own (L1f).
#[test]
fn l1f_a_partial_write_cannot_glue_the_next_record_to_it() {
    let (w, _f, out) = scripted(vec![Step::Accept, Step::Half]);
    for n in 1..=3 {
        line(&w, &format!("line-{n}"));
    }
    assert!(
        out.wait_for(|t| t.contains("dropped")),
        "no notice: {}",
        out.text()
    );
    let lines = out.lines();
    assert_eq!(lines[0], "line-1");
    assert_ne!(lines[1], "line-2", "the half line is cut short: {lines:?}");
    assert_eq!(
        lines[2], "line-3",
        "line 3 starts on its own line: {lines:?}"
    );
    assert_eq!(w.dropped_lines(), 1, "the half line is counted");
}

/// A notice that fails part-way is sent again, on a line of its own (L1i).
#[test]
fn l1i_a_failed_notice_is_sent_again_after_the_next_line() {
    let (w, _f, out) = scripted_with(vec![Step::Accept, Step::Half], 32);
    line(&w, &"x".repeat(64));
    line(&w, "a");
    line(&w, "b");
    assert!(
        out.wait_for(|t| t
            .lines()
            .any(|l| l.ends_with("while stderr was not draining"))),
        "the notice was not sent again: {}",
        out.text()
    );
    let lines = out.lines();
    let b = lines
        .iter()
        .position(|l| l == "b")
        .expect("b on its own line");
    assert_eq!(notices(&lines[b + 1..]), [1], "{lines:?}");
    assert_eq!(
        w.dropped_lines(),
        1,
        "a failed notice is not itself a dropped line"
    );
}

/// A filler line of 9 bytes with its newline.
const FILL: &str = "fill-123";

/// With the writer parked, lines past the byte bound are dropped before the slots run out (L1c-1).
#[test]
fn l1c1_bytes_run_out_before_slots_and_drain_back_to_zero() {
    let (w, _f, gate, out) = parked(8, 40);
    line(&w, "first");
    assert!(gate.wait_entered(), "the writer never took a line");
    for _ in 0..6 {
        line(&w, FILL); // four fit in 40 bytes
    }
    assert_eq!(w.dropped_lines(), 2);
    assert_eq!(w.queued_bytes(), 36);
    gate.open();
    assert!(out.wait_for(|t| t.contains("dropped 2")), "{}", out.text());
    assert!(
        out.wait_for(|t| t.matches(FILL).count() == 4),
        "{}",
        out.text()
    );
    assert_eq!(
        w.queued_bytes(),
        0,
        "every reservation is released once written"
    );
}

/// With the writer parked, a full channel refunds the bytes it reserved (L1c-2).
#[test]
fn l1c2_slots_run_out_before_bytes_and_each_refused_send_refunds() {
    let (w, _f, gate, _out) = parked(2, 1 << 20);
    line(&w, "first");
    assert!(gate.wait_entered(), "the writer never took a line");
    for _ in 0..5 {
        line(&w, FILL);
    }
    assert_eq!(w.dropped_lines(), 3);
    assert_eq!(
        w.queued_bytes(),
        2 * 9,
        "only the two queued lines hold bytes"
    );
    gate.open();
}

/// A line over the byte bound is dropped whole, and the next one goes through (L1c-3).
#[test]
fn l1c3_a_line_over_the_byte_bound_is_dropped_and_the_next_one_written() {
    let (w, _f, gate, out) = parked(8, 16);
    gate.open();
    let big = "x".repeat(32);
    line(&w, &big);
    line(&w, "small");
    assert!(out.wait_for(|t| t.contains("dropped 1")), "{}", out.text());
    assert_eq!(out.lines()[0], "small");
    assert!(
        !out.text().contains(&big[..4]),
        "no part of the big line is written"
    );
    assert_eq!(w.dropped_lines(), 1);
}

/// Drops made while a notice is being written are reported by the next notice (L1e).
#[test]
fn l1e_drops_during_a_notice_write_go_in_the_next_notice() {
    let (w, _f, gate, out) = parked_on(Some("dropped"), 8, 16);
    let big = "x".repeat(32);
    line(&w, &big);
    line(&w, "a");
    assert!(gate.wait_entered(), "the first notice never started");
    for _ in 0..3 {
        line(&w, &big);
    }
    gate.open();
    line(&w, "b");
    assert!(
        out.wait_for(|t| notices(&t.lines().map(str::to_owned).collect::<Vec<_>>()).len() == 2),
        "{}",
        out.text()
    );
    assert_eq!(notices(&out.lines()), [1, 3]);
    assert_eq!(w.dropped_lines(), 4);
}

/// The JSON notice is one object with exactly five keys; the text notice is one fixed sentence (L1g).
#[test]
fn l1g_the_notice_has_one_fixed_shape_in_each_format() {
    let json: serde_json::Value =
        serde_json::from_str(notice_line(7, NoticeFormat::Json).trim_end())
            .expect("one JSON object");
    let keys: Vec<&str> = json
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 5, "{keys:?}");
    for k in ["timestamp", "level", "target", "message", "dropped"] {
        assert!(keys.contains(&k), "{k} missing: {keys:?}");
    }
    assert_eq!(json["dropped"], 7);
    assert_eq!(json["level"], "WARN");
    assert_eq!(json["target"], "mcp_gateway::log");
    chrono::DateTime::parse_from_rfc3339(json["timestamp"].as_str().expect("a string"))
        .expect("RFC 3339");

    let text = notice_line(7, NoticeFormat::Text);
    let (ts, rest) = text.split_once("  ").expect("a timestamp, then the line");
    chrono::DateTime::parse_from_rfc3339(ts).expect("RFC 3339");
    assert_eq!(
        rest,
        "WARN mcp_gateway::log: dropped 7 log lines while stderr was not draining\n"
    );
}

/// The flush writes a pending notice even when no line follows the drop (L1d-1).
#[test]
fn l1d1_the_flush_writes_the_pending_notice_before_it_returns() {
    let (w, f, gate, out) = parked(8, 16);
    gate.open();
    line(&w, &"x".repeat(32)); // dropped, and nothing is written after it
    flush(f);
    assert!(
        out.text().contains("dropped 1 log lines"),
        "no notice at flush: {}",
        out.text()
    );
}

/// A scripted clock that moves by the next step each time it is read.
fn clock(start: Instant, steps: &[u64]) -> impl Fn() -> Instant + '_ {
    let at = std::cell::Cell::new(0);
    move || {
        let i = at.get();
        at.set(i + 1);
        start + Duration::from_millis(steps[..i.min(steps.len())].iter().sum())
    }
}

/// One deadline for the whole flush, whatever the queue does (L1d-2).
#[test]
fn l1d2_the_flush_keeps_one_deadline_and_waits_only_for_what_is_left() {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(2);

    // Never sendable: the deadline passes, and nothing is waited for.
    let waited = std::cell::Cell::new(None);
    let sent = flush_until(
        deadline,
        || Sent::Full,
        |d| {
            waited.set(Some(d));
            true
        },
        clock(start, &[1000, 1000]),
    );
    assert!(!sent);
    assert_eq!(waited.get(), None, "no wait when the marker never went in");

    // Sendable at once: the wait gets the whole budget.
    let sent = flush_until(
        deadline,
        || Sent::Yes,
        |d| {
            waited.set(Some(d));
            true
        },
        clock(start, &[]),
    );
    assert!(sent);
    assert_eq!(waited.get(), Some(Duration::from_secs(2)));

    // Sendable at the last step before expiry: the wait gets only what is left.
    let tries = std::cell::Cell::new(0);
    let scripted_send = || {
        tries.set(tries.get() + 1);
        if tries.get() < 3 {
            Sent::Full
        } else {
            Sent::Yes
        }
    };
    let sent = flush_until(
        deadline,
        scripted_send,
        |d| {
            waited.set(Some(d));
            true
        },
        clock(start, &[500, 1000]),
    );
    assert!(sent);
    assert_eq!(
        waited.get(),
        Some(Duration::from_millis(500)),
        "the remaining budget, never a fresh one"
    );
}

/// The production flush deadline is 2 s (L1d-2).
#[test]
fn l1d2_the_production_flush_deadline_is_two_seconds() {
    assert_eq!(LOG_FLUSH_DEADLINE, Duration::from_secs(2));
}

/// An audit-field line is dropped and counted like any other while the queue
/// is full, and the call that emits it returns (L1a).
#[test]
fn l1a_an_audit_field_line_is_dropped_and_counted_when_the_queue_is_full() {
    crate::test_log_capture::keep_interest_open();
    let (w, _f, gate, out) = parked(1, 1 << 20);
    line(&w, "first");
    assert!(gate.wait_entered(), "the writer never took a line");
    line(&w, "fills the one slot");
    let layer = crate::log_layer(NoticeFormat::Text, w.clone());
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .with(layer);
    tracing::subscriber::with_default(subscriber, || {
        crate::key_server::audit::emit(&crate::key_server::audit::AuditEvent::invalid(
            "probe", None,
        ));
    });
    assert_eq!(
        w.dropped_lines(),
        1,
        "the audit line was dropped, not waited for"
    );
    gate.open();
    assert!(out.wait_for(|t| t.contains("dropped 1")), "{}", out.text());
    assert!(!out.text().contains("key_server audit"), "{}", out.text());
}

/// A text line keeps its escaping through the queue: one line, and no raw
/// control sequence from a field (L1h).
#[test]
fn l1h_a_text_line_is_still_escaped_on_its_way_through_the_queue() {
    crate::test_log_capture::keep_interest_open();
    let (w, _f, out) = scripted(vec![]);
    let layer = crate::log_layer(NoticeFormat::Text, w);
    tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
        tracing::warn!(
            agent = %"mtls:runner\n2026-10-28T12:00:00Z  WARN forged: admin granted\x1b[2K",
            "denied"
        );
    });
    assert!(out.wait_for(|t| t.contains("denied")), "{}", out.text());
    let text = out.text();
    assert_eq!(
        text.matches('\n').count(),
        1,
        "one event, one line: {text:?}"
    );
    assert!(
        !text.contains("\x1b[2K"),
        "a field wrote a raw control sequence: {text:?}"
    );
}
