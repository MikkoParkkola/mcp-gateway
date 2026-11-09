// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 receipt rows R13, R27, R38, R38b, R41: the bounded forward scan and
//! the continuity check across its window.

use serde_json::{Value, json};

use super::answer::{CHAIN_CHECKED, RECEIPT_SCAN};
use super::answer_fixture::{Dl, Fixture, SECRET, write_lines};
use super::answer_receipt_tests::{line_of, rcpt};

fn fat() -> Value {
    let many: Vec<Value> = (0..32)
        .map(|i| json!({"kind": format!("kind-{i:02}-padding-padding"), "severity": "low", "where": "text"}))
        .collect();
    json!(many)
}

#[test]
fn r13_the_receipt_scans_forward_within_its_bound() {
    let fx = Fixture::new(None);
    fx.call("gw-t1");
    for i in 0..10 {
        fx.call(&format!("gw-f{i}"));
    }
    fx.delivery("gw-t1", &Dl::effect("annotated"));
    fx.call("gw-t2");
    for i in 0..200 {
        fx.delivery(
            &format!("gw-g{i}"),
            &Dl::effect("annotated").findings(fat()),
        );
    }
    assert_eq!(rcpt(&fx, "gw-t1")["effect"], "annotated");
    let r = rcpt(&fx, "gw-t2");
    assert_eq!(r["effect"], "no_record");
    let search = &r["answer"]["search"];
    assert_eq!(search["stopped"], "byte limit");
    assert!(search["bytes"].as_u64().unwrap() <= RECEIPT_SCAN + 64 * 1024);
    assert!(search["lines"].as_u64().unwrap() > 0);
}

#[test]
fn r27_the_receipt_shows_the_failed_record() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| e["response_effect"] = json!("delivered"));
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "invalid");
    assert!(line_of(&r).contains("failed its integrity check"));
}

/// C(T), D(T), X with D's line removed, the chain not rewritten.
fn deleted_record() -> Fixture {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    fx.call("gw-x");
    let mut lines = fx.lines();
    lines.remove(fx.delivery_index("gw-t"));
    write_lines(&fx.path, &lines);
    fx
}

#[test]
fn r38_a_deleted_only_record_reads_no_record_and_a_broken_chain() {
    let fx = deleted_record();
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["effect"], "no_record");
    assert_eq!(r["chain"]["window"], "broken");
}

#[test]
fn r38b_continuity_is_checked_across_the_window() {
    let broken_by_edit = Fixture::new(None);
    broken_by_edit.call("gw-t");
    broken_by_edit.delivery("gw-t", &Dl::effect("refused"));
    broken_by_edit.call("gw-x");
    let x = broken_by_edit.lines().len() - 1;
    broken_by_edit.edit(x, |e| e["prev_entry_hash"] = json!("sha256:00"));
    let edited = rcpt(&broken_by_edit, "gw-t");
    assert_eq!(edited["chain"]["window"], "broken");
    assert_eq!(edited["effect"], "unknown", "{edited}");
    let deleted = rcpt(&deleted_record(), "gw-t");
    assert_eq!(deleted["chain"]["window"], "broken");
    assert_eq!(deleted["effect"], "no_record", "{deleted}");
    let intact = Fixture::new(None);
    intact.call("gw-t");
    intact.delivery("gw-t", &Dl::effect("refused"));
    intact.call("gw-x");
    let r = rcpt(&intact, "gw-t");
    assert_eq!(r["chain"]["window"], "intact");
    assert_eq!(r["chain"]["window_scope"], CHAIN_CHECKED);
}

#[test]
fn r41_the_receipt_labels_its_chain_check_and_never_says_verified() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["chain"]["window_scope"], CHAIN_CHECKED);
    assert!(!r["answer"].to_string().contains("verified"));
}
