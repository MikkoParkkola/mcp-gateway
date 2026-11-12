// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Receipt rows for the review findings on the forward scan: unrelated traces
//! never evict the call's own record, an unreadable line and a missing segment
//! are continuity failures, and a broken chain never leaves a stated effect.

use std::io::Write;

use serde_json::json;

use super::answer::CHAIN_UNFINISHED;
use super::answer_fixture::{Dl, Fixture, fat_findings};
use super::answer_receipt_tests::{line_of, rcpt};
use crate::security::transparency_log::segments::{list_segments, sealed_path};

#[test]
fn r13c_unrelated_traces_do_not_evict_the_calls_own_record() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    for i in 0..257 {
        fx.delivery(&format!("gw-u{i}"), &Dl::effect("delivered"));
    }
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["chain"]["window"], "intact", "premise: {r}");
    assert_eq!(r["answer"]["effect"], "delivered", "{r}");
    assert_eq!(r["effect"], "delivered", "{r}");
}

#[test]
fn r38c_a_broken_chain_after_a_found_delivery_is_explained_as_such() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    fx.call("gw-x");
    let x = fx.lines().len() - 1;
    fx.edit(x, |e| e["prev_entry_hash"] = json!("sha256:00"));
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["chain"]["window"], "broken", "premise: {r}");
    assert_eq!(r["answer"]["effect"], "unknown", "{r}");
    assert!(line_of(&r).contains("chain broke"), "{}", line_of(&r));
}

#[test]
fn r38d_a_complete_malformed_line_in_the_window_breaks_continuity() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&fx.path)
        .unwrap();
    file.write_all(b"{this is not json\n").unwrap();
    drop(file);
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["chain"]["window"], "broken", "{r}");
}

#[test]
fn r5b_a_missing_middle_segment_stops_the_scan_and_never_jumps() {
    let fx = Fixture::rotating(None, 4096);
    fx.call("gw-t");
    for i in 0..4 {
        let d = Dl::effect("annotated").findings(fat_findings());
        fx.delivery(&format!("gw-a{i}"), &d);
    }
    let seqs = |fx: &Fixture| -> Vec<u64> {
        list_segments(&fx.path)
            .unwrap()
            .iter()
            .map(|s| s.seq)
            .collect()
    };
    assert!(
        seqs(&fx).starts_with(&[0, 1, 2]),
        "premise: {:?}",
        seqs(&fx)
    );
    std::fs::remove_file(sealed_path(&fx.path, 1)).unwrap();
    let r = rcpt(&fx, "gw-t");
    assert_eq!(r["answer"]["search"]["stopped"], "missing segment", "{r}");
    assert_eq!(r["chain"]["window_scope"], CHAIN_UNFINISHED, "{r}");
}
