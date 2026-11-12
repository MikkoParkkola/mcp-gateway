// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JOIN.4 joiner-level rows: a record reaches a call only when the bytes from
//! the call's end to the record's end are at most `DELIVERY_WINDOW`. The
//! distances are synthetic `above` values, so the exact edge is testable.

use serde_json::json;

use super::answer::{DELIVERY_WINDOW as W, Joined, MAX_PENDING, Searched, Why};
use super::joiner::{Joiner, Seen};
use super::reader::{Line, Which};
use super::rows::Check;
use crate::security::transparency_log::recompute_entry_hash;

fn call(trace: &str) -> Line {
    Line {
        log: Which::Invocation,
        entry: json!({"counter": 1, "trace_id": trace, "request_hash": "sha256:aa"}),
        segment: 0,
        span: None,
    }
}

/// An unsigned delivery record for `trace`, hashed correctly.
fn delivery(trace: &str) -> Line {
    let mut entry = json!({
        "counter": 2, "trace_id": trace, "event": "response_delivery_attempt",
        "response_stage": "transport_finalized", "response_effect": "delivered",
        "response_findings": [],
    });
    entry["entry_hash"] = recompute_entry_hash(&entry).unwrap().into();
    Line {
        log: Which::Invocation,
        entry,
        segment: 0,
        span: None,
    }
}

/// The same record with a field changed after hashing: it fails the trust rule.
fn edited(trace: &str) -> Line {
    let mut line = delivery(trace);
    line.entry["response_effect"] = json!("refused");
    line
}

fn seen(above: u64) -> Seen {
    Seen {
        above,
        head_covered: false,
    }
}

fn is_found(joined: &Joined) -> bool {
    matches!(joined, Joined::Found(_))
}

#[test]
fn r52_the_window_edge_is_exact() {
    for (distance, found) in [(W, true), (W + 1, false)] {
        let check = Check::bare(None);
        let mut joiner = Joiner::new(&check);
        assert!(joiner.observe(&delivery("gw-t"), 1_000));
        let joined = joiner.join(&call("gw-t"), seen(1_000 + distance));
        joiner.count(&joined);
        assert_eq!(is_found(&joined), found, "distance {distance}: {joined:?}");
        assert_eq!(joiner.delivery_beyond_window, usize::from(!found));
        if !found {
            assert_eq!(joined, Joined::NoRecord(Searched::Finished));
        }
    }
}

#[test]
fn r53_a_duplicate_reaches_by_its_nearest_record_and_counts_once_beyond() {
    // One record inside the window, one beyond: fail closed as a duplicate.
    let check = Check::bare(None);
    let mut joiner = Joiner::new(&check);
    joiner.observe(&delivery("gw-t"), 0);
    joiner.observe(&delivery("gw-t"), 200 * 1024);
    let joined = joiner.join(&call("gw-t"), seen(300 * 1024));
    assert_eq!(joined, Joined::Incomplete(Why::Duplicate));
    // Both beyond: no record, counted once.
    let check = Check::bare(None);
    let mut joiner = Joiner::new(&check);
    joiner.observe(&delivery("gw-t"), 0);
    joiner.observe(&delivery("gw-t"), 10);
    let joined = joiner.join(&call("gw-t"), seen(W + 11));
    joiner.count(&joined);
    assert_eq!(joined, Joined::NoRecord(Searched::Finished));
    assert_eq!(joiner.delivery_beyond_window, 1);
}

#[test]
fn r54_a_tombstone_reaches_only_inside_the_window() {
    for (distance, evicted) in [(10, true), (W + 1, false)] {
        let check = Check::bare(None);
        let mut joiner = Joiner::new(&check);
        joiner.observe(&delivery("gw-t"), 0);
        for i in 0..=MAX_PENDING {
            joiner.observe(&delivery(&format!("gw-o{i}")), 0);
        }
        let joined = joiner.join(&call("gw-t"), seen(distance));
        joiner.count(&joined);
        assert_eq!(
            joined == Joined::Incomplete(Why::Evicted),
            evicted,
            "distance {distance}: {joined:?}"
        );
        assert_eq!(joiner.delivery_beyond_window, usize::from(!evicted));
    }
}

#[test]
fn r55_a_second_call_row_of_a_joined_trace_obeys_the_window() {
    let check = Check::bare(None);
    let mut joiner = Joiner::new(&check);
    joiner.observe(&delivery("gw-t"), 0);
    assert!(is_found(&joiner.join(&call("gw-t"), seen(10))));
    let far = joiner.join(&call("gw-t"), seen(W + 1));
    joiner.count(&far);
    assert_eq!(far, Joined::NoRecord(Searched::Finished));
    assert_eq!(joiner.delivery_beyond_window, 1);
}

#[test]
fn r56_a_reopened_trace_keeps_its_reason_through_compaction_inside_the_window() {
    let check = Check::bare(None);
    let mut joiner = Joiner::new(&check);
    joiner.observe(&delivery("gw-t"), 0);
    assert!(is_found(&joiner.join(&call("gw-t"), seen(10))));
    // A second, tampered record reopens the joined trace as poisoned.
    joiner.observe(&edited("gw-t"), 20);
    for i in 0..(2 * MAX_PENDING + 10) {
        joiner.observe(&delivery(&format!("gw-o{i}")), 30);
    }
    let joined = joiner.join(&call("gw-t"), seen(1_000));
    assert_eq!(joined, Joined::Incomplete(Why::Invalid));
}

#[test]
fn r57_the_nearest_untraceable_failure_decides_reach() {
    let check = Check::bare(None);
    let mut joiner = Joiner::new(&check);
    let mut failing = delivery("gw-x");
    failing.entry.as_object_mut().unwrap().remove("trace_id");
    failing.entry["response_effect"] = json!("refused");
    joiner.observe(&failing, 50);
    assert_eq!(
        joiner.join(&call("gw-t"), seen(50 + W)),
        Joined::Incomplete(Why::Unattributed)
    );
    assert_eq!(
        joiner.join(&call("gw-t"), seen(50 + W + 1)),
        Joined::NoRecord(Searched::Finished)
    );
}

/// The look-above hands each folded line the bytes of log above it, counted in
/// line lengths with terminators across segments, never as a file offset: lines
/// read from several small segments sum to the same total as one segment would.
#[tokio::test]
async fn r58_look_above_counts_bytes_across_segments() {
    use super::answer_fixture::Fixture;
    use super::answer_list_tests::get;
    use super::reader::{Limits, Look, read_page_joined};

    let fx = Fixture::rotating(None, 4096);
    for i in 0..40 {
        fx.call(&format!("gw-c{i}"));
    }
    let (_, first) = get(&fx, &[("limit", "30")]).await;
    let token = first["next_cursor"].as_str().expect("a cursor").to_string();
    let cursor = super::cursor::decode(&token).expect("a cursor");
    let mut folded: Vec<(u64, u64)> = Vec::new();
    let mut fold = |line: &Line, above: u64| {
        folded.push((line.entry.to_string().len() as u64 + 1, above));
    };
    let limits = Limits {
        matches: 1,
        bytes: 8 << 20,
    };
    let page = read_page_joined(
        &fx.path,
        None,
        Some(&cursor),
        limits,
        Look::Fold(&mut fold),
        |_, _| false,
    )
    .unwrap();
    assert!(folded.len() >= 20, "{} lines folded", folded.len());
    let total: u64 = folded.iter().map(|(len, _)| len).sum();
    // The oldest folded line has everything else above it, the newest nothing.
    let mut above_it = total;
    for (len, above) in &folded {
        above_it -= len;
        assert_eq!(*above, above_it, "a folded line's `above`");
    }
    assert_eq!(above_it, 0);
    // The page continues counting from the look-above's total.
    assert!(page.above_end.above >= total);
}
