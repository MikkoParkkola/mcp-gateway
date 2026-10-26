// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

// ── CostRecord ────────────────────────────────────────────────────

#[test]
fn cost_record_computes_cost_from_tokens() {
    // GIVEN: 1000 tokens at $15/M
    let rec = CostRecord::new("srv", "tool", 1_000, 15.0);
    // THEN: cost = 1000 * 15 / 1_000_000 = $0.015
    assert!((rec.estimated_cost_usd - 0.015).abs() < 1e-9);
    assert_eq!(rec.backend, "srv");
    assert_eq!(rec.tool, "tool");
    assert_eq!(rec.token_count, 1_000);
}

#[test]
fn cost_record_zero_tokens_is_zero_cost() {
    let rec = CostRecord::new("srv", "tool", 0, 15.0);
    assert!(rec.estimated_cost_usd.abs() < 1e-12);
}

// ── BudgetWindow ──────────────────────────────────────────────────

#[test]
fn budget_window_secs_values_are_correct() {
    assert_eq!(BudgetWindow::Day.secs(), 86_400);
    assert_eq!(BudgetWindow::Week.secs(), 7 * 86_400);
    assert_eq!(BudgetWindow::Month.secs(), 30 * 86_400);
}

// ── SessionCost ───────────────────────────────────────────────────

#[test]
fn session_cost_accumulates_records() {
    let sc = SessionCost::new("sid1", Some("key_a".to_string()));
    sc.record(&CostRecord::new("srv1", "t1", 500, 15.0));
    sc.record(&CostRecord::new("srv2", "t2", 300, 15.0));

    let snap = sc.snapshot();
    assert_eq!(snap.call_count, 2);
    assert_eq!(snap.total_tokens, 800);
    assert!((snap.total_cost_usd - (800.0 * 15.0 / 1_000_000.0)).abs() < 1e-9);
    assert_eq!(snap.by_backend.len(), 2);
    assert_eq!(snap.by_tool.len(), 2);
}

#[test]
fn session_cost_groups_by_backend_and_tool() {
    let sc = SessionCost::new("sid2", None);
    sc.record(&CostRecord::new("srv1", "tool", 100, 10.0));
    sc.record(&CostRecord::new("srv1", "tool", 200, 10.0));
    sc.record(&CostRecord::new("srv2", "other", 50, 10.0));

    let snap = sc.snapshot();
    // Two distinct backends
    let srv1 = snap
        .by_backend
        .iter()
        .find(|b| b.backend == "srv1")
        .unwrap();
    assert_eq!(srv1.call_count, 2);
    assert_eq!(srv1.token_count, 300);
    // Two distinct tool keys
    assert_eq!(snap.by_tool.len(), 2);
}

// ── KeyCost ───────────────────────────────────────────────────────

/// Record `rec` on `kc` at the current time.
fn spend(kc: &KeyCost, rec: &CostRecord) {
    kc.record(rec, crate::clock::unix_secs().ok());
}

#[test]
fn key_cost_window_totals_exclude_old_records() {
    let kc = KeyCost::new("k1");
    // Insert a record manually with a very old timestamp
    let mut old_rec = CostRecord::new("s", "t", 9_999, 15.0);
    old_rec.timestamp = Some(1); // epoch + 1 second — definitely older than 24 h
    spend(&kc, &old_rec);
    spend(&kc, &CostRecord::new("s", "t", 100, 15.0));

    let (tokens, _) = kc
        .window_totals(BudgetWindow::Day.secs())
        .expect("a readable clock");
    // Only the recent record should count
    assert_eq!(tokens, 100);
}

#[test]
fn key_cost_keeps_no_bucket_for_spend_past_the_month() {
    let kc = KeyCost::new("k5");
    let mut old = CostRecord::new("s", "t", 100, 15.0);
    old.timestamp = Some(1);
    spend(&kc, &old);
    spend(&kc, &CostRecord::new("s", "t", 50, 15.0));
    // One hour bucket (the current one); the old spend lives on only in the
    // all-time per-tool row.
    assert_eq!(kc.spend.lock().0.len(), 1);
    assert_eq!(kc.snapshot().by_tool[0].token_count, 150);
}

// ── CostTracker ───────────────────────────────────────────────────

#[test]
fn cost_tracker_records_session_and_key() {
    let tracker = CostTracker::new();
    tracker.record("session1", Some("alice"), "backend1", "tool1", 1_000, 15.0);
    tracker.record("session1", Some("alice"), "backend1", "tool2", 500, 15.0);

    let snap = tracker.session_snapshot("session1").unwrap();
    assert_eq!(snap.call_count, 2);
    assert_eq!(snap.total_tokens, 1_500);
    assert_eq!(snap.api_key_name.as_deref(), Some("alice"));

    let key_snap = tracker.key_snapshot("alice").unwrap();
    assert_eq!(key_snap.api_key_name, "alice");
    // 1500 tokens in 24 h window
    assert_eq!(key_snap.window_24h.tokens, Some(1_500));
}

#[test]
fn cost_tracker_session_without_key() {
    let tracker = CostTracker::new();
    tracker.record("session-anon", None, "srv", "t", 200, 15.0);

    assert!(tracker.session_snapshot("session-anon").is_some());
    // No key entry created
    assert_eq!(tracker.per_key.len(), 0);
}

#[test]
fn cost_tracker_aggregate_sums_all_sessions() {
    let tracker = CostTracker::new();
    tracker.record("s1", Some("a"), "srv", "t", 100, 15.0);
    tracker.record("s2", Some("b"), "srv", "t", 200, 15.0);

    let agg = tracker.aggregate();
    assert_eq!(agg.session_count, 2);
    assert_eq!(agg.total_calls, 2);
    assert_eq!(agg.total_tokens, 300);
}

#[test]
fn cost_tracker_remove_session() {
    let tracker = CostTracker::new();
    tracker.record("s1", None, "srv", "t", 10, 15.0);
    assert!(tracker.session_snapshot("s1").is_some());
    tracker.remove_session("s1");
    assert!(tracker.session_snapshot("s1").is_none());
}

#[test]
fn removing_a_session_keeps_its_calls_in_the_aggregate() {
    let tracker = CostTracker::new();
    tracker.record("s1", None, "srv", "t", 100, 10.0);
    tracker.record("s2", None, "srv", "t", 50, 10.0);
    let before = tracker.aggregate();

    tracker.remove_session("s1");

    let after = tracker.aggregate();
    assert_eq!(after.session_count, 1, "the session itself is gone");
    assert_eq!(after.total_calls, before.total_calls);
    assert_eq!(after.total_tokens, before.total_tokens);
    assert!((after.total_cost_usd - before.total_cost_usd).abs() < 1e-9);
}

#[test]
fn cost_tracker_all_sessions_and_all_keys() {
    let tracker = CostTracker::new();
    tracker.record("s1", Some("k1"), "srv", "t", 10, 15.0);
    tracker.record("s2", Some("k2"), "srv", "t", 20, 15.0);

    assert_eq!(tracker.all_sessions().len(), 2);
    assert_eq!(tracker.all_keys().len(), 2);
}

// ── AggregateCost ─────────────────────────────────────────────────

#[test]
fn aggregate_cost_is_zero_on_empty_tracker() {
    let tracker = CostTracker::new();
    let agg = tracker.aggregate();
    assert_eq!(agg.session_count, 0);
    assert_eq!(agg.total_calls, 0);
    assert!(agg.total_cost_usd.abs() < 1e-12);
}

#[test]
fn an_empty_session_id_opens_no_session_bucket() {
    // A 2026-07-28 request has no session: its spend counts per key only.
    let tracker = CostTracker::new();
    tracker.record("", Some("alice"), "srv", "t", 200, 15.0);
    tracker.record("", Some("bob"), "srv", "t", 100, 15.0);

    assert!(tracker.session_snapshot("").is_none());
    assert!(tracker.all_sessions().is_empty());
    assert_eq!(
        tracker.key_snapshot("alice").unwrap().window_24h.tokens,
        Some(200)
    );
    assert_eq!(
        tracker.key_snapshot("bob").unwrap().window_24h.tokens,
        Some(100)
    );
}

#[test]
fn session_less_spend_still_counts_in_the_aggregate() {
    // The admin total covers every call, with or without a session.
    let tracker = CostTracker::new();
    tracker.record("s1", Some("alice"), "srv", "t", 100, 15.0);
    tracker.record("", Some("bob"), "srv", "t", 200, 15.0);

    let total = tracker.aggregate();
    assert_eq!(total.total_calls, 2);
    assert_eq!(total.total_tokens, 300);
    assert_eq!(
        total.session_count, 1,
        "no session was opened for the empty id"
    );
}

// ── Memory bound (MIK-8000) ───────────────────────────────────────

#[test]
fn many_calls_on_one_key_hold_a_bounded_number_of_entries() {
    // GIVEN: the shared unauthenticated name answering 1000 calls on one tool
    let tracker = CostTracker::new();
    let calls = |n: u64| {
        for _ in 0..n {
            tracker.record("", Some("anonymous"), "srv", "t", 1, 15.0);
        }
    };
    calls(1_000);
    let early = tracker.key_retained("anonymous");
    // THEN: the key holds one tool row and an hour bucket (two, if the run
    // crossed an hour), not one entry per call
    assert!(early <= 3, "the key holds {early} entries after 1000 calls");
    // AND: ten times the calls hold no more, give or take one more hour
    // crossed (the bucket wrap is a tally test)
    calls(9_000);
    let late = tracker.key_retained("anonymous");
    assert!(
        late <= early + 1,
        "{late} entries after 10000 calls, {early} after 1000"
    );
    assert_eq!(
        tracker.key_snapshot("anonymous").unwrap().window_24h.tokens,
        Some(10_000)
    );
}

#[test]
fn many_calls_in_one_session_hold_a_bounded_number_of_entries() {
    // GIVEN: one session answering 1000 calls on one tool
    let tracker = CostTracker::new();
    for _ in 0..1_000 {
        tracker.record("s1", Some("public"), "srv", "t", 1, 15.0);
    }
    // THEN: the session holds one tool row, and its totals are exact
    assert!(
        tracker.session_retained("s1") <= 1,
        "the session holds {} entries after 1000 calls",
        tracker.session_retained("s1")
    );
    let snap = tracker.session_snapshot("s1").unwrap();
    assert_eq!((snap.call_count, snap.total_tokens), (1_000, 1_000));
    assert_eq!(snap.by_tool[0].call_count, 1_000);
}

#[test]
fn a_key_idle_for_a_month_reports_zero_windows_but_keeps_its_tool_rows() {
    // GIVEN: a key whose only spend was 31 days ago
    let kc = KeyCost::new("idle");
    let mut old = CostRecord::new("srv", "t", 7, 15.0);
    old.timestamp = Some(crate::clock::unix_secs().expect("a readable clock") - 31 * 86_400);
    spend(&kc, &old);
    // THEN: every window reads zero; the all-time row is still there
    let snap = kc.snapshot();
    assert_eq!(
        (
            snap.window_24h.tokens,
            snap.window_7d.tokens,
            snap.window_30d.tokens
        ),
        (Some(0), Some(0), Some(0))
    );
    assert_eq!(snap.by_tool[0].token_count, 7);
}

#[test]
fn the_sweep_drops_idle_keys_and_keeps_active_ones() {
    let tracker = CostTracker::new();
    let month_ago = crate::clock::unix_secs().expect("a readable clock") - 31 * 86_400;
    // GIVEN: a key idle for a month
    let idle = Arc::new(KeyCost::new("idle"));
    tracker
        .per_key
        .insert("idle".to_string(), Arc::clone(&idle));
    idle.last_spend.store(month_ago, Ordering::Relaxed);
    // WHEN: another key spends, which runs the due sweep
    tracker.record("", Some("active"), "srv", "t", 1, 15.0);
    // THEN: the idle key is gone; the active key stays
    assert!(tracker.key_snapshot("idle").is_none());
    assert!(tracker.key_snapshot("active").is_some());
}

#[test]
fn key_and_session_breakdowns_fold_tools_past_the_cap() {
    // GIVEN: one key on one session calling 300 distinct tools
    let tracker = CostTracker::new();
    for i in 0..300 {
        tracker.record("s1", Some("k"), "srv", &format!("t{i}"), 1, 15.0);
    }
    // THEN: both breakdowns hold the cap plus (other), with every call counted
    let session = tracker.session_snapshot("s1").unwrap();
    let key = tracker.key_snapshot("k").unwrap();
    for by_tool in [&session.by_tool, &key.by_tool] {
        assert_eq!(by_tool.len(), tally::MAX_TOOL_ROWS + 1);
        assert_eq!(by_tool.iter().map(|row| row.call_count).sum::<u64>(), 300);
    }
    assert_eq!(session.call_count, 300);
}
