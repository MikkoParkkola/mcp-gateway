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
    sc.record(CostRecord::new("srv1", "t1", 500, 15.0));
    sc.record(CostRecord::new("srv2", "t2", 300, 15.0));

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
    sc.record(CostRecord::new("srv1", "tool", 100, 10.0));
    sc.record(CostRecord::new("srv1", "tool", 200, 10.0));
    sc.record(CostRecord::new("srv2", "other", 50, 10.0));

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

#[test]
fn key_cost_window_totals_exclude_old_records() {
    let kc = KeyCost::new("k1", BudgetConfig::default());
    // Insert a record manually with a very old timestamp
    let mut old_rec = CostRecord::new("s", "t", 9_999, 15.0);
    old_rec.timestamp = 1; // epoch + 1 second — definitely older than 24 h
    kc.records.lock().push(old_rec);
    kc.record(CostRecord::new("s", "t", 100, 15.0));

    let (tokens, _) = kc.window_totals(BudgetWindow::Day.secs());
    // Only the recent record should count
    assert_eq!(tokens, 100);
}

#[test]
fn key_cost_budget_status_ok_when_no_limit() {
    let kc = KeyCost::new(
        "k2",
        BudgetConfig {
            hard_limit_usd: None,
            ..Default::default()
        },
    );
    kc.record(CostRecord::new("s", "t", 1_000_000, 15.0)); // $15
    assert_eq!(kc.budget_status(), BudgetStatus::Ok);
}

#[test]
fn key_cost_budget_status_warning_at_80_percent() {
    let kc = KeyCost::new(
        "k3",
        BudgetConfig {
            hard_limit_usd: Some(10.0),
            warning_fraction: 0.8,
            window: BudgetWindow::Day,
        },
    );
    // $8.5 = 85 % of $10 → Warning
    kc.record(CostRecord::new("s", "t", 566_667, 15.0)); // ≈ $8.50
    let status = kc.budget_status();
    assert!(matches!(status, BudgetStatus::Warning { .. }));
}

#[test]
fn key_cost_budget_status_exceeded_at_100_percent() {
    let kc = KeyCost::new(
        "k4",
        BudgetConfig {
            hard_limit_usd: Some(1.0),
            warning_fraction: 0.8,
            window: BudgetWindow::Day,
        },
    );
    kc.record(CostRecord::new("s", "t", 100_000, 15.0)); // $1.50
    assert!(matches!(kc.budget_status(), BudgetStatus::Exceeded { .. }));
}

#[test]
fn key_cost_evict_old_removes_stale_records() {
    let kc = KeyCost::new("k5", BudgetConfig::default());
    let mut old = CostRecord::new("s", "t", 100, 15.0);
    old.timestamp = 1;
    kc.records.lock().push(old);
    kc.record(CostRecord::new("s", "t", 50, 15.0));
    assert_eq!(kc.records.lock().len(), 2);
    kc.evict_old();
    assert_eq!(kc.records.lock().len(), 1);
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
    assert_eq!(key_snap.window_24h.tokens, 1_500);
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
fn cost_tracker_check_budget_ok_for_unknown_key() {
    let tracker = CostTracker::new();
    assert_eq!(tracker.check_budget("nonexistent"), BudgetStatus::Ok);
}

#[test]
fn cost_tracker_check_budget_exceeded() {
    let tracker = CostTracker::new();
    tracker.set_key_budget(
        "bob",
        BudgetConfig {
            hard_limit_usd: Some(0.001),
            ..Default::default()
        },
    );
    tracker.record("s", Some("bob"), "srv", "t", 100, 15.0); // > $0.001
    assert!(matches!(
        tracker.check_budget("bob"),
        BudgetStatus::Exceeded { .. }
    ));
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
