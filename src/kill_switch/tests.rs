use std::time::Duration;

use super::budget::{BudgetWindow, CapabilityErrorBudgetConfig, ErrorBudgetConfig};
use super::KillSwitch;

// ── KillSwitch::kill / revive / is_killed ────────────────────────────────

#[test]
fn kill_server_marks_it_as_killed() {
    // GIVEN: a fresh kill switch
    let ks = KillSwitch::new();
    // WHEN: a server is killed
    ks.kill("backend-a");
    // THEN: it reports as killed
    assert!(ks.is_killed("backend-a"));
}

#[test]
fn revive_server_unmarks_it() {
    // GIVEN: a killed server
    let ks = KillSwitch::new();
    ks.kill("backend-a");
    // WHEN: it is revived
    ks.revive("backend-a");
    // THEN: it is no longer killed
    assert!(!ks.is_killed("backend-a"));
}

#[test]
fn kill_is_idempotent() {
    let ks = KillSwitch::new();
    ks.kill("srv");
    ks.kill("srv"); // second call must not panic
    assert!(ks.is_killed("srv"));
}

#[test]
fn revive_is_idempotent() {
    let ks = KillSwitch::new();
    ks.revive("srv"); // reviving a live server must not panic
    assert!(!ks.is_killed("srv"));
}

#[test]
fn unknown_server_is_not_killed() {
    let ks = KillSwitch::new();
    assert!(!ks.is_killed("nonexistent"));
}

#[test]
fn killed_servers_returns_snapshot() {
    let ks = KillSwitch::new();
    ks.kill("a");
    ks.kill("b");
    let mut killed = ks.killed_servers();
    killed.sort();
    assert_eq!(killed, vec!["a", "b"]);
}

#[test]
fn killed_servers_empty_when_none_killed() {
    let ks = KillSwitch::new();
    assert!(ks.killed_servers().is_empty());
}

// ── Error budget: auto-kill ──────────────────────────────────────────────

/// Shared test helper: `min_samples = 1` lets tests exercise auto-kill
/// without needing to accumulate a minimum window of calls first.
const NO_MIN: usize = 1;

// ── Capability budget test helpers ───────────────────────────────────────

/// Build a `CapabilityErrorBudgetConfig` from raw test parameters.
fn cap_cfg(
    window_size: usize,
    window_duration: Duration,
    threshold: f64,
    min_samples: usize,
    cooldown: Duration,
) -> CapabilityErrorBudgetConfig {
    CapabilityErrorBudgetConfig {
        threshold,
        window_size,
        window_duration,
        min_samples,
        cooldown,
    }
}

/// Build a capability budget config with `min_samples = 1` (no guard).
fn cap_cfg_no_min(
    window_size: usize,
    window_duration: Duration,
    threshold: f64,
    cooldown: Duration,
) -> CapabilityErrorBudgetConfig {
    cap_cfg(window_size, window_duration, threshold, 1, cooldown)
}

#[test]
fn auto_kill_triggers_at_threshold() {
    // GIVEN: window of 4 calls, threshold 0.5, min_samples=1
    let ks = KillSwitch::new();
    let (size, dur, thresh) = (4, Duration::from_secs(300), 0.5);
    // WHEN: 2 successes then 2 failures (50% error rate == threshold)
    ks.record_success("srv", size, dur);
    ks.record_success("srv", size, dur);
    let triggered1 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
    let triggered2 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
    // THEN: second failure tips rate to 50% → auto-kill; first does not
    assert!(!triggered1, "first failure should not yet trigger auto-kill");
    assert!(triggered2, "second failure should trigger auto-kill");
    assert!(ks.is_killed("srv"));
}

#[test]
fn no_auto_kill_below_threshold() {
    // GIVEN: window of 10 calls, threshold 0.5, min_samples=1
    let ks = KillSwitch::new();
    let (size, dur, thresh) = (10, Duration::from_secs(300), 0.5);
    // WHEN: 6 successes + 4 failures (40% error rate < 50%)
    for _ in 0..6 {
        ks.record_success("srv", size, dur);
    }
    for _ in 0..4 {
        ks.record_failure("srv", size, dur, thresh, NO_MIN);
    }
    // THEN: server is NOT killed
    assert!(!ks.is_killed("srv"), "40% error rate should not trigger kill");
}

#[test]
fn auto_kill_does_not_fire_twice() {
    // GIVEN: window of 2, threshold 0.5, min_samples=1
    let ks = KillSwitch::new();
    let (size, dur, thresh) = (2, Duration::from_secs(300), 0.5);
    // First failure: rate=100% >= 50% → auto-kills
    let triggered1 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
    assert!(triggered1, "first failure should trigger auto-kill (100% error rate)");
    assert!(ks.is_killed("srv"));
    // Second failure: server already killed, must NOT re-trigger
    let triggered2 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
    assert!(!triggered2, "already-killed server must not re-trigger");
    // Third failure: still must not re-trigger
    let triggered3 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
    assert!(!triggered3, "already-killed server must not re-trigger on 3rd call");
}

#[test]
fn revive_resets_error_budget() {
    // GIVEN: server auto-killed by budget (min_samples=1, threshold=0.5)
    let ks = KillSwitch::new();
    let thresh = 0.5;
    let (size, dur) = (4, Duration::from_secs(300));
    // Two failures → 100% error rate → auto-kill
    ks.record_failure("srv", size, dur, thresh, NO_MIN);
    ks.record_failure("srv", size, dur, thresh, NO_MIN);
    assert!(ks.is_killed("srv"), "should be auto-killed");
    // WHEN: revived
    ks.revive("srv");
    assert!(!ks.is_killed("srv"), "should be alive after revive");
    // THEN: 3 successes followed by 1 failure → 25% error rate < threshold
    ks.record_success("srv", size, dur);
    ks.record_success("srv", size, dur);
    ks.record_success("srv", size, dur);
    let triggered = ks.record_failure("srv", size, dur, thresh, NO_MIN);
    assert!(!triggered, "25% error rate after revive must not trigger auto-kill");
    assert!(!ks.is_killed("srv"), "server must remain alive");
}

// ── min_samples guard ────────────────────────────────────────────────────

#[test]
fn min_samples_prevents_kill_below_sample_count() {
    // GIVEN: 100% failure rate but only 9 calls (< min_samples=10)
    let ks = KillSwitch::new();
    let (size, dur, thresh, min) = (100, Duration::from_secs(300), 0.8, 10);
    for _ in 0..9 {
        let triggered = ks.record_failure("srv", size, dur, thresh, min);
        assert!(!triggered, "kill must not fire before min_samples reached");
    }
    // THEN: server is alive despite 100% error rate
    assert!(!ks.is_killed("srv"), "should not be killed before min_samples");
}

#[test]
fn min_samples_allows_kill_once_sample_count_reached() {
    // GIVEN: 90% failure rate, min_samples=10
    let ks = KillSwitch::new();
    let (size, dur, thresh, min) = (100, Duration::from_secs(300), 0.8, 10);
    // 1 success + 9 failures → window has exactly 10 samples at 90% error rate
    ks.record_success("srv", size, dur);
    for i in 0..9usize {
        let triggered = ks.record_failure("srv", size, dur, thresh, min);
        if i < 8 {
            // Total samples still < 10 after first 8 failures (1 success + 8 failures = 9)
            assert!(
                !triggered,
                "kill must not fire before min_samples reached (iteration {i})"
            );
        } else {
            // 10th sample: 9/10 = 90% >= 80% threshold → auto-kill
            assert!(triggered, "kill must fire at min_samples when threshold exceeded");
        }
    }
    assert!(ks.is_killed("srv"));
}

#[test]
fn min_samples_one_is_equivalent_to_no_guard() {
    // GIVEN: min_samples=1 — a single failure at 100% rate must auto-kill immediately
    let ks = KillSwitch::new();
    let (size, dur, thresh) = (100, Duration::from_secs(300), 0.5);
    let triggered = ks.record_failure("srv", size, dur, thresh, 1);
    assert!(triggered, "single failure with min_samples=1 must trigger kill");
    assert!(ks.is_killed("srv"));
}

// ── Default threshold is 0.8, not 0.5 ───────────────────────────────────

#[test]
fn default_threshold_does_not_kill_at_50_percent() {
    // GIVEN: default threshold (0.8) with min_samples=10
    let cfg = ErrorBudgetConfig::default();
    let ks = KillSwitch::new();
    // Fill window with exactly 50% failures (5 out of 10)
    for _ in 0..5 {
        ks.record_success("srv", cfg.window_size, cfg.window_duration);
    }
    for _ in 0..5 {
        ks.record_failure(
            "srv",
            cfg.window_size,
            cfg.window_duration,
            cfg.threshold,
            cfg.min_samples,
        );
    }
    // 50% error rate is below 80% default threshold
    assert!(
        !ks.is_killed("srv"),
        "50% error rate must not trigger kill at default 0.8 threshold"
    );
}

// ── Error budget: error_rate / window_counts ─────────────────────────────

#[test]
fn error_rate_zero_with_no_calls() {
    let ks = KillSwitch::new();
    assert!(ks.error_rate("unknown") < f64::EPSILON);
}

#[test]
fn error_rate_computed_correctly() {
    let ks = KillSwitch::new();
    let (size, dur) = (10, Duration::from_secs(300));
    ks.record_success("srv", size, dur);
    ks.record_success("srv", size, dur);
    // threshold=1.0 ensures auto-kill can never trigger; min=1 is irrelevant here
    ks.record_failure("srv", size, dur, 1.0, 1);
    let rate = ks.error_rate("srv");
    assert!((rate - 1.0 / 3.0).abs() < 1e-10, "expected 33% error rate");
}

#[test]
fn window_counts_returns_successes_and_failures() {
    let ks = KillSwitch::new();
    let (size, dur) = (100, Duration::from_secs(300));
    for _ in 0..3 {
        ks.record_success("srv", size, dur);
    }
    ks.record_failure("srv", size, dur, 1.0, 1);
    let (s, f) = ks.window_counts("srv");
    assert_eq!(s, 3);
    assert_eq!(f, 1);
}

// ── BudgetWindow ─────────────────────────────────────────────────────────

#[test]
fn budget_window_evicts_when_full() {
    // GIVEN: window of 3
    let mut w = BudgetWindow::new(3, Duration::from_secs(300));
    w.record(true);
    w.record(true);
    w.record(false);
    w.record(false); // this evicts the first entry (success)
    let (s, f) = w.counts();
    assert_eq!(s + f, 3, "window must not exceed max_calls");
}

#[test]
fn budget_window_evicts_expired_entries() {
    // GIVEN: window with 1ms max_age
    let mut w = BudgetWindow::new(100, Duration::from_millis(1));
    w.record(false);
    // Wait for entry to expire
    std::thread::sleep(Duration::from_millis(5));
    w.record(true); // triggers eviction of the expired failure
    let (s, f) = w.counts();
    assert_eq!(f, 0, "expired failure must be evicted");
    assert_eq!(s, 1);
}

#[test]
fn budget_window_reset_clears_all_entries() {
    let mut w = BudgetWindow::new(10, Duration::from_secs(60));
    w.record(false);
    w.record(false);
    w.reset();
    assert!(w.error_rate() < f64::EPSILON);
    let (s, f) = w.counts();
    assert_eq!(s, 0);
    assert_eq!(f, 0);
}

// ── ErrorBudgetConfig defaults ────────────────────────────────────────────

#[test]
fn error_budget_config_default_values() {
    let cfg = ErrorBudgetConfig::default();
    assert!((cfg.threshold - 0.8).abs() < 1e-10, "default threshold must be 0.8");
    assert_eq!(cfg.window_size, 100);
    assert_eq!(cfg.window_duration, Duration::from_secs(300));
    assert_eq!(cfg.min_samples, 10, "default min_samples must be 10");
}

// ── CapabilityErrorBudgetConfig defaults ─────────────────────────────────

#[test]
fn capability_error_budget_config_default_values() {
    let cfg = CapabilityErrorBudgetConfig::default();
    assert!((cfg.threshold - 0.8).abs() < 1e-10, "default threshold must be 0.8");
    assert_eq!(cfg.window_size, 50);
    assert_eq!(cfg.window_duration, Duration::from_secs(300));
    assert_eq!(cfg.min_samples, 5, "default min_samples must be 5");
    assert_eq!(cfg.cooldown, Duration::from_secs(300));
}

// ── Per-capability: is_capability_disabled ────────────────────────────────

#[test]
fn unknown_capability_is_not_disabled() {
    let ks = KillSwitch::new();
    assert!(!ks.is_capability_disabled("fulcrum", "calendar_get_event"));
}

#[test]
fn capability_not_disabled_after_success_only() {
    // GIVEN: only success records
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(50, Duration::from_secs(300), 1.0, Duration::from_secs(300));
    for _ in 0..10 {
        ks.record_capability_success("fulcrum", "calendar_get", &cfg);
    }
    // THEN: capability is not disabled
    assert!(!ks.is_capability_disabled("fulcrum", "calendar_get"));
}

// ── Per-capability: single capability failure doesn't kill backend ────────

#[test]
fn single_capability_failure_does_not_kill_backend() {
    // GIVEN: a capability with 100% error rate but backend has other successes
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(50, Duration::from_secs(300), 0.8, Duration::from_secs(300));

    // Backend gets many successes from other capabilities (backend-level budget)
    for _ in 0..20 {
        ks.record_success("fulcrum", 100, Duration::from_secs(300));
    }

    // One bad capability fires repeatedly
    for _ in 0..10 {
        ks.record_capability_failure("fulcrum", "broken_tool", &cfg);
    }

    // THEN: backend is alive; only the capability is disabled
    assert!(
        !ks.is_killed("fulcrum"),
        "backend must NOT be killed by a single capability's failures"
    );
    assert!(
        ks.is_capability_disabled("fulcrum", "broken_tool"),
        "broken_tool capability must be disabled"
    );
    // Other capabilities are unaffected
    assert!(
        !ks.is_capability_disabled("fulcrum", "healthy_tool"),
        "unaffected capability must remain enabled"
    );
}

// ── Per-capability: auto-disable at threshold ─────────────────────────────

#[test]
fn capability_auto_disabled_when_threshold_exceeded() {
    // GIVEN: min_samples=1, threshold=0.5
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(10, Duration::from_secs(300), 0.5, Duration::from_secs(300));

    // 1 success + 1 failure → 50% error rate == threshold → auto-disable
    ks.record_capability_success("fulcrum", "tool_a", &cfg);
    let triggered = ks.record_capability_failure("fulcrum", "tool_a", &cfg);
    assert!(triggered, "50% error rate should trigger auto-disable");
    assert!(ks.is_capability_disabled("fulcrum", "tool_a"));
}

#[test]
fn capability_not_disabled_below_threshold() {
    // GIVEN: 40% error rate < 50% threshold
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(10, Duration::from_secs(300), 0.5, Duration::from_secs(300));

    for _ in 0..6 {
        ks.record_capability_success("fulcrum", "tool_b", &cfg);
    }
    for _ in 0..4 {
        ks.record_capability_failure("fulcrum", "tool_b", &cfg);
    }
    assert!(
        !ks.is_capability_disabled("fulcrum", "tool_b"),
        "40% error rate must not disable capability"
    );
}

#[test]
fn capability_auto_disable_does_not_fire_twice() {
    // GIVEN: already-disabled capability
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(300));

    let first = ks.record_capability_failure("fulcrum", "tool_c", &cfg);
    assert!(first, "first failure (100% rate) should trigger auto-disable");

    let second = ks.record_capability_failure("fulcrum", "tool_c", &cfg);
    assert!(!second, "already-disabled capability must not re-trigger");
}

// ── Per-capability: min_samples guard ────────────────────────────────────

#[test]
fn capability_min_samples_prevents_disable_below_sample_count() {
    // GIVEN: 100% failure rate but only 4 calls < min_samples=5
    let ks = KillSwitch::new();
    let cfg = cap_cfg(50, Duration::from_secs(300), 0.8, 5, Duration::from_secs(300));

    for _ in 0..4 {
        let triggered = ks.record_capability_failure("fulcrum", "tool_d", &cfg);
        assert!(!triggered, "must not disable before min_samples reached");
    }
    assert!(!ks.is_capability_disabled("fulcrum", "tool_d"));
}

#[test]
fn capability_min_samples_allows_disable_once_reached() {
    // GIVEN: 80% failure rate, min_samples=5
    let ks = KillSwitch::new();
    let cfg = cap_cfg(50, Duration::from_secs(300), 0.8, 5, Duration::from_secs(300));

    // 1 success + 4 failures = 5 samples, 80% error rate == threshold
    ks.record_capability_success("fulcrum", "tool_e", &cfg);
    for i in 0..4usize {
        let triggered = ks.record_capability_failure("fulcrum", "tool_e", &cfg);
        if i < 3 {
            assert!(!triggered, "must not trigger before 5th sample (iteration {i})");
        } else {
            // 5th sample: 4/5 = 80% >= threshold
            assert!(triggered, "must trigger at 5th sample when threshold met");
        }
    }
    assert!(ks.is_capability_disabled("fulcrum", "tool_e"));
}

// ── Per-capability: auto-recovery after cooldown ──────────────────────────

#[test]
fn capability_auto_recovers_after_cooldown() {
    // GIVEN: a disabled capability with a 10ms cooldown
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_millis(10));

    let triggered = ks.record_capability_failure("fulcrum", "tool_f", &cfg);
    assert!(triggered, "should be disabled immediately");
    // Without cooldown param: confirms it is in the disabled set (no recovery check)
    assert!(ks.is_capability_disabled("fulcrum", "tool_f"));

    // Wait for cooldown to elapse
    std::thread::sleep(Duration::from_millis(20));

    // THEN: capability auto-recovers when checked with the cooldown
    // (the hot-path uses is_capability_disabled_with_cooldown)
    assert!(
        !ks.is_capability_disabled_with_cooldown("fulcrum", "tool_f", cfg.cooldown),
        "capability must auto-recover after cooldown when checked with cooldown param"
    );
    // And now the no-cooldown check also shows it as enabled (entry was purged)
    assert!(
        !ks.is_capability_disabled("fulcrum", "tool_f"),
        "capability must be purged from disabled set after auto-recovery"
    );
}

#[test]
fn capability_does_not_recover_before_cooldown_elapses() {
    // GIVEN: a disabled capability with a 60s cooldown
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(60));

    ks.record_capability_failure("fulcrum", "tool_g", &cfg);
    assert!(ks.is_capability_disabled("fulcrum", "tool_g"));

    // Immediately check — cooldown has not elapsed
    assert!(
        ks.is_capability_disabled("fulcrum", "tool_g"),
        "capability must not recover before cooldown elapses"
    );
}

// ── Per-capability: revive_capability ────────────────────────────────────

#[test]
fn revive_capability_re_enables_disabled_capability() {
    // GIVEN: a disabled capability
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(300));

    ks.record_capability_failure("fulcrum", "tool_h", &cfg);
    assert!(ks.is_capability_disabled("fulcrum", "tool_h"));

    // WHEN: revived by operator
    ks.revive_capability("fulcrum", "tool_h");

    // THEN: capability is re-enabled
    assert!(
        !ks.is_capability_disabled("fulcrum", "tool_h"),
        "capability must be re-enabled after operator revive"
    );
}

#[test]
fn revive_capability_resets_error_budget() {
    // GIVEN: a revived capability that receives successes
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(4, Duration::from_secs(300), 0.5, Duration::from_secs(300));

    // Disable it by recording 2 failures (100% error rate > 0.5 threshold)
    for _ in 0..2 {
        ks.record_capability_failure("fulcrum", "tool_i", &cfg);
    }
    ks.revive_capability("fulcrum", "tool_i");

    // After revive: 3 successes + 1 failure = 25% error rate (below threshold)
    for _ in 0..3 {
        ks.record_capability_success("fulcrum", "tool_i", &cfg);
    }
    let retrigger = ks.record_capability_failure("fulcrum", "tool_i", &cfg);
    assert!(!retrigger, "25% error rate after revive must not re-trigger");
    assert!(!ks.is_capability_disabled("fulcrum", "tool_i"));
}

#[test]
fn revive_capability_is_idempotent_on_live_capability() {
    let ks = KillSwitch::new();
    // Reviving a capability that was never disabled must not panic
    ks.revive_capability("fulcrum", "never_disabled");
    assert!(!ks.is_capability_disabled("fulcrum", "never_disabled"));
}

// ── Per-capability: disabled_capabilities list ────────────────────────────

#[test]
fn disabled_capabilities_returns_empty_when_none_disabled() {
    let ks = KillSwitch::new();
    let list = ks.disabled_capabilities(Duration::from_secs(300));
    assert!(list.is_empty());
}

#[test]
fn disabled_capabilities_lists_disabled_entries() {
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(300));

    ks.record_capability_failure("fulcrum", "tool_j", &cfg);
    ks.record_capability_failure("fulcrum", "tool_k", &cfg);

    let mut list = ks.disabled_capabilities(cfg.cooldown);
    list.sort();
    assert_eq!(list, vec!["fulcrum:tool_j", "fulcrum:tool_k"]);
}

#[test]
fn disabled_capabilities_purges_expired_entries_on_list() {
    // GIVEN: two disabled capabilities with a 10ms cooldown
    let ks = KillSwitch::new();
    let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_millis(10));

    ks.record_capability_failure("fulcrum", "tool_l", &cfg);
    ks.record_capability_failure("fulcrum", "tool_m", &cfg);

    // Both should be disabled immediately (use long cooldown for initial check)
    let before = ks.disabled_capabilities(Duration::from_secs(300));
    assert_eq!(before.len(), 2, "both capabilities should be listed as disabled");

    // Wait for both cooldowns to expire
    std::thread::sleep(Duration::from_millis(20));

    // WHEN: listing with the actual short cooldown
    let after = ks.disabled_capabilities(cfg.cooldown);

    // THEN: both entries are purged (expired), list is empty
    assert!(
        after.is_empty(),
        "expired entries must be purged from the disabled list"
    );
}

// ── Per-capability: error_rate / window_counts ────────────────────────────

#[test]
fn capability_error_rate_zero_with_no_calls() {
    let ks = KillSwitch::new();
    assert!(ks.capability_error_rate("fulcrum", "unknown") < f64::EPSILON);
}

#[test]
fn capability_window_counts_initial_state() {
    let ks = KillSwitch::new();
    let (s, f) = ks.capability_window_counts("fulcrum", "unknown");
    assert_eq!(s, 0);
    assert_eq!(f, 0);
}

#[test]
fn capability_error_rate_computed_correctly() {
    let ks = KillSwitch::new();
    // threshold=1.0 means auto-disable can never trigger
    let cfg = cap_cfg_no_min(10, Duration::from_secs(300), 1.0, Duration::from_secs(300));
    ks.record_capability_success("srv", "cap", &cfg);
    ks.record_capability_success("srv", "cap", &cfg);
    ks.record_capability_failure("srv", "cap", &cfg);
    let rate = ks.capability_error_rate("srv", "cap");
    assert!(
        (rate - 1.0 / 3.0).abs() < 1e-10,
        "expected 33% error rate, got {rate}"
    );
}

// ── Backend-level budget still works as fallback ──────────────────────────

#[test]
fn backend_level_budget_still_kills_when_all_capabilities_fail() {
    // GIVEN: many different capabilities all failing — backend threshold exceeded
    let ks = KillSwitch::new();
    let (backend_ws, backend_wd, thresh, min) = (20, Duration::from_secs(300), 0.8, 1_usize);
    let cap_cfg_val =
        cap_cfg_no_min(20, Duration::from_secs(300), 0.8, Duration::from_secs(300));

    // Flood the backend budget with failures (each represents a different
    // capability, so none individually dominates)
    for i in 0..20u32 {
        let cap = format!("tool_{i}");
        // Record on backend budget
        ks.record_failure("fulcrum", backend_ws, backend_wd, thresh, min);
        // Also record on per-capability budget
        ks.record_capability_failure("fulcrum", &cap, &cap_cfg_val);
    }

    // THEN: backend is killed because cumulative error rate exceeds threshold
    assert!(
        ks.is_killed("fulcrum"),
        "backend must be killed when cumulative error rate exceeds backend threshold"
    );
}
