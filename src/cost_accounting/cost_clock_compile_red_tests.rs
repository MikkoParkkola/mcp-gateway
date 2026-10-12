// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b B1/B2 (AC.2, AC.16), the rows that need the r3/r4 types:
//! `CostRecord.timestamp`, `SessionCostSnapshot::started_at`,
//! `WindowStats.tokens`/`cost_usd` and `EnforcerSnapshot.taken_at` become
//! `Option`, `None` when undated. COMPILE-RED on base (those fields are plain
//! numbers there); the mod line in mod.rs is held back until the fix lands.

use super::*;
use crate::clock::test_clock::{at_secs, before_epoch};

/// A fixed readable time.
const T: u64 = 1_800_000_000;
/// Past every idle window: 30 days for a key, one day for a caller.
const LATER: u64 = T + 40 * 86_400;

/// MIK-8202 B1 (r2/r4): on a dark clock every cost window is unknown
/// (`None`), not the sum of every retained bucket.
/// Mutant B1m (on Err the windows sum from 0 again): killed at the
/// `assert_eq!(.., None)` on `window_24h.tokens`.
#[test]
fn a_dark_clock_leaves_every_cost_window_unknown() {
    let tracker = CostTracker::new();
    {
        let _clock = at_secs(T);
        tracker.record("", Some("ops"), "srv", "tool", 1_000, 15.0);
        let control = tracker.key_snapshot("ops").expect("key");
        assert_eq!(control.window_24h.tokens, Some(1_000), "control");
    }
    let _dark = before_epoch();
    let snap = tracker.key_snapshot("ops").expect("key");
    for (name, window) in [
        ("24h", &snap.window_24h),
        ("7d", &snap.window_7d),
        ("30d", &snap.window_30d),
    ] {
        assert_eq!(window.tokens, None, "{name} tokens on a dark clock");
        assert_eq!(window.cost_usd, None, "{name} cost on a dark clock");
    }
}

/// MIK-8202 B1 (r2/r3/r4): a cost recorded on a dark clock is undated. It
/// counts in the lifetime totals (aggregate and the key's all-time per-tool
/// sums), and no window counts it once the clock reads.
/// Mutant B1n (the record dated 0): killed at `assert_eq!(rec.timestamp, None)`.
/// Mutant "undated record bucketed at the next readable time": killed at
/// `assert_eq!(snap.window_24h.tokens, Some(0))`.
/// Mutant "undated record dropped": killed at the aggregate tokens assertion.
#[test]
fn a_cost_recorded_on_a_dark_clock_is_undated_and_counted_only_in_lifetime_totals() {
    let tracker = CostTracker::new();
    {
        let _dark = before_epoch();
        let rec = CostRecord::new("srv", "tool", 1_000, 15.0);
        assert_eq!(rec.timestamp, None, "a dark record carries no date");
        tracker.record("s-dark", Some("ops"), "srv", "tool", 1_000, 15.0);
    }
    assert_eq!(
        tracker.aggregate().total_tokens,
        1_000,
        "the undated call counts in the lifetime total"
    );
    let _clock = at_secs(T);
    let snap = tracker.key_snapshot("ops").expect("key");
    let lifetime: u64 = snap.by_tool.iter().map(|t| t.token_count).sum();
    assert_eq!(lifetime, 1_000, "the key's all-time per-tool sums count it");
    assert_eq!(snap.window_24h.tokens, Some(0), "no window counts it");
    assert_eq!(snap.window_30d.tokens, Some(0), "no window counts it");
}

/// MIK-8202 B1rec (r3): an undated entry is neither expired nor idle once
/// the clock reads. A caller with only undated spend survives the caller
/// sweep, and a key with only undated spend survives the per-key idle sweep;
/// each sweep is triggered by a dated spend of another caller or key at
/// `LATER`, past both idle windows.
/// Mutant "undated stored as 0 and read as a time" (caller): killed at
/// `assert!(caller.is_some())`. Same mutant on the key's `last_spend`:
/// killed at `assert!(tracker.key_snapshot("dark-key").is_some())`.
/// Mutant "caller `first_spend` dated 0": killed at the `started_at` assertion.
#[test]
fn an_undated_entry_is_neither_expired_nor_idle_when_the_clock_reads() {
    let tracker = CostTracker::new();
    {
        let _dark = before_epoch();
        tracker.record_caller("dark-caller", "srv", "tool", 1_000, 15.0);
        tracker.record("", Some("dark-key"), "srv", "tool", 1_000, 15.0);
    }
    let _clock = at_secs(LATER);
    // Each first dated spend finds its sweep due (the next-sweep marks start at 0).
    tracker.record_caller("dated-caller", "srv", "tool", 1, 15.0);
    tracker.record("", Some("dated-key"), "srv", "tool", 1, 15.0);
    let caller = tracker.caller_snapshot("dark-caller");
    assert!(
        caller.is_some(),
        "an undated caller entry was swept or read as expired"
    );
    assert_eq!(
        caller.expect("caller").started_at,
        None,
        "undated first spend"
    );
    assert!(
        tracker.key_snapshot("dark-key").is_some(),
        "an undated key was swept as month-idle"
    );
}

/// MIK-8202 B1s (r3/r4): a session started on a dark clock has
/// `started_at: None`.
/// Mutant "`started_at` dated 0" (`Some(0)`): killed at the `assert_eq!`.
#[test]
fn a_session_started_on_a_dark_clock_has_no_start_time() {
    let tracker = CostTracker::new();
    {
        let _dark = before_epoch();
        tracker.record("s-dark", None, "srv", "tool", 1, 15.0);
    }
    let _clock = at_secs(T);
    let snap = tracker.session_snapshot("s-dark").expect("session");
    assert_eq!(snap.started_at, None);
    tracker.record("s-dated", None, "srv", "tool", 1, 15.0);
    assert_eq!(
        tracker
            .session_snapshot("s-dated")
            .expect("session")
            .started_at,
        Some(T),
        "control: a readable clock dates the session"
    );
}

/// MIK-8202 B2t (r3/r4): the UI `snapshot()` on a dark clock is undated
/// (`taken_at: None`); the save path keeps its own concrete reading.
/// Mutant "`taken_at` dated 0" (`Some(0)`): killed at the `assert_eq!(.., None)`.
#[cfg(feature = "cost-governance")]
#[test]
fn the_ui_cost_snapshot_on_a_dark_clock_is_undated() {
    use super::config::CostGovernanceConfig;
    use super::enforcer::BudgetEnforcer;
    use super::registry::CostRegistry;
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    let enforcer = BudgetEnforcer::new(cfg.clone(), std::sync::Arc::new(CostRegistry::new(&cfg)));
    {
        let _clock = at_secs(T);
        assert_eq!(enforcer.snapshot().taken_at, Some(T), "control");
    }
    let _dark = before_epoch();
    assert_eq!(enforcer.snapshot().taken_at, None);
}

/// Every number under a date-named key in `value`, at any depth.
fn dates(value: &serde_json::Value, out: &mut Vec<(String, serde_json::Value)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                let dated = key.ends_with("_at") || key == "timestamp" || key.starts_with("last_");
                if dated && inner.is_number() {
                    out.push((key.clone(), inner.clone()));
                }
                dates(inner, out);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| dates(item, out)),
        _ => {}
    }
}

/// Z-cost (MIK-8202 P4b, lead): a key born on a dark clock holds its
/// last-spend time as an internal 0, which is safe only if no read path
/// takes that 0 for a date. Nothing the tracker reports carries a 0 date for
/// entries born dark, and the one internal reader (the month-idle sweep)
/// takes the first real spend over the placeholder, so the key ages from it.
/// Mutant: the dated spend no longer replaces the placeholder (the
/// `last_spend.fetch_max` dropped), so the key is never idle: killed at
/// "a dated spend did not replace the undated placeholder".
#[test]
fn no_read_path_takes_the_undated_spend_placeholder_for_a_date() {
    let tracker = CostTracker::new();
    {
        let _dark = before_epoch();
        tracker.record_caller("dark-caller", "srv", "tool", 1_000, 15.0);
        tracker.record("", Some("dark-key"), "srv", "tool", 1_000, 15.0);
    }
    {
        let _clock = at_secs(T);
        let reported = serde_json::json!({
            "keys": tracker.all_keys(),
            "caller": tracker.caller_snapshot("dark-caller"),
        });
        let mut found = Vec::new();
        dates(&reported, &mut found);
        assert!(
            found.iter().all(|(_, value)| value.as_u64() != Some(0)),
            "a 0 reported as a date: {found:?}"
        );
        tracker.record("", Some("dark-key"), "srv", "tool", 1, 15.0);
    }
    let _clock = at_secs(LATER);
    // A spend on another key runs the month-idle sweep at LATER.
    tracker.record("", Some("other-key"), "srv", "tool", 1, 15.0);
    assert!(
        tracker.key_snapshot("dark-key").is_none(),
        "a dated spend did not replace the undated placeholder"
    );
}
