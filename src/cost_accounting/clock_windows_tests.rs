// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b B1 (AC.2, AC.16), the rows that compile today: on a clock
//! before 1970 the cost windows are unknown, never the sum of every bucket.
//! Base reads the wall clock directly in `now_secs`, so the forced clock does
//! not reach it: each row is red on base because base answers with the real
//! clock's windows where the row asks for "unknown".

use super::*;
use crate::clock::test_clock::{at_secs, before_epoch};

/// A fixed readable time, well after any bucket the tracker could hold.
const T: u64 = 1_800_000_000;

/// One key with one call, recorded at `T`.
fn tracker_with_spend() -> CostTracker {
    let tracker = CostTracker::new();
    let _clock = at_secs(T);
    tracker.record("", Some("ops"), "srv", "tool", 1_000, 15.0);
    tracker
}

/// MIK-8202 B1api (r2/r4): `/ui/api/costs` serializes `tracker.all_keys()`
/// (ui/mod.rs `costs`), so on a dark clock every window field is `null`.
/// This row serializes the same expression the handler does.
/// Mutant B1m: killed at the `is_null` assertion on `window_24h.tokens`.
/// Mutant "windows serialize 0 when unknown": killed at the same assertion.
#[test]
fn a_dark_clock_serializes_the_cost_windows_as_null() {
    let tracker = tracker_with_spend();
    let _dark = before_epoch();
    let keys = serde_json::to_value(tracker.all_keys()).expect("serialize");
    let key = &keys[0];
    for window in ["window_24h", "window_7d", "window_30d"] {
        for field in ["tokens", "cost_usd"] {
            assert!(
                key[window][field].is_null(),
                "{window}.{field} on a dark clock must be null (unknown): {key}"
            );
        }
    }
}

/// MIK-8202 B1api, the dashboard half (r4 folds): the four window cells in
/// index.html render a null window as "unknown", so none may fall back to 0
/// with `?? 0`. Red on base: all four use `?? 0`.
/// Mutant "a cell keeps `?? 0`": killed at the `assert!` naming that field.
#[test]
fn the_dashboard_window_cells_do_not_render_an_unknown_window_as_zero() {
    let html = include_str!("../gateway/ui/index.html");
    for field in [
        "window_24h?.tokens",
        "window_24h?.cost_usd",
        "window_7d?.cost_usd",
        "window_30d?.cost_usd",
    ] {
        let lines: Vec<&str> = html.lines().filter(|line| line.contains(field)).collect();
        assert!(
            !lines.is_empty(),
            "the dashboard no longer reads {field}: this row lost its subject"
        );
        for line in lines {
            assert!(
                !line.contains("?? 0"),
                "the dashboard renders an unknown {field} as 0: {line}"
            );
        }
    }
}
