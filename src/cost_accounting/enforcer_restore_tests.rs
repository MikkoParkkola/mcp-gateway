// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Restoring the saved daily totals on start: what comes back, and what a
//! damaged or out-of-range `costs.json` cannot do to a cap.

use super::tests::enforcer_with;
use super::*;

/// A `costs.json` as the server writes it: per-tool and per-key daily
/// totals, saved at `saved_at`.
fn persisted(
    saved_at: u64,
    tools: &[(&str, f64)],
    keys: &[(&str, f64)],
) -> crate::cost_accounting::persistence::PersistedCosts {
    use crate::cost_accounting::persistence::{PersistedCosts, ToolTotal};
    PersistedCosts {
        saved_at,
        tool_totals: tools
            .iter()
            .map(|(name, usd)| {
                (
                    (*name).to_string(),
                    ToolTotal {
                        call_count: 0,
                        total_cost_usd: *usd,
                        avg_cost_usd: 0.0,
                    },
                )
            })
            .collect(),
        key_totals: keys.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
    }
}

fn now_secs() -> u64 {
    crate::cost_accounting::persistence::now_secs()
}

// MIK-8904.COST.1: what was spent today before a restart is spent today
// after it. The global total is the sum of the per-tool totals, which
// `record_spend` keeps equal; the file carries no global total of its own.
#[test]
fn a_restore_on_the_same_day_brings_back_every_daily_total() {
    let e = enforcer_with(true, Some(10.0), &[], &[], &[]);
    e.restore(&persisted(
        now_secs(),
        &[("a", 0.30), ("b", 0.20)],
        &[("k1", 0.25), ("k2", 0.25)],
    ));
    let snap = e.snapshot();
    assert!((snap.global_daily_usd - 0.50).abs() < 1e-6, "{snap:?}");
    assert!((snap.tool_daily["a"] - 0.30).abs() < 1e-6);
    assert!((snap.tool_daily["b"] - 0.20).abs() < 1e-6);
    assert!((snap.key_daily["k1"] - 0.25).abs() < 1e-6);
    assert!((snap.key_daily["k2"] - 0.25).abs() < 1e-6);
}

// MIK-8904.COST.2: a cap reached before the restart still refuses after it,
// for a key, a tool and the global budget.
#[test]
fn a_cap_reached_before_a_restart_still_refuses_after_it() {
    let saved = persisted(now_secs(), &[("t", 0.10)], &[("k1", 0.10)]);

    let per_key = enforcer_with(true, None, &[], &[("k1", 0.10)], &[("other", 0.05)]);
    per_key.restore(&saved);
    assert!(
        !per_key.check("other", Some("k1")).allowed,
        "the key's cap was forgotten"
    );

    let per_tool = enforcer_with(true, None, &[("t", 0.10)], &[], &[("t", 0.05)]);
    per_tool.restore(&saved);
    assert!(
        !per_tool.check("t", None).allowed,
        "the tool's cap was forgotten"
    );

    let global = enforcer_with(true, Some(0.10), &[], &[], &[("other", 0.05)]);
    global.restore(&saved);
    assert!(
        !global.check("other", None).allowed,
        "the global cap was forgotten"
    );
}

// A damaged or tampered file restores nothing for a value no run could
// have saved, rather than wrapping or saturating into a cap.
#[test]
fn a_saved_value_out_of_range_restores_nothing() {
    let e = enforcer_with(true, Some(10.0), &[], &[], &[]);
    e.restore(&persisted(
        now_secs(),
        &[
            ("neg", -1.0),
            ("nan", f64::NAN),
            ("inf", f64::INFINITY),
            ("huge", 1e15),
            ("ok", 0.25),
        ],
        &[("k", f64::NAN)],
    ));
    let snap = e.snapshot();
    assert!((snap.global_daily_usd - 0.25).abs() < 1e-6, "{snap:?}");
    for tool in ["neg", "nan", "inf", "huge"] {
        assert!(!snap.tool_daily.contains_key(tool), "{tool}: {snap:?}");
    }
    assert!(!snap.key_daily.contains_key("k"), "{snap:?}");
}

// Two values each in range can still sum past the counter. Each is still
// restored: dropping one would reopen that tool's own exhausted cap. The
// global total saturates instead of wrapping.
#[test]
fn saved_values_that_sum_past_the_counter_all_come_back() {
    let e = enforcer_with(true, Some(10.0), &[], &[], &[]);
    e.restore(&persisted(
        now_secs(),
        &[("a", 1e13), ("b", 1e13), ("ok", 0.25)],
        &[],
    ));
    let snap = e.snapshot();
    #[allow(clippy::cast_precision_loss)]
    let saturated = u64::MAX as f64 / 1_000_000.0;
    assert!((snap.global_daily_usd - saturated).abs() < 1.0, "{snap:?}");
    for tool in ["a", "b", "ok"] {
        assert!(snap.tool_daily.contains_key(tool), "{tool}: {snap:?}");
    }
}

// A counter that saturated is saved as exactly `u64::MAX` micro-USD. It
// must come back saturated, or the exhausted budget resets on restart.
#[test]
fn a_saturated_total_comes_back_saturated() {
    let before = enforcer_with(true, None, &[], &[], &[]);
    before.record_spend("t", Some("k"), 1e13);
    before.record_spend("t", Some("k"), 1e13);
    let snap = before.snapshot();
    let saved = persisted(
        now_secs(),
        &[("t", snap.tool_daily["t"])],
        &[("k", snap.key_daily["k"])],
    );

    let after = enforcer_with(true, None, &[], &[], &[]);
    after.restore(&saved);
    assert_eq!(
        after.tool_daily.get("t").map(|a| a.current()),
        Some(u64::MAX)
    );
    assert_eq!(
        after.key_daily.get("k").map(|a| a.current()),
        Some(u64::MAX)
    );
}

// MIK-8904.COST.3: a day that ended while the gateway was down is not
// carried into the next one. The day is the enforcer's own day function.
#[test]
fn a_restore_after_the_day_changed_starts_every_total_at_zero() {
    let e = enforcer_with(true, Some(10.0), &[], &[], &[]);
    e.restore(&persisted(
        now_secs() - 2 * 86_400,
        &[("a", 0.30)],
        &[("k1", 0.30)],
    ));
    let snap = e.snapshot();
    assert!(snap.global_daily_usd.abs() < 1e-9, "{snap:?}");
    assert!(snap.tool_daily.get("a").is_none_or(|usd| usd.abs() < 1e-9));
    assert!(snap.key_daily.get("k1").is_none_or(|usd| usd.abs() < 1e-9));
}
