// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Daily spend resets at the host's local midnight (MIK-8901, ADR-026),
//! including the 25- and 23-hour DST days. Each step fixes the clock at one
//! instant, since a spend or a snapshot reads the clock more than once.

use super::*;
use crate::clock::test_clock::at_secs;
use crate::cost_accounting::config::CostGovernanceConfig;
use crate::cost_accounting::registry::CostRegistry;
use chrono_tz::Europe;

fn enforcer() -> BudgetEnforcer {
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    let registry = Arc::new(CostRegistry::new(&cfg));
    BudgetEnforcer::new(cfg, registry)
}

/// Spend `usd` (when non-zero) at `secs`, then read the day's global total.
fn at(e: &BudgetEnforcer, secs: u64, usd: f64) -> f64 {
    let _clock = at_secs(secs);
    if usd > 0.0 {
        e.record_spend("t", Some("k"), usd);
    }
    e.snapshot().global_daily_usd
}

/// Walk `steps` of (instant, spend, expected day total) on one enforcer.
fn walk(steps: &[(u64, &str, f64, f64)]) {
    let e = {
        let _clock = at_secs(steps[0].0);
        enforcer()
    };
    for &(secs, local, usd, want) in steps {
        let got = at(&e, secs, usd);
        assert!(
            (got - want).abs() < 1e-9,
            "at {local} ({secs}): day total {got}, want {want}"
        );
    }
}

/// 2026-10-25 in Amsterdam lasts 25 hours. Spend resets once at each local
/// midnight and not at 00:00 UTC (02:00 local) or across the repeated hour.
/// Mutant: days counted as `secs / 86_400` reset at 02:00 local instead.
#[test]
fn the_25_hour_day_resets_once_at_each_local_midnight() {
    let _zone = crate::local_day::test_zone(Europe::Amsterdam);
    walk(&[
        (1_792_879_199, "10-24 23:59:59 CEST", 1.0, 1.0),
        (1_792_879_200, "10-25 00:00:00 CEST", 0.0, 0.0),
        (1_792_879_200, "10-25 00:00:00 CEST", 2.0, 2.0),
        (1_792_888_200, "10-25 02:30:00 CEST", 1.0, 3.0),
        (1_792_891_800, "10-25 02:30:00 CET", 1.0, 4.0),
        (1_792_969_199, "10-25 23:59:59 CET", 0.0, 4.0),
        (1_792_969_200, "10-26 00:00:00 CET", 0.0, 0.0),
        (1_792_969_200, "10-26 00:00:00 CET", 0.5, 0.5),
    ]);
}

/// 2027-03-28 in Amsterdam lasts 23 hours: one reset at each local midnight,
/// none across the skipped hour, and the next day still gets its own reset.
#[test]
fn the_23_hour_day_resets_once_at_each_local_midnight() {
    let _zone = crate::local_day::test_zone(Europe::Amsterdam);
    walk(&[
        (1_806_188_399, "03-27 23:59:59 CET", 1.0, 1.0),
        (1_806_188_400, "03-28 00:00:00 CET", 0.0, 0.0),
        (1_806_188_400, "03-28 00:00:00 CET", 2.0, 2.0),
        (1_806_195_599, "03-28 01:59:59 CET", 1.0, 3.0),
        (1_806_195_600, "03-28 03:00:00 CEST", 1.0, 4.0),
        (1_806_271_199, "03-28 23:59:59 CEST", 0.0, 4.0),
        (1_806_271_200, "03-29 00:00:00 CEST", 0.0, 0.0),
        (1_806_271_200, "03-29 00:00:00 CEST", 0.5, 0.5),
    ]);
}
