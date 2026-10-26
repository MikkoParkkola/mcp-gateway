// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Daily spend resets at the host's local midnight (ADR-026),
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

// ── Restore across the upgrade (ADR-026) ─────────────────────────────────────

use crate::cost_accounting::persistence::{PersistedCosts, ToolTotal};
use chrono_tz::{America, Asia};

/// A snapshot of `usd` on tool "t", saved at `saved_at` under `basis`.
fn snapshot(saved_at: u64, usd: f64, basis: Option<&str>) -> PersistedCosts {
    let mut saved = PersistedCosts {
        saved_at,
        day_basis: basis.map(str::to_owned),
        ..PersistedCosts::default()
    };
    let total = ToolTotal {
        call_count: 1,
        total_cost_usd: usd,
        avg_cost_usd: usd,
    };
    saved.tool_totals.insert("t".to_owned(), total);
    saved
}

/// A fresh process at `secs` that restores `saved`.
fn booted(secs: u64, saved: &PersistedCosts) -> BudgetEnforcer {
    let _clock = at_secs(secs);
    let e = enforcer();
    e.restore(saved);
    e
}

/// What a save at `secs` writes, as the save path builds it.
fn saved_at(e: &BudgetEnforcer, secs: u64) -> PersistedCosts {
    let _clock = at_secs(secs);
    let snap = e.snapshot_for_save().expect("a readable clock");
    let mut saved = snapshot(secs, 0.0, snap.day_basis.as_deref());
    for (tool, usd) in snap.tool_daily {
        saved.tool_totals.insert(
            tool,
            ToolTotal {
                call_count: 1,
                total_cost_usd: usd,
                avg_cost_usd: usd,
            },
        );
    }
    saved
}

/// Each (instant, label, spend, expected day total) step on `e`.
fn steps(e: &BudgetEnforcer, steps: &[(u64, &str, f64, f64)]) {
    for &(secs, local, usd, want) in steps {
        let got = at(e, secs, usd);
        assert!(
            (got - want).abs() < 1e-9,
            "at {local} ({secs}): day total {got}, want {want}"
        );
    }
}

/// T4, east of UTC: a pre-upgrade snapshot restored at 00:30 local keeps its
/// UTC day open, resets once at 00:00 UTC (01:00 CET), then at local
/// midnight. The costs API names UTC until that reset. Mutant: the restore
/// does not re-date the accumulators built before it (no reset at 01:00).
#[test]
fn a_pre_upgrade_snapshot_resets_once_at_utc_midnight_east_of_utc() {
    let _zone = crate::local_day::test_zone(Europe::Amsterdam);
    let e = booted(1_794_353_400, &snapshot(1_794_340_800, 1.0, None));
    {
        let _clock = at_secs(1_794_353_400);
        assert_eq!(e.day_zone(), "UTC");
    }
    steps(
        &e,
        &[
            (1_794_353_400, "11-11 00:30 CET", 0.0, 1.0),
            (1_794_353_400, "11-11 00:30 CET", 1.0, 2.0),
            (1_794_355_199, "11-11 00:59:59 CET", 0.0, 2.0),
        ],
    );
    // Key "k" is not in the snapshot: its row, made after the restore, resets
    // with the global total, so the two allowances never drift apart.
    let key = |secs| {
        let _clock = at_secs(secs);
        e.snapshot().key_daily.get("k").copied().unwrap_or(0.0)
    };
    assert!((key(1_794_355_199) - 1.0).abs() < 1e-9);
    assert!(
        key(1_794_355_200).abs() < 1e-9,
        "the key row resets at 00:00 UTC too"
    );
    steps(
        &e,
        &[
            (1_794_355_200, "11-11 01:00 CET, 00:00 UTC", 0.0, 0.0),
            (1_794_355_200, "11-11 01:00 CET", 0.5, 0.5),
            (1_794_437_999, "11-11 23:59:59 CET", 0.0, 0.5),
            (1_794_438_000, "11-12 00:00 CET", 0.0, 0.0),
        ],
    );
    let _clock = at_secs(1_794_355_200);
    assert_eq!(e.day_zone(), "Europe/Amsterdam");
}

/// T4, west of UTC: restored at 17:00 EST, the UTC day resets at 19:00 EST
/// (00:00 UTC), not at local midnight 5 hours later, and local midnight then
/// resets again. Mutant: legacy and local days share one key space (no reset
/// at 19:00, since the local date still matches the UTC day number).
#[test]
fn a_pre_upgrade_snapshot_resets_once_at_utc_midnight_west_of_utc() {
    let _zone = crate::local_day::test_zone(America::New_York);
    let e = booted(1_794_348_000, &snapshot(1_794_340_800, 1.0, None));
    steps(
        &e,
        &[
            (1_794_348_000, "11-10 17:00 EST", 0.0, 1.0),
            (1_794_355_199, "11-10 18:59:59 EST", 0.0, 1.0),
            (1_794_355_200, "11-10 19:00 EST, 00:00 UTC", 0.0, 0.0),
            (1_794_355_200, "11-10 19:00 EST", 0.5, 0.5),
            (1_794_373_199, "11-10 23:59:59 EST", 0.0, 0.5),
            (1_794_373_200, "11-11 00:00 EST", 0.0, 0.0),
        ],
    );
}

/// A day basis this build does not recognise keeps the saved spend, counted
/// as a pre-upgrade snapshot: its UTC day stays open and resets once at
/// 00:00 UTC. Discarding it would hand an edited file a fresh daily
/// allowance. Mutant: the basis is dropped (the day total reads 0 at 00:30).
#[test]
fn an_unrecognised_day_basis_keeps_the_saved_spend_as_a_utc_day() {
    let _zone = crate::local_day::test_zone(Europe::Amsterdam);
    let e = booted(1_794_353_400, &snapshot(1_794_340_800, 1.0, Some("solar")));
    {
        let _clock = at_secs(1_794_353_400);
        assert_eq!(e.day_zone(), "UTC");
    }
    steps(
        &e,
        &[
            (1_794_353_400, "11-11 00:30 CET", 0.0, 1.0),
            (1_794_355_199, "11-11 00:59:59 CET", 0.0, 1.0),
            (1_794_355_200, "11-11 01:00 CET, 00:00 UTC", 0.0, 0.0),
        ],
    );
}

/// T4c: once a read on the next UTC day has closed the legacy day, a clock
/// set back into it stays local: a save records "local" and the costs API
/// names the host zone. Mutant: the legacy day is matched by date alone (the
/// save at 00:40 CET records no basis, and a restart repeats the UTC reset).
#[test]
fn a_clock_set_back_does_not_reopen_the_legacy_day() {
    let _zone = crate::local_day::test_zone(Europe::Amsterdam);
    let e = booted(1_794_353_400, &snapshot(1_794_340_800, 1.0, None));
    assert!((at(&e, 1_794_355_200, 0.5) - 0.5).abs() < 1e-9);
    let set_back = saved_at(&e, 1_794_354_000);
    assert_eq!(set_back.day_basis.as_deref(), Some("local"));
    let _clock = at_secs(1_794_354_000);
    assert_eq!(e.day_zone(), "Europe/Amsterdam");
}

/// T4b: a save while the legacy UTC day is open records no basis, so a
/// restart still resets once at UTC midnight; a save after it records
/// "local", and a later restart keeps that spend until local midnight, with
/// no second UTC reset. Mutant: saves always write "local" (the restart at
/// 00:59:59 CET files the spend under the local day and never resets at 01:00).
#[test]
fn restarts_keep_exactly_one_utc_reset_across_saves() {
    let _zone = crate::local_day::test_zone(Europe::Amsterdam);
    let first = booted(1_794_353_400, &snapshot(1_794_340_800, 1.0, None));
    at(&first, 1_794_354_000, 1.0);
    let open_day = saved_at(&first, 1_794_354_000);
    assert_eq!(open_day.day_basis, None);

    let second = booted(1_794_355_199, &open_day);
    steps(
        &second,
        &[
            (1_794_355_199, "11-11 00:59:59 CET", 0.0, 2.0),
            (1_794_355_200, "11-11 01:00 CET, 00:00 UTC", 0.0, 0.0),
            (1_794_398_400, "11-11 13:00 CET", 0.5, 0.5),
        ],
    );
    let local_day = saved_at(&second, 1_794_398_400);
    assert_eq!(local_day.day_basis.as_deref(), Some("local"));

    let third = booted(1_794_437_999, &local_day);
    steps(
        &third,
        &[
            (1_794_437_999, "11-11 23:59:59 CET", 0.0, 0.5),
            (1_794_438_000, "11-12 00:00 CET", 0.0, 0.0),
        ],
    );
}

/// Whether the saved spend counts after booting at `boot` under `zone`.
fn restored(zone: chrono_tz::Tz, boot: u64, saved: &PersistedCosts) -> bool {
    let _zone = crate::local_day::test_zone(zone);
    let e = booted(boot, saved);
    at(&e, boot, 0.0) > 0.0
}

/// T5: a snapshot saved under local days restores on the same local date and
/// is skipped on the next, whatever the UTC dates say, and a host whose zone
/// changed restores by the zone at load. Mutant: the restore compares UTC
/// days (`saved_at / 86_400`), which flips the first five rows.
#[test]
fn a_local_snapshot_restores_by_the_local_date_in_the_zone_at_load() {
    let local = |saved_at| snapshot(saved_at, 1.0, Some("local"));
    // 23:30 CET on 11-10, loaded at 00:30 CET on 11-11: one UTC date, two
    // local dates, so the budgets start fresh.
    assert!(!restored(
        Europe::Amsterdam,
        1_794_353_400,
        &local(1_794_349_800)
    ));
    // 00:30 CET loaded at 01:30 CET: two UTC dates, one local date.
    assert!(restored(
        Europe::Amsterdam,
        1_794_357_000,
        &local(1_794_353_400)
    ));
    // 18:30 EST loaded at 19:30 EST: the same, west of UTC.
    assert!(restored(
        America::New_York,
        1_794_357_000,
        &local(1_794_353_400)
    ));
    // Saved at 23:30 in Amsterdam (17:30 in New York), loaded on a host now
    // in New York at 19:30 its time (01:30 next day in Amsterdam): restored.
    assert!(restored(
        America::New_York,
        1_794_357_000,
        &local(1_794_349_800)
    ));
    // Saved at 19:00 in Amsterdam (23:30 in Kolkata), loaded in Kolkata at
    // 00:15 its next day (19:45 in Amsterdam): skipped.
    assert!(!restored(
        Asia::Kolkata,
        1_794_336_300,
        &local(1_794_333_600)
    ));
    // A pre-upgrade snapshot from an earlier UTC day is skipped, as before.
    assert!(!restored(
        Europe::Amsterdam,
        1_794_357_000,
        &snapshot(1_794_340_800, 1.0, None)
    ));
}

/// T6 (TZ.5): a spend that read its day at 23:59:59 local and lands after
/// midnight is dated to the earlier day, so the new day reads 0, unless
/// another spend has already rolled over, when it counts on the newer day
/// (a rollover only moves forward). Under Europe/Amsterdam, on local days.
#[test]
fn a_spend_straddling_local_midnight_keeps_its_earlier_day() {
    let _zone = crate::local_day::test_zone(Europe::Amsterdam);
    let before_midnight = local_day_key(1_794_437_999);
    // Built before the clock moves on: the test clock holds one reading per
    // thread, and a guard dropped inside another clears both.
    let (alone, overtaken) = {
        let _clock = at_secs(1_794_437_999);
        (DailyAccumulator::new(), DailyAccumulator::new())
    };
    let _midnight = at_secs(1_794_438_000);

    alone.add_on(Some(before_midnight), 1_000_000);
    assert_eq!(alone.current(), 0, "dated to 11-11, read on 11-12");

    overtaken.add(500_000);
    overtaken.add_on(Some(before_midnight), 1_000_000);
    assert_eq!(
        overtaken.current(),
        1_500_000,
        "counts on 11-12 once it has rolled over"
    );
}
