// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A name budgeted for the first time at a restart starts from the overflow
//! spend it may have made that day, as a reload would start it: the save
//! records the owned names and each row's creation figure (ADR-023).

use super::cost_estimate_restart_tests::{CAP, Scope, T, governed};
use super::persistence::boot_cost_governance;
use super::support::build_persisted_costs;
use crate::clock::test_clock::at_secs;
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::persistence::{self as cost_persistence, PersistedCosts};

/// A first process that never budgets `target`: the map full, then $3 of
/// `target`'s spend in the overflow. Returns what its shutdown save writes.
fn unbudgeted_first_process(scope: Scope, dir: &std::path::Path) -> PersistedCosts {
    let (_, enforcer) = boot_cost_governance(&governed(scope, None), dir);
    let enforcer = enforcer.expect("enabled governance builds an enforcer");
    for i in 0..CAP {
        scope.spend(&enforcer, &format!("filler-{i}"), 0.01);
    }
    scope.spend(&enforcer, "target", 3.0);
    let persisted = build_persisted_costs(&enforcer.snapshot_for_save().expect("a readable clock"));
    cost_persistence::save(&dir.join("costs.json"), &persisted).expect("shutdown save");
    persisted
}

/// The saved overflow and `target`'s saved row in `scope`.
fn saved_figures(scope: Scope, saved: &PersistedCosts) -> (f64, Option<f64>) {
    match scope {
        Scope::Tool => (
            saved.tool_overflow_usd,
            saved.tool_totals.get("target").map(|t| t.total_cost_usd),
        ),
        Scope::Key => (
            saved.key_overflow_usd,
            saved.key_totals.get("target").copied(),
        ),
    }
}

/// `target`'s estimate in a restarted enforcer's snapshot, in `scope`.
fn restored_estimate(scope: Scope, enforcer: &BudgetEnforcer) -> Option<f64> {
    let snap = enforcer.snapshot();
    match scope {
        Scope::Tool => snap.tool_estimate.get("target").copied(),
        Scope::Key => snap.key_estimate.get("target").copied(),
    }
}

/// RESTORE.4: a name the restarted config budgets for the first time starts
/// from the overflow spend it may have made that day, as a reload would
/// start it. $3 sits in the overflow and `target` has no row. Restarted with
/// `target` budgeted at $3.50, a $1 call is judged on $3 + $1 and refused
/// (on its row alone it reads $1 and is admitted); at $4.50 it is admitted.
/// The seed is an estimate apart from real spend: no row appears, and the
/// global total stays as saved.
fn restore4(scope: Scope) {
    let _clock = at_secs(T);
    let dir = tempfile::tempdir().expect("tempdir");
    let saved = unbudgeted_first_process(scope, dir.path());
    assert_eq!(
        saved_figures(scope, &saved),
        (3.0, None),
        "{scope:?}: premise: $3 in the overflow, no row for target"
    );

    let (_, tight) = boot_cost_governance(&governed(scope, Some(3.5)), dir.path());
    let tight = tight.expect("armed");
    assert!(
        !scope.admits(&tight, "target"),
        "{scope:?}: a $1 call on $3 of earlier overflow spend fits a $3.50 budget"
    );
    assert_eq!(
        restored_estimate(scope, &tight),
        Some(3.0),
        "{scope:?}: seeded with the overflow"
    );
    let snap = tight.snapshot();
    let row = match scope {
        Scope::Tool => snap.tool_daily.get("target").copied(),
        Scope::Key => snap.key_daily.get("target").copied(),
    };
    assert_eq!(
        row.unwrap_or(0.0),
        0.0,
        "{scope:?}: the seed is not real spend"
    );
    let saved_global: f64 = saved
        .tool_totals
        .values()
        .map(|t| t.total_cost_usd)
        .sum::<f64>()
        + saved.tool_overflow_usd;
    assert!(
        (snap.global_daily_usd - saved_global).abs() < 1e-9,
        "{scope:?}: global {} as saved {saved_global}",
        snap.global_daily_usd
    );

    let (_, roomy) = boot_cost_governance(&governed(scope, Some(4.5)), dir.path());
    assert!(
        scope.admits(&roomy.expect("armed"), "target"),
        "{scope:?}: 3 + 1 fits $4.50"
    );
}

#[test]
fn restore4_tool() {
    restore4(Scope::Tool);
}

#[test]
fn restore4_key() {
    restore4(Scope::Key);
}

/// A first process where `target` gains a row after the overflow began, as
/// T7b builds it: the map full, $2 of an unrelated name's spend in the
/// overflow, a publication that budgets `filler-0` (so a place frees), then
/// $0.50 of `target` settled under it (its row is born with $2 in the
/// overflow), then $1 more of the unrelated name in the overflow ($3).
fn born_first_process(scope: Scope, dir: &std::path::Path) -> PersistedCosts {
    let (_, enforcer) = boot_cost_governance(&governed(scope, None), dir);
    let enforcer = enforcer.expect("enabled governance builds an enforcer");
    for i in 0..CAP {
        scope.spend(&enforcer, &format!("filler-{i}"), 0.01);
    }
    scope.spend(&enforcer, "unrelated", 2.0);
    let mut published = governed(scope, None);
    scope
        .limits(&mut published.budgets)
        .insert("filler-0".to_owned(), 50.0);
    enforcer.seed_estimates(&published.budgets);
    let names = match scope {
        Scope::Tool => ("target", None),
        Scope::Key => ("read", Some("target")),
    };
    enforcer.settle_under(&published, None, names, 0.5);
    scope.spend(&enforcer, "unrelated", 1.0);
    let persisted = build_persisted_costs(&enforcer.snapshot_for_save().expect("a readable clock"));
    cost_persistence::save(&dir.join("costs.json"), &persisted).expect("shutdown save");
    persisted
}

/// RESTORE.7, a name with a restored row: it is seeded with the overflow at
/// its row's creation that day ($2), not the overflow at the save ($3).
/// Restarted with `target` budgeted at $3.00, a $1 call is judged on
/// 2 + 0.5 + 1 = 3.5 and refused (on its row alone it reads 1.5); at $4.00
/// it is admitted, which a seed from the overflow total (4.5) refuses.
fn restore7_row(scope: Scope) {
    let _clock = at_secs(T);
    let dir = tempfile::tempdir().expect("tempdir");
    let saved = born_first_process(scope, dir.path());
    assert_eq!(
        saved_figures(scope, &saved),
        (3.0, Some(0.5)),
        "{scope:?}: premise: $3 in the overflow, $0.50 in target's row"
    );

    let (_, tight) = boot_cost_governance(&governed(scope, Some(3.0)), dir.path());
    let tight = tight.expect("armed");
    assert!(
        !scope.admits(&tight, "target"),
        "{scope:?}: 2 + 0.5 + 1 = 3.5 fits a $3.00 budget"
    );
    assert_eq!(
        restored_estimate(scope, &tight),
        Some(2.0),
        "{scope:?}: seeded with the born figure"
    );
    let (_, roomy) = boot_cost_governance(&governed(scope, Some(4.0)), dir.path());
    assert!(
        scope.admits(&roomy.expect("armed"), "target"),
        "{scope:?}: 3.5 fits $4.00 (an overflow seed reads 4.5)"
    );
}

#[test]
fn restore7_row_tool() {
    restore7_row(Scope::Tool);
}

#[test]
fn restore7_row_key() {
    restore7_row(Scope::Key);
}

/// A hand-built file for `scope`: `saved_at` today, `overflow` in the
/// overflow, an `owned` set and `born` figures when given, an `estimate`
/// for `target` when given, and `rows` of real spend.
struct File {
    overflow: f64,
    owned: Option<Vec<&'static str>>,
    born: Option<Vec<(&'static str, f64)>>,
    estimate: Option<f64>,
    rows: Vec<(&'static str, f64)>,
}

impl File {
    fn write(&self, scope: Scope, dir: &std::path::Path) {
        let mut costs = PersistedCosts {
            saved_at: T,
            day_basis: Some("local".to_owned()),
            ..PersistedCosts::default()
        };
        let owned = self
            .owned
            .as_ref()
            .map(|names| names.iter().map(|n| (*n).to_owned()).collect());
        let born = self.born.as_ref().map(|figures| {
            figures
                .iter()
                .map(|(n, usd)| ((*n).to_owned(), *usd))
                .collect()
        });
        let estimate: std::collections::HashMap<String, f64> = self
            .estimate
            .map(|usd| ("target".to_owned(), usd))
            .into_iter()
            .collect();
        for (name, usd) in &self.rows {
            match scope {
                Scope::Tool => {
                    let total = crate::cost_accounting::persistence::ToolTotal {
                        call_count: 1,
                        total_cost_usd: *usd,
                        avg_cost_usd: *usd,
                    };
                    costs.tool_totals.insert((*name).to_owned(), total);
                }
                Scope::Key => {
                    costs.key_totals.insert((*name).to_owned(), *usd);
                }
            }
        }
        match scope {
            Scope::Tool => {
                costs.tool_overflow_usd = self.overflow;
                costs.tool_owned = owned;
                costs.tool_born = born;
                costs.tool_estimate = estimate;
            }
            Scope::Key => {
                costs.key_overflow_usd = self.overflow;
                costs.key_owned = owned;
                costs.key_born = born;
                costs.key_estimate = estimate;
            }
        }
        cost_persistence::save(&dir.join("costs.json"), &costs).expect("save");
    }
}

/// RESTORE.7: with no restored row the seed is the saved overflow, even when
/// a creation figure was saved for the name: $3, not $2. At $3.50 a $1 call
/// reads 3 + 1 and is refused (a seed from the creation figure reads 3).
fn restore7_born_no_row(scope: Scope) {
    let _clock = at_secs(T);
    let dir = tempfile::tempdir().expect("tempdir");
    File {
        overflow: 3.0,
        owned: Some(vec![]),
        born: Some(vec![("target", 2.0)]),
        estimate: None,
        rows: vec![],
    }
    .write(scope, dir.path());
    let (_, restarted) = boot_cost_governance(&governed(scope, Some(3.5)), dir.path());
    let restarted = restarted.expect("armed");
    assert!(
        !scope.admits(&restarted, "target"),
        "{scope:?}: 3 + 1 > 3.5"
    );
    assert_eq!(restored_estimate(scope, &restarted), Some(3.0), "{scope:?}");
}

#[test]
fn restore7_born_no_row_tool() {
    restore7_born_no_row(Scope::Tool);
}

#[test]
fn restore7_born_no_row_key() {
    restore7_born_no_row(Scope::Key);
}

/// RESTORE.6: a file saved before the owned names existed restores as
/// today: its overflow and rows come back, and nothing is seeded.
#[test]
fn restore6_an_old_file_seeds_nothing() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        File {
            overflow: 3.0,
            owned: None,
            born: None,
            estimate: None,
            rows: vec![("other", 1.0)],
        }
        .write(scope, dir.path());
        let (_, restarted) = boot_cost_governance(&governed(scope, Some(3.5)), dir.path());
        let restarted = restarted.expect("armed");
        let snap = restarted.snapshot();
        let (overflow, other) = match scope {
            Scope::Tool => (
                snap.tool_overflow_usd,
                snap.tool_daily.get("other").copied(),
            ),
            Scope::Key => (snap.key_overflow_usd, snap.key_daily.get("other").copied()),
        };
        assert_eq!(
            (overflow, other),
            (3.0, Some(1.0)),
            "{scope:?}: premise: restored"
        );
        assert_eq!(
            restored_estimate(scope, &restarted),
            None,
            "{scope:?}: not seeded"
        );
        assert!(
            scope.admits(&restarted, "target"),
            "{scope:?}: judged on 0 + 1"
        );
    }
}

/// RESTORE.5: a name budgeted before and after the restart is not seeded,
/// though the overflow holds $3: at $1.50 a $1 call is admitted.
#[test]
fn restore5_an_idle_budgeted_name_is_not_seeded() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, first) = boot_cost_governance(&governed(scope, Some(1.5)), dir.path());
        let first = first.expect("armed");
        for i in 0..CAP {
            scope.spend(&first, &format!("filler-{i}"), 0.01);
        }
        scope.spend(&first, "other", 3.0);
        let saved = build_persisted_costs(&first.snapshot_for_save().expect("a readable clock"));
        cost_persistence::save(&dir.path().join("costs.json"), &saved).expect("save");
        assert_eq!(saved_figures(scope, &saved).0, 3.0, "{scope:?}: premise");

        let (_, restarted) = boot_cost_governance(&governed(scope, Some(1.5)), dir.path());
        let restarted = restarted.expect("armed");
        assert_eq!(restored_estimate(scope, &restarted), None, "{scope:?}");
        assert!(scope.admits(&restarted, "target"), "{scope:?}: 0 + 1 < 1.5");
    }
}

/// RESTORE.5: a snapshot from an earlier day restores and seeds nothing.
#[test]
fn restore5_an_earlier_day_seeds_nothing() {
    for scope in [Scope::Tool, Scope::Key] {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let _yesterday = at_secs(T - 86_400);
            unbudgeted_first_process(scope, dir.path());
        }
        let _clock = at_secs(T);
        let (_, restarted) = boot_cost_governance(&governed(scope, Some(3.5)), dir.path());
        let restarted = restarted.expect("armed");
        let snap = restarted.snapshot();
        assert_eq!(snap.global_daily_usd, 0.0, "{scope:?}: nothing restored");
        assert_eq!(restored_estimate(scope, &restarted), None, "{scope:?}");
    }
}

/// D4: a name with a restored estimate is not seeded again even when the
/// saved owned set lacks it (a hand-edited or mixed file): it keeps $1.50,
/// distinct from its creation figure ($2) and the overflow ($3).
#[test]
fn restore7_a_restored_estimate_is_kept() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        File {
            overflow: 3.0,
            owned: Some(vec![]),
            born: Some(vec![("target", 2.0)]),
            estimate: Some(1.5),
            rows: vec![],
        }
        .write(scope, dir.path());
        let (_, restarted) = boot_cost_governance(&governed(scope, Some(3.0)), dir.path());
        let restarted = restarted.expect("armed");
        assert_eq!(restored_estimate(scope, &restarted), Some(1.5), "{scope:?}");
        assert!(scope.admits(&restarted, "target"), "{scope:?}: 1.5 + 1 < 3");
    }
}

/// Governance with `target` and every name in `names` budgeted at $50.
fn budgeting(
    scope: Scope,
    names: &[String],
) -> crate::cost_accounting::config::CostGovernanceConfig {
    let mut cfg = governed(scope, Some(50.0));
    for name in names {
        scope.limits(&mut cfg.budgets).insert(name.clone(), 50.0);
    }
    cfg
}

/// D5: the names the saving process owned are owned again before the rows
/// go through the cap. More owned names than the cap, each with a row, plus
/// a full cap of unbudgeted names and $3 in the overflow; restarted with
/// none of them budgeted, every owned row survives, and `target`, budgeted
/// by a reload after the restart, is not seeded (its spend is in its row):
/// at $2 a $1 call reads 0.5 + 1 and is admitted.
#[test]
fn restore5_owned_names_are_carried_through_a_full_cap() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        let owned: Vec<String> = (0..CAP + 8).map(|i| format!("own-{i}")).collect();
        let (_, first) = boot_cost_governance(&budgeting(scope, &owned), dir.path());
        let first = first.expect("armed");
        for name in &owned {
            scope.spend(&first, name, 0.01);
        }
        scope.spend(&first, "target", 0.5);
        for i in 0..CAP {
            scope.spend(&first, &format!("filler-{i}"), 0.01);
        }
        scope.spend(&first, "other", 3.0);
        let saved = build_persisted_costs(&first.snapshot_for_save().expect("a readable clock"));
        cost_persistence::save(&dir.path().join("costs.json"), &saved).expect("save");

        let (_, restarted) = boot_cost_governance(&governed(scope, None), dir.path());
        let restarted = restarted.expect("armed");
        let snap = restarted.snapshot();
        let rows = match scope {
            Scope::Tool => &snap.tool_daily,
            Scope::Key => &snap.key_daily,
        };
        let kept = owned.iter().filter(|n| rows.contains_key(*n)).count();
        assert_eq!(kept, CAP + 8, "{scope:?}: every owned row survives the cap");
        assert_eq!(rows.get("target").copied(), Some(0.5), "{scope:?}");
        restarted.seed_estimates(&governed(scope, Some(2.0)).budgets);
        assert_eq!(
            restored_estimate(scope, &restarted),
            None,
            "{scope:?}: owned, not seeded"
        );
        let published = governed(scope, Some(2.0));
        let (tool, key) = match scope {
            Scope::Tool => ("target", None),
            Scope::Key => ("read", Some("target")),
        };
        assert!(
            restarted.check_under(&published, tool, key).allowed,
            "{scope:?}: 0.5 + 1 < 2"
        );
    }
}

/// RESTORE.6: the save lists every owned name, including one only a reload
/// budgeted, and one a reload budgeted yesterday whose figure has expired.
#[test]
fn restore6_the_save_lists_every_owned_name() {
    for scope in [Scope::Tool, Scope::Key] {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, enforcer) = boot_cost_governance(&governed(scope, None), dir.path());
        let enforcer = enforcer.expect("armed");
        {
            let _yesterday = at_secs(T - 86_400);
            let mut budgets = governed(scope, None).budgets;
            scope
                .limits(&mut budgets)
                .insert("yesterday".to_owned(), 5.0);
            enforcer.seed_estimates(&budgets);
        }
        let _clock = at_secs(T);
        let mut budgets = governed(scope, None).budgets;
        scope
            .limits(&mut budgets)
            .insert("reloaded".to_owned(), 5.0);
        enforcer.seed_estimates(&budgets);
        let saved = build_persisted_costs(&enforcer.snapshot_for_save().expect("a readable clock"));
        let (owned, estimate) = match scope {
            Scope::Tool => (saved.tool_owned.clone(), &saved.tool_estimate),
            Scope::Key => (saved.key_owned.clone(), &saved.key_estimate),
        };
        let owned = owned.expect("a current save lists its owned names");
        assert!(
            owned.contains(&"reloaded".to_owned()),
            "{scope:?}: {owned:?}"
        );
        assert!(
            owned.contains(&"yesterday".to_owned()),
            "{scope:?}: {owned:?}"
        );
        assert!(
            !estimate.contains_key("yesterday"),
            "{scope:?}: its figure expired"
        );
    }
}

/// D6: a damaged owned list restores as a file saved before the list
/// existed: the rest loads, nothing is seeded.
#[test]
fn restore6_a_damaged_owned_list_seeds_nothing() {
    let _clock = at_secs(T);
    let dir = tempfile::tempdir().expect("tempdir");
    let json = format!(
        r#"{{"saved_at": {T}, "day_basis": "local", "tool_totals": {{}}, "key_totals": {{}},
            "tool_overflow_usd": 3.0, "tool_owned": 7, "tool_born": {{}}}}"#
    );
    std::fs::write(dir.path().join("costs.json"), json).expect("write");
    let (_, restarted) = boot_cost_governance(&governed(Scope::Tool, Some(3.5)), dir.path());
    let restarted = restarted.expect("armed");
    assert_eq!(
        restarted.snapshot().tool_overflow_usd,
        3.0,
        "the rest loads"
    );
    assert_eq!(
        restored_estimate(Scope::Tool, &restarted),
        None,
        "nothing seeded"
    );
}

/// The format marker: an absent creation-figure map reads as `None` (a
/// legacy file), a present empty one as `Some` (a current file).
#[test]
fn restore2_an_absent_born_map_differs_from_an_empty_one() {
    let base = r#""saved_at": 1, "tool_totals": {}, "key_totals": {}"#;
    let absent: PersistedCosts = serde_json::from_str(&format!("{{{base}}}")).expect("parses");
    let empty: PersistedCosts = serde_json::from_str(&format!(
        r#"{{{base}, "tool_born": {{}}, "key_born": {{}}}}"#
    ))
    .expect("parses");
    assert!(absent.tool_born.is_none() && absent.key_born.is_none());
    assert_eq!(empty.tool_born.map(|m| m.len()), Some(0));
    assert_eq!(empty.key_born.map(|m| m.len()), Some(0));
}

/// RESTORE.2: a saved creation figure is validated like every persisted
/// figure. A NaN (saved as `null`), a negative one, and one above what a
/// file may hold each fail, the rest of the file loads, and `target` (with
/// its restored row) is charged the saved overflow, the upper bound, never
/// less: at $4 a $1 call reads 3 + 0.5 + 1 and is refused, where a dropped
/// figure (1.5) or the corrupt one read as born 2 (3.5) would admit it.
#[test]
fn restore2_a_corrupt_creation_figure_is_dropped() {
    for scope in [Scope::Tool, Scope::Key] {
        for bad in [serde_json::Value::Null, (-1.0).into(), 1.0e14.into()] {
            let _clock = at_secs(T);
            let dir = tempfile::tempdir().expect("tempdir");
            born_first_process(scope, dir.path());
            let path = dir.path().join("costs.json");
            let mut json: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
            let field = match scope {
                Scope::Tool => "tool_born",
                Scope::Key => "key_born",
            };
            json[field]["target"] = bad.clone();
            std::fs::write(&path, json.to_string()).expect("write");

            let (_, restarted) = boot_cost_governance(&governed(scope, Some(4.0)), dir.path());
            let restarted = restarted.expect("armed");
            assert_eq!(
                restored_estimate(scope, &restarted),
                Some(3.0),
                "{scope:?} {bad}"
            );
            assert!(
                !scope.admits(&restarted, "target"),
                "{scope:?} {bad}: 3 + 0.5 + 1 > 4"
            );
        }
    }
}

/// RESTORE.2: a save carries today's creation figures only: one recorded
/// yesterday is not in today's save.
#[test]
fn restore2_a_save_carries_todays_creation_figures_only() {
    for scope in [Scope::Tool, Scope::Key] {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, enforcer) = boot_cost_governance(&governed(scope, None), dir.path());
        let enforcer = enforcer.expect("armed");
        {
            let _yesterday = at_secs(T - 86_400);
            for i in 0..CAP {
                scope.spend(&enforcer, &format!("filler-{i}"), 0.01);
            }
            scope.spend(&enforcer, "unrelated", 2.0);
            let mut published = governed(scope, None);
            scope
                .limits(&mut published.budgets)
                .insert("filler-0".to_owned(), 50.0);
            enforcer.seed_estimates(&published.budgets);
            let names = match scope {
                Scope::Tool => ("target", None),
                Scope::Key => ("read", Some("target")),
            };
            enforcer.settle_under(&published, None, names, 0.5);
            let saved =
                build_persisted_costs(&enforcer.snapshot_for_save().expect("a readable clock"));
            let born = match scope {
                Scope::Tool => saved.tool_born,
                Scope::Key => saved.key_born,
            };
            assert_eq!(
                born.and_then(|m| m.get("target").copied()),
                Some(2.0),
                "{scope:?}: premise: recorded yesterday"
            );
        }
        let _clock = at_secs(T);
        let saved = build_persisted_costs(&enforcer.snapshot_for_save().expect("a readable clock"));
        let born = match scope {
            Scope::Tool => saved.tool_born,
            Scope::Key => saved.key_born,
        };
        assert_eq!(
            born.map(|m| m.contains_key("target")),
            Some(false),
            "{scope:?}"
        );
    }
}

/// A seed survives a second restart once: seeded $3 at the first, saved
/// with $1 more in the overflow and $0.25 of real spend on `target`, the
/// second restart judges 3 + 0.25, not a reseed from the grown overflow.
#[test]
fn restore_a_seed_is_taken_once_across_two_restarts() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        unbudgeted_first_process(scope, dir.path());
        {
            let (_, first) = boot_cost_governance(&governed(scope, Some(10.0)), dir.path());
            let first = first.expect("armed");
            assert_eq!(
                restored_estimate(scope, &first),
                Some(3.0),
                "{scope:?}: premise"
            );
            scope.spend(&first, "unrelated", 1.0);
            scope.spend(&first, "target", 0.25);
            let saved =
                build_persisted_costs(&first.snapshot_for_save().expect("a readable clock"));
            cost_persistence::save(&dir.path().join("costs.json"), &saved).expect("save");
        }
        let (_, second) = boot_cost_governance(&governed(scope, Some(10.0)), dir.path());
        let second = second.expect("armed");
        assert_eq!(
            restored_estimate(scope, &second),
            Some(3.0),
            "{scope:?}: not reseeded"
        );
        let snap = second.snapshot();
        let row = match scope {
            Scope::Tool => snap.tool_daily.get("target").copied(),
            Scope::Key => snap.key_daily.get("target").copied(),
        };
        assert_eq!(row, Some(0.25), "{scope:?}");
    }
}

/// D3: the seed's overflow is the saved overflow, read before the rows go
/// through the cap: rows that spill during the restore do not inflate it.
#[test]
fn restore7_rows_spilled_at_restore_do_not_inflate_the_seed() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let dir = tempfile::tempdir().expect("tempdir");
        let names: Vec<&'static str> = (0..CAP + 5)
            .map(|i| &*Box::leak(format!("row-{i}").into_boxed_str()))
            .collect();
        File {
            overflow: 3.0,
            owned: Some(vec![]),
            born: Some(vec![]),
            estimate: None,
            rows: names.iter().map(|n| (*n, 1.0)).collect(),
        }
        .write(scope, dir.path());
        let (_, restarted) = boot_cost_governance(&governed(scope, Some(3.5)), dir.path());
        let restarted = restarted.expect("armed");
        let snap = restarted.snapshot();
        let overflow = match scope {
            Scope::Tool => snap.tool_overflow_usd,
            Scope::Key => snap.key_overflow_usd,
        };
        assert!(
            overflow > 3.0,
            "{scope:?}: premise: rows spilled ({overflow})"
        );
        assert_eq!(restored_estimate(scope, &restarted), Some(3.0), "{scope:?}");
    }
}
