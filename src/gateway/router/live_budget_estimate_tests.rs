// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A name budgeted by reload with no day row of its own starts from the
//! day's overflow total, never from zero (ADR-023): its earlier spend may sit
//! in that total once 256 unbudgeted rows fill the map. The estimate is taken
//! once, when the generation that adds the budget publishes, and lasts the
//! enforcer's day.

use std::sync::Arc;

use super::direct_guards_fixture::Fx;
use super::live_budget_members_tests::{CAP, Scope, full_fixture, settle};
use super::live_budget_tests::{fixture, governance, reload};
use crate::clock::test_clock::at_secs;
use crate::config_reload::Generation;
use crate::cost_accounting::config::CostGovernanceConfig;
use crate::gateway::meta_mcp::invoke::dispatch_guards::{Admission, DirectOutcome};

/// A fixed instant for the rows that cross a day; any instant works, since
/// the next day is read 24 hours on.
const T: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn budget(scope: Scope, cfg: &mut CostGovernanceConfig, name: &str, usd: f64) {
    let limits = match scope {
        Scope::Tool => &mut cfg.budgets.per_tool,
        Scope::Key => &mut cfg.budgets.per_key,
    };
    limits.insert(name.to_owned(), usd);
}

/// Spend `usd` on `name` in `scope` with no reservation. With the map full
/// and `name` unbudgeted and new, it lands in the overflow total.
fn spend(fx: &Fx, scope: Scope, name: &str, usd: f64) {
    let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
    match scope {
        Scope::Tool => enforcer.record_spend(name, None, usd),
        Scope::Key => enforcer.record_spend("read", Some(name), usd),
    }
}

/// Whether a $1 call on `name` is admitted under the live generation. The
/// reservation is released when the admission drops.
fn admitted(fx: &Fx, scope: Scope, name: &str) -> bool {
    let generation = fx.state.live_config.generation();
    let call = scope.call(name, &generation);
    fx.state.meta_mcp.admit_spend_for(&call).is_ok()
}

/// Settle one $1 call on `name` admitted under `generation`, which may be
/// older than the live one.
fn settle_pinned(fx: &Fx, scope: Scope, name: &str, generation: &Generation) {
    let call = scope.call(name, generation);
    fx.state.meta_mcp.account_dispatch(
        &call,
        DirectOutcome::Success { spend: true },
        &Admission::default(),
    );
}

/// A full map with $3 of `target`'s spend in the overflow total.
async fn with_overflow(scope: Scope) -> Fx {
    let fx = full_fixture(scope).await;
    spend(&fx, scope, "target", 3.0);
    let (rows, overflow) = scope.rows(&fx);
    assert!(!rows.contains_key("target"), "{scope:?}: no row of its own");
    assert!(
        (overflow - 3.0).abs() < 1e-9,
        "{scope:?}: overflow {overflow}"
    );
    fx
}

/// T7: a reload budgets `target` at $3.50 while $3 of the day's overflow may
/// be its spend; a $1 call is judged at $4 and refused, not judged from zero.
#[tokio::test]
async fn t7_a_name_budgeted_by_reload_starts_from_the_overflow_total() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        reload(&fx, |c| budget(scope, c, "target", 3.5));
        assert!(!admitted(&fx, scope, "target"), "{scope:?}: 3 + 1 > 3.5");
        // The same figure under a budget that fits it: the estimate is the
        // overflow total, not more.
        reload(&fx, |c| budget(scope, c, "target", 4.5));
        assert!(admitted(&fx, scope, "target"), "{scope:?}: 3 + 1 < 4.5");
    }
}

/// T9: repeated reloads keep the first estimate. Unrelated overflow spend
/// lands between them, so a re-take would read $5 and a compounding one $8.
#[tokio::test]
async fn t9_repeated_reloads_keep_the_first_estimate() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        reload(&fx, |c| budget(scope, c, "target", 3.5));
        spend(&fx, scope, "unrelated", 2.0);
        // The same file again.
        reload(&fx, |_| {});
        assert!(!admitted(&fx, scope, "target"), "{scope:?}: still 3 + 1");
        // Only the amount changes.
        reload(&fx, |c| budget(scope, c, "target", 4.5));
        assert!(
            admitted(&fx, scope, "target"),
            "{scope:?}: 3 + 1 < 4.5; a re-take or a compounding estimate refuses"
        );
    }
}

/// T10: overflow spend settled between a generation's preparation and its
/// publication is in the estimate; spend a call pinned to the older
/// generation settles after it lands in the name's own row, counted once.
#[tokio::test]
async fn t10_spend_settled_while_the_budget_is_added_counts_once() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        let live = &fx.state.live_config;
        let before = live.generation();
        let mut config = (*live.get()).clone();
        budget(scope, &mut config.cost_governance, "target", 5.5);
        let prepared = live
            .prepare(config, &crate::config::EnvOverlay::none())
            .expect("prepares");
        // Settled after preparation, before publication.
        spend(&fx, scope, "late", 2.0);
        live.publish(Arc::new(prepared));
        assert!(
            !admitted(&fx, scope, "target"),
            "{scope:?}: 5 + 1 > 5.5; an estimate taken at preparation reads 3"
        );

        // A call admitted under the older generation, where `target` is
        // unbudgeted, settles now.
        let (_, overflow) = scope.rows(&fx);
        settle_pinned(&fx, scope, "target", &before);
        let (rows, overflow_after) = scope.rows(&fx);
        assert_eq!(
            rows.get("target").copied(),
            Some(1.0),
            "{scope:?}: {rows:?}"
        );
        assert!((overflow_after - overflow).abs() < 1e-9, "{scope:?}");
    }
}

/// T11, local day: the estimate does not survive into the next day.
#[tokio::test]
async fn t11_the_estimate_ends_with_the_day() {
    for scope in [Scope::Tool, Scope::Key] {
        let clock = at_secs(T);
        let fx = with_overflow(scope).await;
        reload(&fx, |c| budget(scope, c, "target", 3.5));
        assert!(!admitted(&fx, scope, "target"), "{scope:?}: same day");
        drop(clock);
        let _next = at_secs(T + DAY);
        assert!(admitted(&fx, scope, "target"), "{scope:?}: next day");
    }
}

/// T11, legacy UTC day: after a pre-upgrade restore the enforcer counts the
/// restored UTC day, and the estimate ends with that day.
#[tokio::test]
async fn t11_the_estimate_ends_with_a_restored_utc_day() {
    for scope in [Scope::Tool, Scope::Key] {
        // Noon UTC, so the next read a day on is the next UTC day.
        let noon = T - T % DAY + DAY / 2;
        let clock = at_secs(noon);
        let fx = fixture(&governance(|c| {
            c.tool_costs.insert("target".to_owned(), 1.0);
        }))
        .await;
        // As at startup: the restore runs before any spend.
        let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
        enforcer.restore(&crate::cost_accounting::persistence::PersistedCosts {
            saved_at: noon - 60,
            ..Default::default()
        });
        scope.fill(&fx, CAP);
        spend(&fx, scope, "target", 3.0);
        assert!(
            !scope.rows(&fx).0.contains_key("target"),
            "{scope:?}: in the overflow"
        );
        reload(&fx, |c| budget(scope, c, "target", 3.5));
        assert!(!admitted(&fx, scope, "target"), "{scope:?}: same UTC day");
        drop(clock);
        let _next = at_secs(noon + DAY);
        assert!(admitted(&fx, scope, "target"), "{scope:?}: next day");
    }
}

/// T7b: a row does not prove a name never overflowed. `target` overflows,
/// a reload budgets a filler and so frees a place, `target` then gains a row;
/// budgeting `target` charges the overflow total at that row's creation.
#[tokio::test]
async fn t7b_a_row_created_after_the_overflow_began_keeps_that_overflow() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        reload(&fx, |c| budget(scope, c, "filler-0", 50.0));
        // Under the live generation: only its budgets free the place.
        settle(&fx, scope, "target");
        assert_eq!(
            scope.rows(&fx).0.get("target").copied(),
            Some(1.0),
            "{scope:?}: the freed place"
        );
        reload(&fx, |c| budget(scope, c, "target", 4.5));
        assert!(
            !admitted(&fx, scope, "target"),
            "{scope:?}: 1 + 3 + 1 > 4.5; the row alone reads 2"
        );
        reload(&fx, |c| budget(scope, c, "target", 5.5));
        assert!(admitted(&fx, scope, "target"), "{scope:?}: 1 + 3 + 1 < 5.5");
    }
}

/// T10b: with the overflow at zero there is nothing to estimate, yet a call
/// pinned to the outgoing generation that settles after the budget is added
/// still lands in the name's own row.
#[tokio::test]
async fn t10b_a_zero_overflow_seed_still_owns_the_row() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = full_fixture(scope).await;
        let before = fx.state.live_config.generation();
        reload(&fx, |c| budget(scope, c, "target", 3.5));
        settle_pinned(&fx, scope, "target", &before);
        let (rows, overflow) = scope.rows(&fx);
        assert_eq!(
            rows.get("target").copied(),
            Some(1.0),
            "{scope:?}: {rows:?}"
        );
        assert!(overflow.abs() < 1e-9, "{scope:?}: overflow {overflow}");
    }
}

/// T9b, a regression control (green before the estimate exists): a name
/// budgeted at startup that has not spent is not seeded by an unrelated
/// reload; only a publication that starts budgeting a name does.
#[tokio::test]
async fn t9b_an_idle_startup_budget_is_not_seeded() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = fixture(&governance(|c| {
            for name in ["target", "idle"] {
                c.tool_costs.insert(name.to_owned(), 1.0);
            }
            budget(scope, c, "idle", 3.5);
        }))
        .await;
        scope.fill(&fx, CAP);
        spend(&fx, scope, "target", 3.0);
        reload(&fx, |c| budget(scope, c, "target", 50.0));
        assert!(admitted(&fx, scope, "idle"), "{scope:?}: idle starts at 0");
    }
}

/// T9c: a budget removed and re-added on the same day keeps its first
/// estimate; overflow spend in between is not charged to it.
#[tokio::test]
async fn t9c_remove_and_re_add_keeps_the_first_estimate() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        reload(&fx, |c| budget(scope, c, "target", 4.5));
        reload(&fx, |c| {
            c.budgets.per_tool.remove("target");
            c.budgets.per_key.remove("target");
        });
        spend(&fx, scope, "unrelated", 2.0);
        reload(&fx, |c| budget(scope, c, "target", 3.5));
        assert!(!admitted(&fx, scope, "target"), "{scope:?}: 3 + 1 > 3.5");
        reload(&fx, |c| budget(scope, c, "target", 4.5));
        assert!(
            admitted(&fx, scope, "target"),
            "{scope:?}: 3 + 1 < 4.5; a re-take reads 5"
        );
    }
}

/// T9d: a call pinned to the outgoing generation, which does not budget the
/// name, settling after the seed does not erase the estimate.
#[tokio::test]
async fn t9d_an_old_generation_settle_keeps_the_estimate() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        let before = fx.state.live_config.generation();
        reload(&fx, |c| budget(scope, c, "target", 4.5));
        settle_pinned(&fx, scope, "target", &before);
        assert!(
            !admitted(&fx, scope, "target"),
            "{scope:?}: 1 + 3 + 1 > 4.5; without the estimate 1 + 1"
        );
    }
}

/// T7c: an owned name's spend in a gap with no budget lands in its own row.
/// Budgeted (figure 3), unbudgeted, $1 of spend, a check pinned to the
/// generation that budgeted it, budgeted again: judged at 1 + 3 + 1.
#[tokio::test]
async fn t7c_spend_in_a_gap_with_no_budget_stays_in_the_row() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        reload(&fx, |c| budget(scope, c, "target", 50.0));
        let budgeted = fx.state.live_config.generation();
        reload(&fx, |c| {
            c.budgets.per_tool.remove("target");
            c.budgets.per_key.remove("target");
        });
        let (_, overflow) = scope.rows(&fx);
        spend(&fx, scope, "target", 1.0);
        let (rows, overflow_after) = scope.rows(&fx);
        assert_eq!(rows.get("target").copied(), Some(1.0), "{scope:?}: own row");
        assert!((overflow_after - overflow).abs() < 1e-9, "{scope:?}");
        let call = scope.call("target", &budgeted);
        drop(fx.state.meta_mcp.admit_spend_for(&call));
        reload(&fx, |c| budget(scope, c, "target", 4.5));
        assert!(
            !admitted(&fx, scope, "target"),
            "{scope:?}: 1 + 3 + 1 > 4.5"
        );
        reload(&fx, |c| budget(scope, c, "target", 5.5));
        assert!(admitted(&fx, scope, "target"), "{scope:?}: 1 + 3 + 1 < 5.5");
    }
}

/// T9e: a name budgeted at startup is owned from the start: removed by a
/// reload, its spend still lands in its row, and budgeted again it takes no
/// figure from the overflow.
#[tokio::test]
async fn t9e_a_startup_budget_removed_and_re_added_takes_no_figure() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = fixture(&governance(|c| {
            c.tool_costs.insert("idle".to_owned(), 1.0);
            budget(scope, c, "idle", 50.0);
        }))
        .await;
        scope.fill(&fx, CAP);
        spend(&fx, scope, "other", 3.0);
        let startup = fx.state.live_config.generation();
        reload(&fx, |c| {
            c.budgets.per_tool.remove("idle");
            c.budgets.per_key.remove("idle");
        });
        spend(&fx, scope, "idle", 1.0);
        assert_eq!(
            scope.rows(&fx).0.get("idle").copied(),
            Some(1.0),
            "{scope:?}"
        );
        let call = scope.call("idle", &startup);
        drop(fx.state.meta_mcp.admit_spend_for(&call));
        reload(&fx, |c| budget(scope, c, "idle", 2.5));
        assert!(
            admitted(&fx, scope, "idle"),
            "{scope:?}: 1 + 1 < 2.5, no figure"
        );
    }
}

/// T10c: ownership outlives the day. Budgeted on day 1; on day 2 the cap
/// fills again, and a call pinned to the day-1 generation that did not
/// budget the name settles into the name's own row.
#[tokio::test]
async fn t10c_ownership_outlives_the_day() {
    for scope in [Scope::Tool, Scope::Key] {
        let day1 = at_secs(T);
        let fx = with_overflow(scope).await;
        let before = fx.state.live_config.generation();
        reload(&fx, |c| budget(scope, c, "target", 50.0));
        drop(day1);
        let _day2 = at_secs(T + DAY);
        for i in 0..CAP {
            spend(&fx, scope, &format!("day2-{i}"), 0.01);
        }
        settle_pinned(&fx, scope, "target", &before);
        assert_eq!(
            scope.rows(&fx).0.get("target").copied(),
            Some(1.0),
            "{scope:?}"
        );
    }
}

/// T10e: the figure is taken before the swap. Seeded, a call pinned to the
/// outgoing generation settles before the new generation publishes; the
/// publication takes no second figure, and the spend is counted once.
#[tokio::test]
async fn t10e_a_settle_between_the_seed_and_the_swap_counts_once() {
    for scope in [Scope::Tool, Scope::Key] {
        let _clock = at_secs(T);
        let fx = with_overflow(scope).await;
        let live = &fx.state.live_config;
        let before = live.generation();
        let mut config = (*live.get()).clone();
        budget(scope, &mut config.cost_governance, "target", 4.5);
        let enforcer = fx.state.meta_mcp.budget_enforcer.as_ref().expect("armed");
        enforcer.seed_estimates(
            &before.config().cost_governance.budgets,
            &config.cost_governance.budgets,
        );
        settle_pinned(&fx, scope, "target", &before);
        live.set(config);
        assert!(
            !admitted(&fx, scope, "target"),
            "{scope:?}: 1 + 3 + 1 > 4.5"
        );
        reload(&fx, |c| budget(scope, c, "target", 5.5));
        assert!(
            admitted(&fx, scope, "target"),
            "{scope:?}: counted once, 5 < 5.5"
        );
    }
}
