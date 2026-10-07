// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7763: the budget check and the spend record must not leave a window in
//! which concurrent calls all pass against the same remaining allowance.

use std::sync::{Arc, Barrier};

use super::*;
use crate::cost_accounting::config::{BudgetLimits, CostGovernanceConfig};
use crate::cost_accounting::registry::CostRegistry;

const CALLERS: usize = 8;
const COST: f64 = 0.01;
const TOOL: &str = "metered";
const KEY: &str = "dev_key";

/// Which budget scope carries the limit.
#[derive(Clone, Copy, Debug)]
enum Scope {
    Global,
    Tool,
    Key,
}

/// A limit that admits `fits` calls of `COST` and refuses the next: a call is
/// refused once its projected spend reaches the limit, so half a call above
/// `fits` calls is the first value that refuses call `fits + 1`.
fn enforcer(scope: Scope, fits: usize) -> Arc<BudgetEnforcer> {
    #[allow(clippy::cast_precision_loss)]
    let limit = fits as f64 * COST + COST / 2.0;
    let mut budgets = BudgetLimits::default();
    match scope {
        Scope::Global => budgets.daily = Some(limit),
        Scope::Tool => {
            budgets.per_tool.insert(TOOL.to_string(), limit);
        }
        Scope::Key => {
            budgets.per_key.insert(KEY.to_string(), limit);
        }
    }
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        budgets,
        ..CostGovernanceConfig::default()
    };
    cfg.tool_costs.insert(TOOL.to_string(), COST);
    let registry = Arc::new(CostRegistry::new(&cfg));
    Arc::new(BudgetEnforcer::new(cfg, registry))
}

/// Every caller checks, all wait until every check has answered, then each
/// admitted caller records its spend: the schedule of calls that were all
/// admitted before any of them was recorded.
fn admitted_when_all_check_before_any_records(enforcer: &Arc<BudgetEnforcer>) -> usize {
    let barrier = Arc::new(Barrier::new(CALLERS));
    let handles: Vec<_> = (0..CALLERS)
        .map(|_| {
            let (enforcer, barrier) = (Arc::clone(enforcer), Arc::clone(&barrier));
            std::thread::spawn(move || {
                let verdict = enforcer.check(TOOL, Some(KEY));
                barrier.wait();
                if verdict.allowed {
                    enforcer.record_spend(TOOL, Some(KEY), verdict.cost_usd);
                }
                verdict.allowed
            })
        })
        .collect();
    handles
        .into_iter()
        .map(|h| usize::from(h.join().unwrap()))
        .sum()
}

#[test]
fn concurrent_calls_against_a_budget_that_fits_n_minus_one_admit_exactly_n_minus_one() {
    for scope in [Scope::Global, Scope::Tool, Scope::Key] {
        let enforcer = enforcer(scope, CALLERS - 1);
        assert_eq!(
            admitted_when_all_check_before_any_records(&enforcer),
            CALLERS - 1,
            "{scope:?}: one call too many was admitted"
        );
    }
}

#[test]
fn a_refused_call_holds_nothing_back_from_the_next() {
    let enforcer = enforcer(Scope::Global, 1);
    let first = enforcer.check(TOOL, Some(KEY));
    assert!(first.allowed);
    let refused = enforcer.check(TOOL, Some(KEY));
    assert!(
        !refused.allowed,
        "a second call must not fit beside the first"
    );
    drop(refused);
    drop(first);
    assert!(
        enforcer.check(TOOL, Some(KEY)).allowed,
        "a call that never ran must give its allowance back"
    );
}

#[test]
fn a_settled_call_counts_once_after_its_hold_drops() {
    let enforcer = enforcer(Scope::Global, 2);
    let first = enforcer.check(TOOL, Some(KEY));
    assert!(first.allowed);
    enforcer.record_spend(TOOL, Some(KEY), first.cost_usd);
    drop(first);
    // Spent once, reserved nothing: one more call fits, a second does not.
    let second = enforcer.check(TOOL, Some(KEY));
    assert!(second.allowed, "the settled call must not be counted twice");
    enforcer.record_spend(TOOL, Some(KEY), second.cost_usd);
    drop(second);
    assert!(!enforcer.check(TOOL, Some(KEY)).allowed);
}

#[test]
fn a_clone_of_a_result_shares_one_hold() {
    let enforcer = enforcer(Scope::Global, 1);
    let first = enforcer.check(TOOL, Some(KEY));
    let copy = first.clone();
    drop(first);
    assert!(
        !enforcer.check(TOOL, Some(KEY)).allowed,
        "the copy still holds the allowance"
    );
    drop(copy);
    assert!(enforcer.check(TOOL, Some(KEY)).allowed);
}

/// MIK-7880: an add that lands after a rollover publishes the new day but
/// before the counter is cleared is kept. The hook parks the resetting add in
/// that window and lands a second add from another thread; with the reset and
/// the adds serialized, that add waits out the window instead.
#[test]
fn an_add_inside_the_day_reset_window_is_kept() {
    use std::sync::mpsc;
    use std::time::Duration;

    let acc = Arc::new(DailyAccumulator::stale(current_day() - 1, 700));
    assert_eq!(acc.current(), 0, "yesterday's spend is not today's");
    let (done, landed) = mpsc::channel();
    let inner = Arc::clone(&acc);
    let slot = std::rc::Rc::new(std::cell::Cell::new(None));
    let hold = std::rc::Rc::clone(&slot);
    AFTER_DAY_PUBLISH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            hold.set(Some(std::thread::spawn(move || {
                inner.add(5);
                let _ = done.send(());
            })));
            // Unserialized, the add completes inside the window; serialized,
            // it is blocked and this wait times out.
            let _ = landed.recv_timeout(Duration::from_millis(500));
        }));
    });
    acc.add(3);
    slot.take()
        .expect("the reset window was reached")
        .join()
        .unwrap();
    assert_eq!(acc.current(), 8, "an add inside the reset window was lost");
}

/// MIK-7903 (MIK-7763C.1): a check that runs after a call's spend is added,
/// before its reservation would be released, sees the call once.
///
/// The hook fires inside `settle` right after the adds and starts call B's
/// check on another thread. With the release in the same step under the
/// ledger lock, B waits and then sees only the spend; otherwise it sees the
/// spend and the reservation together and is refused.
#[test]
fn a_check_during_a_settle_counts_the_call_once() {
    use std::sync::Mutex;
    use std::thread::JoinHandle;

    for scope in [Scope::Global, Scope::Tool, Scope::Key] {
        // GIVEN: room for exactly two calls, and call A admitted
        let enforcer = enforcer(scope, 2);
        let a = enforcer.check(TOOL, Some(KEY));
        assert!(a.allowed, "{scope:?}: call A is admitted");
        let slot: Arc<Mutex<Option<JoinHandle<bool>>>> = Arc::default();
        let (inner, hook_slot) = (Arc::clone(&enforcer), Arc::clone(&slot));
        AFTER_SPEND_ADDED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let b = std::thread::spawn(move || inner.check(TOOL, Some(KEY)).allowed);
                *hook_slot.lock().unwrap() = Some(b);
            }));
        });
        // WHEN: A settles while B checks
        enforcer.settle(a.hold.as_deref(), TOOL, Some(KEY), a.cost_usd);
        let b = slot.lock().unwrap().take().expect("the hook ran");
        // THEN: B fits, because A counts once (spent), not twice (spent + held)
        assert!(b.join().unwrap(), "{scope:?}: call B was refused");
        drop(a);
    }
}

/// MIK-7903: a settled hold gives nothing back on drop, so another call's
/// reservation is never released with it.
#[test]
fn dropping_a_settled_hold_keeps_other_reservations() {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let micro = (COST * 1_000_000.0) as u64;
    // GIVEN: two admitted calls, A and B
    let enforcer = enforcer(Scope::Global, 4);
    let a = enforcer.check(TOOL, Some(KEY));
    let b = enforcer.check(TOOL, Some(KEY));
    // WHEN: A settles and its hold is dropped
    enforcer.settle(a.hold.as_deref(), TOOL, Some(KEY), a.cost_usd);
    drop(a);
    // THEN: B's reservation is still held whole, and A's spend is recorded
    let pending = locked(&enforcer.ledger);
    assert_eq!(
        (pending.global, pending.tool(TOOL), pending.key(KEY)),
        (micro, micro, micro),
        "B's reservation was released with A's"
    );
    drop(pending);
    assert!((enforcer.snapshot().global_daily_usd - COST).abs() < 1e-9);
    drop(b);
}

/// A total at the top of the range saturates rather than wrapping to a small
/// number that would read as budget left.
#[test]
fn a_daily_total_saturates_instead_of_wrapping() {
    let acc = DailyAccumulator::stale(current_day(), u64::MAX - 1);
    assert_eq!(acc.add(5), u64::MAX);
}

/// An add that sampled an earlier day than the stored one (it read the clock
/// before midnight and took the lock after a later add rolled over) must not
/// reset the day backward and erase the newer day's spend.
#[test]
fn an_add_on_an_earlier_day_never_resets_backward() {
    let acc = DailyAccumulator::stale(current_day() + 1, 700);
    assert_eq!(acc.add(5), 705, "the newer day's spend was erased");
    assert_eq!(acc.current(), 705, "the newer day's spend is still counted");
}
