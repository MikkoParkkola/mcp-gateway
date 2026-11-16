// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Retirement inside the HTTP stop total: the tail's logger bound and exit
//! status, the watchdog, and where the plan is stored.

use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tokio::time::Instant;

use super::{EXIT_OVERRUN, Exit, RetirePlan, WATCHDOG_SLACK, arm_with, finish, logger_bound, tail};
use crate::log_writer::test_sinks::{WATCHDOG, line, parked};
use crate::log_writer::{FlushEnd, LOG_FLUSH_DEADLINE, StopOutcome};

/// A plain stop's plan ending `in_` from now, its runtime wait 2 s earlier.
fn plan_ending_in(in_: Duration) -> RetirePlan {
    let end = Instant::now() + in_;
    let runtime_end = end
        .checked_sub(Duration::from_secs(2))
        .expect("the clock is past its first 2 s");
    RetirePlan::new(end, runtime_end, Exit::Plain)
}

/// A stored-code cell of its own for one row.
fn fresh_code() -> &'static AtomicI32 {
    Box::leak(Box::new(AtomicI32::new(-1)))
}

/// Run `tail` on its own thread under the watchdog; its code and how long it took.
fn timed_tail(
    code: ExitCode,
    left_running: bool,
    plan: Option<RetirePlan>,
    flush: crate::log_writer::LogFlush,
) -> (ExitCode, Duration) {
    let (sent, got) = mpsc::channel();
    thread::spawn(move || {
        let started = std::time::Instant::now();
        let code = tail(code, left_running, plan, flush);
        let _ = sent.send((code, started.elapsed()));
    });
    got.recv_timeout(WATCHDOG)
        .expect("the tail returned within the watchdog")
}

/// U2 (RETIRE.4): with a plan, a logger that never drains is cut at the
/// plan's logger end, well inside the 2 s it gets without a plan, and the
/// tail exits 75.
#[test]
fn the_tail_cuts_a_stuck_logger_at_the_plans_logger_end() {
    let (w, flush, gate, _out) = parked(16, 1 << 16);
    line(&w, "stuck");
    assert!(
        gate.wait_entered(),
        "premise: the writer is parked in its sink"
    );
    let (code, took) = timed_tail(
        ExitCode::SUCCESS,
        false,
        Some(plan_ending_in(Duration::from_millis(300))),
        flush,
    );
    gate.open();
    assert_eq!(
        code,
        ExitCode::from(EXIT_OVERRUN),
        "a logger not joined by its end did not exit 75"
    );
    assert!(
        took < LOG_FLUSH_DEADLINE,
        "the stuck logger was given {took:?}, past the plan's logger end"
    );
}

/// U2 (RETIRE.4): the other side of the bound: a plan ending far off still
/// gives a stuck logger no more than its 2 s, then exits 75.
#[test]
fn the_tail_gives_a_stuck_logger_at_most_its_two_seconds() {
    let (w, flush, gate, _out) = parked(16, 1 << 16);
    line(&w, "stuck");
    assert!(
        gate.wait_entered(),
        "premise: the writer is parked in its sink"
    );
    let (code, took) = timed_tail(
        ExitCode::SUCCESS,
        false,
        Some(plan_ending_in(Duration::from_secs(60))),
        flush,
    );
    gate.open();
    assert_eq!(
        code,
        ExitCode::from(EXIT_OVERRUN),
        "a logger not joined in its 2 s did not exit 75"
    );
    assert!(
        took >= LOG_FLUSH_DEADLINE,
        "the stuck logger was cut after {took:?}, before its 2 s"
    );
}

/// U2 (RETIRE.4): a healthy logger is joined and the tail keeps the code
/// dispatch returned.
#[test]
fn the_tail_joins_a_healthy_logger_and_keeps_dispatchs_code() {
    let (w, flush, gate, out) = parked(16, 1 << 16);
    gate.open();
    line(&w, "fine");
    let (code, _) = timed_tail(
        ExitCode::FAILURE,
        false,
        Some(plan_ending_in(Duration::from_secs(60))),
        flush,
    );
    assert_eq!(
        code,
        ExitCode::FAILURE,
        "a clean tail changed dispatch's code"
    );
    assert!(
        out.lines().iter().any(|l| l == "fine"),
        "the joined logger did not write its line"
    );
}

/// A worker handle that has already ended, for a `NotJoined` outcome.
fn ended_worker() -> thread::JoinHandle<FlushEnd> {
    thread::spawn(|| FlushEnd::Clean)
}

/// U2b (RETIRE.4): with a plan, an overrun runtime wait or a logger not
/// joined exits 75 and stores 75; a clean tail keeps dispatch's code (1 here,
/// neither 0 nor 75) and stores it.
#[test]
fn an_overrun_or_unjoined_tail_exits_75_and_a_clean_one_keeps_its_code() {
    let joined = StopOutcome::Joined(FlushEnd::Clean);
    let stored = fresh_code();
    let code = finish(ExitCode::FAILURE, true, Some(&joined), stored);
    assert_eq!(
        code,
        ExitCode::from(EXIT_OVERRUN),
        "an overrun runtime wait kept its code"
    );
    assert_eq!(
        stored.load(Ordering::SeqCst),
        75,
        "the overrun status was not stored"
    );

    let stored = fresh_code();
    let not_joined = StopOutcome::NotJoined(ended_worker());
    let code = finish(ExitCode::FAILURE, false, Some(&not_joined), stored);
    assert_eq!(
        code,
        ExitCode::from(EXIT_OVERRUN),
        "a logger not joined kept its code"
    );
    assert_eq!(
        stored.load(Ordering::SeqCst),
        75,
        "the unjoined status was not stored"
    );

    let stored = fresh_code();
    let code = finish(ExitCode::FAILURE, false, Some(&joined), stored);
    assert_eq!(
        code,
        ExitCode::FAILURE,
        "a clean tail changed dispatch's code"
    );
    assert_eq!(
        stored.load(Ordering::SeqCst),
        1,
        "a clean tail did not store its code"
    );
}

/// U5 (RETIRE.3): without a plan (stdio, every other command) the status is
/// today's: dispatch's code even after an exhausted runtime wait, and nothing
/// is stored for a watchdog that was never armed.
#[test]
fn without_a_plan_the_tail_keeps_todays_status() {
    let stored = fresh_code();
    let code = finish(ExitCode::SUCCESS, true, None, stored);
    assert_eq!(
        code,
        ExitCode::SUCCESS,
        "a planless tail turned an overrun into 75"
    );
    assert_eq!(
        stored.load(Ordering::SeqCst),
        -1,
        "a planless tail stored a code"
    );
}

/// Arm a watchdog for a stop ending at `end` with `stored`, its exit
/// recording the code and when it came; returns the receiver.
fn armed(
    end: std::time::Instant,
    stored: &'static AtomicI32,
) -> mpsc::Receiver<(i32, std::time::Instant)> {
    let (sent, got) = mpsc::channel();
    let handle = arm_with(end, stored, move |code| {
        let _ = sent.send((code, std::time::Instant::now()));
    });
    assert!(handle.is_some(), "the watchdog was not armed");
    got
}

/// U3 (RETIRE.4): with no code stored, the watchdog exits 75 at D + 500 ms,
/// never before.
#[test]
fn the_watchdog_exits_75_at_its_slack_past_the_end() {
    let end = std::time::Instant::now();
    let (code, at) = armed(end, fresh_code())
        .recv_timeout(WATCHDOG)
        .expect("the watchdog fired");
    assert_eq!(
        code,
        i32::from(EXIT_OVERRUN),
        "the watchdog's exit was not 75"
    );
    assert!(
        at >= end + WATCHDOG_SLACK,
        "the watchdog fired before D + 500 ms"
    );
}

/// U3 (RETIRE.4): a code stored before the watchdog fires is the exit code.
#[test]
fn the_watchdog_exits_with_the_stored_code() {
    // Production's order: armed at the stop, the code stored later by the tail.
    let stored = fresh_code();
    let fired = armed(std::time::Instant::now() + Duration::from_secs(1), stored);
    stored.store(0, Ordering::SeqCst);
    let (code, _) = fired.recv_timeout(WATCHDOG).expect("the watchdog fired");
    assert_eq!(code, 0, "the watchdog ignored the stored code");
}

/// U3 (RETIRE.4): armed after D + 500 ms already passed, it fires at once.
#[test]
fn a_watchdog_armed_late_fires_at_once() {
    let end = std::time::Instant::now()
        .checked_sub(Duration::from_secs(2))
        .expect("the clock is past its first 2 s");
    let (code, _) = armed(end, fresh_code())
        .recv_timeout(WATCHDOG)
        .expect("a late watchdog fired");
    assert_eq!(
        code,
        i32::from(EXIT_OVERRUN),
        "a late watchdog's exit was not 75"
    );
}

/// U3b (RETIRE.4): the tail stored its code (1, a clean tail's FAILURE), then
/// the main thread is held, as main.rs's join can be: the watchdog exits
/// with that stored code, not 75.
#[test]
fn a_held_main_thread_exits_with_the_code_the_tail_stored() {
    // Armed at the stop, as in production; the tail's finish stores the code later.
    let stored = fresh_code();
    let fired = armed(std::time::Instant::now() + Duration::from_secs(1), stored);
    let joined = StopOutcome::Joined(FlushEnd::Clean);
    let _ = finish(ExitCode::FAILURE, false, Some(&joined), stored);
    let (code, _) = fired.recv_timeout(WATCHDOG).expect("the watchdog fired");
    assert_eq!(
        code, 1,
        "the watchdog did not exit with the tail's stored code"
    );
}

/// U6 (RETIRE.4): the plan is stored in one place, the HTTP stop's path in
/// run.rs, after its budget is fixed from the trigger; the start checks,
/// which also build a budget, never touch it.
#[test]
fn the_plan_is_stored_once_after_the_stop_fixes_its_budget() {
    use crate::test_source_text::{production_text, sanitize};
    let run = sanitize(&production_text(include_str!("gateway/server/run.rs")));
    let stores: Vec<usize> = run
        .match_indices("RetirePlan::new(")
        .map(|(at, _)| at)
        .collect();
    let [store] = stores.as_slice() else {
        panic!(
            "run.rs must store the plan exactly once, found {}",
            stores.len()
        );
    };
    let fixed = run
        .find("StopBudget::fixed_at(")
        .expect("run.rs fixes the stop's budget");
    assert!(
        fixed < *store,
        "the plan is stored before the stop fixes its budget"
    );
    let checks = sanitize(&production_text(include_str!(
        "gateway/server/start_checks.rs"
    )));
    assert!(
        !checks.contains("retire"),
        "the start checks touch the plan"
    );
}

/// RETIRE.4, the watchdog's exit: `std::process::exit` flushes stdout under
/// its lock, so a stdout write on the watchdog's path could hold the exit it
/// exists to force. Nothing in this module, the whole watchdog path, writes
/// to stdout; the tail's one diagnostic goes to stderr.
#[test]
fn the_watchdog_path_writes_nothing_to_stdout() {
    use crate::test_source_text::{production_text, sanitize};
    let code = sanitize(&production_text(include_str!("retire.rs")));
    assert!(
        !code.contains("stdout"),
        "the watchdog's module reaches stdout"
    );
    // `print!` and `println!`, but not their stderr twins `eprint!`/`eprintln!`.
    for (at, _) in code.match_indices("print") {
        let stderr_twin = code[..at].ends_with('e');
        let is_macro = code[at..].starts_with("print!(") || code[at..].starts_with("println!(");
        assert!(
            stderr_twin || !is_macro,
            "the watchdog's module prints to stdout"
        );
    }
}

/// Whitespace-free production code of `source`, for wiring rows rustfmt cannot break.
fn wired(source: &str) -> String {
    use crate::test_source_text::{production_text, sanitize};
    sanitize(&production_text(source))
        .split_whitespace()
        .collect()
}

/// U6b (RETIRE.4): the plan cell is wired end to end: `cli::run` makes it and
/// hands it to the runtime and to dispatch, the HTTP serve gives it to the
/// gateway, the stop stores the plan in it and then arms the watchdog, and the
/// tail reads it. Deleting any link leaves the stop unbounded.
#[test]
fn the_plan_cell_is_wired_from_cli_run_to_the_stop_and_the_watchdog() {
    let run = wired(include_str!("gateway/server/run.rs"));
    let fixed = run
        .find("StopBudget::fixed_at(")
        .expect("the budget is fixed");
    let after = &run[fixed..];
    let set = after
        .find("cell.set(plan)")
        .expect("the stop stores the plan in the cell");
    let arm = after
        .find("crate::retire::arm(&plan)")
        .expect("the stop arms the watchdog");
    assert!(set < arm, "the watchdog is armed before the plan is stored");
    let entry = wired(include_str!("cli/entry.rs"));
    for link in [
        "RetireCell::default()",
        "block_on(mode,&plan,dispatch(args,std::sync::Arc::clone(&plan)))",
        "asyncfndispatch(cli:Cli,plan:crate::retire::RetireCell)",
        "Box::pin(run_server(cli,plan))",
        "asyncfnrun_server(cli:Cli,plan:crate::retire::RetireCell)",
        "gateway.set_retire_cell(plan)",
        "crate::retire::tail(code,left_running,plan.get().copied(),",
    ] {
        assert!(entry.contains(link), "cli::run's plan wiring lost `{link}`");
    }
    let construct = wired(include_str!("gateway/server/construct.rs"));
    assert!(
        construct.contains("self.retire=Some(cell)"),
        "the gateway's setter drops the cell"
    );
}

/// U2 (RETIRE.4), the logger's bound itself, on both sides of its min: a
/// plan ending far off leaves the usual 2 s, a near one cuts to its end.
#[test]
fn the_logger_bound_is_the_sooner_of_its_two_seconds_and_the_logger_end() {
    let now = std::time::Instant::now();
    let far = plan_ending_in(Duration::from_secs(60));
    assert_eq!(
        logger_bound(now, &far),
        now + LOG_FLUSH_DEADLINE,
        "a far logger end did not leave the usual 2 s"
    );
    let near = plan_ending_in(Duration::from_millis(300));
    assert_eq!(
        logger_bound(now, &near),
        near.logger_end().into_std(),
        "a near logger end did not cut the bound"
    );
}
