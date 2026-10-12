// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4a compile-red row R3: written against the changed `Task` API
//! (`create`/`complete`/`fail` return `Result`, outcomes by reference,
//! `TaskModelError::ClockUnreadable`), so it does not build on the code
//! before that change. Kept apart so it can be held back on its own.

use serde_json::json;

use super::lifecycle_tests::{at, error, task, wire};
use super::*;

/// MIK-8202.AC.16 (R3, mutants M3a and M3b): on a clock that reads before
/// 1970, `Task::create`, `complete` and `fail` return
/// `TaskModelError::ClockUnreadable` and apply nothing. The caller keeps its
/// outcome (passed by reference) and the task stays live; once the clock
/// reads, the same outcome completes or fails it. A late outcome on a terminal
/// task is still `Ok(())`, and a non-object result is `Err(InvalidInput)`.
/// Mutant M3a: `complete` applies the outcome dated at the epoch on the clock
/// error. Mutant M3b: the same for `fail`.
#[test]
fn create_complete_and_fail_on_a_dark_clock_keep_the_outcome() {
    let result = json!({ "content": [{ "type": "text", "text": "kept" }] });
    let kept = result.clone();
    let mut live = task();
    let mut failing = task();
    let mut terminal = task();
    terminal
        .transition(TaskTransition::Complete(json!({ "content": [] })), at(1))
        .expect("a live task completes");

    let dark = crate::clock::test_clock::before_epoch();
    assert_eq!(
        Task::create("dark-probe").err(),
        Some(TaskModelError::ClockUnreadable),
        "create on a dark clock is an error, never an epoch-dated task"
    );
    assert_eq!(live.complete(&result), Err(TaskModelError::ClockUnreadable));
    assert_eq!(wire(&live)["status"], "working", "nothing was applied");
    assert_eq!(result, kept, "the caller still holds its outcome");
    assert_eq!(failing.fail(&error()), Err(TaskModelError::ClockUnreadable));
    assert_eq!(wire(&failing)["status"], "working", "nothing was applied");
    assert_eq!(
        terminal.complete(&result),
        Ok(()),
        "a late outcome is ignored"
    );
    assert_eq!(
        live.complete(&json!("not an object")),
        Err(TaskModelError::InvalidInput)
    );
    assert_eq!(wire(&live)["status"], "working");
    drop(dark);

    assert_eq!(live.complete(&result), Ok(()));
    assert_eq!(wire(&live)["status"], "completed");
    assert_eq!(wire(&live)["result"], kept);
    assert_eq!(failing.fail(&error()), Ok(()));
    assert_eq!(wire(&failing)["status"], "failed");
    assert_eq!(
        wire(&failing)["error"],
        json!({ "code": -32042, "message": "upstream refused", "data": { "detail": [1, 2] } })
    );
}
