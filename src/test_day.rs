// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A test that saves daily spend and reads it back must judge both on one UTC
//! day: a budget's day rolls at 00:00 UTC, so a save before midnight and a
//! restore after it correctly read 0 (MIK-8395). [`same_utc_day`] runs a
//! scenario between two readings of the day and runs it once more when they
//! differ, so the caller asserts on values from a single day. It never
//! asserts itself; the caller does.

use std::future::Future;

/// Today's UTC day number from the crate clock. A clock that cannot be read
/// fails the test that asked: a day it cannot name proves nothing.
fn utc_day() -> u64 {
    crate::clock::unix_secs().expect("a readable clock") / 86_400
}

/// Run `scenario` within one UTC day and return what it observed.
pub(crate) fn same_utc_day<T>(scenario: impl FnMut() -> T) -> T {
    same_utc_day_with(utc_day, scenario)
}

/// [`same_utc_day`] for an async scenario.
pub(crate) async fn same_utc_day_async<T, F: Future<Output = T>>(scenario: impl FnMut() -> F) -> T {
    same_utc_day_async_with(utc_day, scenario).await
}

/// [`same_utc_day`] with the day read by `day`, so a row can script it.
fn same_utc_day_with<T>(mut day: impl FnMut() -> u64, mut scenario: impl FnMut() -> T) -> T {
    let before = day();
    let seen = scenario();
    if day() == before {
        return seen;
    }
    rerun_notice();
    let before = day();
    let seen = scenario();
    assert_eq!(day(), before, "{DOUBLE_CHANGE}");
    seen
}

/// Said once in the test's output when a scenario runs a second time.
fn rerun_notice() {
    eprintln!("same_utc_day: the UTC day changed during the scenario; running it once more");
}

/// Why a scenario cannot be judged: the day changed on both runs.
const DOUBLE_CHANGE: &str = "the UTC day changed during both runs of the scenario, so neither run's values belong to one day";

/// [`same_utc_day_async`] with the day read by `day`.
async fn same_utc_day_async_with<T, F: Future<Output = T>>(
    mut day: impl FnMut() -> u64,
    mut scenario: impl FnMut() -> F,
) -> T {
    let before = day();
    let seen = scenario().await;
    if day() == before {
        return seen;
    }
    rerun_notice();
    let before = day();
    let seen = scenario().await;
    assert_eq!(day(), before, "{DOUBLE_CHANGE}");
    seen
}

#[cfg(test)]
mod tests {
    use super::{same_utc_day_async_with, same_utc_day_with};

    /// Days read in turn from `days`.
    fn scripted(days: &'static [u64]) -> impl FnMut() -> u64 {
        let mut next = days.iter().copied();
        move || next.next().expect("a scripted day for every read")
    }

    /// Control: on one day the scenario runs exactly once.
    #[test]
    fn a_scenario_within_one_day_runs_once() {
        let mut runs = 0;
        // Days to spare, so a helper that reruns anyway fails on `runs`, not on
        // the script running out.
        let seen = same_utc_day_with(scripted(&[7, 7, 7, 7]), || {
            runs += 1;
            runs
        });
        assert_eq!((runs, seen), (1, 1));
    }

    /// The day changes during the first run: it runs once more and the
    /// second run's value is returned.
    #[test]
    fn same_utc_day_reruns_once_when_the_day_changes() {
        let mut runs = 0;
        let seen = same_utc_day_with(scripted(&[7, 8, 8, 8]), || {
            runs += 1;
            runs
        });
        assert_eq!((runs, seen), (2, 2));
    }

    /// The day changes during both runs: a test cannot be judged, and the
    /// helper says so instead of looping.
    #[test]
    #[should_panic(expected = "the UTC day changed during both runs")]
    fn a_day_change_during_both_runs_panics() {
        let _ = same_utc_day_with(scripted(&[7, 8, 8, 9]), || ());
    }

    /// The async form follows the same rule.
    #[tokio::test]
    async fn the_async_form_reruns_once_when_the_day_changes() {
        let mut runs = 0;
        let seen = same_utc_day_async_with(scripted(&[7, 8, 8, 8]), || {
            runs += 1;
            let run = runs;
            async move { run }
        })
        .await;
        assert_eq!((runs, seen), (2, 2));
    }
}
