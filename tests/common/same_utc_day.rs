// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A copy of the crate's `same_utc_day` (`src/test_day.rs`) for integration
//! tests, which cannot reach crate-private helpers. The day is read from the
//! host clock directly: the crate's clock module is private, and test code
//! may read the clock (MIK-8202 AC.14). A test that
//! saves daily spend and reads it back must judge both on one UTC day: a
//! budget's day rolls at 00:00 UTC (MIK-8395). The scenario runs between two
//! readings of the day and once more when they differ; the caller asserts.
#![allow(
    clippy::disallowed_methods,
    reason = "test code reads the host clock; the crate's clock module is private (MIK-8202 AC.14)"
)]

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

/// Today's UTC day number, from the clock that dates a cost save.
fn utc_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the host clock reads after 1970")
        .as_secs()
        / 86_400
}

/// Run `scenario` within one UTC day and return what it observed.
pub fn same_utc_day<T>(scenario: impl FnMut() -> T) -> T {
    same_utc_day_with(utc_day, scenario)
}

/// [`same_utc_day`] with the day read by `day`, so a row can script it.
fn same_utc_day_with<T>(mut day: impl FnMut() -> u64, mut scenario: impl FnMut() -> T) -> T {
    let before = day();
    let seen = scenario();
    if day() == before {
        return seen;
    }
    eprintln!("same_utc_day: the UTC day changed during the scenario; running it once more");
    let before = day();
    let seen = scenario();
    assert_eq!(
        day(),
        before,
        "the UTC day changed during both runs of the scenario, so neither run's values belong to one day"
    );
    seen
}

/// [`same_utc_day`] for an async scenario.
pub async fn same_utc_day_async<T, F: Future<Output = T>>(scenario: impl FnMut() -> F) -> T {
    same_utc_day_async_with(utc_day, scenario).await
}

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
    eprintln!("same_utc_day: the UTC day changed during the scenario; running it once more");
    let before = day();
    let seen = scenario().await;
    assert_eq!(
        day(),
        before,
        "the UTC day changed during both runs of the scenario, so neither run's values belong to one day"
    );
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

    /// The day changes during both runs: the helper says so instead of looping.
    #[test]
    #[should_panic(expected = "the UTC day changed during both runs")]
    fn a_day_change_during_both_runs_panics() {
        same_utc_day_with(scripted(&[7, 8, 8, 9]), || ());
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
