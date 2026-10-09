// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One bounded wait for tests that see a time-bounded product path finish
//! (MIK-8171): a loaded runner can miss the first try, so a test polls within
//! a bound it states, never on the first answer alone.

use std::ops::ControlFlow;
use std::time::Duration;

/// How often [`wait_until`] polls.
const POLL: Duration = Duration::from_millis(20);

/// Run `step` until it breaks with a value, for at most `bound` of tokio
/// time; `Err` carries the last observation when the bound passes first. An
/// answer that arrives only after the bound is not within it, so it is an
/// `Err` too.
/// Measured on the tokio clock, so a paused-time test must not wait on
/// blocking work with it.
pub(crate) async fn wait_until<T, F, Fut>(bound: Duration, mut step: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ControlFlow<T, String>>,
{
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        let outcome = step().await;
        let late = tokio::time::Instant::now() >= deadline;
        let observed = match outcome {
            ControlFlow::Break(value) if !late => return Ok(value),
            ControlFlow::Break(_) => return Err(format!("answered only after {bound:?}")),
            ControlFlow::Continue(observed) => observed,
        };
        if late {
            return Err(observed);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Poll `done` until it holds, for at most `bound` of real time (MIK-8216).
///
/// For a paused-clock test that waits on blocking work an OS thread does,
/// which [`wait_until`] cannot see: the tokio clock never moves while this
/// waits. Each round yields, so tasks run, then sleeps 2 ms of real time, and
/// neither lets the paused clock auto-advance to a pending timer.
pub(crate) async fn wait_real_time(
    bound: Duration,
    mut done: impl FnMut() -> bool,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        if done() {
            return Ok(());
        }
        if start.elapsed() >= bound {
            return Err(format!("did not happen within {bound:?} of real time"));
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;
    use std::time::Duration;

    use super::{wait_real_time, wait_until};

    /// A wait whose condition never holds gives up at its bound, with the
    /// last observation, and not later.
    #[tokio::test(start_paused = true)]
    async fn a_wait_that_never_succeeds_gives_up_at_its_bound() {
        let bound = Duration::from_secs(1);
        let started = tokio::time::Instant::now();
        let waited = tokio::time::timeout(
            bound * 2,
            wait_until(bound, || async {
                ControlFlow::<(), _>::Continue("never".to_owned())
            }),
        )
        .await
        .expect("the wait gives up within twice its bound");
        assert_eq!(waited, Err("never".to_owned()));
        assert!(started.elapsed() >= bound, "not before its bound");
    }

    /// A condition that holds on the third poll returns its value.
    #[tokio::test(start_paused = true)]
    async fn a_wait_returns_the_value_once_its_condition_holds() {
        let mut polls = 0;
        let value = wait_until(Duration::from_secs(1), || {
            polls += 1;
            let done = polls == 3;
            async move {
                if done {
                    ControlFlow::Break(polls)
                } else {
                    ControlFlow::Continue(format!("poll {polls}"))
                }
            }
        })
        .await;
        assert_eq!(value, Ok(3));
    }

    /// MIK-8216: work an OS thread finishes late, off the runtime, is still
    /// waited for. The writer lands well after 1000 scheduler turns are over,
    /// so the wait must be measured in real time; and the paused clock, with a
    /// timer pending, must not move while it waits, so no later interval could
    /// stand in for the one under test.
    #[tokio::test]
    async fn a_late_os_thread_write_is_waited_for_on_a_still_clock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("late");
        tokio::time::pause();
        let pending = tokio::spawn(tokio::time::sleep(Duration::from_secs(300)));
        let before = tokio::time::Instant::now();
        let target = file.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            std::fs::write(&target, b"{}").expect("write");
        });
        let waited = wait_real_time(Duration::from_secs(30), || file.exists()).await;
        let moved = tokio::time::Instant::now() - before;
        writer.join().expect("writer thread");
        pending.abort();
        assert_eq!(waited, Ok(()), "the late write was not waited for");
        assert_eq!(
            moved,
            Duration::ZERO,
            "the paused clock moved while waiting: a later interval could explain the file"
        );
    }
}
