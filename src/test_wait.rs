// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One bounded wait for tests that see a time-bounded product path finish
//! (MIK-8171): a loaded runner can miss the first try, so a test polls within
//! a bound it states, never on the first answer alone.

use std::ops::ControlFlow;
use std::time::Duration;

pub(crate) use crate::gateway::test_helpers::HANG_BOUND;

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

/// Run `row` on its own current-thread runtime on a spawned thread, failing
/// with `hung` if it has not finished within `bound` of real time. The row
/// may pause its runtime's clock; this watchdog runs outside it, so a hang
/// still fails the test (the stuck thread is leaked, not joined) (MIK-8360).
pub(crate) fn watched_row<F>(bound: Duration, hung: &str, row: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(row());
        let _ = done.send(());
    });
    match finished.recv_timeout(bound) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("{hung}"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the row panicked; its message is above")
        }
    }
}

/// Whether a test that cannot run on this host must fail instead of skipping, from `TESTS_REQUIRE_ALL`: unset or
/// `0` skips (`0` is the local opt-out), `1` requires, and any other value is an error naming it, so a typo cannot
/// silently turn required mode off. CI sets `1` in every test shard (`scripts/ci/shard_tests.py`), the packaged-crate
/// suite's included (it runs through `shard_tests.py with-home`); a file the package leaves out is skipped there
/// through [`skip_unshipped`]. The Python rule is `scripts/ci/required_mode.py`.
pub(crate) fn required_mode(value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!(
            "TESTS_REQUIRE_ALL must be 0 or 1 when set, got {other:?}"
        )),
    }
}

/// `TESTS_REQUIRE_ALL` as this process sees it.
fn require_all_value() -> Option<String> {
    match std::env::var("TESTS_REQUIRE_ALL") {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => panic!("TESTS_REQUIRE_ALL is not valid unicode"),
    }
}

/// The one way a test skips because this host lacks something it needs (a user right, a loopback family, a file a
/// checkout should have): prints `skipped: <requirement>`, or panics where required mode is on, so a feature's only
/// check cannot pass by not running. A file the package leaves out on purpose goes through [`skip_unshipped`]
/// instead. The caller returns right after it (`scripts/ci/check_rust_skips.py` checks that).
///
/// # Panics
///
/// In required mode, and on a `TESTS_REQUIRE_ALL` value that is not `0` or `1`.
pub(crate) fn skip_or_fail(requirement: &str) {
    match required_mode(require_all_value().as_deref()) {
        Ok(true) => panic!("required here but unavailable on this host: {requirement}"),
        Ok(false) => eprintln!("skipped: {requirement}"),
        Err(message) => panic!("{message}"),
    }
}

/// [`skip_unshipped`]'s rule, apart so its rows can state every case. In the unpacked published crate a file the
/// package leaves out is missing by design, a property of the crate and not of the host, so the test skips in every
/// mode. Anywhere else the missing file is [`skip_or_fail`]'s missing requirement: it fails in required mode. A
/// `TESTS_REQUIRE_ALL` value that is not `0` or `1` is an error either way.
pub(crate) fn unshipped_verdict(
    packaged: bool,
    value: Option<&str>,
    what: &str,
) -> Result<(), String> {
    if required_mode(value)? && !packaged {
        return Err(format!(
            "required here but unavailable on this host: {what}"
        ));
    }
    Ok(())
}

/// The one way a test skips because the crate under test is the unpacked published crate and the repository file it
/// needs is one the package leaves out on purpose (Cargo.toml `include`). `packaged` is the caller's own check of the
/// crate it reads (`Cargo.toml.orig` and no `.git`: `boundary_pins::packaged`). In a packaged crate it prints
/// `skipped (not shipped in the packaged crate): <what>` in every mode; in a checkout it is [`skip_or_fail`]. The
/// caller returns right after it (`scripts/ci/check_rust_skips.py` checks that).
///
/// # Panics
///
/// In a checkout under required mode, and on a `TESTS_REQUIRE_ALL` value that is not `0` or `1`.
pub(crate) fn skip_unshipped(packaged: bool, what: &str) {
    match unshipped_verdict(packaged, require_all_value().as_deref(), what) {
        Ok(()) if packaged => eprintln!("skipped (not shipped in the packaged crate): {what}"),
        Ok(()) => eprintln!("skipped: {what}"),
        Err(message) => panic!("{message}"),
    }
}

#[cfg(tp3)]
#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;
    use std::time::Duration;

    use std::process::Output;

    use super::{required_mode, unshipped_verdict, wait_real_time, wait_until};

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

    const PLANTED: &str = "the planted requirement";

    /// A1: unset and `0` skip (the local opt-out).
    #[test]
    fn a1_unset_and_zero_skip() {
        assert_eq!(required_mode(None), Ok(false));
        assert_eq!(required_mode(Some("0")), Ok(false));
    }

    /// A2: exactly `1` requires; every other value, empty included, is an error naming it.
    #[test]
    fn a2_one_requires_and_any_other_value_is_an_error() {
        assert_eq!(required_mode(Some("1")), Ok(true));
        for bad in ["", "yes", " 1", "true"] {
            let err = required_mode(Some(bad)).unwrap_err();
            assert!(err.contains(&format!("{bad:?}")), "{err}");
        }
    }

    /// U1: in the unpacked published crate, a file the package leaves out skips in every mode, required mode
    /// included: its absence is a property of the crate, not of the host.
    #[test]
    fn u1_an_unshipped_file_skips_in_a_packaged_crate_in_every_mode() {
        for value in [None, Some("0"), Some("1")] {
            assert_eq!(unshipped_verdict(true, value, PLANTED), Ok(()), "{value:?}");
        }
    }

    /// U2: in a checkout the same missing file is a missing requirement: it fails in required mode, naming it,
    /// and skips otherwise.
    #[test]
    fn u2_an_unshipped_file_in_a_checkout_fails_in_required_mode() {
        assert_eq!(
            unshipped_verdict(false, Some("1"), PLANTED),
            Err(format!(
                "required here but unavailable on this host: {PLANTED}"
            ))
        );
        assert_eq!(unshipped_verdict(false, None, PLANTED), Ok(()));
        assert_eq!(unshipped_verdict(false, Some("0"), PLANTED), Ok(()));
    }

    /// U3: a value that is not `0` or `1` is an error in a packaged crate too.
    #[test]
    fn u3_a_bad_value_is_an_error_in_a_packaged_crate_too() {
        let err = unshipped_verdict(true, Some("yes"), PLANTED).unwrap_err();
        assert!(err.contains("\"yes\""), "{err}");
    }

    fn child(value: Option<&str>) -> Output {
        child_running("test_wait::tests::skip_child", value)
    }

    /// The test binary running only the ignored row `test`, with `TESTS_REQUIRE_ALL` set to `value` or removed.
    fn child_running(test: &str, value: Option<&str>) -> Output {
        let mut cmd = crate::test_home::test_binary();
        cmd.args(["--ignored", "--exact", test, "--nocapture"]);
        cmd.env_remove("TESTS_REQUIRE_ALL");
        if let Some(v) = value {
            cmd.env("TESTS_REQUIRE_ALL", v);
        }
        cmd.output().expect("the child runs")
    }

    /// Run only by U4, in a child: the real helper in a packaged crate.
    #[test]
    #[ignore = "run by u4, in a child with its own environment"]
    fn unshipped_packaged_child() {
        super::skip_unshipped(true, PLANTED);
    }

    /// Run only by U4, in a child: the real helper in a checkout.
    #[test]
    #[ignore = "run by u4, in a child with its own environment"]
    fn unshipped_checkout_child() {
        super::skip_unshipped(false, PLANTED);
    }

    /// U4: the real helper reads the variable. In a packaged crate, unset, `0` and `1` all print the unshipped
    /// skip line and pass; in a checkout, unset and `0` print the plain skip line and `1` fails naming the file,
    /// as `skip_or_fail` does; a value that is not `0` or `1` fails naming it in both.
    #[test]
    fn u4_the_real_unshipped_helper_reads_the_variable() {
        const PACKAGED: &str = "test_wait::tests::unshipped_packaged_child";
        const CHECKOUT: &str = "test_wait::tests::unshipped_checkout_child";
        for value in [None, Some("0"), Some("1")] {
            let out = child_running(PACKAGED, value);
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "{value:?}: {err}");
            assert!(
                err.contains(&format!(
                    "skipped (not shipped in the packaged crate): {PLANTED}"
                )),
                "{value:?}: {err}"
            );
        }
        for value in [None, Some("0")] {
            let out = child_running(CHECKOUT, value);
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "{value:?}: {err}");
            assert!(
                err.contains(&format!("skipped: {PLANTED}")),
                "{value:?}: {err}"
            );
        }
        let out = child_running(CHECKOUT, Some("1"));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(
            err.contains(&format!(
                "required here but unavailable on this host: {PLANTED}"
            )),
            "{err}"
        );
        for child in [PACKAGED, CHECKOUT] {
            let out = child_running(child, Some("yes"));
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "{child}: {err}");
            assert!(err.contains("\"yes\""), "{child}: {err}");
        }
    }

    /// Run only by A4, in a child with its own environment.
    #[test]
    #[ignore = "run by a4, in a child with its own environment"]
    fn skip_child() {
        super::skip_or_fail(PLANTED);
    }

    /// A4: the real helper reads the variable: unset and `0` print the skip line and pass; `1` fails naming the
    /// requirement; any other value panics naming the value.
    #[test]
    fn a4_the_real_helper_reads_the_variable() {
        for value in [None, Some("0")] {
            let out = child(value);
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "{value:?}: {err}");
            assert!(
                err.contains(&format!("skipped: {PLANTED}")),
                "{value:?}: {err}"
            );
        }
        let out = child(Some("1"));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(
            err.contains(&format!(
                "required here but unavailable on this host: {PLANTED}"
            )),
            "{err}"
        );
        let out = child(Some("yes"));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(err.contains("\"yes\""), "{err}");
    }
}
