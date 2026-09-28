// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `env_poll`, `WarnLimiter` and `EnvPoller` (#1286).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{DEBOUNCE, ENV_POLL, RELOAD_TICK, TEST_ENV_POLL, WarnLimiter, env_poll};
use crate::config::EnvOverlay;
use crate::gateway::test_helpers::write_owner_only;

fn write(path: &Path, text: &str) {
    write_owner_only(path, text).unwrap();
}

/// The overlay a load of `paths` applies, as the live one was built.
fn applied(paths: &[PathBuf]) -> EnvOverlay {
    EnvOverlay::from_paths_checked(paths).expect("the load succeeds")
}

fn one_file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.env");
    write(&path, text);
    (dir, path)
}

/// U1
#[test]
fn u1_equal_text_is_none() {
    let (_d, p) = one_file("K=1\n");
    let paths = vec![p];
    assert_eq!(env_poll(&applied(&paths), &paths), None);
}

/// U2: differs, and keeps reporting while it differs.
#[test]
fn u2_changed_text_is_some_on_every_call() {
    let (_d, p) = one_file("K=1\n");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    write(&p, "K=2\n");
    assert_eq!(env_poll(&overlay, &paths), Some(p.clone()));
    assert_eq!(env_poll(&overlay, &paths), Some(p), "no suppression");
}

/// U4
#[test]
fn u4_a_file_that_appeared_is_some() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("late.env");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    write(&p, "K=1\n");
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// U4b
#[test]
fn u4b_a_file_still_absent_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let paths = vec![dir.path().join("never.env")];
    assert_eq!(env_poll(&applied(&paths), &paths), None);
}

/// U5
#[test]
fn u5_a_file_that_vanished_is_some() {
    let (_d, p) = one_file("K=1\n");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    std::fs::remove_file(&p).unwrap();
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// U6: refused by the loader's own mode rule (a world bit), which holds for
/// root too, so this is not an EACCES test.
#[cfg(unix)]
#[test]
fn u6_a_mode_refused_file_is_some() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_d, p) = one_file("K=1\n");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// U7: the first differing path in `paths` order.
#[test]
fn u7_the_first_differing_path_is_returned() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a.env"), dir.path().join("b.env"));
    write(&a, "A=1\n");
    write(&b, "B=1\n");
    let paths = vec![b.clone(), a.clone()];
    let overlay = applied(&paths);
    write(&a, "A=2\n");
    write(&b, "B=2\n");
    assert_eq!(env_poll(&overlay, &paths), Some(b));
}

fn restore_mtime(path: &Path, mtime: std::time::SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
}

/// U8: same size, mtime put back: content is what is compared.
#[test]
fn u8_a_same_size_rewrite_with_the_mtime_restored_is_some() {
    let (_d, p) = one_file("K=1\n");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
    write(&p, "K=2\n");
    restore_mtime(&p, mtime);
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// U8b: same size and mtime, same content.
#[test]
fn u8b_an_unchanged_file_with_a_touched_mtime_is_none() {
    let (_d, p) = one_file("K=1\n");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
    write(&p, "K=1\n");
    restore_mtime(&p, mtime);
    assert_eq!(env_poll(&overlay, &paths), None);
}

/// U9: no read cap: a byte past 1 MiB is seen.
#[test]
fn u9_a_large_file_is_read_in_full() {
    let mut text = String::new();
    while text.len() < 2 * 1024 * 1024 {
        text.push_str("PAD=0123456789abcdef0123456789abcdef\n");
    }
    let (_d, p) = one_file(&text);
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    assert_eq!(env_poll(&overlay, &paths), None);
    let at = text[1024 * 1024 + 1..].find('0').unwrap() + 1024 * 1024 + 1;
    let mut changed = text.into_bytes();
    changed[at] = b'9';
    write(&p, std::str::from_utf8(&changed).unwrap());
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// U12: a path the overlay neither loaded nor found absent (a tolerant load
/// that failed on it) differs.
#[test]
fn u12_a_path_in_neither_sources_nor_absent_is_some() {
    let (_d, p) = one_file("K=1\n");
    assert_eq!(
        env_poll(&EnvOverlay::none(), std::slice::from_ref(&p)),
        Some(p)
    );
}

/// U13: compared with the applied overlay, not with the previous tick.
#[test]
fn u13_an_unchanged_file_that_differs_from_the_applied_text_stays_some() {
    let (_d, p) = one_file("K=1\n");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    write(&p, "K=2\n");
    assert_eq!(env_poll(&overlay, &paths), Some(p.clone()));
    assert_eq!(
        env_poll(&overlay, &paths),
        Some(p),
        "the file is unchanged since the last tick, but not what was applied"
    );
}

/// U14: a poll faster than the debounce would restart it forever.
#[test]
fn u14_every_poll_interval_outlasts_the_debounce() {
    assert!(ENV_POLL > DEBOUNCE + RELOAD_TICK);
    assert!(TEST_ENV_POLL > DEBOUNCE + RELOAD_TICK);
}

fn at(base: Instant, secs: u64) -> Instant {
    base + Duration::from_secs(secs)
}

/// R1
#[test]
fn r1_the_same_error_within_a_minute_warns_once() {
    let (mut l, t, p) = (WarnLimiter::default(), Instant::now(), Path::new("/a"));
    assert!(l.should_warn(p, "E1", at(t, 0)));
    assert!(!l.should_warn(p, "E1", at(t, 10)));
}

/// R2
#[test]
fn r2_a_different_error_warns() {
    let (mut l, t, p) = (WarnLimiter::default(), Instant::now(), Path::new("/a"));
    assert!(l.should_warn(p, "E1", at(t, 0)));
    assert!(l.should_warn(p, "E2", at(t, 1)));
}

/// R2b: every change of error is new information.
#[test]
fn r2b_a_flip_between_errors_warns_every_time() {
    let (mut l, t, p) = (WarnLimiter::default(), Instant::now(), Path::new("/a"));
    assert!(l.should_warn(p, "E1", at(t, 0)));
    assert!(l.should_warn(p, "E2", at(t, 1)));
    assert!(l.should_warn(p, "E1", at(t, 2)));
}

/// R3
#[test]
fn r3_the_same_error_warns_again_after_a_minute() {
    let (mut l, t, p) = (WarnLimiter::default(), Instant::now(), Path::new("/a"));
    let warned: Vec<bool> = [0, 30, 59, 60]
        .into_iter()
        .map(|s| l.should_warn(p, "E1", at(t, s)))
        .collect();
    assert_eq!(warned, [true, false, false, true]);
}

/// R4: one slot per path, not one global slot.
#[test]
fn r4_two_failing_paths_each_warn_once() {
    let (mut l, t) = (WarnLimiter::default(), Instant::now());
    let (a, b) = (Path::new("/a"), Path::new("/b"));
    let warned: Vec<bool> = [(a, "E1"), (b, "E2"), (a, "E1"), (b, "E2")]
        .into_iter()
        .zip(0..)
        .map(|((p, e), s)| l.should_warn(p, e, at(t, s)))
        .collect();
    assert_eq!(warned, [true, true, false, false]);
}

/// A link loop where an env file should be: two links pointing at each other.
#[cfg(unix)]
fn link_loop(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let other = dir.join(format!("{name}.other"));
    std::os::unix::fs::symlink(&other, &path).unwrap();
    std::os::unix::fs::symlink(&path, &other).unwrap();
    path
}

/// U15: a lookup error is not absence: the checked load fails rather than
/// recording the file missing and succeeding without its values.
#[cfg(unix)]
#[test]
fn u15_a_lookup_error_fails_the_load_instead_of_reading_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    let looped = link_loop(dir.path(), "a.env");
    assert!(
        EnvOverlay::from_paths_checked(&[looped]).is_err(),
        "a link loop must fail the load, not read as a missing file"
    );
}

/// U16: a file recorded absent that now fails its lookup differs, so the
/// failure is reported instead of compared equal to "missing".
#[cfg(unix)]
#[test]
fn u16_a_lookup_error_on_a_recorded_absent_path_differs() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.env");
    let paths = vec![p.clone()];
    let overlay = applied(&paths);
    link_loop(dir.path(), "a.env");
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// U17: a path listed twice and rewritten between the two loads differs
/// while any load disagrees with the disk.
#[test]
fn u17_a_duplicated_path_differs_while_one_load_is_stale() {
    let (_d, p) = one_file("K=1\n");
    let mut overlay = EnvOverlay::default();
    overlay.apply_file(&p).unwrap();
    write(&p, "K=2\n");
    overlay.apply_file(&p).unwrap();
    let paths = vec![p.clone(), p.clone()];
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// U18: a path recorded both absent and loaded (it appeared between two
/// loads) differs, whether the file is now present or missing.
#[test]
fn u18_a_path_recorded_absent_and_loaded_differs() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.env");
    let mut overlay = EnvOverlay::default();
    overlay.apply_file(&p).unwrap();
    write(&p, "K=1\n");
    overlay.apply_file(&p).unwrap();
    let paths = vec![p.clone(), p.clone()];
    assert_eq!(env_poll(&overlay, &paths), Some(p.clone()));
    std::fs::remove_file(&p).unwrap();
    assert_eq!(env_poll(&overlay, &paths), Some(p));
}

/// An env with one recorded file, so a tick runs its read: with none, the
/// poller skips the read entirely (U21). The read under test is injected, so
/// the path is never opened.
fn one_env_file() -> std::sync::Arc<crate::config::LiveEnv> {
    std::sync::Arc::new(crate::config::LiveEnv::new(
        std::sync::Arc::new(EnvOverlay::none()),
        crate::config::ResolvedEnvFiles::new(vec![PathBuf::from("/unread.env")], false),
    ))
}

/// How many times `stalled_read` has started. Only U19 uses it.
static STALLED_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A poll read that never finishes in time, like a stalled NFS mount.
fn stalled_read(_: &EnvOverlay, _: &[PathBuf]) -> Option<PathBuf> {
    STALLED_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    std::thread::sleep(Duration::from_secs(10));
    None
}

/// U19: a stalled read does not hold the tick, so the rewatch loop gets
/// back to its shutdown check; the next tick waits on the same read.
#[tokio::test]
async fn u19_a_stalled_read_returns_within_the_wait() {
    let mut poller = super::EnvPoller::new(
        one_env_file(),
        std::sync::Arc::default(),
        PathBuf::from("/cfg.yaml"),
    )
    .with_read(stalled_read);
    for _ in 0..3 {
        let tick = tokio::time::timeout(
            Duration::from_secs(2),
            poller.tick(Duration::from_millis(100)),
        )
        .await;
        assert!(
            matches!(tick, Ok(None)),
            "a stalled read must not hold the tick"
        );
    }
    assert_eq!(
        STALLED_READS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a stalled read is awaited again, never started twice: at most one thread"
    );
}

/// U20: a failed config-file reload primes the limiter with its error, so
/// the first retry of the same error does not warn a second time.
#[test]
fn u20_a_config_file_failure_primes_the_limiter_for_its_retries() {
    use super::super::ReloadTrigger;
    let counts = super::EnvReloadCounts::default();
    let mut limiter = WarnLimiter::default();
    let config = PathBuf::from("/cfg.yaml");
    counts.settled(&mut limiter, Some("E"), &ReloadTrigger::ConfigFile);
    counts.report_failure(&mut limiter, &ReloadTrigger::Retry(config), "E");
    assert_eq!(
        counts.warns.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the retry repeats the config-file failure's warning"
    );
}

/// A second stalled read, kept apart from `stalled_read` so U19's count
/// stays exact when the two tests run in parallel.
fn stalled_read_for_l7(_: &EnvOverlay, _: &[PathBuf]) -> Option<PathBuf> {
    std::thread::sleep(Duration::from_secs(10));
    None
}

/// L7: a stalled read is warned about once, not on every tick.
#[test]
fn l7_a_stalled_read_is_warned_about_once() {
    use crate::test_log_capture::{count, records};
    let mut poller = super::EnvPoller::new(
        one_env_file(),
        std::sync::Arc::default(),
        PathBuf::from("/cfg.yaml"),
    )
    .with_read(stalled_read_for_l7);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let logs = records(|| {
        runtime.block_on(async {
            for _ in 0..3 {
                assert!(poller.tick(Duration::from_millis(50)).await.is_none());
            }
        });
    });
    assert_eq!(count(&logs, "WARN", "env-file read has not finished"), 1);
}

/// A poll read that dies, so its result channel closes empty.
fn dying_read(_: &EnvOverlay, _: &[PathBuf]) -> Option<PathBuf> {
    panic!("the poll read died");
}

/// L8: a read that ends without a result is warned about, not taken for
/// "no difference".
#[test]
fn l8_a_read_that_dies_is_warned_about() {
    use crate::test_log_capture::{count, records};
    let mut poller = super::EnvPoller::new(
        one_env_file(),
        std::sync::Arc::default(),
        PathBuf::from("/cfg.yaml"),
    )
    .with_read(dying_read);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let logs = records(|| {
        runtime.block_on(async {
            assert!(poller.tick(Duration::from_secs(5)).await.is_none());
        });
    });
    assert_eq!(count(&logs, "WARN", "ended without a result"), 1);
}

/// A poll read slow enough to overrun a short wait once, then finish.
fn slow_read(_: &EnvOverlay, _: &[PathBuf]) -> Option<PathBuf> {
    std::thread::sleep(Duration::from_millis(300));
    None
}

/// L9: a stall that ends clears the warning state, so the next stall is
/// warned about again.
#[test]
fn l9_a_new_stall_after_recovery_is_warned_about_again() {
    use crate::test_log_capture::{count, records};
    let mut poller = super::EnvPoller::new(
        one_env_file(),
        std::sync::Arc::default(),
        PathBuf::from("/cfg.yaml"),
    )
    .with_read(slow_read);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let logs = records(|| {
        runtime.block_on(async {
            let short = Duration::from_millis(20);
            assert!(poller.tick(short).await.is_none(), "first stall");
            assert!(
                poller.tick(Duration::from_secs(5)).await.is_none(),
                "it ends"
            );
            assert!(poller.tick(short).await.is_none(), "second stall");
        });
    });
    assert_eq!(count(&logs, "WARN", "env-file read has not finished"), 2);
}

/// Reads started by `counted_read`. Only U21 uses it.
static COUNTED_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn counted_read(_: &EnvOverlay, _: &[PathBuf]) -> Option<PathBuf> {
    COUNTED_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    None
}

/// U21: with no env files (the default) a tick starts no read thread, and
/// still retries a failed reload.
#[tokio::test]
async fn u21_no_env_files_starts_no_read_and_still_retries() {
    use super::super::ReloadTrigger;
    let reloads = std::sync::Arc::new(super::EnvReloadCounts::default());
    let mut poller = super::EnvPoller::new(
        std::sync::Arc::default(),
        std::sync::Arc::clone(&reloads),
        PathBuf::from("/cfg.yaml"),
    )
    .with_read(counted_read);
    assert!(poller.tick(Duration::from_secs(1)).await.is_none());
    reloads.settled(
        &mut WarnLimiter::default(),
        Some("E"),
        &ReloadTrigger::ConfigFile,
    );
    assert!(matches!(
        poller.tick(Duration::from_secs(1)).await,
        Some(ReloadTrigger::Retry(_))
    ));
    assert_eq!(
        COUNTED_READS.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no env files, no read"
    );
}

/// U23: after a config-file failure, a retry under a still-differing env
/// file with the same error does not warn again; a different error does.
#[test]
fn u23_an_env_file_retry_of_a_config_failure_does_not_warn_again() {
    use super::super::ReloadTrigger;
    let counts = super::EnvReloadCounts::default();
    let mut limiter = WarnLimiter::default();
    let env = ReloadTrigger::EnvFile(PathBuf::from("/a.env"));
    counts.settled(&mut limiter, Some("E"), &ReloadTrigger::ConfigFile);
    counts.report_failure(&mut limiter, &env, "E");
    let warns = || counts.warns.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(warns(), 0, "the same error was already warned about");
    counts.report_failure(&mut limiter, &env, "E2");
    assert_eq!(warns(), 1, "a different error is new information");
}

/// A spawn that always fails, like a process out of threads.
fn failing_spawn(_: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    Err(std::io::Error::other("no threads"))
}

/// U22 and L10: when a read cannot be started, a failed reload is still
/// retried, and the failure is warned about once, not every tick.
#[test]
fn u22_l10_a_read_that_cannot_start_still_retries_and_warns_once() {
    use super::super::ReloadTrigger;
    use crate::test_log_capture::{count, records};
    let reloads = std::sync::Arc::new(super::EnvReloadCounts::default());
    reloads.settled(
        &mut WarnLimiter::default(),
        Some("E"),
        &ReloadTrigger::ConfigFile,
    );
    let mut poller = super::EnvPoller::new(one_env_file(), reloads, PathBuf::from("/cfg.yaml"))
        .with_spawn(failing_spawn);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let logs = records(|| {
        runtime.block_on(async {
            for _ in 0..3 {
                assert!(matches!(
                    poller.tick(Duration::from_secs(1)).await,
                    Some(ReloadTrigger::Retry(_))
                ));
            }
        });
    });
    assert_eq!(count(&logs, "WARN", "cannot start an env-file read"), 1);
}

/// U24: after a config-file failure E1 and a retry failing with E2, E1
/// coming back is a change from the latest warning, E2, and warns.
#[test]
fn u24_an_error_that_changes_back_after_a_prime_warns_again() {
    use super::super::ReloadTrigger;
    let counts = super::EnvReloadCounts::default();
    let mut limiter = WarnLimiter::default();
    let retry = ReloadTrigger::Retry(PathBuf::from("/cfg.yaml"));
    counts.settled(&mut limiter, Some("E1"), &ReloadTrigger::ConfigFile);
    counts.report_failure(&mut limiter, &retry, "E2");
    counts.report_failure(&mut limiter, &retry, "E1");
    assert_eq!(
        counts.warns.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "E2 is new, and E1 after E2 is a change"
    );
}

/// U25: a path that warned E1, then a config-file failure that warned E2:
/// E1 returning on that path is a change from the latest warning and warns.
#[test]
fn u25_an_error_returning_after_a_newer_config_failure_warns() {
    use super::super::ReloadTrigger;
    let counts = super::EnvReloadCounts::default();
    let mut limiter = WarnLimiter::default();
    let env = ReloadTrigger::EnvFile(PathBuf::from("/a.env"));
    counts.report_failure(&mut limiter, &env, "E1");
    std::thread::sleep(Duration::from_millis(5));
    counts.settled(&mut limiter, Some("E2"), &ReloadTrigger::ConfigFile);
    counts.report_failure(&mut limiter, &env, "E1");
    assert_eq!(
        counts.warns.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "E1, then E2 from the config file, then E1 again: each is a change"
    );
}

/// Spawn attempts made by `flaky_spawn`. Only L10b uses it.
static FLAKY_SPAWNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Fails the first and third spawn, starts the second.
fn flaky_spawn(read: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    match FLAKY_SPAWNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
        1 => std::thread::Builder::new().spawn(read).map(drop),
        _ => Err(std::io::Error::other("no threads")),
    }
}

/// L10b: a read that starts again clears the spawn warning, so the next
/// spawn failure is warned about again.
#[test]
fn l10b_a_new_spawn_failure_after_recovery_warns_again() {
    use crate::test_log_capture::{count, records};
    let mut poller = super::EnvPoller::new(
        one_env_file(),
        std::sync::Arc::default(),
        PathBuf::from("/cfg.yaml"),
    )
    .with_read(|_, _| None)
    .with_spawn(flaky_spawn);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let logs = records(|| {
        runtime.block_on(async {
            for _ in 0..3 {
                let _ = poller.tick(Duration::from_secs(5)).await;
            }
        });
    });
    assert_eq!(count(&logs, "WARN", "cannot start an env-file read"), 2);
}
