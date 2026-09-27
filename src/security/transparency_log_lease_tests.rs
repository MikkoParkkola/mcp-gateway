// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The writer lease: one logger per path, for its whole lifetime, with a
//! bounded wait for a restart overlap and no file lock on the append path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::lease::{LEASE_RETRY, acquire_with};
use super::rotation_tests::{append, cfg, log_path, verify};
use super::segments::list_segments;

/// Append until `n` more rotations have happened, counted by the newest
/// sealed segment number: with retention, the number of sealed files stops
/// growing, but each rotation still seals a higher number.
fn rotate_n(l: &TransparencyLogger, path: &std::path::Path, n: u64) {
    let newest = |p: &std::path::Path| list_segments(p).unwrap().last().map_or(0, |s| s.seq + 1);
    let target = newest(path) + n;
    let mut i = 0;
    while newest(path) < target {
        append(l, i);
        i += 1;
        assert!(i < 5_000, "no rotation happened");
    }
}
use super::segments::sibling;
use super::*;

fn cfg_wait(path: &std::path::Path, wait: u64) -> Arc<TransparencyLogConfig> {
    let mut c = (*cfg(path, 2, false)).clone();
    c.lease_wait_secs = wait;
    Arc::new(c)
}

/// Assert a second open of `path` is refused as `LeaseHeld`, naming it.
#[track_caller]
fn assert_refused(path: &std::path::Path) {
    match TransparencyLogger::open(cfg(path, 2, false)) {
        Ok(_) => panic!("a second logger opened a leased path"),
        Err(e) => {
            assert!(is_lease_held(&e), "wrong error kind: {e}");
            assert!(e.to_string().contains(&path.display().to_string()), "{e}");
        }
    }
}

/// T1: the lease holds from open to drop, across every kind of write.
#[test]
fn a_second_logger_is_refused_for_the_whole_life_of_the_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    assert_refused(&path);
    append(&l, 0);
    assert_refused(&path);
    rotate_n(&l, &path, 1);
    assert_refused(&path);
    rotate_n(&l, &path, 3); // retention 2: expiries run
    assert_refused(&path);
    // A synced append re-reads the tail through recovery.
    l.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
        .unwrap();
    assert_refused(&path);
    assert!(verify(&path, false).ok);
}

/// T2: dropping the holder releases the lease; the next logger resumes the
/// chain.
#[test]
fn dropping_the_logger_releases_the_lease() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    append(&l, 0);
    drop(l);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    append(&l, 1);
    assert!(verify(&path, false).ok);
}

/// Env var that turns this test binary into the T1b child.
const CHILD: &str = "MCP_TLOG_LEASE_CHILD";

/// T1b child side: opens the path it is given and exits with 0 (opened),
/// 3 (`LeaseHeld`) or 4 (other error). A no-op in a normal run.
#[test]
fn lease_child_process() {
    let Ok(path) = std::env::var(CHILD) else {
        return;
    };
    let code = match TransparencyLogger::open(cfg(std::path::Path::new(&path), 2, false)) {
        Ok(_) => 0,
        Err(e) if is_lease_held(&e) => 3,
        Err(_) => 4,
    };
    std::process::exit(code);
}

/// T1b: another process is refused too (flock and `LockFileEx` across
/// processes), after every kind of write.
#[test]
fn another_process_is_refused_for_the_whole_life_of_the_logger() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let child = || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "security::transparency_log::lease_tests::lease_child_process",
                "--test-threads=1",
            ])
            .env(CHILD, &path)
            .status()
            .unwrap()
            .code()
    };
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    assert_eq!(child(), Some(3), "child must see LeaseHeld after open");
    rotate_n(&l, &path, 3);
    assert_eq!(child(), Some(3), "child must see LeaseHeld after rotations");
    drop(l);
    assert_eq!(child(), Some(0), "released on drop");
}

/// T3: a holder that lets go inside the wait window: the second open waits,
/// then succeeds.
#[test]
fn a_restart_overlap_inside_the_window_starts() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    let holder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(l);
    });
    let t = Instant::now();
    let second = TransparencyLogger::open(cfg_wait(&path, 2));
    let waited = t.elapsed();
    holder.join().unwrap();
    assert!(second.is_ok(), "{:?}", second.err());
    assert!(
        waited >= Duration::from_millis(250),
        "did not wait: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(2),
        "waited past the release: {waited:?}"
    );
}

/// T4: a holder that keeps the lease past the window: refused after it.
#[test]
fn a_holder_past_the_window_is_refused_after_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let _l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    let t = Instant::now();
    let e = TransparencyLogger::open(cfg_wait(&path, 1))
        .err()
        .expect("refused");
    let waited = t.elapsed();
    assert!(is_lease_held(&e), "{e}");
    assert!(
        waited >= Duration::from_secs(1),
        "gave up early: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(3),
        "waited too long: {waited:?}"
    );
}

/// T5: a zero wait refuses at once.
#[test]
fn a_zero_wait_refuses_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let _l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    let t = Instant::now();
    let e = TransparencyLogger::open(cfg_wait(&path, 0))
        .err()
        .expect("refused");
    assert!(is_lease_held(&e), "{e}");
    assert!(t.elapsed() < Duration::from_millis(200));
}

/// T6: a lease file that cannot be opened is its own error, returned at
/// once, never reported as another process holding the log.
#[test]
fn an_unopenable_lease_file_fails_at_once_and_is_not_lease_held() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    std::fs::create_dir(sibling(&path, "lock")).unwrap();
    let t = Instant::now();
    let e = TransparencyLogger::open(cfg_wait(&path, 5))
        .err()
        .expect("a directory is not a lease file");
    assert!(!is_lease_held(&e), "{e}");
    assert!(t.elapsed() < Duration::from_millis(500), "it waited");
}

/// The wait loop, without real time: it sleeps `LEASE_RETRY` between
/// attempts and gives up at the window.
#[test]
fn the_wait_retries_every_100_ms_until_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let _l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    let start = Instant::now();
    let clock = std::cell::Cell::new(start);
    let mut sleeps = Vec::new();
    let e = acquire_with(
        &path,
        Duration::from_secs(1),
        &mut |d| {
            sleeps.push(d);
            clock.set(clock.get() + d);
        },
        &|| clock.get(),
    )
    .err()
    .expect("never released");
    assert!(is_lease_held(&e));
    assert_eq!(LEASE_RETRY, Duration::from_millis(100));
    assert_eq!(sleeps.len(), 10, "{sleeps:?}");
    assert!(sleeps.iter().all(|d| *d == LEASE_RETRY), "{sleeps:?}");
}

/// Contention, then a different failure: that failure comes back as it is.
#[test]
fn a_non_contention_error_mid_wait_returns_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let holder = std::cell::RefCell::new(Some(
        TransparencyLogger::open(cfg(&path, 2, false)).unwrap(),
    ));
    let lock = sibling(&path, "lock");
    let now = Instant::now();
    let e = acquire_with(
        &path,
        Duration::from_secs(60),
        &mut |_| {
            // Release, then put a directory where the lease file was.
            drop(holder.borrow_mut().take());
            let _ = std::fs::remove_file(&lock);
            std::fs::create_dir(&lock).unwrap();
        },
        &|| now,
    )
    .err()
    .expect("a directory is not a lease file");
    assert!(!is_lease_held(&e), "{e}");
}

/// The default wait is 10 s, in the file config and the runtime copy, and a
/// configured value carries through the conversion.
#[test]
fn the_default_wait_is_ten_seconds() {
    fn parse<T: serde::de::DeserializeOwned>(_like: &T, yaml: &str) -> T {
        serde_yaml::from_str(yaml).unwrap()
    }
    let file = crate::config::Config::default().security.transparency_log;
    assert_eq!(file.lease_wait_secs, 10);
    let runtime: TransparencyLogConfig = (&file).into();
    assert_eq!(runtime.lease_wait_secs, 10);
    let parsed = parse(&file, "lease_wait_secs: 3\n");
    assert_eq!(TransparencyLogConfig::from(&parsed).lease_wait_secs, 3);
}

/// R4: with the lease held, no append path takes a file lock: one attempt,
/// the open's, through appends, synced appends, rotation, retention and
/// recovery.
#[test]
fn appends_take_no_file_lock_once_the_lease_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let lock = sibling(&path, "lock");
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    assert_eq!(crate::fs_lock::lock_attempts(&lock), 1);
    append(&l, 0);
    l.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
        .unwrap();
    rotate_n(&l, &path, 4);
    assert_eq!(crate::fs_lock::lock_attempts(&lock), 1);
}

/// A lock re-taken on the append path would wait on our own lease forever:
/// appends across rotations must finish.
#[test]
fn appends_across_rotations_do_not_deadlock_on_the_lease() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let (tx, rx) = std::sync::mpsc::channel();
    let p = path.clone();
    std::thread::spawn(move || {
        let l = TransparencyLogger::open(cfg(&p, 2, false)).unwrap();
        for i in 0..200 {
            append(&l, i);
        }
        l.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
            .unwrap();
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("appends deadlocked on the held lease");
    assert!(verify(&path, false).ok);
}
