// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the config lock ([`super`]).

/// The one line the filesystem tests cannot reach without a seam: which
/// create failures mean no writer can exist.
#[test]
fn only_a_read_only_or_unwritable_directory_blocks_every_writer() {
    use std::io::{Error, ErrorKind};
    assert_eq!(
        super::creation_blocked(&Error::from(ErrorKind::ReadOnlyFilesystem)),
        Some("read-only filesystem")
    );
    assert!(super::creation_blocked(&Error::from(ErrorKind::PermissionDenied)).is_some());
    for other in [
        ErrorKind::StorageFull,
        ErrorKind::AlreadyExists,
        ErrorKind::NotFound,
    ] {
        assert_eq!(
            super::creation_blocked(&Error::from(other)),
            None,
            "{other:?}"
        );
    }
}

use super::lock_path;
use std::path::Path;

#[test]
fn the_sidecar_sits_next_to_the_config() {
    assert_eq!(
        lock_path(Path::new("/etc/mcp/gateway.yaml")),
        Path::new("/etc/mcp/.gateway.yaml.lock")
    );
    assert_eq!(
        lock_path(Path::new("gateway.yaml")),
        Path::new(".gateway.yaml.lock")
    );
}

/// MIK-8132: a sidecar with an inherited ACL (copied in, or checked out
/// by git) is refused with the repair to run, never with only the rule it
/// broke.
#[cfg(windows)]
#[test]
fn a_shared_sidecar_is_refused_with_its_repair() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    let lock = lock_path(&config);
    std::fs::write(&lock, "").expect("sidecar with an inherited ACL");

    let refused = super::lock_config_blocking(&config, std::time::Instant::now(), |_| {});

    let Err(super::NotLocked::Failed(message)) = refused else {
        panic!("a shared sidecar must refuse the lock");
    };
    assert!(
        message.contains("To repair it") && message.contains(".gateway.yaml.lock"),
        "{message}"
    );
}

/// MIK-8153: a config named through a symlink and through its target is
/// one config, so both spellings meet one lock.
#[cfg(unix)]
#[test]
fn a_symlink_and_its_target_share_one_lock() {
    let real = tempfile::tempdir().expect("real dir");
    let other = tempfile::tempdir().expect("link dir");
    let target = real.path().join("gateway.yaml");
    std::fs::write(&target, "backends: {}\n").expect("config");
    let link = other.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&target, &link).expect("link");

    let now = std::time::Instant::now;
    let held = super::lock_config_blocking(&target, now(), |_| {}).expect("lock via target");
    let second = super::lock_config_blocking(&link, now(), |_| {});

    assert!(
        matches!(second, Err(super::NotLocked::Busy)),
        "the link spelling must meet the target's lock"
    );
    drop(held);
}

/// A sidecar other accounts can open (a `0644` one checked out by git,
/// say) is one they can lock, stalling every config write. One this
/// user owns is made owner-only before it is locked.
#[cfg(unix)]
#[test]
fn a_readable_sidecar_is_made_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    let lock = lock_path(&config);
    std::fs::write(&lock, "").expect("sidecar");
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let held = super::lock_config_blocking(&config, std::time::Instant::now(), |_| {});

    assert!(held.is_ok(), "the lock is taken");
    let mode = std::fs::metadata(&lock).expect("stat").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

/// Abandoned threads are capped: with [`super::MAX_ABANDONED`] callers
/// gone while their threads stay stuck, the next start is refused; once
/// those threads return, starts work again.
#[tokio::test]
async fn abandoned_threads_are_capped_until_they_return() {
    use super::{Abandoned, MAX_ABANDONED, NoResult, off_runtime_in};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    // This test's own count, so other tests' threads never touch it.
    static MINE: Abandoned = Abandoned(AtomicUsize::new(0));
    let mut stuck = Vec::new();
    for _ in 0..MAX_ABANDONED {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        stuck.push(release);
        let call = off_runtime_in(&MINE, move || wait.recv().is_ok());
        tokio::pin!(call);
        // Polled once, which starts the thread, then dropped: the caller
        // leaves, the thread stays.
        tokio::select! {
            biased;
            _ = &mut call => panic!("the thread waits for its release"),
            () = std::future::ready(()) => {}
        }
    }
    assert_eq!(MINE.0.load(SeqCst), MAX_ABANDONED);
    assert_eq!(
        off_runtime_in(&MINE, || ()).await,
        Err(NoResult::Stalled),
        "refused past the cap"
    );

    drop(stuck);
    let mut spins = 0_u32;
    while MINE.0.load(SeqCst) != 0 && spins < 10_000_000 {
        std::thread::yield_now();
        spins += 1;
    }
    assert_eq!(MINE.0.load(SeqCst), 0, "returned threads are uncounted");
    assert_eq!(off_runtime_in(&MINE, || 7).await, Ok(7));
}

/// A result its caller never received (a held lock) is dropped while
/// the thread still counts as abandoned: closing it can stall on the
/// same mount, so the thread is not uncounted until that drop returns.
#[tokio::test]
async fn an_undelivered_result_is_dropped_before_the_thread_is_uncounted() {
    use super::{Abandoned, off_runtime_in};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::mpsc;
    static MINE: Abandoned = Abandoned(AtomicUsize::new(0));
    /// Drops only once released, saying first that it has started.
    struct SlowClose(mpsc::Sender<()>, mpsc::Receiver<()>);
    impl Drop for SlowClose {
        fn drop(&mut self) {
            let _ = self.0.send(());
            let _ = self.1.recv();
        }
    }
    let (closing, closed) = mpsc::channel();
    let (release, wait) = mpsc::channel::<()>();
    let (start, begin) = mpsc::channel::<()>();
    let mut call = Box::pin(off_runtime_in(&MINE, move || {
        let _ = begin.recv();
        SlowClose(closing, wait)
    }));
    tokio::select! {
        biased;
        _ = call.as_mut() => panic!("the thread waits to start"),
        () = std::future::ready(()) => {}
    }
    // The caller leaves before the thread has a result.
    drop(call);
    start.send(()).expect("the thread is waiting");

    closed
        .recv()
        .expect("the undelivered result is being dropped");
    assert_eq!(
        MINE.0.load(SeqCst),
        1,
        "still counted while its result closes"
    );
    drop(release);
}

/// The per-user owner rule, without a second account: a sidecar owned by
/// another uid is refused, the user's own is accepted.
#[cfg(unix)]
#[test]
fn a_per_user_lock_accepts_only_the_users_own_sidecar() {
    let refused = super::judge_owner(1000, 1001).expect_err("another user's sidecar");
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(refused.to_string().contains("belongs to another user"));
    super::judge_owner(1001, 1001).expect("the user's own sidecar");
}

/// The vault lock passes the real effective uid: a sidecar this user
/// created, then loosened, is accepted and tightened, never refused.
#[cfg(unix)]
#[test]
fn the_vault_lock_passes_the_real_uid() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let lock = dir.path().join("vault.lock");
    std::fs::write(&lock, "").expect("write");
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let held = super::lock_file_blocking(&lock, std::time::Instant::now());
    assert!(held.is_ok(), "the user's own sidecar was refused");
    let mode = std::fs::metadata(&lock).expect("stat").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

/// The lock path itself asks the owner rule: with another uid expected,
/// a private sidecar this user owns is refused. Skipping the check, or
/// moving it below the early return for a private file, turns this green
/// into a pass and so fails it.
#[cfg(unix)]
#[test]
fn the_vault_lock_refuses_a_sidecar_owned_by_anyone_else() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let lock = dir.path().join("vault.lock");
    std::fs::write(&lock, "").expect("write");
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let me = rustix::process::geteuid().as_raw();
    super::EXPECTED_OWNER.with(|uid| uid.set(Some(me + 1)));
    let refused = super::lock_file_blocking(&lock, std::time::Instant::now());
    super::EXPECTED_OWNER.with(|uid| uid.set(None));
    match refused {
        Err(super::NotLocked::Failed(why)) => {
            assert!(why.contains("belongs to another user"), "{why}");
        }
        other => panic!("not refused: {:?}", other.is_ok()),
    }
}
