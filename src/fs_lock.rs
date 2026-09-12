// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cross-process advisory file locking, shared by every on-disk store that
//! needs to serialize a read-repair-write (or read-modify-write) critical
//! section across independent OS processes sharing a directory.
//!
//! On unix this is a real `flock` held on a dedicated `.lock` sidecar file,
//! released automatically when the returned guard drops. On non-unix
//! platforms it degrades to opening (and creating) the sidecar file with no
//! actual advisory lock — single-node collection stores still rely on atomic
//! rename / hard-link for torn-write safety, so the only gap is cross-process
//! interleaving on Windows, which no current deployment target exercises.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// An exclusive advisory lock on a dedicated lock file, released on drop.
///
/// On unix this is a real `flock`; the lock file's fd holds the lock across
/// whatever atomic rename/hard-link the caller performs while holding the
/// guard. Drop explicitly unlocks before closing so an inherited duplicate
/// cannot extend the owner's normal guard lifetime. On non-unix the legacy
/// blocking constructor opens the file without an advisory lock.
pub(crate) struct ExclusiveFileLock {
    file: File,
}

impl ExclusiveFileLock {
    /// Acquire a lifetime custody lock without waiting for another process.
    ///
    /// Unlike the legacy blocking helper, unsupported platforms refuse custody.
    #[cfg(unix)]
    pub(crate) fn try_acquire(lock_path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut opts = OpenOptions::new();
        opts.create(true).write(true).read(true);
        set_owner_only(&mut opts);
        opts.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
        let file = opts.open(lock_path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("custody lock is not a regular file"));
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
        Ok(Self { file })
    }

    #[cfg(not(unix))]
    pub(crate) fn try_acquire(_lock_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nonblocking custody lock is unavailable",
        ))
    }

    /// Block until an exclusive lock on `lock_path` is acquired, creating the
    /// sidecar file (owner-only, `0600` on unix) if it does not exist yet.
    pub(crate) fn acquire(lock_path: &Path) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).read(true);
        set_owner_only(&mut opts);
        let file = opts.open(lock_path)?;
        lock_exclusive(&file)?;
        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        // File close alone leaves a fork/dup reference holding the same lock.
        // Drop cannot return an unlock error; File still closes without panic.
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

/// Restrict a newly-created lock file to owner read/write (`0600`) on unix.
#[cfg(unix)]
fn set_owner_only(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    opts.mode(0o600);
}

/// No-op on non-unix: file permissions are managed by the platform ACLs.
#[cfg(not(unix))]
fn set_owner_only(_opts: &mut OpenOptions) {}

/// Take an exclusive `flock` on unix. `rustix` is an already-present
/// dependency (promoted to direct with the `fs` feature); no new crate is
/// compiled to get this.
#[cfg(unix)]
fn lock_exclusive(file: &File) -> io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

/// ponytail: cross-process advisory locking on non-unix is out of scope for
/// the single-node file backends that use this lock today. Upgrade to
/// `LockFileEx` if a Windows multi-process deployment ever needs it.
#[cfg(not(unix))]
fn lock_exclusive(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[track_caller]
    fn assert_owner_drop_releases_inherited_descriptor(
        acquire: fn(&Path) -> io::Result<ExclusiveFileLock>,
    ) {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".inherited-description.lock");
        let owner = acquire(&path).expect("own the real kernel lock");
        // try_clone shares the exact open-file description, as fork does.
        // Opening the same pathname again would not establish this condition.
        let inherited = owner.file.try_clone().expect("duplicate the owner's fd");
        let identity = owner.file.metadata().unwrap();
        assert_eq!(
            ExclusiveFileLock::try_acquire(&path)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock),
            "a live owning guard must exclude the contender"
        );
        // The original already owns the lock. This succeeds only because the
        // duplicate shares that description; a second open would WouldBlock.
        rustix::fs::flock(
            &inherited,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .expect("duplicate must share the already locked open-file description");

        drop(owner);
        let retained = inherited.metadata().expect("duplicate remains open");
        assert_eq!(
            (retained.dev(), retained.ino()),
            (identity.dev(), identity.ino())
        );
        let path_identity = std::fs::metadata(&path).expect("Drop must preserve the lock sidecar");
        assert_eq!(
            (path_identity.dev(), path_identity.ino()),
            (identity.dev(), identity.ino()),
            "reacquisition must use the existing sidecar inode"
        );
        let reacquired = ExclusiveFileLock::try_acquire(&path);
        assert!(
            reacquired.is_ok(),
            "owner Drop must release while its inherited descriptor remains open: {:?}",
            reacquired.as_ref().err()
        );
        let next_owner = reacquired.unwrap();
        let still_retained = inherited
            .metadata()
            .expect("duplicate survives reacquisition");
        assert_eq!(
            (still_retained.dev(), still_retained.ino()),
            (path_identity.dev(), path_identity.ino())
        );
        assert_eq!(
            ExclusiveFileLock::try_acquire(&path)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock),
            "the reacquired owning guard must still exclude contenders"
        );
        drop(next_owner);
        let final_control = ExclusiveFileLock::try_acquire(&path);
        assert!(
            final_control.is_ok(),
            "second owner release must permit reacquisition: {:?}",
            final_control.as_ref().err()
        );
        // Keep the duplicate through every assertion above, including the new
        // owner's exclusion control. It must never be dropped to force green.
        drop(inherited);
    }

    #[test]
    #[cfg(unix)]
    fn personal_accounts_s11_blocking_drop_releases_inherited_descriptor() {
        assert_owner_drop_releases_inherited_descriptor(ExclusiveFileLock::acquire);
    }

    #[test]
    #[cfg(unix)]
    fn personal_accounts_s11_nonblocking_drop_releases_inherited_descriptor() {
        assert_owner_drop_releases_inherited_descriptor(ExclusiveFileLock::try_acquire);
    }

    #[test]
    #[cfg(unix)]
    fn personal_accounts_try_lock_refuses_contention_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".personal-account-authority.lock");
        let first = ExclusiveFileLock::acquire(&path).expect("existing blocking lock control");
        let (sender, receiver) = std::sync::mpsc::channel();
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let contender_path = path.clone();
        let contender = std::thread::spawn(move || {
            ready_sender.send(()).expect("contender readiness");
            let result = ExclusiveFileLock::try_acquire(&contender_path);
            let _ = sender.send(result.err().map(|error| error.kind()));
        });
        ready_receiver.recv().expect("contender started");
        let second = receiver.recv_timeout(std::time::Duration::from_secs(1));
        // Release even after a timeout so a wrongly blocking implementation
        // cannot strand the worker and hang the whole test process.
        drop(first);
        contender.join().expect("contender thread completed");
        assert_eq!(
            second,
            Ok(Some(io::ErrorKind::WouldBlock)),
            "contention must be reported while the first lock is held"
        );
        let after_release = ExclusiveFileLock::try_acquire(&path);
        assert!(after_release.is_ok(), "released lock must be acquirable");
    }

    #[test]
    #[cfg(unix)]
    fn personal_accounts_try_lock_creates_private_sidecar() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".personal-account-authority.lock");
        let acquired = ExclusiveFileLock::try_acquire(&path);
        assert!(acquired.is_ok(), "uncontended custody lock must succeed");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn acquire_creates_sidecar_and_releases_on_drop() {
        // GIVEN: a lock path that does not exist yet.
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(".test.lock");
        assert!(!lock_path.exists());

        // WHEN: a lock is acquired and immediately dropped.
        {
            let _lock = ExclusiveFileLock::acquire(&lock_path).expect("acquire");
        }

        // THEN: the sidecar file now exists and a second acquire succeeds
        // (proves the first guard released the lock on drop).
        assert!(lock_path.exists());
        let _second = ExclusiveFileLock::acquire(&lock_path).expect("re-acquire after drop");
    }

    #[test]
    #[cfg(unix)]
    fn acquire_serializes_concurrent_threads() {
        // GIVEN: many threads racing to acquire the same lock and record
        // whether they ever observed another thread inside the critical
        // section concurrently.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let lock_path = Arc::new(dir.path().join(".contended.lock"));
        let inside = Arc::new(AtomicUsize::new(0));
        let max_inside = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let lock_path = Arc::clone(&lock_path);
                let inside = Arc::clone(&inside);
                let max_inside = Arc::clone(&max_inside);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let _lock = ExclusiveFileLock::acquire(&lock_path).expect("acquire");
                    let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    max_inside.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    inside.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // THEN: at most one thread was ever inside the critical section.
        assert_eq!(
            max_inside.load(Ordering::SeqCst),
            1,
            "flock failed to serialize concurrent critical sections"
        );
    }
}
