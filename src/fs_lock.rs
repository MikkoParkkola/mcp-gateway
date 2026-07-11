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
/// guard. On non-unix it degrades to opening the file with no advisory lock.
pub(crate) struct ExclusiveFileLock {
    _file: File,
}

impl ExclusiveFileLock {
    /// Block until an exclusive lock on `lock_path` is acquired, creating the
    /// sidecar file (owner-only, `0600` on unix) if it does not exist yet.
    pub(crate) fn acquire(lock_path: &Path) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).read(true);
        set_owner_only(&mut opts);
        let file = opts.open(lock_path)?;
        lock_exclusive(&file)?;
        Ok(Self { _file: file })
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
