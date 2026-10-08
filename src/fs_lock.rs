// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cross-process advisory file locking, shared by every on-disk store that
//! needs to serialize a read-repair-write (or read-modify-write) critical
//! section across independent OS processes sharing a directory.
//!
//! On unix this is a real `flock` held on a dedicated `.lock` sidecar file,
//! released automatically when the returned guard drops. On non-unix the
//! blocking lock is `std::fs::File::lock` (`LockFileEx` on Windows). It used
//! to be a no-op there, and that serialized nothing, not even two threads
//! in one process: `save_client_id`'s self-heal could hand a caller an id
//! that another caller then overwrote on disk.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// An exclusive advisory lock on a dedicated lock file, released on drop.
///
/// On unix this is a real `flock`; the lock file's fd holds the lock across
/// whatever atomic rename/hard-link the caller performs while holding the
/// guard. Drop explicitly unlocks before closing so an inherited duplicate
/// cannot extend the owner's normal guard lifetime. On non-unix the blocking
/// constructor takes `File::lock`, released when the handle closes on drop.
pub(crate) struct ExclusiveFileLock {
    // On non-unix the lock lives on this handle and ends when it closes, so
    // nothing reads the field; holding it open for the guard's lifetime IS
    // the lock.
    #[cfg_attr(
        not(any(unix, windows)),
        expect(dead_code, reason = "only the unix and Windows paths read the handle")
    )]
    file: File,
    #[cfg(windows)]
    pins: Vec<DirPin>,
}

/// A judged store directory. On Windows its handle, held without delete
/// sharing for exactly the custody lifetime, so neither the directory nor any
/// ancestor can be renamed or swapped for a junction while the store is open
/// (design §2.2, R2-1). Empty elsewhere: a mode check holds nothing.
pub(crate) struct DirPin(
    #[cfg(windows)]
    #[expect(dead_code, reason = "held open, never read")]
    pub(crate) File,
);

impl ExclusiveFileLock {
    fn held(file: File) -> Self {
        Self {
            file,
            #[cfg(windows)]
            pins: Vec::new(),
        }
    }

    /// Keep a judged directory open for as long as this custody lasts.
    #[cfg_attr(not(windows), expect(clippy::needless_pass_by_value))]
    pub(crate) fn pinning(
        #[cfg_attr(not(windows), allow(unused_mut))] mut self,
        pin: DirPin,
    ) -> Self {
        #[cfg(windows)]
        self.pins.push(pin);
        #[cfg(not(windows))]
        let DirPin() = pin;
        self
    }

    /// Acquire a lifetime custody lock without waiting for another process.
    ///
    /// Unlike the legacy blocking helper, unsupported platforms refuse custody.
    #[cfg(unix)]
    pub(crate) fn try_acquire(lock_path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;

        #[cfg(test)]
        count_attempt(lock_path);

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
        Ok(Self::held(file))
    }

    /// Windows: an owner-only sidecar shared for read and write (never
    /// delete), so a contender can open it and meet the lock itself.
    #[cfg(windows)]
    pub(crate) fn try_acquire(lock_path: &Path) -> io::Result<Self> {
        use crate::private_fs::{Share, create_file_private, judge_file};
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };

        #[cfg(test)]
        count_attempt(lock_path);
        let file = match create_file_private(lock_path, Share::LockSidecar) {
            // An existing sidecar is judged before it is trusted, exactly as a
            // unix sidecar with a foreign mode would be refused.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let file = OpenOptions::new()
                    .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(lock_path)
                    .map_err(|error| {
                        // A holder that shares less than read/write is still a
                        // holder (design R8): the store is owned, not broken.
                        if error.raw_os_error() == Some(32) {
                            io::Error::from(io::ErrorKind::WouldBlock)
                        } else {
                            error
                        }
                    })?;
                judge_file(&file).map_err(|reason| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("custody lock is not private: {reason:?}"),
                    )
                })?;
                file
            }
            other => other?,
        };
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
            std::fs::TryLockError::Error(error) => error,
        })?;
        Ok(Self::held(file))
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn try_acquire(_lock_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nonblocking custody lock is unavailable",
        ))
    }

    /// One non-blocking attempt at an exclusive lease on `lock_path`, on
    /// every platform: `Ok(None)` when another handle holds it, `Err` for any
    /// other failure (a directory in the way, a read-only volume, locking
    /// unsupported). A separate constructor from [`Self::try_acquire`], which
    /// judges its sidecar's privacy on Windows and refuses on any platform
    /// with neither unix nor Windows custody.
    pub(crate) fn try_lease(lock_path: &Path) -> io::Result<Option<Self>> {
        #[cfg(test)]
        count_attempt(lock_path);
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).read(true);
        set_owner_only(&mut opts);
        let file = opts.open(lock_path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self::held(file))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// Block until an exclusive lock on `lock_path` is acquired, creating the
    /// sidecar file (owner-only, `0600` on unix) if it does not exist yet.
    pub(crate) fn acquire(lock_path: &Path) -> io::Result<Self> {
        #[cfg(test)]
        count_attempt(lock_path);
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).read(true);
        set_owner_only(&mut opts);
        let file = opts.open(lock_path)?;
        lock_exclusive(&file)?;
        Ok(Self::held(file))
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

/// Windows releases a closed handle's byte-range locks "when resources allow",
/// not at close, so a reopen right after a drop can still meet the old lock.
/// Unlocking first makes the release synchronous.
#[cfg(windows)]
impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
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

/// `File::lock` on non-unix: `LockFileEx` on Windows, held by this handle and
/// released when it closes.
#[cfg(not(unix))]
fn lock_exclusive(file: &File) -> io::Result<()> {
    file.lock()
}

/// Test-only: lock attempts per lock path, so a test can prove a code path
/// takes no file lock at all.
#[cfg(test)]
static LOCK_ATTEMPTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, usize>>,
> = std::sync::LazyLock::new(Default::default);

#[cfg(test)]
fn count_attempt(lock_path: &Path) {
    *LOCK_ATTEMPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(lock_path.to_path_buf())
        .or_default() += 1;
}

/// Test-only: how many lock attempts `lock_path` has seen.
#[cfg(test)]
pub(crate) fn lock_attempts(lock_path: &Path) -> usize {
    LOCK_ATTEMPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(lock_path)
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unix-only: reads inode identity (MetadataExt) to prove the inherited descriptor is released.
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
    // Unix-only: inherited-descriptor (fd dup) release scenario.
    #[cfg(unix)]
    fn personal_accounts_s11_blocking_drop_releases_inherited_descriptor() {
        assert_owner_drop_releases_inherited_descriptor(ExclusiveFileLock::acquire);
    }

    #[test]
    // Unix-only: inherited-descriptor (fd dup) release scenario.
    #[cfg(unix)]
    fn personal_accounts_s11_nonblocking_drop_releases_inherited_descriptor() {
        assert_owner_drop_releases_inherited_descriptor(ExclusiveFileLock::try_acquire);
    }

    #[test]
    fn personal_accounts_try_lock_refuses_contention_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".personal-account-authority.lock");
        // The holder takes the sidecar through `try_acquire`: on Windows the contender
        // judges an existing sidecar, and one the legacy `acquire` created is not owner-only.
        let first = ExclusiveFileLock::try_acquire(&path).expect("the first holder takes the lock");
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
    // POSIX mode bits: asserts 0600 owner-only; Windows enforces owner-only through DACLs (win_acl).
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
                    // Long enough that an unserialized lock overlaps every time.
                    std::thread::sleep(std::time::Duration::from_millis(50));
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
            "the lock failed to serialize concurrent critical sections"
        );
    }
}
