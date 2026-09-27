// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The writer lease: one process writes a log path, for its whole lifetime.
//!
//! The hot path caches the chain's counter and previous hash, so two writers
//! on one path fork the chain whatever else is locked. `open` therefore takes
//! an exclusive lease on `<path>.lock` and the logger holds it until it
//! drops; a second writer is refused with [`LeaseHeld`]. The wait is bounded
//! so a supervisor that starts the new process a moment before the old one
//! exits still starts.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::fs_lock::ExclusiveFileLock;

/// How often a contended lease is retried while waiting.
pub(super) const LEASE_RETRY: Duration = Duration::from_millis(100);

/// Another writer holds the log at `path`.
#[derive(Debug)]
pub(crate) struct LeaseHeld {
    path: PathBuf,
}

impl std::fmt::Display for LeaseHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "audit log {} is being written by another gateway process \
             (its lease {} is held); run one gateway per log path",
            self.path.display(),
            super::segments::sibling(&self.path, "lock").display()
        )
    }
}

impl std::error::Error for LeaseHeld {}

/// Whether `error` is the writer-lease refusal, not an ordinary open failure.
#[must_use]
pub(crate) fn is_lease_held(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.downcast_ref::<LeaseHeld>().is_some())
}

/// Take the writer lease for the log at `path`, waiting up to `wait` while
/// another handle holds it.
pub(super) fn acquire(path: &Path, wait: Duration) -> io::Result<ExclusiveFileLock> {
    acquire_with(path, wait, &mut std::thread::sleep, &Instant::now)
}

/// [`acquire`] with the clock and sleeper injected (tests drive the loop
/// without real time). Retries only on contention; any other error returns
/// at once, unchanged.
pub(super) fn acquire_with(
    path: &Path,
    wait: Duration,
    sleep: &mut dyn FnMut(Duration),
    now: &dyn Fn() -> Instant,
) -> io::Result<ExclusiveFileLock> {
    let lock_path = super::segments::sibling(path, "lock");
    let start = now();
    let mut warned = false;
    loop {
        return ExclusiveFileLock::acquire(&lock_path);
        if now().duration_since(start) >= wait {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                LeaseHeld {
                    path: path.to_path_buf(),
                },
            ));
        }
        if !warned {
            warned = true;
            tracing::warn!(
                path = %path.display(),
                wait_secs = wait.as_secs(),
                "waiting for the audit log lease, held by another process"
            );
        }
        sleep(LEASE_RETRY);
    }
}
