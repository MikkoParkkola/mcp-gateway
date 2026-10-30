// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The lock a reload takes when it did not start the write.

use std::path::{Path, PathBuf};
use std::time::Instant;

use super::{
    Locked, NotLocked, Recovery, classify_unlockable, journal_pending, lock_config,
    lock_config_deferred, no_writer_possible, off_runtime,
};
use crate::identity_grants::journal::resolved;

/// What a reload that did not start the write may do about the lock.
pub(crate) enum ReaderLock {
    /// Held (and any journal recovered): load its target under it.
    Held(Locked),
    /// No writer can exist (read-only filesystem, or a directory this
    /// account cannot write) and no journal is pending: load this resolved
    /// config without it.
    Unlocked(PathBuf),
    /// Do not load this time; the next event retries. The reason, for a log.
    Skip(String),
}

/// Take the lock for a reader: the file watcher, the env poll, a reload
/// the admin asked for. Writers replace gateway.yaml by atomic rename, so an
/// unlocked reader sees whole old or whole new bytes; the lock keeps it from
/// loading bytes a refused reload is about to roll back.
///
/// Read without the lock only when the sidecar cannot even be created
/// because no writer can exist here, and no journal is pending (a stat finds
/// none). Every other failure skips this reload: never an unlocked read.
pub(crate) async fn reader_lock(config: &Path, deadline: Instant) -> ReaderLock {
    reader_lock_with(config, deadline, Recovery::OnAcquire).await
}

/// [`reader_lock`] for an audited gateway: a pending journal is left for
/// the holder to recover after its recovery intent.
pub(crate) async fn reader_lock_deferred(config: &Path, deadline: Instant) -> ReaderLock {
    reader_lock_with(config, deadline, Recovery::Deferred).await
}

async fn reader_lock_with(config: &Path, deadline: Instant, recovery: Recovery) -> ReaderLock {
    let locked = match recovery {
        Recovery::OnAcquire => lock_config(config, deadline).await,
        Recovery::Deferred => lock_config_deferred(config, deadline).await,
    };
    match locked {
        Ok(locked) => ReaderLock::Held(locked),
        Err(NotLocked::Busy) => ReaderLock::Skip(format!(
            "another writer holds the lock beside {} past the wait",
            config.display()
        )),
        Err(NotLocked::Failed(message)) => {
            let probed = config.to_path_buf();
            let probe = off_runtime(move || {
                let target = resolved(&probed);
                let journal = crate::config_persistence::journal::journal_path(&target);
                (
                    no_writer_possible(&target),
                    journal_pending(&target),
                    target,
                    journal,
                )
            })
            .await
            .ok();
            classify_unlockable(config, message, probe)
        }
    }
}
