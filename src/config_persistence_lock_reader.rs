// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The lock a reload takes when it did not start the write.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::{
    Locked, NotLocked, Recovery, lock_config, lock_config_deferred, lock_path, off_runtime,
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
        Err(NotLocked::Failed(message) | NotLocked::Refused(message)) => {
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

/// What a reader does when its lock cannot be taken at all, given the probe
/// (why no writer can exist, whether a journal is pending, the resolved
/// config and its journal path); a probe that did not run skips.
fn classify_unlockable(
    config: &Path,
    message: String,
    probe: Option<(Option<&'static str>, bool, PathBuf, PathBuf)>,
) -> ReaderLock {
    let Some((no_writer, pending, target, journal)) = probe else {
        return ReaderLock::Skip(message);
    };
    match no_writer {
        None => ReaderLock::Skip(message),
        Some(_) if pending => ReaderLock::Skip(format!(
            "a pending write's journal {} sits beside a file this gateway cannot lock; resolve the pending write from the writable side",
            journal.display()
        )),
        Some(why) => {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                    tracing::warn!(path = %config.display(), reason = why, "reading gateway.yaml without the config lock: no writer can exist here");
                });
            ReaderLock::Unlocked(target)
        }
    }
}

/// Why no writer can exist beside `config`: creating its lock sidecar fails
/// on a read-only filesystem, or because this account cannot write the
/// directory. `None` for any other failure, or when the sidecar exists (the
/// failure was then the lock itself, not its creation).
pub(crate) fn no_writer_possible(config: &Path) -> Option<&'static str> {
    let lock = lock_path(&resolved(config));
    if std::fs::symlink_metadata(&lock).is_ok() {
        return None;
    }
    match super::super::create_new_private(&lock) {
        Err(e) => creation_blocked(&e),
        // Created after all: the earlier failure was something else, and the
        // sidecar stays, as every sidecar does.
        Ok(_) => None,
    }
}

/// Whether a failed sidecar create means no writer can exist here: a
/// read-only filesystem, or a directory this account cannot write. Any other
/// failure (no space, a name in the way) does not.
pub(super) fn creation_blocked(error: &io::Error) -> Option<&'static str> {
    match error.kind() {
        io::ErrorKind::ReadOnlyFilesystem => Some("read-only filesystem"),
        io::ErrorKind::PermissionDenied => Some("this account cannot write the config directory"),
        _ => None,
    }
}

/// A journal beside `config`, or one whose absence cannot be established.
pub(crate) fn journal_pending(config: &Path) -> bool {
    !matches!(
        std::fs::symlink_metadata(super::super::journal::journal_path(config)),
        Err(e) if e.kind() == io::ErrorKind::NotFound
    )
}
