// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The lock a reload takes when it did not start the write.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::{
    Locked, NotLocked, Recovery, lock_config_deferred, lock_path, off_runtime, recover_held,
};
use crate::config_persistence::journal::v2::{abandoned_path, retired_path};
use crate::identity_grants::journal::resolved;

/// Why a reload skipped: an abandoned config-write file was found.
pub(crate) const ABANDONED_PENDING: &str = "An abandoned config-write file sits beside the config \
     and holds audit records this gateway cannot deliver. The running config stays until the log \
     the file names is configured, or until the file is moved aside by hand and kept as evidence.";
/// Why a reload skipped: a retired manifest was found, which this build cannot read yet.
pub(crate) const MANIFEST_UNREAD: &str = "This build cannot read the retired config-write manifest \
     beside the config. It stays as evidence: move it aside by hand, or use a build that reads it.";
/// Why a reload skipped: whether an artifact is there could not be told.
pub(crate) const ARTIFACT_UNPROVEN: &str = "Whether a config write is pending beside the config \
     could not be checked; the running config stays until that directory can be read.";

/// The reason a reload must not load `target`, or `None` once the abandoned file and the retired
/// manifest are both proven absent. Reads only; blocks on the filesystem.
fn artifact_blocks(target: &Path) -> Option<&'static str> {
    for (path, found) in [
        (abandoned_path(target), ABANDONED_PENDING),
        (retired_path(target), MANIFEST_UNREAD),
    ] {
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Some(ARTIFACT_UNPROVEN),
            Ok(_) => return Some(found),
        }
    }
    None
}

/// What a reload that did not start the write may do about the lock.
pub(crate) enum ReaderLock {
    /// Held (and any journal recovered): load its target under it.
    Held(Locked),
    /// No writer can exist (read-only filesystem, or a directory this
    /// account cannot write) and no journal is pending: load this resolved
    /// config without it.
    /// Like `Held`, only once no abandoned file or retired manifest is there.
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

// Invariant: `Held` and `Unlocked`, the two outcomes that let a reload load, are returned only
// after the abandoned file and the retired manifest are proven absent; every other state is a
// `Skip` that wrote nothing. The lock is always taken deferred, so the check runs before any
// journal recovery, which then runs on the same lock for `Recovery::OnAcquire`.
async fn reader_lock_with(config: &Path, deadline: Instant, recovery: Recovery) -> ReaderLock {
    match lock_config_deferred(config, deadline).await {
        Ok(locked) => {
            // The lock moves into the worker and back, so a cancelled caller never leaves a
            // recovery running unlocked.
            let checked = off_runtime(Some(config), move || {
                if let Some(why) = artifact_blocks(&locked.target) {
                    return Err(why.to_owned());
                }
                let mut locked = locked;
                if matches!(recovery, Recovery::OnAcquire) {
                    recover_held(&mut locked).map_err(|error| match error {
                        NotLocked::Busy => "the config lock was lost during recovery".to_owned(),
                        NotLocked::Failed(why) | NotLocked::Refused(why) => why,
                    })?;
                }
                Ok(locked)
            })
            .await;
            match checked {
                Ok(Ok(locked)) => ReaderLock::Held(locked),
                Ok(Err(why)) => ReaderLock::Skip(why),
                Err(_) => ReaderLock::Skip(format!(
                    "the artifact check beside {} did not finish",
                    config.display()
                )),
            }
        }
        Err(NotLocked::Busy) => ReaderLock::Skip(format!(
            "another writer holds the lock beside {} past the wait",
            config.display()
        )),
        Err(NotLocked::Failed(message) | NotLocked::Refused(message)) => {
            let probed = config.to_path_buf();
            let probe = off_runtime(Some(config), move || {
                let target = resolved(&probed);
                let journal = crate::config_persistence::journal::journal_path(&target);
                Probe {
                    no_writer: no_writer_possible(&target),
                    pending: journal_pending(&target),
                    blocked: artifact_blocks(&target),
                    target,
                    journal,
                }
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
fn classify_unlockable(config: &Path, message: String, probe: Option<Probe>) -> ReaderLock {
    let Some(Probe {
        no_writer,
        pending,
        blocked,
        target,
        journal,
    }) = probe
    else {
        return ReaderLock::Skip(message);
    };
    // No lock and no journal: the artifacts decide before any unlocked load.
    if no_writer.is_some()
        && !pending
        && let Some(why) = blocked
    {
        return ReaderLock::Skip(why.to_owned());
    }
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
    !absent(&super::super::journal::journal_path(config))
}

/// Whether `path` is proven absent: only a `NotFound` from `symlink_metadata` proves it. A
/// dangling symlink, a permission error or any other failure counts as present.
pub(crate) fn absent(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == io::ErrorKind::NotFound)
}

/// What a reader found beside a config whose lock it could not take.
struct Probe {
    /// Why no writer can exist here, if none can.
    no_writer: Option<&'static str>,
    /// A journal, or one whose absence could not be established.
    pending: bool,
    /// Why an abandoned file or a retired manifest forbids the load, if one does.
    blocked: Option<&'static str>,
    target: PathBuf,
    journal: PathBuf,
}
