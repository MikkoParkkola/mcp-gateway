// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared byte writer for gateway.yaml (ADR-024): exact bytes, written
//! under the config lock pair, then one reload, and the old bytes back on
//! disk whenever that reload refuses.
//!
//! Web UI settings saves (a spliced file) and configuration-history restores
//! (stored bytes) both write through [`replace_detached`]. It refuses a write
//! made from a stale view of the file, keeps the original in a private copy
//! with a journal ([`crate::config_persistence::journal`]) until a reload has
//! accepted the new bytes, and puts the original back on a refused reload or
//! a failed write. A crash anywhere is recovered by the next holder of the
//! config lock.
//!
//! Lock order, for every holder: the reload lock, then the config sidecar
//! lock, then (for a save that also writes secrets) the vault lock. Nothing
//! ranked earlier is taken while a later one is held.
#![expect(
    dead_code,
    reason = "its first callers, the web UI settings save and the configuration-history restore, read the outcome and error fields; they land next"
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config_persistence::journal;
use crate::config_persistence::lock::{NotLocked, lock_config_recovering};
use crate::config_persistence::{FileMode, Symlink, write_atomic};
use crate::config_reload::{ConfigWriteError, ReloadOutcome};

use super::ReloadContext;

/// The SHA-256 of a file's bytes, lowercase hex: the revision a diff or a
/// history view was made from. Not `config_revision`, which also covers the
/// process environment and `file:` secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileRevision(String);

impl FileRevision {
    /// The revision of `bytes`.
    #[must_use]
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self(crate::hashing::sha256_hex(bytes))
    }

    /// The hex digest.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the file must hold for the write to go ahead.
pub(crate) enum Expected {
    /// Whatever it holds.
    Any,
    /// The bytes the caller's diff or history view was made from.
    Revision(FileRevision),
}

/// What happens to the bytes a successful write replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Replaced {
    /// Removed once the new bytes are accepted.
    Discard,
    /// Kept beside the file as `gateway.yaml.<UTC time>.rejected`.
    KeepBeside,
}

/// The new bytes, from the current ones; `Err` refuses the write.
pub(crate) type Compute = Box<dyn FnOnce(&[u8]) -> Result<Vec<u8>, String> + Send>;

/// One replacement of gateway.yaml.
pub(crate) struct Replace {
    pub(crate) expected: Expected,
    pub(crate) compute: Compute,
    pub(crate) replaced: Replaced,
}

/// A replacement that was written and accepted.
#[derive(Debug)]
pub(crate) struct ReplaceOutcome {
    /// The new revision; `None` when the bytes were already the file's.
    pub(crate) revision: Option<FileRevision>,
    /// The kept copy, for [`Replaced::KeepBeside`].
    pub(crate) kept_beside: Option<PathBuf>,
    /// The reload that accepted it.
    pub(crate) reload: ReloadOutcome,
}

/// Why nothing was applied. Every kind but `RollbackFailed` and
/// `Unconfirmed` leaves the old file on disk and running; those two leave a
/// journal that the next holder of the config lock recovers.
#[derive(Debug)]
pub(crate) enum ReplaceError {
    /// A lock stayed held past the wait; nothing was read.
    Busy,
    /// The file changed since the caller's view; its current revision.
    Stale { current: FileRevision },
    /// The compute refused, or produced bytes the loader cannot read.
    Refused(String),
    /// gateway.yaml no longer resolves to the file this gateway started on.
    Unsupported(String),
    /// Staging the original or the journal failed; nothing was replaced.
    Stage(String),
    /// Writing the new bytes failed; the original is back.
    Write(String),
    /// The reload refused the new bytes; the original is back.
    ReloadRefused(String),
    /// Putting the original back failed; the journal stays `staged`.
    RollbackFailed { journal: PathBuf, error: String },
    /// The reload accepted the bytes but that could not be recorded
    /// durably; nothing is acknowledged.
    Unconfirmed { journal: PathBuf, error: String },
    /// Anything else: a lock that cannot be taken at all, an unusable
    /// journal, an unreadable file, a write task that died.
    Failed(String),
}

/// Write `replace` in a task of its own: dropping the caller (a request
/// handler whose client went away) drops only the wait, never a write
/// between its rename and its reload.
pub(crate) async fn replace_detached(
    ctx: Arc<ReloadContext>,
    replace: Replace,
    wait: Duration,
) -> Result<ReplaceOutcome, ReplaceError> {
    tokio::spawn(async move { ctx.replace_locked(replace, wait).await })
        .await
        .unwrap_or_else(|e| {
            Err(ReplaceError::Failed(format!(
                "the config write task failed: {e}"
            )))
        })
}

impl ReloadContext {
    async fn replace_locked(
        &self,
        replace: Replace,
        wait: Duration,
    ) -> Result<ReplaceOutcome, ReplaceError> {
        let deadline = Instant::now() + wait;
        // The reload lock, then the config sidecar lock: the order every
        // holder takes them in (module docs).
        let _reload_guard = self.lock_reload_within(wait).await.map_err(|e| match e {
            ConfigWriteError::Busy => ReplaceError::Busy,
            ConfigWriteError::Failed(message) => ReplaceError::Failed(message),
        })?;
        let (_held, recovered) = lock_config_recovering(&self.config_path, deadline)
            .await
            .map_err(|e| match e {
                NotLocked::Busy => ReplaceError::Busy,
                NotLocked::Failed(message) => ReplaceError::Failed(message),
            })?;
        self.pay_owed_reload(recovered).await;

        let target = crate::identity_grants::journal::resolved(&self.config_path);
        if target != self.trusted_config {
            return Err(ReplaceError::Unsupported(format!(
                "{} now resolves to {}, not to {}, the file this gateway started on; nothing was written",
                self.config_path.display(),
                target.display(),
                self.trusted_config.display()
            )));
        }
        let current = std::fs::read(&target).map_err(|e| {
            ReplaceError::Failed(format!("reading {} failed: {e}", target.display()))
        })?;
        if let Expected::Revision(seen) = &replace.expected {
            let now = FileRevision::of(&current);
            if &now != seen {
                return Err(ReplaceError::Stale { current: now });
            }
        }
        let new = (replace.compute)(&current).map_err(ReplaceError::Refused)?;
        if std::str::from_utf8(&new).is_err() {
            return Err(ReplaceError::Refused(
                "the new gateway.yaml is not UTF-8 text".to_string(),
            ));
        }
        if new == current {
            // Nothing to write, but still a reload, so a retry after a failed
            // one does not leave the runtime stale. Nothing was committed, so
            // a refusal needs no rollback.
            let reload = self
                .reload_outcome_locked()
                .await
                .map_err(ReplaceError::ReloadRefused)?;
            return Ok(ReplaceOutcome {
                revision: None,
                kept_beside: None,
                reload,
            });
        }
        self.commit(&target, &current, &new, replace.replaced).await
    }

    /// Stage, journal, write, reload; then keep the new bytes or put the
    /// original back.
    async fn commit(
        &self,
        target: &std::path::Path,
        current: &[u8],
        new: &[u8],
        replaced: Replaced,
    ) -> Result<ReplaceOutcome, ReplaceError> {
        let config = &self.config_path;
        let original = journal::stage_original(config, current)
            .map_err(|e| ReplaceError::Stage(format!("staging the original failed: {e}")))?;
        if let Err(e) = journal::begin(config, &original, FileRevision::of(current).0) {
            let _ = std::fs::remove_file(&original);
            return Err(ReplaceError::Stage(format!(
                "writing the replace journal failed: {e}"
            )));
        }
        // gateway.yaml is owner-only, as every config write leaves it.
        if let Err(e) = write_atomic(target, new, FileMode::Private, Symlink::Follow) {
            return Err(self.roll_back(ReplaceError::Write(format!(
                "writing {} failed: {e}",
                target.display()
            ))));
        }
        match self.reload_outcome_locked().await {
            Ok(reload) => {
                if let Err(e) = journal::mark_all_renamed(config) {
                    return Err(ReplaceError::Unconfirmed {
                        journal: journal::journal_path(config),
                        error: e.to_string(),
                    });
                }
                let kept_beside = match replaced {
                    Replaced::KeepBeside => keep_beside(&original, target),
                    Replaced::Discard => None,
                };
                if let Err(e) = journal::finish(config) {
                    // The new bytes stand and were accepted; the journal says
                    // `all_renamed`, so the next lock holder only cleans up.
                    tracing::warn!(error = %e, path = %config.display(), "removing the replace journal failed; the next config write removes it");
                }
                Ok(ReplaceOutcome {
                    revision: Some(FileRevision::of(new)),
                    kept_beside,
                    reload,
                })
            }
            Err(refusal) => Err(self.roll_back(ReplaceError::ReloadRefused(refusal))),
        }
    }

    /// Put the original back (the same recovery the next lock holder would
    /// run) and report `error`, or `RollbackFailed` when that fails too.
    fn roll_back(&self, error: ReplaceError) -> ReplaceError {
        match journal::recover(&self.config_path) {
            Ok(_) => error,
            Err(rollback) => ReplaceError::RollbackFailed {
                journal: journal::journal_path(&self.config_path),
                error: rollback,
            },
        }
    }
}

/// Move the staged original to `gateway.yaml.<UTC time>.rejected` beside the
/// target, never over an existing name (`-2`, `-3` on a clash). A failure
/// leaves it where it is, for the journal cleanup to remove, and is logged:
/// the save itself succeeded.
fn keep_beside(original: &std::path::Path, target: &std::path::Path) -> Option<PathBuf> {
    // A clock before 1970 still keeps the copy, under a name that says so.
    let stamp = crate::clock::utc_now().map_or_else(
        |_| "before-epoch".to_owned(),
        |now| now.format("%Y%m%dT%H%M%SZ").to_string(),
    );
    let base = format!("{}.{stamp}.rejected", target.display());
    for n in 1..100 {
        let name = if n == 1 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let kept = PathBuf::from(name);
        // A hard link never replaces an existing name, unlike a rename.
        match std::fs::hard_link(original, &kept) {
            Ok(()) => {
                let _ = std::fs::remove_file(original);
                return Some(kept);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                tracing::warn!(error = %e, path = %kept.display(), "keeping the replaced gateway.yaml failed");
                return None;
            }
        }
    }
    tracing::warn!(path = %base, "keeping the replaced gateway.yaml failed: every name is taken");
    None
}
