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
//! ranked earlier is taken while a later one is held: the config sidecar
//! before the vault, never the reverse.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config_persistence::journal;
use crate::config_persistence::lock::{Locked, NotLocked, lock_config};
use crate::config_persistence::{FileMode, Symlink, write_atomic};
use crate::config_reload::{ConfigWriteError, ReloadOutcome};
use crate::secret_store::{
    NewSecretOwned, PendingSecrets, SaveError, SecretStore, Vault, create_secrets,
};

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
    #[cfg_attr(
        all(not(feature = "webui"), not(test)),
        expect(dead_code, reason = "read by the web UI's discovery route")
    )]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the file must hold for the write to go ahead.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) enum Expected {
    /// Whatever it holds.
    Any,
    /// The bytes the caller's diff or history view was made from.
    Revision(FileRevision),
}

/// What happens to the bytes a successful write replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) enum Replaced {
    /// Removed once the new bytes are accepted.
    Discard,
    /// Kept beside the file as `gateway.yaml.<UTC time>.rejected`.
    KeepBeside,
}

/// The new bytes, from the current ones; `Err` refuses the write.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
/// The second argument is the reference texts of the [`SecretStep`]'s new
/// entries, in its order; empty without one.
pub(crate) type Compute = Box<dyn FnOnce(&[u8], &[String]) -> Result<Vec<u8>, String> + Send>;

/// Secrets a replacement saves with the file: created in the store under the
/// config hold, after the revision check and before `compute`, which writes
/// their references. The writer keeps them when the new bytes stand, deletes
/// them only when the old file provably stayed, and otherwise leaves them
/// listed as unused.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
pub(crate) struct SecretStep {
    pub(crate) vault: Vault,
    pub(crate) store: Arc<dyn SecretStore + Send + Sync>,
    pub(crate) values: Vec<NewSecretOwned>,
}

/// One replacement of gateway.yaml.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) struct Replace {
    pub(crate) expected: Expected,
    pub(crate) compute: Compute,
    pub(crate) replaced: Replaced,
    pub(crate) secrets: Option<SecretStep>,
}

/// A replacement that was written and accepted.
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) struct ReplaceOutcome {
    /// The new revision; `None` when the bytes were already the file's.
    pub(crate) revision: Option<FileRevision>,
    /// The kept copy, for [`Replaced::KeepBeside`].
    pub(crate) kept_beside: Option<PathBuf>,
    /// The reload that accepted it.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "first callers: the web UI settings save and the configuration-history restore"
        )
    )]
    pub(crate) reload: ReloadOutcome,
}

/// Why nothing was applied. Every kind but `RollbackFailed` and
/// `Unconfirmed` leaves the old file on disk and running; those two leave a
/// journal that the next holder of the config lock recovers.
#[derive(Debug)]
#[expect(
    dead_code,
    reason = "the error payloads are read by the first callers: the web UI settings save and the configuration-history restore"
)]
pub(crate) enum ReplaceError {
    /// A lock stayed held past the wait; nothing was read.
    Busy,
    /// The file changed since the caller's view; its current revision.
    Stale { current: FileRevision },
    /// The compute refused, or produced bytes that are not UTF-8 text. Bytes
    /// the loader rejects are `ReloadRefused`, after the rollback.
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
    /// The secret store refused the [`SecretStep`]; nothing was written.
    Secrets(SaveError<std::convert::Infallible>),
}

/// Write `replace` in a task of its own: dropping the caller (a request
/// handler whose client went away) drops only the wait, never a write
/// between its rename and its reload.
///
/// Invariant (ADR-024): a save's compute closure produces its bytes through
/// a refusing in-place editor (the key editor or `edit_text`), never through
/// a `CommentLoss::Rewrite` render, so a refusal surfaces as
/// [`ReplaceError::Refused`] and nothing is written.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
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

/// What happens to a replacement's new store entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
pub(crate) enum Settle {
    /// The new bytes stand and name them.
    Keep,
    /// The old file provably stayed: delete them.
    Discard,
    /// The file on disk may name them: keep them, listed as unused.
    Abandon,
}

/// How a finished replacement settles its entries, by its final result:
/// a rollback that fails becomes `RollbackFailed`, so every other refusal
/// left the old file in place. `Failed` keeps them: it proves nothing about
/// the file. A write task that dies never reaches this: [`Entries`]' drop
/// settles that case.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
pub(crate) fn settle_for(result: &Result<ReplaceOutcome, ReplaceError>) -> Settle {
    // Every kind named, no wildcard: a new one must say whether it proves
    // the old file stayed, or it would delete entries the file may name.
    let Err(error) = result else {
        return Settle::Keep;
    };
    match error {
        // Refused before anything was written.
        ReplaceError::Busy
        | ReplaceError::Stale { .. }
        | ReplaceError::Refused(_)
        | ReplaceError::Stage(_)
        | ReplaceError::Secrets(_)
        // The rollback came back: a failed one is `RollbackFailed`.
        | ReplaceError::Unsupported(_)
        | ReplaceError::Write(_)
        | ReplaceError::ReloadRefused(_) => Settle::Discard,
        // The file on disk may name them; `Failed` proves nothing either way.
        ReplaceError::RollbackFailed { .. }
        | ReplaceError::Unconfirmed { .. }
        | ReplaceError::Failed(_) => Settle::Abandon,
    }
}

/// This replacement's new entries until they are settled. Dropped unsettled
/// (a panic, a write task that died) it discards them while the old file
/// stands and abandons them once `write_atomic` may have replaced it.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
struct Entries {
    pending: Option<PendingSecrets>,
    renamed: bool,
}

#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
impl Entries {
    /// Keep and abandon touch no store, so they run here and now: a queued
    /// closure that a shutting-down runtime never runs would drop the
    /// entries undecided, which deletes them. Only a discard calls the
    /// store, off the async worker (a keychain call blocks for up to 2 s);
    /// if that closure never runs, the drop discards all the same.
    async fn settle(mut self, how: Settle) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        match how {
            Settle::Keep | Settle::Abandon => settle_now(pending, how),
            Settle::Discard => {
                if let Err(e) = tokio::task::spawn_blocking(move || settle_now(pending, how)).await
                {
                    tracing::warn!(error = %e, "discarding a refused save's secret entries failed; they are listed as unused");
                }
            }
        }
    }
}

impl Drop for Entries {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let how = if self.renamed {
            Settle::Abandon
        } else {
            Settle::Discard
        };
        match (how, tokio::runtime::Handle::try_current()) {
            (Settle::Discard, Ok(runtime)) => {
                drop(runtime.spawn_blocking(move || settle_now(pending, how)));
            }
            _ => settle_now(pending, how),
        }
    }
}

#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
fn settle_now(pending: PendingSecrets, how: Settle) {
    match how {
        Settle::Keep => pending.keep(),
        Settle::Abandon => pending.abandon(),
        Settle::Discard => {
            let left = pending.discard();
            if !left.is_empty() {
                tracing::warn!(
                    entries = left.len(),
                    "secret entries of a refused config save could not be removed; they are listed as unused"
                );
            }
        }
    }
}

#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
async fn create_entries(
    step: SecretStep,
    deadline: Instant,
) -> Result<PendingSecrets, ReplaceError> {
    tokio::task::spawn_blocking(move || {
        create_secrets(step.vault, step.store, &step.values, deadline)
    })
    .await
    .map_err(|e| ReplaceError::Failed(format!("the secret save task failed: {e}")))?
    .map_err(ReplaceError::Secrets)
}

#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
impl ReloadContext {
    async fn replace_locked(
        &self,
        replace: Replace,
        wait: Duration,
    ) -> Result<ReplaceOutcome, ReplaceError> {
        let deadline = Instant::now() + wait;
        // The reload lock, then the config sidecar lock: the order every
        // holder takes them in (module docs).
        let reload_guard = self.lock_reload_within(wait).await.map_err(|e| match e {
            ConfigWriteError::Busy => ReplaceError::Busy,
            ConfigWriteError::Failed(message) => ReplaceError::Failed(message),
        })?;
        // The target is resolved once, by the lock: the owed reload, the
        // trust check, the read and the commit are all about that one file.
        let locked = lock_config(&self.config_path, deadline)
            .await
            .map_err(|e| {
                self.note_refused_lock();
                match e {
                    NotLocked::Busy => ReplaceError::Busy,
                    NotLocked::Failed(message) => ReplaceError::Failed(message),
                }
            })?;
        let target = locked.target.clone();
        self.pay_owed_reload(locked.recovered, &target).await;

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
        let mut entries = Entries {
            pending: None,
            renamed: false,
        };
        let refs = match replace.secrets {
            // An empty step saves nothing: no entry for the bytes to name.
            Some(step) if !step.values.is_empty() => {
                let pending = create_entries(step, deadline).await?;
                let refs = pending.refs().to_vec();
                entries.pending = Some(pending);
                refs
            }
            _ => Vec::new(),
        };
        let result = self
            .write_computed(
                &locked,
                &target,
                &current,
                (replace.compute, replace.replaced),
                &refs,
                &mut entries,
            )
            .await;
        // The config locks go before any store call: a discard's keychain
        // deletes must not hold up the next writer. A death in between is
        // the `Entries` guard's.
        drop(locked);
        drop(reload_guard);
        let how = settle_for(&result);
        entries.settle(how).await;
        result
    }

    /// Compute, check and commit the new bytes; `entries` learns when the
    /// rename happened.
    async fn write_computed(
        &self,
        locked: &Locked,
        target: &std::path::Path,
        current: &[u8],
        (compute, replaced): (Compute, Replaced),
        refs: &[String],
        entries: &mut Entries,
    ) -> Result<ReplaceOutcome, ReplaceError> {
        let new = compute(current, refs).map_err(ReplaceError::Refused)?;
        if std::str::from_utf8(&new).is_err() {
            return Err(ReplaceError::Refused(
                "the new gateway.yaml is not UTF-8 text".to_string(),
            ));
        }
        // The path may have moved, or the config been deleted, while the
        // bytes were computed: refuse before anything is reloaded or staged,
        // rather than report on a config the path no longer names.
        locked
            .may_write(&self.config_path)
            .map_err(ReplaceError::Unsupported)?;
        if new == current {
            if entries.pending.is_some() {
                // The compute dropped the references: nothing would name the
                // entries just created.
                return Err(ReplaceError::Refused(
                    "the new config does not name the saved secrets".to_string(),
                ));
            }
            // Nothing to write, but still a reload, so a retry after a failed
            // one does not leave the runtime stale. Nothing was committed, so
            // a refusal needs no rollback.
            let reload = self
                .reload_outcome_locked_at(target)
                .await
                .map_err(ReplaceError::ReloadRefused)?;
            return Ok(ReplaceOutcome {
                revision: None,
                kept_beside: None,
                reload,
            });
        }
        self.commit(target, current, &new, replaced, entries).await
    }

    /// Stage, journal, write, reload; then keep the new bytes or put the
    /// original back.
    async fn commit(
        &self,
        target: &std::path::Path,
        current: &[u8],
        new: &[u8],
        replaced: Replaced,
        entries: &mut Entries,
    ) -> Result<ReplaceOutcome, ReplaceError> {
        // Every step uses `target`, resolved once and checked against the
        // trusted path, so a link re-pointed mid-write cannot split them.
        let original = journal::stage_original(target, current)
            .map_err(|e| ReplaceError::Stage(format!("staging the original failed: {e}")))?;
        // The kept copy exists before anything is replaced: a save that
        // cannot keep it is refused, never reported done without it.
        let kept_beside = match replaced {
            Replaced::KeepBeside => match keep_beside(&original, target) {
                Ok(kept) => Some(kept),
                Err(e) => {
                    return Err(Self::roll_back(target, ReplaceError::Stage(e)));
                }
            },
            Replaced::Discard => None,
        };
        let unkeep = || {
            if let Some(kept) = &kept_beside {
                let _ = std::fs::remove_file(kept);
            }
        };
        if let Err(e) = journal::begin(target, FileRevision::of(current).0) {
            unkeep();
            return Err(Self::roll_back(
                target,
                ReplaceError::Stage(format!("writing the replace journal failed: {e}")),
            ));
        }
        // From here the file on disk may name this save's entries: set before
        // the write, so a death inside it keeps them (listed as unused)
        // rather than deleting what the new file may already name. A write
        // error comes back after a proven rollback and discards.
        entries.renamed = true;
        // gateway.yaml is owner-only, as every config write leaves it.
        if let Err(e) = write_atomic(target, new, FileMode::Private, Symlink::Replace) {
            unkeep();
            return Err(Self::roll_back(
                target,
                ReplaceError::Write(format!("writing {} failed: {e}", target.display())),
            ));
        }
        let reloaded = self.reload_outcome_locked_at(target).await;
        // The reload reads gateway.yaml through its configured path. If a
        // symlink there moved meanwhile, it loaded some other file: put ours
        // back, and owe a reload so the runtime leaves that other file too.
        if crate::identity_grants::journal::resolved(&self.config_path) != target {
            unkeep();
            self.reload_owed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Err(Self::roll_back(
                target,
                ReplaceError::Unsupported(format!(
                    "{} was re-pointed during the write; nothing was applied",
                    self.config_path.display()
                )),
            ));
        }
        match reloaded {
            Ok(reload) => {
                if let Err(e) = journal::mark_all_renamed(target) {
                    return Err(ReplaceError::Unconfirmed {
                        journal: journal::journal_path(target),
                        error: e.to_string(),
                    });
                }
                if let Err(e) = journal::finish(target) {
                    // The new bytes stand and were accepted; the journal says
                    // `all_renamed`, so the next lock holder only cleans up.
                    tracing::warn!(error = %e, path = %target.display(), "removing the replace journal failed; the next config write removes it");
                }
                Ok(ReplaceOutcome {
                    revision: Some(FileRevision::of(new)),
                    kept_beside,
                    reload,
                })
            }
            Err(refusal) => {
                unkeep();
                Err(Self::roll_back(
                    target,
                    ReplaceError::ReloadRefused(refusal),
                ))
            }
        }
    }

    /// Put the original back, or remove a staged copy no journal names yet
    /// (the same recovery the next lock holder would run), and report
    /// `error`; or `RollbackFailed` when that fails too.
    fn roll_back(target: &std::path::Path, error: ReplaceError) -> ReplaceError {
        match journal::recover(target) {
            Ok(_) => error,
            Err(rollback) => ReplaceError::RollbackFailed {
                journal: journal::journal_path(target),
                error: rollback,
            },
        }
    }
}

/// Keep the staged original as `gateway.yaml.<UTC time>.rejected` beside the
/// target: a second hard link to it, so it survives the journal cleanup that
/// removes the staged name. Never over an existing name (`-2`, `-3` on a
/// clash).
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
fn keep_beside(original: &std::path::Path, target: &std::path::Path) -> Result<PathBuf, String> {
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
            Ok(()) => return Ok(kept),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(format!(
                    "keeping the replaced gateway.yaml as {} failed: {e}",
                    kept.display()
                ));
            }
        }
    }
    Err(format!(
        "keeping the replaced gateway.yaml failed: every name like {base} is taken"
    ))
}
