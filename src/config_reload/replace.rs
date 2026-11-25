// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared byte writer for gateway.yaml (ADR-024): exact bytes, written
//! under the config lock pair, then one reload, and the old bytes back on
//! disk whenever that reload refuses.
//!
//! Web UI settings saves (a spliced file) and configuration-history restores
//! (stored bytes) both write through [`replace_audited`]. It refuses a write
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
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::config::UnreadConfig;
use crate::config_persistence::journal;
use crate::config_persistence::lock::{Locked, NotLocked, lock_config, lock_config_deferred};
use crate::config_persistence::{FileMode, Symlink, write_atomic};
use crate::config_reload::ConfigWriteError;
pub(crate) use crate::config_reload::first_key::{ReplaceReload, StatusChange};
use crate::config_reload::history::Source;
use crate::secret_store::{PendingSecrets, create_secrets};

use super::ReloadContext;
pub(crate) use super::replace_refusal::RefusalClass;
pub(super) use super::replace_refusal::post_write_class;
#[cfg(test)]
use crate::gateway::restart_config_floor::seams::{AdmittedPoint, ReloadSource};
use crate::gateway::restart_config_floor::{AdmissionGuard, AdmitKind};

// The revision type lives with the config commit primitive, which every
// build compiles; the replace path names it from there.
pub(crate) use crate::config_persistence::commit::FileRevision;

#[path = "replace_request.rs"]
mod request;
pub(crate) use request::{Expected, Replace, ReplaceError, ReplaceOutcome, Replaced, SecretStep};
// Named only by the settings save, which builds where it does.
#[cfg(any(test, feature = "webui"))]
pub(crate) use request::Compute;

/// The writer's task, in a task of its own: dropping the caller (a request
/// handler whose client went away) drops only the wait, never a write
/// between its rename and its reload. Reached only through
/// [`replace_audited`](audit::replace_audited).
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
async fn spawn_locked(
    ctx: Arc<ReloadContext>,
    replace: Replace,
    audit: Audit,
    source: Source,
    wait: Duration,
    receipt: Option<receipt::RevokeCheck>,
) -> Result<(ReplaceOutcome, Option<receipt::RevokeReceipt>), (ReplaceError, Trace)> {
    // The gate admits before the task exists; the guard lives in the task, so a
    // dead task releases it, and the task moves it into `Entries` before any
    // secret entry is staged.
    let admitted = ctx
        .registry
        .config_gate()
        .admit(AdmitKind::Write)
        .map_err(|refusal| (ReplaceError::Gated(refusal), Trace::default()))?;
    // Read after the join, whatever became of the task.
    let trace = Arc::new(WriteTrace::default());
    let filled = Arc::clone(&trace);
    let result = tokio::spawn(async move {
        ctx.replace_locked(replace, audit, source, wait, receipt, admitted, filled)
            .await
    })
    .await
    .unwrap_or_else(|e| {
        Err(ReplaceError::Failed(format!(
            "the config write task failed: {e}"
        )))
    });
    let trace = trace.snapshot();
    match result {
        Ok((mut outcome, receipt)) => {
            outcome.intent_id = trace.intent_id;
            Ok((outcome, receipt))
        }
        Err(error) => Err((error, trace)),
    }
}

#[cfg(test)]
#[path = "replace_order.rs"]
pub(crate) mod order;

#[path = "replace_audit.rs"]
mod audit;
#[path = "replace_receipt.rs"]
mod receipt;
#[path = "replace_trace.rs"]
mod trace;
pub(crate) use audit::IntentId;
#[cfg(feature = "webui")]
pub(crate) use audit::replace_audited_revoke;
#[cfg(test)]
pub(crate) use audit::replace_detached;
pub(crate) use audit::{Audit, Intent, IntentSink, startup_recovery_intent};
pub(crate) use audit::{AuditPosture, GatewayAuth};
#[cfg(feature = "webui")]
pub(crate) use audit::{BackendOp, NO_AUDIT_LOG};
#[cfg(any(test, feature = "webui"))]
pub(crate) use audit::{IntentKind, replace_audited, replace_traced};
#[cfg(feature = "webui")]
pub(crate) use receipt::RevokeCheck;
pub(crate) use trace::{Trace, WriteTrace};

#[path = "replace_entries.rs"]
mod entries;
#[path = "replace_slots.rs"]
mod slots;
use entries::Entries;

#[path = "replace_validate.rs"]
mod validate;

/// The settings preview (U8): a child of the writer, so it validates as the
/// writer does.
#[path = "ui_diff.rs"]
pub(crate) mod ui_diff;
/// The settings save (U8): the writer's caller for a UI edit.
#[cfg(any(test, feature = "webui"))]
#[path = "ui_save.rs"]
pub(crate) mod ui_save;
use slots::{fill_secrets, fits_when_filled, same_fields};

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
        | ReplaceError::Gated(_)
        | ReplaceError::Stale { .. }
        | ReplaceError::Refused(_)
        | ReplaceError::NoAuditLog
        | ReplaceError::AuditRefused(_)
        | ReplaceError::Stage(_)
        | ReplaceError::Secrets(_)
        | ReplaceError::NoConfigFile
        | ReplaceError::ConfigRefused(_)
        // The rollback came back: a failed one is `RollbackFailed`.
        | ReplaceError::Unsupported(_)
        | ReplaceError::Write(_)
        | ReplaceError::ReloadRefused { .. } => Settle::Discard,
        // The file on disk may name them; `Failed` proves nothing either way.
        ReplaceError::RollbackFailed { .. }
        | ReplaceError::Unconfirmed { .. }
        | ReplaceError::Failed(_) => Settle::Abandon,
    }
}

/// Each secret's field, in the step's order.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
fn step_fields(step: Option<&SecretStep>) -> Vec<String> {
    step.map(|step| step.values.iter().map(|v| v.field.clone()).collect())
        .unwrap_or_default()
}

/// `outcome` with the references this write filled, by field, read before the
/// entries are settled (a kept entry's reference is what the file holds).
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
fn with_references(
    mut outcome: ReplaceOutcome,
    fields: Vec<String>,
    entries: &Entries,
) -> ReplaceOutcome {
    if let Some(pending) = &entries.pending {
        outcome.secrets = fields
            .into_iter()
            .zip(pending.refs().iter().cloned())
            .collect();
    }
    outcome
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
        mut audit: Audit,
        source: Source,
        wait: Duration,
        receipt: Option<receipt::RevokeCheck>,
        admitted: AdmissionGuard,
        trace: Arc<WriteTrace>,
    ) -> Result<(ReplaceOutcome, Option<receipt::RevokeReceipt>), ReplaceError> {
        let deadline = Instant::now() + wait;
        // The reload lock, then the config sidecar lock: the order every
        // holder takes them in (module docs).
        let reload_guard = self.lock_reload_within(wait).await.map_err(|e| match e {
            ConfigWriteError::Busy => ReplaceError::Busy,
            ConfigWriteError::Failed(message) => ReplaceError::Failed(message),
        })?;
        // The target is resolved once, by the lock: the owed reload, the
        // trust check, the read and the commit are all about that one file.
        // An audited write recovers nothing before its recovery intent, so
        // its lock leaves a pending journal where it is, and a refused lock
        // restores nothing.
        let audited = matches!(audit, Audit::Required { .. });
        let locked = if audited {
            lock_config_deferred(&self.config_path, deadline).await
        } else {
            lock_config(&self.config_path, deadline).await
        }
        .map_err(|e| {
            if !audited {
                self.note_refused_lock();
            }
            match e {
                NotLocked::Busy => ReplaceError::Busy,
                NotLocked::Failed(message) => ReplaceError::Failed(message),
                NotLocked::Refused(message) => ReplaceError::ConfigRefused(message),
            }
        })?;
        let target = locked.target.clone();
        let (locked, recovery_intent_id) = self.recover_before_write(&mut audit, locked).await?;

        let current = self.read_trusted(&target)?;
        if let Expected::Revision(seen) = &replace.expected {
            let now = FileRevision::of(&current);
            if &now != seen {
                return Err(ReplaceError::Stale { current: now });
            }
        }
        // The write's one guard moves in before any entry is staged: a task
        // that dies while staging drops `Entries`, whose detached discard then
        // holds the count until its store calls are done.
        let mut entries = Entries {
            pending: None,
            renamed: false,
            admitted: Some(admitted),
            trace,
            #[cfg(test)]
            gate: self.registry.config_gate(),
        };
        // The new bytes are computed, and their slots checked against the
        // secrets, before any entry exists: a refusal creates nothing.
        #[cfg(test)]
        if receipt.is_some() {
            order::record(&target, "target_compute");
        }
        let template = (replace.compute)(&current).map_err(ReplaceError::Refused)?;
        let step = replace.secrets.filter(|step| !step.values.is_empty());
        let fields = step_fields(step.as_ref());
        same_fields(&template, step.as_ref())?;
        fits_when_filled(&template)?;
        self.validate_template(&target, &template, step.as_ref(), replace.status_change)
            .await?;
        // gateway.yaml deleted while the bytes were computed or checked: the
        // missing file, before any intent or entry exists.
        Self::still_there(&locked, &self.config_path)?;
        // The operation's own intent, once its checks pass and before any
        // entry or byte changes. Unchanged bytes write nothing but still
        // reload, which applies whatever the disk holds that the running
        // config does not: recorded as an outside change, since no loaded
        // revision is kept to tell (over-reports, never under-reports).
        let unchanged = step.is_none() && template.bytes() == current.as_slice();
        receipt::record_write_intent(
            &mut audit,
            &current,
            unchanged,
            recovery_intent_id,
            &target,
            &entries.trace,
        )?;
        let result = match step {
            None => Ok(template.bytes().to_vec()),
            Some(step) => fill_secrets(template, step, deadline, &mut entries).await,
        };
        let result = match result {
            Ok(new) => {
                #[cfg(test)]
                entries
                    .gate
                    .call_admitted(AdmittedPoint::WriterAfterStaging);
                self.write_computed(
                    &locked,
                    &target,
                    &current,
                    (new, replace.replaced, replace.status_change),
                    &mut entries,
                    source,
                )
                .await
            }
            Err(refused) => Err(refused),
        };
        let result = result.map(|outcome| with_references(outcome, fields, &entries));
        let how = settle_for(&result);
        #[cfg(test)]
        let recording_receipt = receipt.is_some();
        let result = receipt::check_revoke_receipt(result, receipt, &current, &target);
        // The config locks go before any store call: a discard's keychain
        // deletes must not hold up the next writer. A death in between is
        // the `Entries` guard's.
        drop(locked);
        #[cfg(test)]
        if recording_receipt {
            order::record(&target, "file_unlock");
        }
        drop(reload_guard);
        #[cfg(test)]
        if recording_receipt {
            order::record(&target, "reload_unlock");
        }
        #[cfg(test)]
        entries.gate.call_admitted(AdmittedPoint::WriterAfterLocks);
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
        (new, replaced, status_change): (Vec<u8>, Replaced, StatusChange),
        entries: &mut Entries,
        source: Source,
    ) -> Result<ReplaceOutcome, ReplaceError> {
        if std::str::from_utf8(&new).is_err() {
            return Err(ReplaceError::Refused(
                "the new gateway.yaml is not UTF-8 text".to_string(),
            ));
        }
        // The path may have moved, or the config been deleted, while the
        // bytes were computed: refuse before anything is reloaded or staged,
        // rather than report on a config the path no longer names.
        // Deleted while the entries were created: the missing file; the
        // entries are discarded, as nothing was written.
        Self::still_there(locked, &self.config_path)?;
        locked
            .may_write(&self.config_path)
            .map_err(ReplaceError::Unsupported)?;
        if new == current {
            if entries.pending.is_some() {
                // Unreachable after the slot check (a filled slot changes the
                // bytes); refused rather than leave entries nothing names.
                return Err(ReplaceError::Refused(
                    "the new config does not name the saved secrets".to_string(),
                ));
            }
            // Nothing to write, but still a reload, so a retry after a failed
            // one does not leave the runtime stale. Nothing was committed, so
            // a refusal needs no rollback.
            // The principal arrives with its own row (H8).
            let (reload, reload_applied) =
                self.reload_applied_at(target, source)
                    .await
                    .map_err(|refusal| ReplaceError::ReloadRefused {
                        class: post_write_class(&refusal),
                        reason: refusal.text,
                    })?;
            #[cfg(test)]
            self.record_write_reload();
            return Ok(ReplaceOutcome {
                revision: None,
                kept_beside: None,
                reload: ReplaceReload::Applied(reload),
                secrets: Vec::new(),
                intent_id: None,
                reload_applied,
            });
        }
        self.commit(
            target,
            current,
            &new,
            (replaced, status_change),
            entries,
            source,
        )
        .await
    }
    /// Stage, journal, write, reload; then keep the new bytes or put the
    /// original back.
    async fn commit(
        &self,
        target: &std::path::Path,
        current: &[u8],
        new: &[u8],
        (replaced, status_change): (Replaced, StatusChange),
        entries: &mut Entries,
        source: Source,
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
                    return Err(Self::roll_back(
                        target,
                        ReplaceError::Stage(e),
                        &entries.trace,
                    ));
                }
            },
            Replaced::Discard => None,
        };
        let unkeep = || {
            if let Some(kept) = &kept_beside {
                let _ = std::fs::remove_file(kept);
            }
        };
        if let Err(e) = journal::begin(target, FileRevision::of(current).as_str().to_owned()) {
            unkeep();
            return Err(Self::roll_back(
                target,
                ReplaceError::Stage(format!("writing the replace journal failed: {e}")),
                &entries.trace,
            ));
        }
        // From here the file on disk may name this save's entries: set before
        // the write, so a death inside it keeps them (listed as unused)
        // rather than deleting what the new file may already name. A write
        // error comes back after a proven rollback and discards.
        entries.renamed = true;
        // From here the new bytes may be on disk.
        entries.trace.written.store(true, Ordering::SeqCst);
        // Test seam: an armed `FailWrite` fails the write before it starts,
        // so the rollback after it has the original to put back.
        #[cfg(test)]
        let injected =
            journal::fault::fires(target, |f| matches!(f, journal::fault::Fault::FailWrite))
                .is_some();
        #[cfg(not(test))]
        let injected = false;
        // gateway.yaml is owner-only, as every config write leaves it.
        let written = if injected {
            Err(std::io::Error::other("injected: the write fails"))
        } else {
            write_atomic(target, new, FileMode::Private, Symlink::Replace)
        };
        if let Err(e) = written {
            unkeep();
            return Err(Self::roll_back(
                target,
                ReplaceError::Write(format!("writing {} failed: {e}", target.display())),
                &entries.trace,
            ));
        }
        #[cfg(test)]
        order::record(target, "commit");
        // The principal arrives with its own row (H8).
        let reloaded = self.reload_applied_at(target, source).await;
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
                &entries.trace,
            ));
        }
        let (reload, reload_applied) = match reloaded {
            Ok((reload, applied)) => {
                #[cfg(test)]
                self.record_write_reload();
                (ReplaceReload::Applied(reload), applied)
            }
            // The operator's option B1 (ADR-024, amended): a first key the
            // question held is refused by the reload for its status change
            // alone, and its bytes stay for the next start, which accepts
            // them. No other caller passes `HoldForRestart`, and no other
            // refusal reaches this arm.
            Err(refusal)
                if status_change == StatusChange::HoldForRestart
                    && refusal.kind == super::lock_api::ReloadRefusalKind::StatusChange =>
            {
                let held = ReplaceReload::HeldForRestart {
                    refusal: refusal.text,
                    keys: refusal.waiting,
                };
                // Held for the next start: nothing published now.
                (held, false)
            }
            Err(refusal) => {
                unkeep();
                return Err(Self::roll_back(
                    target,
                    ReplaceError::ReloadRefused {
                        class: post_write_class(&refusal),
                        reason: refusal.text,
                    },
                    &entries.trace,
                ));
            }
        };
        if let Err(e) = journal::mark_all_renamed(target) {
            return Err(ReplaceError::Unconfirmed {
                journal: journal::journal_path(target),
                error: e.to_string(),
            });
        }
        if let Err(e) = journal::finish(target) {
            // The new bytes stand; the journal says `all_renamed`, so the
            // next lock holder only cleans up.
            tracing::warn!(error = %e, path = %target.display(), "removing the replace journal failed; the next config write removes it");
        }
        Ok(ReplaceOutcome {
            revision: Some(FileRevision::of(new)),
            kept_beside,
            reload,
            secrets: Vec::new(),
            intent_id: None,
            reload_applied,
        })
    }

    /// The locked target's bytes, once it is still the file this gateway
    /// started on. The read every loader uses, mode and owner judged on the
    /// handle read: a file another account can change is refused before any
    /// intent, entry or write, so its edit is never rewritten owner-only.
    fn read_trusted(&self, target: &std::path::Path) -> Result<Vec<u8>, ReplaceError> {
        if target != self.trusted_config.as_path() {
            return Err(ReplaceError::Unsupported(format!(
                "{} now resolves to {}, not to {}, the file this gateway started on; nothing was written",
                self.config_path.display(),
                target.display(),
                self.trusted_config.display()
            )));
        }
        match crate::config::read_config_text(target) {
            Ok(Some(text)) => Ok(text.into_bytes()),
            Ok(None) => Err(ReplaceError::NoConfigFile),
            Err(UnreadConfig::Refused(why)) => Err(ReplaceError::ConfigRefused(why)),
            Err(UnreadConfig::Failed(why) | UnreadConfig::NotTheConfig(why)) => {
                Err(ReplaceError::Failed(why))
            }
        }
    }

    /// The reload log's Write entry: the running `environment` after this
    /// write's own completed reload.
    #[cfg(test)]
    fn record_write_reload(&self) {
        let environment = self.live_config.get().environment.clone();
        self.registry
            .config_gate()
            .record_reload(ReloadSource::Write, &environment.unwrap_or_default());
    }

    /// Put the original back, or remove a staged copy no journal names yet
    /// (the same recovery the next lock holder would run), and report
    /// `error`; or `RollbackFailed` when that fails too.
    fn roll_back(
        target: &std::path::Path,
        error: ReplaceError,
        trace: &WriteTrace,
    ) -> ReplaceError {
        // Test-only: a write that is undone still leaves its mark in the trace.
        #[cfg(test)]
        order::record(target, "rollback");
        match journal::recover(target) {
            Ok(_) => {
                // A staging cleanup before the write puts nothing back.
                if trace.written.load(Ordering::SeqCst) {
                    trace.restored.store(true, Ordering::SeqCst);
                }
                error
            }
            Err(rollback) => ReplaceError::RollbackFailed {
                journal: journal::journal_path(target),
                error: rollback.into_message(),
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
