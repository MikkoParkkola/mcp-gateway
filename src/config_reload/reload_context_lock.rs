// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How [`ReloadContext`] takes the reload lock and loads gateway.yaml: the
//! bounded lock wait, the off-worker file load, the pinned reload and the
//! reload a lock recovery left owed (moved from `reload_context.rs`).

use std::sync::Arc;
use std::time::Duration;

use crate::config_reload::history::Source;
use crate::config_reload::{ConfigWriteError, ReloadOutcome};

use super::{EvaluatedReload, ReloadContext, STOPPED};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadRefusalKind {
    Posture,
    Other,
    /// The file's only fault is a first key (`waiting` names the keys).
    StatusChange,
    /// The file changes the multi-user status and fails another check as
    /// well: recorded as invalid config by this kind, never by its text.
    Faulty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReloadRefusal {
    pub(crate) kind: ReloadRefusalKind,
    pub(crate) text: String,
    /// The waiting keys of a `StatusChange` refusal; empty for every other kind.
    pub(crate) waiting: Vec<String>,
}

impl From<String> for ReloadRefusal {
    fn from(text: String) -> Self {
        Self {
            kind: ReloadRefusalKind::Other,
            text,
            waiting: Vec::new(),
        }
    }
}

impl ReloadContext {
    /// Take the reload lock, giving up after `wait`.
    ///
    /// The bound covers *acquiring* the lock, not holding it. A write that wins
    /// the lock then runs its reload to completion, however long that takes;
    /// what the bound prevents is every other write queueing behind that one
    /// forever.
    ///
    /// Only config *writes* are bounded at all. A reload triggered by the
    /// meta-tool, the admin UI reload button, or the file watcher still waits as
    /// long as it takes: refusing one of those would silently drop a config
    /// change the operator already made on disk, which trades a hang for a lost
    /// edit. A refused write, by contrast, has changed nothing and can be
    /// retried.
    pub(super) async fn lock_reload_within(
        &self,
        wait: Duration,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, ()>, ConfigWriteError> {
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
        tokio::time::timeout(wait, self.registry.lock_reload())
            .await
            .map_err(|_| {
                // Every caller returns on this error and none reaches
                // `note_refused_lock`, so the skip is tallied exactly once.
                self.reporting.tally.skipped();
                ConfigWriteError::Busy
            })
    }

    /// The reload lock, then the config sidecar with no recovery (a pending
    /// journal stays where it is), each within `wait`: the order every holder
    /// takes them in, for a caller that changes something beside the config,
    /// such as a secret entry, and must not race a config write.
    #[cfg(feature = "webui")]
    pub(crate) async fn hold_config(
        &self,
        wait: Duration,
    ) -> std::result::Result<ConfigHeld<'_>, ConfigWriteError> {
        let deadline = std::time::Instant::now() + wait;
        let reload = self.lock_reload_within(wait).await?;
        let locked =
            crate::config_persistence::lock::lock_config_deferred(&self.config_path, deadline)
                .await
                .map_err(ConfigWriteError::from)?;
        Ok(ConfigHeld {
            _reload: reload,
            locked,
        })
    }

    /// Run the file load on its own thread and wait for it without holding a
    /// runtime worker (#1808).
    ///
    /// The load reads the config file and every env file; on a stalled NFS or
    /// FUSE mount that read blocks for as long as the mount does. Awaiting it
    /// here keeps the workers free and lets shutdown drop this future; nothing
    /// the thread computes is published unless this future is still waiting.
    /// Both failure arms refuse the reload, as a failed load always has. A
    /// panicking load is a refusal only where panics unwind: the release
    /// profile aborts on any panic, here as everywhere else.
    pub(super) async fn load_off_worker(
        &self,
        path: std::path::PathBuf,
    ) -> std::result::Result<EvaluatedReload, String> {
        // The reload lock alone does not bound threads: a reload whose future
        // is dropped (a client that disconnects, a caller's timeout) releases
        // the lock while its read is still stalled. The permit travels into the
        // thread and is released only when that read returns.
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: config reload applies the operator's backend set; no caller request"
        )]
        let read_slot = self.registry.reload_read_slot();
        let slot = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(STOPPED.to_owned()),
            slot = read_slot.acquire_owned() => {
                slot.map_err(|_| "config reload load slot closed".to_owned())?
            }
        };
        let (done, result) = tokio::sync::oneshot::channel();
        let (load, path, live, env) = (
            self.load,
            path,
            Arc::clone(&self.live_config),
            Arc::clone(&self.env),
        );
        (self.spawn)(Box::new(move || {
            // Released when the read returns, not when the reload that asked
            // for it gives up.
            let _slot = slot;
            drop(done.send(load(&path, &live, &env)));
        }))
        .map_err(|e| format!("config reload could not start its file read: {e}"))?;
        tokio::select! {
            biased;
            () = self.stop.cancelled() => Err(STOPPED.to_owned()),
            done = result => {
                done.map_err(|_| "config reload file read ended without a result".to_owned())?
            }
        }
    }

    /// The reload transaction itself, loading gateway.yaml from `path`: the
    /// target the caller's config lock resolved, so the reload reads the file
    /// it locked even if a symlink at `config_path` moves meanwhile. The
    /// caller must already hold the reload lock; taking it here as well would
    /// deadlock on the non-reentrant mutex. An accepted reload pays any reload
    /// a lock recovery left owed.
    pub(super) async fn reload_outcome_locked_at(
        &self,
        path: &std::path::Path,
        source: Source,
    ) -> std::result::Result<ReloadOutcome, ReloadRefusal> {
        let applied = self.reload_applied_at(path, source).await;
        applied.map(|(outcome, _)| outcome)
    }

    /// [`Self::reload_outcome_locked_at`], and whether the reload published an
    /// effective change: the patch's own predicate, never its summary text.
    /// Crate-private, so the public `ReloadOutcome` keeps its shape.
    pub(super) async fn reload_applied_at(
        &self,
        path: &std::path::Path,
        source: Source,
    ) -> std::result::Result<(ReloadOutcome, bool), ReloadRefusal> {
        // Audits the overrides the registry holds however this ends: applied,
        // refused, or dropped at an await after registering backends.
        let _audit = (self.reporting.override_audit.as_deref()).map(|a| a.guard(&self.registry));
        // Before anything changes: records stay in the order reloads take
        // this, which is `lock_reload`'s (design D-1).
        let mut slot = crate::config_reload::history::RecordSlot::take(&self.live_config).await;
        let mut judged = None;
        let mut applied = false;
        let outcome = self
            .reload_transaction(path, source.clone(), &mut slot, &mut judged, &mut applied)
            .await;
        let refusals = &self.reporting.refusals;
        match &outcome {
            Ok(_) => {
                self.reload_owed
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                self.live_config.note_first_key(None);
                refusals.reload_applied();
                self.reporting.tally.applied();
            }
            // The file's only fault is a first key: the fact names its keys
            // (the question's check (d) passed, so a start from it is not
            // refused), and the ledger row has its own code.
            Err(refusal) if refusal.kind == ReloadRefusalKind::StatusChange => {
                self.live_config.note_first_key(Some(
                    crate::config_reload::live_config::FirstKeyWait {
                        keys: refusal.waiting.clone(),
                        start_refusal: None,
                    },
                ));
                refusals.record_first_key_waiting();
                self.reporting.tally.refused();
                let pending = self.live_config.refused_record(source, None);
                slot.spawn(&self.live_config, pending);
            }
            // A faulty first key: invalid config by its kind, never by its
            // text (which carries the shared reload prefix).
            Err(refusal) if refusal.kind == ReloadRefusalKind::Faulty => {
                self.live_config.note_first_key(judged.take());
                refusals.record_invalid_config();
                self.reporting.tally.refused();
                let pending = self.live_config.refused_record(source, None);
                slot.spawn(&self.live_config, pending);
            }
            Err(refusal) => {
                // Every other verdict of a reload that read the file keeps an
                // established wait only as judged again on that file (none
                // when nothing waited, the file did not load, or it holds no
                // waiting key now); one stopped by shutdown read nothing and
                // leaves it.
                if crate::config_reload::reload_failure(&refusal.text)
                    != crate::config_reload::ReloadFailure::ShuttingDown
                {
                    self.live_config.note_first_key(judged.take());
                }
                // The typed error was flattened to text on the way here.
                // Parse the file once more and pass that error's location.
                // Never a line taken out of the text.
                let line = if crate::config_reload::refusals::carries_file_line(&refusal.text) {
                    line_of_refused_file(path)
                } else {
                    None
                };
                refusals.record(
                    crate::config_reload::refusals::RefusalKind::Reload,
                    None,
                    &refusal.text,
                    line,
                );
                self.reporting.tally.refused();
                let pending = self.live_config.refused_record(source, line);
                slot.spawn(&self.live_config, pending);
            }
        }
        slot.finish().await;
        outcome.map(|outcome| (outcome, applied))
    }

    /// Note what a lock recovery did, then pay an owed reload of `target`,
    /// the file the caller locked, before the caller's own work, so no early return leaves the running config on
    /// bytes recovery took away. The caller holds the reload lock. A failed
    /// reload stays owed and is logged; the caller's work goes on, and its
    /// own reload (every writer ends with one) tries again.
    pub(super) async fn pay_owed_reload(
        &self,
        recovered: crate::config_persistence::journal::Recovered,
        target: &std::path::Path,
    ) {
        use std::sync::atomic::Ordering::SeqCst;
        if recovered == crate::config_persistence::journal::Recovered::RolledBack {
            self.reload_owed.store(true, SeqCst);
        }
        if self.reload_owed.load(SeqCst)
            && let Err(error) = self.reload_outcome_locked_at(target, Source::File).await
        {
            let class = match crate::config_reload::reload_failure(&error.text) {
                crate::config_reload::ReloadFailure::ShuttingDown => "shutting_down",
                crate::config_reload::ReloadFailure::PostureRefused
                | crate::config_reload::ReloadFailure::Internal => "internal",
            };
            tracing::warn!(kind = ?error.kind, class, "the reload owed after restoring gateway.yaml failed; it is retried on the next one");
        }
    }

    /// A refused lock may still have restored gateway.yaml (its journal then
    /// could not be removed): owe the reload back to the restored bytes. Also
    /// the one place a skipped reload is tallied: every entry point that could
    /// not take the lock comes through here.
    pub(super) fn note_refused_lock(&self) {
        self.reporting.tally.skipped();
        if crate::config_persistence::journal::take_restored(&self.config_path) {
            self.reload_owed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// The parser line of a file a reload just refused, when the parser has one.
///
/// `figment_data` runs `from_str` and then stringifies the error, so the
/// location is gone before the reload sees it. This is that same parse, into
/// `Config` rather than the loose `Dict`: a `Dict` accepts a scalar of the
/// wrong type, and a type error would then have no location. `Error::location`
/// covers a syntax error and a serde message the deserializer placed. A file
/// that deserializes has no location; that is a later validation. The line is
/// the location's, never a number read out of the message.
///
/// The file is read again, so a save landing between the refusal and this
/// read is the text parsed; the watcher reloads that save and records it on
/// its own. The parse sees the file alone, without the `MCP_GATEWAY_*`
/// overlay: a wrong-typed value the overlay replaces still yields its line,
/// which is a real fault in the file.
fn line_of_refused_file(path: &std::path::Path) -> Option<u32> {
    let text = crate::config::Config::guarded_text(path).ok()?;
    let error = crate::yaml::from_str::<crate::config::Config>(&text).err()?;
    u32::try_from(error.location()?.line()).ok()
}

/// The reload lock and the config sidecar, held until dropped.
#[cfg(feature = "webui")]
pub(crate) struct ConfigHeld<'a> {
    _reload: tokio::sync::MutexGuard<'a, ()>,
    /// The sidecar, with the target it resolved.
    pub(crate) locked: crate::config_persistence::lock::Locked,
}

#[cfg(tp3)]
#[cfg(test)]
mod tests {
    use super::{ReloadRefusal, ReloadRefusalKind};
    use crate::config_reload::reload_context::replace::{RefusalClass, post_write_class};

    /// K3: oracle is Other with unchanged text; this control already passes.
    #[test]
    fn k3_string_is_other() {
        let refusal = ReloadRefusal::from("neutral canary".to_owned());
        assert_eq!(refusal.kind, ReloadRefusalKind::Other);
        assert_eq!(refusal.text, "neutral canary");
    }

    /// K5: red oracle is Posture even when the text supplies no posture hint.
    #[test]
    fn k5_posture_kind_with_neutral_text() {
        let refusal = ReloadRefusal {
            kind: ReloadRefusalKind::Posture,
            text: "neutral".into(),
            waiting: Vec::new(),
        };
        assert_eq!(post_write_class(&refusal), RefusalClass::Posture);
    }

    /// K5: oracle is Internal despite posture-looking text; the stub passes.
    #[test]
    fn k5_other_kind_with_posture_text() {
        let refusal = ReloadRefusal {
            kind: ReloadRefusalKind::Other,
            text: format!(
                "{} refusing to serve HTTP",
                crate::config_reload::POSTURE_REFUSED_PREFIX
            ),
            waiting: Vec::new(),
        };
        assert_eq!(post_write_class(&refusal), RefusalClass::Internal);
    }

    /// R5: a status change that surfaces only at the reload after a `Refuse`
    /// write was rolled back, so it is not kept and is no restart-pending
    /// answer: the internal class, as kind `Other` is.
    #[test]
    fn r5_a_post_write_status_change_is_internal() {
        let refusal = ReloadRefusal {
            kind: ReloadRefusalKind::StatusChange,
            text: "neutral".into(),
            waiting: vec!["first".into()],
        };
        assert_eq!(post_write_class(&refusal), RefusalClass::Internal);
    }

    /// K5: red oracle is `ShuttingDown` for the shared shutdown literal.
    #[test]
    fn k5_other_kind_with_shutdown_text() {
        let refusal = ReloadRefusal {
            kind: ReloadRefusalKind::Other,
            text: crate::config_reload::SHUTDOWN_ABORTED_ERROR.to_owned(),
            waiting: Vec::new(),
        };
        assert_eq!(post_write_class(&refusal), RefusalClass::ShuttingDown);
    }
}
