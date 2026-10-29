// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How [`ReloadContext`] takes the reload lock and loads gateway.yaml: the
//! bounded lock wait, the off-worker file load, the pinned reload and the
//! reload a lock recovery left owed (moved from `reload_context.rs`).

use std::sync::Arc;
use std::time::Duration;

use crate::config_reload::{ConfigWriteError, ReloadOutcome};

use super::{EvaluatedReload, ReloadContext, STOPPED};

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
    ) -> std::result::Result<ReloadOutcome, String> {
        // Audits the overrides the registry holds however this ends: applied,
        // refused, or dropped at an await after registering backends.
        let _audit = (self.reporting.override_audit.as_deref()).map(|a| a.guard(&self.registry));
        let outcome = self.reload_transaction(path).await;
        let refusals = &self.reporting.refusals;
        match &outcome {
            Ok(_) => {
                self.reload_owed
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                refusals.reload_applied();
                self.reporting.tally.applied();
            }
            Err(refusal) => {
                refusals.record(
                    crate::config_reload::refusals::RefusalKind::Reload,
                    None,
                    refusal,
                );
                self.reporting.tally.refused();
            }
        }
        outcome
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
            && let Err(error) = self.reload_outcome_locked_at(target).await
        {
            tracing::warn!(%error, path = %target.display(), "the reload owed after restoring gateway.yaml failed; it is retried on the next one");
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
