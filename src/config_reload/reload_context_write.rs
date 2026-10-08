// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config write half of [`ReloadContext`]: write or mutate `gateway.yaml`,
//! then reload, all under the reload lock (moved from `reload_context.rs`).

use std::time::{Duration, Instant};

use crate::config::Config;
use crate::config_persistence::CommentLoss;
use crate::config_persistence::lock::lock_config;
use crate::config_reload::{
    ConfigMutation, ConfigWriteError, MutateError, RELOAD_LOCK_WAIT, ReloadOutcome,
};

use super::ReloadContext;

impl ReloadContext {
    /// Write `config` to `path`, then reload, with both steps under one lock.
    ///
    /// Waits [`RELOAD_LOCK_WAIT`] for the reload lock. See
    /// [`Self::write_and_reload_outcome_within`] for why the wait is bounded.
    ///
    /// # Errors
    ///
    /// [`ConfigWriteError::Busy`] when the lock did not come free in time, and
    /// [`ConfigWriteError::Failed`] on validation, serialization, write,
    /// rename, or reload failure.
    ///
    /// The write must be inside the same critical section as the reload. Two
    /// admin UI edits that write first and lock second can interleave so that
    /// one reload reads the other's file, and the caller is told its own edit
    /// was applied. Holding one guard across write-read-apply-publish is what
    /// makes an edit's own bytes the ones it reloads.
    pub async fn write_and_reload_outcome(
        &self,
        path: &std::path::Path,
        config: &Config,
    ) -> std::result::Result<ReloadOutcome, ConfigWriteError> {
        self.write_and_reload_outcome_within(path, RELOAD_LOCK_WAIT, config)
            .await
    }

    /// [`Self::write_and_reload_outcome`] with an explicit bound on the wait.
    ///
    /// The bound is a parameter so a test can prove the busy path without
    /// spending the production wait in wall-clock time.
    ///
    /// # Errors
    ///
    /// As [`Self::write_and_reload_outcome`].
    pub async fn write_and_reload_outcome_within(
        &self,
        path: &std::path::Path,
        wait: Duration,
        config: &Config,
    ) -> std::result::Result<ReloadOutcome, ConfigWriteError> {
        // One deadline for both locks: the in-process reload lock, then the
        // cross-process config lock, both held through the reload.
        let deadline = Instant::now() + wait;
        let _reload_guard = self.lock_reload_within(wait).await?;
        let held = lock_config(path, deadline).await?;
        crate::config_persistence::write_config_with(path, config, CommentLoss::Rewrite, &held)
            .map_err(|e| ConfigWriteError::from(MutateError::from(e)))?;
        self.reload_outcome_locked()
            .await
            .map_err(|e| ConfigWriteError::Failed(format!("Config written but reload failed: {e}")))
    }

    /// Read the config, apply `mutate`, write, and reload, all under one guard.
    ///
    /// The read belongs inside the guard. Two admin UI edits that each read the
    /// file before locking will each build their change on the same starting
    /// copy, and whichever writes second erases the other's change while
    /// telling its caller the edit was saved.
    ///
    /// Waits [`RELOAD_LOCK_WAIT`] for the reload lock. See
    /// [`Self::mutate_and_reload_outcome_within`] for why the wait is bounded.
    ///
    /// # Errors
    ///
    /// [`ConfigWriteError::Busy`] when the lock did not come free in time, and
    /// [`ConfigWriteError::Failed`] on load, write, rename, or reload failure. A
    /// refusal from `mutate` is not an error; it comes back as
    /// [`ConfigMutation::Rejected`].
    pub async fn mutate_and_reload_outcome<T, E, F>(
        &self,
        path: &std::path::Path,
        mutate: F,
    ) -> std::result::Result<ConfigMutation<T, E>, ConfigWriteError>
    where
        F: FnOnce(&mut Config) -> std::result::Result<T, E>,
    {
        self.mutate_and_reload_outcome_within(path, RELOAD_LOCK_WAIT, mutate)
            .await
    }

    /// [`Self::mutate_and_reload_outcome`] with an explicit bound on the wait.
    ///
    /// # Errors
    ///
    /// As [`Self::mutate_and_reload_outcome`].
    pub async fn mutate_and_reload_outcome_within<T, E, F>(
        &self,
        path: &std::path::Path,
        wait: Duration,
        mutate: F,
    ) -> std::result::Result<ConfigMutation<T, E>, ConfigWriteError>
    where
        F: FnOnce(&mut Config) -> std::result::Result<T, E>,
    {
        self.mutate_locked(path, wait, CommentLoss::Rewrite, mutate)
            .await
            .map_err(Into::into)
    }

    /// [`Self::mutate_and_reload_outcome_within`] in `mode` for a write that
    /// would drop comments.
    pub(crate) async fn mutate_locked<T, E, F>(
        &self,
        path: &std::path::Path,
        wait: Duration,
        mode: CommentLoss,
        mutate: F,
    ) -> std::result::Result<ConfigMutation<T, E>, crate::config_reload::write::MutateError>
    where
        F: FnOnce(&mut Config) -> std::result::Result<T, E>,
    {
        let deadline = Instant::now() + wait;
        let _reload_guard = self.lock_reload_within(wait).await?;
        // The config lock is held from the load through the reload, so another
        // process's write can neither land between this load and this write
        // nor between this write and the reload that reads it back.
        // A file that does not load is refused before the config lock is
        // taken, so the refusal adds no lock file (GH462); it is loaded again
        // under the lock.
        crate::config_persistence::load_existing_or_default(path)
            .map_err(|e| crate::config_reload::write::load_failure(path, &e, mode))?;
        let held = lock_config(path, deadline)
            .await
            .map_err(ConfigWriteError::from)?;
        let mut config = crate::config_persistence::load_existing_or_default(path)
            .map_err(|e| crate::config_reload::write::load_failure(path, &e, mode))?;
        let value = match mutate(&mut config) {
            Ok(value) => value,
            Err(rejection) => return Ok(ConfigMutation::Rejected(rejection)),
        };
        // A write that changes nothing still reloads: a retry after a failed
        // reload finds its value on disk and must not leave the runtime stale.
        crate::config_persistence::write_config_with(path, &config, mode, &held)?;
        let outcome = self
            .reload_outcome_locked()
            .await
            .map_err(|e| crate::config_reload::write::reload_failure(&e, mode))?;
        Ok(ConfigMutation::Applied(value, Some(outcome)))
    }
}
