// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-file writes that reload the live gateway afterwards.

use std::path::Path;

use crate::config::Config;
use crate::config_persistence::{CommentLoss, Unwritten};

use super::{ReloadContext, ReloadOutcome};

/// Why a config write did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWriteError {
    /// Another reload or write held the reload lock for longer than this write
    /// was willing to wait. Nothing was read, written, or reloaded, so the same
    /// request can simply be retried.
    Busy,
    /// The write itself failed. The message describes which step.
    Failed(String),
}

impl std::fmt::Display for ConfigWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => write!(
                f,
                "the gateway is applying another config change; nothing was written, retry shortly"
            ),
            Self::Failed(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ConfigWriteError {}

impl From<String> for ConfigWriteError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

/// Serialize `config`, write it atomically, then trigger hot-reload when a
/// reload context is available.
///
/// Persistence is always authoritative for the on-disk file. Hot-reload then
/// applies only the subset of changes supported by [`ReloadContext`] (for
/// example, backend changes); server listener changes remain on disk until the
/// process is restarted.
///
/// # Errors
///
/// [`ConfigWriteError::Busy`] when a reload held the lock too long, and
/// [`ConfigWriteError::Failed`] on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> std::result::Result<(), ConfigWriteError> {
    write_config_and_reload_outcome(path, config, reload_context)
        .await
        .map(|_| ())
}

/// Serialize `config`, write it atomically, then return any hot-reload outcome.
///
/// # Errors
///
/// [`ConfigWriteError::Busy`] when a reload held the lock too long, and
/// [`ConfigWriteError::Failed`] on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload_outcome(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> std::result::Result<Option<ReloadOutcome>, ConfigWriteError> {
    if let Some(ctx) = reload_context {
        // Write and reload share one lock inside the context. Writing here
        // first would reopen the race the lock exists to close.
        return ctx.write_and_reload_outcome(path, config).await.map(Some);
    }

    crate::config_persistence::write_config(path, config)?;
    Ok(None)
}

/// What a guarded read-modify-write did: either the change was applied and
/// persisted, or the caller's own check rejected it and nothing was written.
pub enum ConfigMutation<T, E> {
    /// The change was applied, persisted, and (when a reload context exists)
    /// reloaded.
    Applied(T, Option<ReloadOutcome>),
    /// The caller's closure refused the change. The file is untouched.
    Rejected(E),
}

/// Read the config, apply `mutate` to it, and persist the result without
/// letting another writer slip in between the read and the write.
///
/// Reading outside the lock is what makes edits vanish: two requests each read
/// the same starting file, each apply their own change to that stale copy, and
/// the second write erases the first change while reporting success. Doing the
/// read inside the same critical section as the write is what stops it.
///
/// # Errors
///
/// [`ConfigWriteError::Busy`] when a reload held the lock too long, and
/// [`ConfigWriteError::Failed`] on load, validation, write, rename, or reload failure.
/// A refusal from `mutate` is not an error; it comes back as
/// [`ConfigMutation::Rejected`] with the file untouched.
pub async fn mutate_config_and_reload<T, E, F>(
    path: &Path,
    reload_context: Option<&ReloadContext>,
    mutate: F,
) -> std::result::Result<ConfigMutation<T, E>, ConfigWriteError>
where
    F: FnOnce(&mut Config) -> std::result::Result<T, E>,
{
    mutate_config_and_reload_with(path, reload_context, CommentLoss::Rewrite, mutate)
        .await
        .map_err(Into::into)
}

/// [`mutate_config_and_reload`] in `mode`: the web UI refuses a write that
/// would drop the file's comments, and a write that changes nothing writes
/// and reloads nothing.
pub(crate) async fn mutate_config_and_reload_with<T, E, F>(
    path: &Path,
    reload_context: Option<&ReloadContext>,
    mode: CommentLoss,
    mutate: F,
) -> std::result::Result<ConfigMutation<T, E>, Unwritten>
where
    F: FnOnce(&mut Config) -> std::result::Result<T, E>,
{
    if let Some(ctx) = reload_context {
        return ctx
            .mutate_locked(path, super::RELOAD_LOCK_WAIT, mode, mutate)
            .await;
    }

    // No live gateway to reload, so no reload lock exists to hold. This path is
    // the CLI acting on a config file nothing else is serving.
    let mut config = crate::config_persistence::load_existing_or_default(path)
        .map_err(|e| format!("Failed to load {}: {e}", path.display()))?;
    match mutate(&mut config) {
        Ok(value) => {
            crate::config_persistence::write_config_with(path, &config, mode)?;
            Ok(ConfigMutation::Applied(value, None))
        }
        Err(rejection) => Ok(ConfigMutation::Rejected(rejection)),
    }
}
