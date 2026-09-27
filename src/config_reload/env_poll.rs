// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Env files are polled by content, not watched (#1286).
//!
//! A watch on an env file's directory goes stale when a link in its path is
//! retargeted, and no event arrives on NFS or FUSE. Reading every recorded
//! path each tick and comparing it with what the live overlay was built from
//! has neither failure.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::ReloadTrigger;
use crate::config::{EnvOverlay, LiveEnv};

/// How often the recorded env files are read and compared.
pub(super) const ENV_POLL: Duration = Duration::from_secs(2);

/// How long the reload task waits after the last trigger before reloading.
/// Every trigger restarts it.
pub(super) const DEBOUNCE: Duration = Duration::from_millis(500);

/// How often the reload task checks whether the debounce has elapsed.
pub(super) const RELOAD_TICK: Duration = Duration::from_millis(100);

/// The poll interval tests run with: above `DEBOUNCE + RELOAD_TICK`, as every
/// poll interval must be, or each trigger restarts the debounce forever.
#[cfg(test)]
pub(super) const TEST_ENV_POLL: Duration = Duration::from_millis(700);

/// The interval the watcher polls at.
#[cfg(not(test))]
pub(super) const POLL_EVERY: Duration = ENV_POLL;
#[cfg(test)]
pub(super) const POLL_EVERY: Duration = TEST_ENV_POLL;

// Every poll interval must outlast the debounce, which restarts on each
// trigger: a faster poll would postpone the reload forever.
const _: () = assert!(ENV_POLL.as_millis() > DEBOUNCE.as_millis() + RELOAD_TICK.as_millis());

/// How long a path's repeated, unchanged reload error stays at debug.
const WARN_EVERY: Duration = Duration::from_secs(60);

/// The first recorded env file whose content differs from what `applied` was
/// built from, in `paths` order.
/// A failing file keeps differing, so it is retried every tick.
pub(super) fn env_poll(applied: &EnvOverlay, paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|p| applied.differs_on_disk(p)).cloned()
}

/// Log what triggered the pending reload. A failing env file re-triggers
/// every poll, so its trigger is logged at debug; the outcome is logged once
/// by [`report_reloaded`] or through the [`WarnLimiter`].
pub(super) fn log_trigger(trigger: &ReloadTrigger) {
    match trigger {
        ReloadTrigger::ConfigFile => {
            tracing::info!("Config watcher: config file changed, triggering reload");
        }
        ReloadTrigger::EnvFile(path) => {
            tracing::debug!(
                path = %path.display(),
                "Config watcher: env file differs from the loaded one, triggering reload"
            );
        }
    }
}

/// Log a reload an env-file change started and that succeeded.
pub(super) fn report_reloaded(path: &Path, outcome: &super::ReloadOutcome) {
    tracing::info!(
        path = %path.display(),
        changes = %outcome.changes,
        restart_required = outcome.restart_required,
        "Config reload: env file changed, reloaded"
    );
}

/// The poll's state between ticks.
pub(super) struct EnvPoller {
    env: Arc<LiveEnv>,
    reloads: Arc<EnvReloadCounts>,
    /// The last path that differed, kept until a tick finds none.
    last_differing: Option<PathBuf>,
}

impl EnvPoller {
    pub(super) fn new(env: Arc<LiveEnv>, reloads: Arc<EnvReloadCounts>) -> Self {
        Self {
            env,
            reloads,
            last_differing: None,
        }
    }

    /// The path to trigger a reload for this tick, if any.
    pub(super) async fn tick(&mut self) -> Option<PathBuf> {
        let applied = self.env.get();
        let paths = self.env.env_paths().as_paths().to_vec();
        // Off the async workers: on NFS or FUSE a read can stall.
        let differs = tokio::task::spawn_blocking(move || env_poll(&applied, &paths))
            .await
            .ok()
            .flatten();
        match differs {
            Some(path) => {
                self.last_differing = Some(path.clone());
                Some(path)
            }
            // The file is back at the loaded bytes, but the reload it caused
            // failed and may have carried a valid config edit: retry it once.
            None if self.reloads.failed.load(Ordering::SeqCst) => self.last_differing.take(),
            None => {
                self.last_differing = None;
                None
            }
        }
    }
}

/// Rate-limits the warning for an env-file reload that keeps failing: per
/// path, a warning only when that path's error changed or `WARN_EVERY` passed.
#[derive(Default)]
pub(super) struct WarnLimiter {
    last: BTreeMap<PathBuf, (String, Instant)>,
}

impl WarnLimiter {
    /// Whether this failure of `path` should be logged at warn (else debug).
    pub(super) fn should_warn(&mut self, path: &Path, error: &str, now: Instant) -> bool {
        let warn = self.last.get(path).is_none_or(|(last_error, at)| {
            last_error != error || now.duration_since(*at) >= WARN_EVERY
        });
        if warn {
            self.last
                .insert(path.to_path_buf(), (error.to_owned(), now));
        }
        warn
    }
}

/// Env-file reloads the reload task ran and warned about, counted where it
/// runs them so a test sees attempts rather than coalesced triggers.
#[derive(Default)]
pub(super) struct EnvReloadCounts {
    pub(super) attempts: std::sync::atomic::AtomicUsize,
    pub(super) warns: std::sync::atomic::AtomicUsize,
    /// Whether the last reload, whatever triggered it, failed.
    failed: std::sync::atomic::AtomicBool,
}

impl EnvReloadCounts {
    /// Record how a reload ended. A success clears every path's warning
    /// state, so a failure that comes back is warned about at once.
    pub(super) fn settled(&self, limiter: &mut WarnLimiter, ok: bool) {
        self.failed.store(!ok, Ordering::SeqCst);
        if ok {
            *limiter = WarnLimiter::default();
        }
    }

    /// Count a reload that an `EnvFile` trigger started.
    pub(super) fn count_attempt(&self, trigger: &ReloadTrigger) {
        if matches!(trigger, ReloadTrigger::EnvFile(_)) {
            self.attempts.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Log a failed env-file reload: warn when `limiter` allows, else debug.
    /// A posture refusal keeps its own wording (a decision about the config,
    /// not a file to fix) but is throttled like any other retried failure.
    pub(super) fn report_failure(
        &self,
        limiter: &mut WarnLimiter,
        path: &Path,
        error: &str,
        posture_refusal: bool,
    ) {
        if !limiter.should_warn(path, error, Instant::now()) {
            tracing::debug!(
                path = %path.display(),
                error = %error,
                "Config reload: env-file reload still failing"
            );
            return;
        }
        self.warns.fetch_add(1, Ordering::SeqCst);
        if posture_refusal {
            tracing::warn!(path = %path.display(), "Config reload: {error}");
        } else {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "Config reload: env file changed but the reload failed; \
                 keeping the current config and retrying every poll"
            );
        }
    }
}

#[cfg(test)]
#[path = "env_poll_tests.rs"]
mod tests;
