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
        ReloadTrigger::Retry(_) => {
            tracing::debug!("Config watcher: the last reload failed, retrying it");
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
/// What one poll reads: the first recorded path that differs.
type PollRead = fn(&EnvOverlay, &[PathBuf]) -> Option<PathBuf>;

pub(super) struct EnvPoller {
    env: Arc<LiveEnv>,
    reloads: Arc<EnvReloadCounts>,
    /// The config the gateway was started with, named in a retry.
    config: PathBuf,
    /// A read that has not finished yet, awaited again on the next tick
    /// instead of starting another.
    pending: Option<tokio::sync::oneshot::Receiver<Option<PathBuf>>>,
    /// Whether the pending read has already been warned about.
    stalled: bool,
    read: PollRead,
    /// Ticks started, for tests that count loop iterations.
    #[cfg(all(test, target_os = "linux"))]
    ticks: Arc<std::sync::atomic::AtomicUsize>,
}

impl EnvPoller {
    pub(super) fn new(env: Arc<LiveEnv>, reloads: Arc<EnvReloadCounts>, config: PathBuf) -> Self {
        Self {
            env,
            reloads,
            config,
            pending: None,
            stalled: false,
            read: env_poll,
            #[cfg(all(test, target_os = "linux"))]
            ticks: Arc::default(),
        }
    }

    /// A handle on the count of ticks started.
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn ticks(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.ticks)
    }

    /// Replace the read, so a test can make it stall.
    #[cfg(test)]
    pub(super) fn with_read(mut self, read: PollRead) -> Self {
        self.read = read;
        self
    }

    /// The reload to trigger this tick, if any. Waits at most `wait` for the
    /// read, so the caller always gets back to its shutdown check.
    pub(super) async fn tick(&mut self, wait: std::time::Duration) -> Option<ReloadTrigger> {
        #[cfg(all(test, target_os = "linux"))]
        self.ticks.fetch_add(1, Ordering::SeqCst);
        if self.pending.is_none() && self.env.env_paths().as_paths().is_empty() {
            // No env files, the default: nothing to read, so no thread.
            return self
                .reloads
                .failed
                .load(Ordering::SeqCst)
                .then(|| ReloadTrigger::Retry(self.config.clone()));
        }
        let mut read = if let Some(read) = self.pending.take() {
            read
        } else {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let (applied, paths) = (self.env.get(), self.env.env_paths().as_paths().to_vec());
            let poll = self.read;
            // A detached thread, not `spawn_blocking`: a read stalled on NFS
            // or FUSE must not hold the runtime's shutdown, which waits for
            // blocking tasks.
            std::thread::Builder::new()
                .name("env-poll".into())
                .spawn(move || {
                    let _ = tx.send(poll(&applied, &paths));
                })
                .ok()?;
            rx
        };
        let Ok(result) = tokio::time::timeout(wait, &mut read).await else {
            // Still reading: check the same read again next tick. Warned once
            // per stall, because env-file changes go unseen until it ends.
            if !self.stalled {
                tracing::warn!(
                    "Config watcher: an env-file read has not finished; env-file changes are \
                     not detected until it does"
                );
            }
            self.stalled = true;
            self.pending = Some(read);
            return None;
        };
        self.stalled = false;
        let differs = result.unwrap_or_else(|_| {
            tracing::warn!("Config watcher: an env-file read ended without a result");
            None
        });
        match differs {
            Some(path) => Some(ReloadTrigger::EnvFile(path)),
            // A failed reload may have carried a valid config edit that no
            // later change will trigger again (the env file was put back):
            // retry every tick until one succeeds.
            None if self.reloads.failed.load(Ordering::SeqCst) => {
                Some(ReloadTrigger::Retry(self.config.clone()))
            }
            None => None,
        }
    }
}

/// Log an identity-grants read error at ERROR once per minute per distinct
/// error, else at DEBUG: a failed config reload is retried every poll and
/// re-reads the grants file each time.
pub(super) fn report_grants_refusal(
    limiter: &parking_lot::Mutex<WarnLimiter>,
    path: &Path,
    reason: &str,
) {
    if limiter.lock().should_warn(path, reason, Instant::now()) {
        tracing::error!(
            path = %path.display(),
            %reason,
            "Identity-grant reload refused; the live grants still apply"
        );
    } else {
        tracing::debug!(%reason, "Identity-grant reload still refused");
    }
}

/// Log that the grants reload lock was busy, throttled like a read error:
/// every retried config reload tries the grants reload first.
pub(super) fn report_grants_busy(limiter: &parking_lot::Mutex<WarnLimiter>, path: &Path) {
    if limiter.lock().should_warn(path, "busy", Instant::now()) {
        tracing::error!(path = %path.display(), "Identity-grant reload busy");
    } else {
        tracing::debug!("Identity-grant reload still busy");
    }
}

/// Rate-limits the warning for an env-file reload that keeps failing: per
/// path, a warning only when that path's error changed or `WARN_EVERY` passed.
#[derive(Debug, Default)]
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
    /// Whether the last reload failed.
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }

    /// Record how a reload ended. A success clears every path's warning
    /// state, so a failure that comes back is warned about at once.
    ///
    /// A config-file failure is recorded under `config`, the key its retries
    /// use, so the first retry does not repeat the warning it already logged.
    pub(super) fn settled(
        &self,
        limiter: &mut WarnLimiter,
        error: Option<&str>,
        trigger: &ReloadTrigger,
        config: &Path,
    ) {
        self.failed.store(error.is_some(), Ordering::SeqCst);
        match (error, trigger) {
            (None, _) => *limiter = WarnLimiter::default(),
            (Some(error), ReloadTrigger::ConfigFile) => {
                let _ = (config, error);
            }
            (Some(_), _) => {}
        }
    }

    /// Count a reload that an `EnvFile` trigger started.
    pub(super) fn count_attempt(&self, trigger: &ReloadTrigger) {
        if matches!(trigger, ReloadTrigger::EnvFile(_)) {
            self.attempts.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Log a reload the poll started (an env-file change or a retry) that
    /// failed: warn when `limiter` allows for that path, else debug. A
    /// posture refusal keeps its own wording (a decision about the config,
    /// not a file to fix) but is throttled like any other retried failure.
    pub(super) fn report_failure(
        &self,
        limiter: &mut WarnLimiter,
        trigger: &ReloadTrigger,
        error: &str,
    ) {
        let (ReloadTrigger::EnvFile(path) | ReloadTrigger::Retry(path)) = trigger else {
            return;
        };
        if !limiter.should_warn(path, error, Instant::now()) {
            tracing::debug!(
                path = %path.display(),
                error = %error,
                "Config reload: still failing"
            );
            return;
        }
        self.warns.fetch_add(1, Ordering::SeqCst);
        if super::is_posture_refusal(error) {
            tracing::warn!(path = %path.display(), "Config reload: {error}");
        } else {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "Config reload: failed; keeping the current config and retrying every poll"
            );
        }
    }
}

#[cfg(test)]
#[path = "env_poll_tests.rs"]
mod tests;
