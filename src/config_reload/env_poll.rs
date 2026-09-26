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
use std::time::{Duration, Instant};

use crate::config::EnvOverlay;

/// How often the recorded env files are read and compared.
pub(super) const ENV_POLL: Duration = Duration::from_secs(2);

/// How long the reload task waits after the last trigger before reloading.
/// Every trigger restarts it.
pub(super) const DEBOUNCE: Duration = Duration::from_millis(500);

/// How often the reload task checks whether the debounce has elapsed.
pub(super) const RELOAD_TICK: Duration = Duration::from_millis(100);

/// The poll interval the end-to-end tests inject.
#[cfg(test)]
pub(super) const TEST_ENV_POLL: Duration = Duration::from_millis(700);

/// How long a path's repeated, unchanged reload error stays at debug.
const WARN_EVERY: Duration = Duration::from_secs(60);

/// The first recorded env file whose content differs from what `applied` was
/// built from, in `paths` order.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "red-first stub; the fix wires it in")
)]
pub(super) fn env_poll(applied: &EnvOverlay, paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|p| applied.differs_on_disk(p)).cloned()
}

/// Rate-limits the warning for an env-file reload that keeps failing: per
/// path, a warning only when that path's error changed or `WARN_EVERY` passed.
#[derive(Default)]
pub(super) struct WarnLimiter {
    last: BTreeMap<PathBuf, (String, Instant)>,
}

impl WarnLimiter {
    /// Whether this failure of `path` should be logged at warn (else debug).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "red-first stub; the fix wires it in")
    )]
    pub(super) fn should_warn(&mut self, _path: &Path, _error: &str, _now: Instant) -> bool {
        let _ = (&self.last, WARN_EVERY);
        true
    }
}

/// Env-file reloads the reload task ran and warned about, counted where it
/// runs them so a test sees attempts rather than coalesced triggers.
#[derive(Default)]
pub(super) struct EnvReloadCounts {
    pub(super) attempts: std::sync::atomic::AtomicUsize,
    #[cfg_attr(
        not(all(test, target_os = "linux")),
        expect(dead_code, reason = "red-first stub; the fix wires it in")
    )]
    pub(super) warns: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
#[path = "env_poll_tests.rs"]
mod tests;
