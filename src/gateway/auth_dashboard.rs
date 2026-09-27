// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard bootstrap value and the browser sessions it opens.
// Red commit only: the stubs have no production caller yet.
#![cfg_attr(not(test), allow(dead_code))]

use std::time::{Duration, Instant, SystemTime};

/// A one-time value that exchanges for a dashboard session.
///
/// Printed by `serve` as part of a link. It is NOT the admin credential: the
/// link's query string reaches this gateway's own request log, so putting the
/// real token there would leak it into a file that outlives the browser tab.
/// This value is single-use and dies with the process.
#[derive(Debug)]
pub struct DashboardBootstrap {
    value: std::sync::Mutex<Option<String>>,
    /// Opaque handles issued to browsers, valid for this process only.
    sessions: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl DashboardBootstrap {
    /// Mint an opaque session for a browser that presented the bootstrap value.
    ///
    /// The cookie carries THIS, never the admin credential. A bearer token in a
    /// cookie is long-lived and, without TLS, recoverable from the wire; an
    /// opaque handle is meaningless anywhere but this process and expires with
    /// it. Kept in memory: a dashboard session is not worth persisting, and
    /// nothing on disk means nothing to steal from disk.
    pub fn issue_session(&self) -> String {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        let handle =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(handle.clone());
        }
        handle
    }

    /// `true` when this handle was issued by this process and is still valid.
    #[must_use]
    pub fn session_is_valid(&self, handle: &str) -> bool {
        self.sessions
            .lock()
            .is_ok_and(|sessions| sessions.contains(handle))
    }

    /// Mint a fresh single-use value.
    #[must_use]
    pub fn new() -> Self {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        let value =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
        Self {
            value: std::sync::Mutex::new(Some(value)),
            sessions: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// The value to print, while it remains unused.
    #[must_use]
    pub fn peek(&self) -> Option<String> {
        self.value.lock().ok().and_then(|v| v.clone())
    }

    /// Consume the value if it matches. Single use: a second attempt fails even
    /// with the right value, so a link left in a shell history is spent.
    #[must_use]
    pub fn consume(&self, candidate: &str) -> bool {
        let Ok(mut guard) = self.value.lock() else {
            return false;
        };
        match guard.as_deref() {
            Some(expected) if expected == candidate => {
                *guard = None;
                true
            }
            _ => false,
        }
    }

    /// Mint a session at `now`, sweeping entries already past `limits`.
    pub(crate) fn issue_session_at(&self, _now: Now, _limits: &SessionLimits) -> String {
        self.issue_session()
    }

    /// Whether `handle` is a live session at `now`.
    pub(crate) fn check_session(
        &self,
        handle: &str,
        _now: Now,
        _limits: &SessionLimits,
        _touch: Touch,
    ) -> SessionCheck {
        if self.session_is_valid(handle) {
            SessionCheck::Valid
        } else {
            SessionCheck::Unknown
        }
    }

    /// End the session `handle`; `true` when it existed.
    pub(crate) fn revoke(&self, _handle: &str) -> bool {
        false
    }

    /// Replace any unused bootstrap value with a fresh one and return it.
    pub(crate) fn rearm(&self) -> String {
        String::new()
    }

    /// Test seam: move both clocks of `handle` back by `by`.
    #[cfg(test)]
    pub(crate) fn backdate(&self, _handle: &str, _by: Duration) {}

    /// Test seam: how many sessions the store holds.
    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.lock().map_or(0, |s| s.len())
    }
}

/// How long a dashboard session may live, read from the live config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionLimits {
    /// Longest gap between two activity checks.
    pub(crate) idle: Duration,
    /// Longest life from issue.
    pub(crate) absolute: Duration,
}

impl From<&crate::config::DashboardSessionConfig> for SessionLimits {
    fn from(config: &crate::config::DashboardSessionConfig) -> Self {
        Self {
            idle: Duration::from_secs(config.idle_timeout_secs),
            absolute: Duration::from_secs(config.absolute_timeout_secs),
        }
    }
}

/// One reading of both clocks.
///
/// `Instant` never steps backwards but stops while the host is suspended;
/// `SystemTime` keeps counting through suspend but can be stepped. A session
/// is judged by both, so neither failure can extend it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Now {
    pub(crate) mono: Instant,
    pub(crate) wall: SystemTime,
}

impl Now {
    /// Both clocks, read now.
    pub(crate) fn read() -> Self {
        Self {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

/// Whether a check counts as operator activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Touch {
    /// Operator activity: a valid check restarts the idle clock.
    Yes,
    /// A background refresh or a delivery re-check: checked, never extended.
    No,
}

/// The answer for one presented session handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionCheck {
    /// Issued here and within both limits.
    Valid,
    /// Issued here but past a limit; removed by this check.
    Expired,
    /// Never issued here, already removed, or from before a restart.
    Unknown,
}

impl Default for DashboardBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "auth_dashboard_tests.rs"]
mod tests;
