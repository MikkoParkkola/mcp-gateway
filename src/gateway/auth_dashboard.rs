// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard bootstrap value and the browser sessions it opens.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// A one-time value that exchanges for a dashboard session.
///
/// Printed by `serve` as part of a link. It is NOT the admin credential: the
/// link's query string reaches this gateway's own request log, so putting the
/// real token there would leak it into a file that outlives the browser tab.
/// This value is single-use and dies with the process.
#[derive(Debug)]
pub struct DashboardBootstrap {
    value: Mutex<Option<String>>,
    /// Opaque handles issued to browsers, valid for this process only, with
    /// when each was issued and last used. `ponytail:` one mutex over the map;
    /// a dashboard has a handful of sessions, not thousands.
    sessions: Mutex<HashMap<String, SessionTimes>>,
}

/// When a session was issued and when it last saw operator activity.
#[derive(Debug, Clone, Copy)]
struct SessionTimes {
    issued: Now,
    last_seen: Now,
}

impl SessionTimes {
    /// Past the idle or the absolute limit, by either clock.
    fn expired(&self, now: Now, limits: &SessionLimits) -> bool {
        exceeds(self.last_seen, now, limits.idle) || exceeds(self.issued, now, limits.absolute)
    }
}

/// `true` when more than `limit` separates `since` from `now` on EITHER clock.
///
/// The monotonic clock stops while the host sleeps, so it alone would let a
/// laptop wake overnight to a live session; the wall clock can be stepped, so
/// it alone would let a backward step extend one. A wall clock that reads
/// earlier than `since` counts as no time passed, and the monotonic clock
/// still decides.
fn exceeds(since: Now, now: Now, limit: Duration) -> bool {
    let mono = now.mono.saturating_duration_since(since.mono);
    let wall = now.wall.duration_since(since.wall).unwrap_or_default();
    let _ = wall;
    mono > limit
}

impl DashboardBootstrap {
    /// Mint an opaque session for a browser that presented the bootstrap value.
    ///
    /// The cookie carries THIS, never the admin credential. A bearer token in a
    /// cookie is long-lived and, without TLS, recoverable from the wire; an
    /// opaque handle is meaningless anywhere but this process and expires with
    /// it. Kept in memory: a dashboard session is not worth persisting, and
    /// nothing on disk means nothing to steal from disk.
    pub(crate) fn issue_session_at(&self, now: Now, limits: &SessionLimits) -> String {
        let handle = random_value();
        if let Ok(mut sessions) = self.sessions.lock() {
            // Sweep on issue: the only way the map grows, so it is the one
            // place that has to shrink it.
            sessions.retain(|_, times| !times.expired(now, limits));
            sessions.insert(
                handle.clone(),
                SessionTimes {
                    issued: now,
                    last_seen: now,
                },
            );
        }
        handle
    }

    /// A session issued now under the default limits. Test fixtures only.
    #[cfg(test)]
    pub fn issue_session(&self) -> String {
        self.issue_session_at(Now::read(), &SessionLimits::default())
    }

    /// `true` when `handle` is live now under the default limits, without
    /// counting as activity. Test fixtures only.
    #[cfg(test)]
    #[must_use]
    pub fn session_is_valid(&self, handle: &str) -> bool {
        self.check_session(handle, Now::read(), &SessionLimits::default(), Touch::No)
            == SessionCheck::Valid
    }

    /// Mint a fresh single-use value.
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: Mutex::new(Some(random_value())),
            sessions: Mutex::new(HashMap::new()),
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

    /// Whether `handle` is a live session at `now`.
    ///
    /// An expired handle is removed by the check that finds it. `Touch::Yes`
    /// restarts the idle clock of a valid session; `Touch::No` checks without
    /// extending, for background refreshes and delivery re-checks.
    pub(crate) fn check_session(
        &self,
        handle: &str,
        now: Now,
        limits: &SessionLimits,
        touch: Touch,
    ) -> SessionCheck {
        let Ok(mut sessions) = self.sessions.lock() else {
            return SessionCheck::Unknown;
        };
        let Some(times) = sessions.get_mut(handle) else {
            return SessionCheck::Unknown;
        };
        if times.expired(now, limits) {
            sessions.remove(handle);
            return SessionCheck::Expired;
        }
        if touch == Touch::Yes {
            times.last_seen = now;
        }
        SessionCheck::Valid
    }

    /// End the session `handle`; `true` when it existed.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn revoke(&self, handle: &str) -> bool {
        self.sessions
            .lock()
            .is_ok_and(|mut sessions| sessions.remove(handle).is_some())
    }

    /// Replace any unused bootstrap value with a fresh one and return it.
    ///
    /// The old value dies here, so a link printed earlier and leaked since
    /// (scrollback, a shipped log) stops working the moment a new one exists.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn rearm(&self) -> String {
        let fresh = random_value();
        if let Ok(mut value) = self.value.lock() {
            *value = Some(fresh.clone());
        }
        fresh
    }

    /// Test seam: move both clocks of `handle` back by `by`, the same as `by`
    /// passing with no activity.
    #[cfg(test)]
    pub(crate) fn backdate(&self, handle: &str, by: Duration) {
        let back = |t: Now| Now {
            mono: t
                .mono
                .checked_sub(by)
                .expect("backdate within the monotonic range"),
            wall: t.wall - by,
        };
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(times) = sessions.get_mut(handle)
        {
            times.issued = back(times.issued);
            times.last_seen = back(times.last_seen);
        }
    }

    /// Test seam: how many sessions the store holds.
    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.lock().map_or(0, |s| s.len())
    }
}

/// 32 random bytes, base64url: a bootstrap value or a session handle.
fn random_value() -> String {
    use rand::RngExt;
    let bytes: [u8; 32] = rand::rng().random();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// How long a dashboard session may live, read from the live config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionLimits {
    /// Longest gap between two activity checks.
    pub(crate) idle: Duration,
    /// Longest life from issue.
    pub(crate) absolute: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self::from(&crate::config::DashboardSessionConfig::default())
    }
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
