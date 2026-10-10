// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard bootstrap value and the browser sessions it opens.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// A one-time value that exchanges for a dashboard session.
///
/// Printed by `serve` as part of a link. It is NOT the admin credential: the
/// link's query string reaches this gateway's own request log, so putting the
/// real token there would leak it into a file that outlives the browser tab.
/// This value is single-use and dies with the process.
#[derive(Debug)]
pub struct DashboardBootstrap {
    /// The unused value, and the wall-clock time a session it opens must end
    /// by: the expiry of the credential that minted it, when that has one.
    value: Mutex<Option<(String, Option<SystemTime>)>>,
    /// The port the listener bound, 0 until known: `server.port: 0` asks the
    /// OS for one, and a link must name the real one.
    bound_port: AtomicU16,
    /// Opaque handles issued to browsers, valid for this process only, with
    /// when each was issued and last used. `ponytail:` one mutex over the map;
    /// a dashboard has a handful of sessions, not thousands.
    sessions: Mutex<HashMap<String, SessionTimes>>,
    /// The code a loopback redemption hands to the public origin (#2130), while
    /// unused: at most one, since the bootstrap value it comes from is single use.
    #[cfg(feature = "webui")]
    handoff: Mutex<Option<Handoff>>,
}

/// How long a handoff code may wait to be entered on the public origin.
#[cfg(feature = "webui")]
pub(crate) const HANDOFF_TTL: Duration = Duration::from_secs(60);

/// A one-time code minted by a loopback redemption, carrying that redemption's
/// credential cap to the session it opens.
#[cfg(feature = "webui")]
#[derive(Debug)]
struct Handoff {
    value: String,
    minted: Now,
    cap: Option<SystemTime>,
}

/// A redeemed bootstrap value: when the session it opens must end by, if the
/// credential that minted it expires.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Redemption {
    pub(crate) not_after: Option<SystemTime>,
    /// The clocks the redemption was checked against, which the session or
    /// code it yields is issued at: a second read could land on a clock that
    /// stepped before 1970 in between (MIK-8202).
    pub(crate) now: Now,
}

/// When a session was issued and when it last saw operator activity.
#[derive(Debug, Clone, Copy)]
struct SessionTimes {
    issued: Now,
    last_seen: Now,
    /// Ends here even inside the limits: the minting credential's expiry.
    not_after: Option<SystemTime>,
}

impl SessionTimes {
    /// Past the idle or the absolute limit by either clock, past the cap, or
    /// judged on a wall clock that reads before 1970.
    fn expired(&self, now: Now, limits: &SessionLimits) -> bool {
        wall_unreadable(now)
            || exceeds(self.last_seen, now, limits.idle)
            || exceeds(self.issued, now, limits.absolute)
            || self.not_after.is_some_and(|cap| cap_reached(now, cap))
    }
}

/// A wall clock before 1970 refuses every dashboard credential (MIK-8202):
/// without it a session would rest on the monotonic clock alone, which stops
/// while the host sleeps, so a suspend would outlive the idle limit.
fn wall_unreadable(now: Now) -> bool {
    now.wall.duration_since(std::time::UNIX_EPOCH).is_err()
}

/// Whether `now` is at or past the minting credential's expiry `cap`. A wall
/// clock reading before 1970 cannot be placed against a real expiry, so the
/// cap counts as reached (MIK-8202); the monotonic limits are unchanged.
fn cap_reached(now: Now, cap: SystemTime) -> bool {
    now.wall.duration_since(std::time::UNIX_EPOCH).is_err() || now.wall >= cap
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
    mono > limit || wall > limit
}

impl DashboardBootstrap {
    /// Mint an opaque session for a browser that presented the bootstrap value.
    ///
    /// The cookie carries THIS, never the admin credential. A bearer token in a
    /// cookie is long-lived and, without TLS, recoverable from the wire; an
    /// opaque handle is meaningless anywhere but this process and expires with
    /// it. Kept in memory: a dashboard session is not worth persisting, and
    /// nothing on disk means nothing to steal from disk.
    #[cfg(test)]
    pub(crate) fn issue_session_at(&self, now: Now, limits: &SessionLimits) -> String {
        self.issue_session_until(now, limits, None)
    }

    /// A session that also ends at `not_after`, when a cap is given.
    pub(crate) fn issue_session_until(
        &self,
        now: Now,
        limits: &SessionLimits,
        not_after: Option<SystemTime>,
    ) -> String {
        let handle = random_value();
        if let Ok(mut sessions) = self.sessions.lock() {
            // Sweep on issue: the only way the map grows, so it is the one
            // place that has to shrink it.
            // Not on an unreadable wall clock: every session would read as
            // expired and be deleted (MIK-8202).
            if !wall_unreadable(now) {
                sessions.retain(|_, times| !times.expired(now, limits));
            }
            sessions.insert(
                handle.clone(),
                SessionTimes {
                    issued: now,
                    last_seen: now,
                    not_after,
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
            value: Mutex::new(Some((random_value(), None))),
            bound_port: AtomicU16::new(0),
            sessions: Mutex::new(HashMap::new()),
            #[cfg(feature = "webui")]
            handoff: Mutex::new(None),
        }
    }

    /// The value to print, while it remains unused.
    #[must_use]
    pub fn peek(&self) -> Option<String> {
        self.value
            .lock()
            .ok()
            .and_then(|v| v.as_ref().map(|(value, _)| value.clone()))
    }

    /// Consume the value if it matches. Single use: a second attempt fails even
    /// with the right value, so a link left in a shell history is spent. A
    /// burn, not a redemption: it issues nothing, so it spends the value
    /// whatever the clock reads (#1529: a copy presented from elsewhere must
    /// die on first use).
    #[must_use]
    pub fn consume(&self, candidate: &str) -> bool {
        self.take_matching(candidate).is_some()
    }

    /// Consume the value if it matches, returning the cap it was minted with.
    /// A wall clock before 1970 refuses it unspent: the session it would
    /// issue could not be dated, and the operator keeps a working link
    /// (MIK-8202).
    pub(crate) fn consume_capped(&self, candidate: &str) -> Option<Redemption> {
        let now = Now::read();
        if wall_unreadable(now) {
            tracing::warn!(
                "dashboard bootstrap refused: the host clock reads before 1970; the link is kept"
            );
            return None;
        }
        self.take_matching(candidate)
            .map(|(_, not_after)| Redemption { not_after, now })
    }

    /// Take the value and its cap if `candidate` matches it.
    fn take_matching(&self, candidate: &str) -> Option<(String, Option<SystemTime>)> {
        let mut guard = self.value.lock().ok()?;
        match guard.as_ref() {
            Some((expected, _)) if expected == candidate => guard.take(),
            _ => None,
        }
    }

    /// Whether some live session at `now` has a handle whose SHA-256 is
    /// `digest`: the delivery re-check of an events subscription made from a
    /// dashboard session (MIK-7769), which keeps only the digest. Never
    /// extends a session; a logout or expiry answers `false`.
    pub(crate) fn live_digest(&self, digest: &str, now: Now, limits: &SessionLimits) -> bool {
        let Ok(sessions) = self.sessions.lock() else {
            return false;
        };
        sessions.iter().any(|(handle, times)| {
            !times.expired(now, limits) && crate::hashing::sha256_hex(handle.as_bytes()) == digest
        })
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
        if wall_unreadable(now) {
            return SessionCheck::ClockUnreadable;
        }
        if times.expired(now, limits) {
            sessions.remove(handle);
            return SessionCheck::Expired;
        }
        if touch == Touch::Yes {
            times.last_seen = now;
        }
        SessionCheck::Valid
    }

    /// End the session `handle`; `true` only when it was live at `now`. An
    /// expired entry is removed too, but it ended at its limit, not here.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn revoke(&self, handle: &str, now: Now, limits: &SessionLimits) -> bool {
        self.sessions
            .lock()
            .ok()
            .and_then(|mut sessions| sessions.remove(handle))
            .is_some_and(|times| !times.expired(now, limits))
    }

    /// Replace any unused bootstrap value with a fresh one and return it.
    ///
    /// The old value dies here, so a link printed earlier and leaked since
    /// (scrollback, a shipped log) stops working the moment a new one exists.
    #[cfg(test)]
    pub(crate) fn rearm(&self) -> String {
        self.rearm_until(None)
    }

    /// Like [`Self::rearm`], with a wall-clock cap for the session it opens.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn rearm_until(&self, not_after: Option<SystemTime>) -> String {
        let fresh = random_value();
        if let Ok(mut value) = self.value.lock() {
            *value = Some((fresh.clone(), not_after));
        }
        fresh
    }

    /// Mint the code a loopback redemption shows, replacing any unused one. It
    /// carries `cap`, the redeemed link's credential cap, to the session.
    #[cfg(feature = "webui")]
    pub(crate) fn mint_handoff(&self, now: Now, cap: Option<SystemTime>) -> String {
        let value = random_value();
        if let Ok(mut slot) = self.handoff.lock() {
            *slot = Some(Handoff {
                value: value.clone(),
                minted: now,
                cap,
            });
        }
        value
    }

    /// Spend the handoff code if `candidate` is it, it is under
    /// [`HANDOFF_TTL`] old on both clocks, and its cap has not passed. A wrong
    /// value spends nothing: anyone could otherwise cancel an operator's
    /// sign-in. Compared in constant time; every code has the same length.
    #[cfg(feature = "webui")]
    pub(crate) fn take_handoff(&self, candidate: &str, now: Now) -> Option<Redemption> {
        use subtle::ConstantTimeEq as _;
        let mut slot = self.handoff.lock().ok()?;
        let (expired, matches) = {
            let live = slot.as_ref()?;
            (
                wall_unreadable(now)
                    || exceeds(live.minted, now, HANDOFF_TTL)
                    || live.cap.is_some_and(|cap| cap_reached(now, cap)),
                bool::from(live.value.as_bytes().ct_eq(candidate.as_bytes())),
            )
        };
        if expired {
            // An unreadable wall clock refuses the code but keeps it
            // (MIK-8202).
            if !wall_unreadable(now) {
                *slot = None;
            }
            return None;
        }
        if !matches {
            return None;
        }
        slot.take().map(|live| Redemption {
            not_after: live.cap,
            now,
        })
    }

    /// Test seam: move both clocks of the handoff code back by `by`.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) fn backdate_handoff(&self, by: Duration) {
        if let Ok(mut slot) = self.handoff.lock()
            && let Some(live) = slot.as_mut()
        {
            live.minted = Now {
                mono: live
                    .minted
                    .mono
                    .checked_sub(by)
                    .expect("backdate within the monotonic range"),
                wall: live.minted.wall - by,
            };
        }
    }

    /// Record the port the listener actually bound.
    pub(crate) fn set_bound_port(&self, port: u16) {
        self.bound_port.store(port, Ordering::Relaxed);
    }

    /// The port the listener actually bound, once known.
    pub(crate) fn bound_port(&self) -> Option<u16> {
        match self.bound_port.load(Ordering::Relaxed) {
            0 => None,
            port => Some(port),
        }
    }

    /// Test seam: move both clocks of `handle` back by `by`, the same as `by`
    /// passing with no activity.
    #[cfg(all(test, feature = "webui"))]
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
    /// Both clocks, read now. The wall clock comes through `crate::clock`
    /// (MIK-8202): one that reads before 1970 is kept as a time before the
    /// epoch, which `wall_unreadable` refuses, so a session is never judged
    /// against it.
    pub(crate) fn read() -> Self {
        Self {
            mono: Instant::now(),
            wall: crate::clock::system_time_or_before_epoch(),
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
    /// Not judged: the wall clock reads before 1970. Refused for now and
    /// kept, since it may be live once the clock reads (MIK-8202).
    ClockUnreadable,
}

impl Default for DashboardBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "auth_dashboard_tests.rs"]
mod tests;
