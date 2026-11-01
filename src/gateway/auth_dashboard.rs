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
    value: Mutex<Option<(Secret, Bound)>>,
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
    /// The UI live stream's caps and shared watcher: one per gateway, and it
    /// lives here because every gateway builds exactly one of these.
    #[cfg(feature = "webui")]
    stream: crate::gateway::ui::stream::StreamHub,
}

/// How long a handoff code may wait to be entered on the public origin.
#[cfg(feature = "webui")]
pub(crate) const HANDOFF_TTL: Duration = Duration::from_secs(60);

/// A one-time code minted by a loopback redemption, carrying that redemption's
/// credential cap to the session it opens.
#[cfg(feature = "webui")]
#[derive(Debug)]
struct Handoff {
    value: Secret,
    minted: Now,
    cap: Bound,
}

/// What a link, a handoff code and the session they open stay bound to: the
/// minting credential's expiry, and the API key that minted it, by its quota
/// identity. `key` is `None` for the bearer and the startup link, which are
/// bearer-class by design (K13).
#[derive(Debug, Clone, Default)]
pub(crate) struct Bound {
    pub(crate) not_after: Option<SystemTime>,
    pub(crate) key: Option<crate::gateway::auth::QuotaPrincipal>,
}

impl Bound {
    /// Bound by an expiry alone.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn until(not_after: Option<SystemTime>) -> Self {
        Self {
            not_after,
            key: None,
        }
    }

    /// Whether the minting key is gone from `keys`, no longer admin, or past
    /// its expiry at `now`: then the link, code or session dies at this use.
    fn key_dead(&self, keys: &crate::gateway::auth::ResolvedAuthConfig, now: Now) -> bool {
        self.key
            .as_ref()
            .is_some_and(|key| !keys.admin_key_live(key, chrono::DateTime::from(now.wall)))
    }
}

/// A redeemed bootstrap value: what the session it opens stays bound to.
#[derive(Debug, Clone)]
pub(crate) struct Redemption {
    pub(crate) bound: Bound,
    /// The clocks the redemption was checked against, which the session or
    /// code it yields is issued at: a second read could land on a clock that
    /// stepped before 1970 in between (MIK-8202).
    pub(crate) now: Now,
}

/// When a session was issued and when it last saw operator activity.
#[derive(Debug, Clone)]
struct SessionTimes {
    issued: Now,
    last_seen: Now,
    /// Ends at the minting credential's expiry even inside the limits, and
    /// with the minting key.
    bound: Bound,
}

impl SessionTimes {
    /// Past the idle or the absolute limit by either clock, past the cap, or
    /// judged on a wall clock that reads before 1970.
    fn expired(&self, now: Now, limits: &SessionLimits) -> bool {
        wall_unreadable(now)
            || exceeds(self.last_seen, now, limits.idle)
            || exceeds(self.issued, now, limits.absolute)
            || self
                .bound
                .not_after
                .is_some_and(|cap| cap_reached(now, cap))
    }
}

/// A wall clock before 1970 refuses every dashboard credential (MIK-8202):
/// without it a session would rest on the monotonic clock alone, which stops
/// while the host sleeps, so a suspend would outlive the idle limit.
pub(super) fn wall_unreadable(now: Now) -> bool {
    !now.wall_readable()
}

/// Whether `now` is at or past the minting credential's expiry `cap`. A wall
/// clock reading before 1970 cannot be placed against a real expiry, so the
/// cap counts as reached (MIK-8202); the monotonic limits are unchanged.
fn cap_reached(now: Now, cap: SystemTime) -> bool {
    !now.wall_readable() || now.wall >= cap
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
        self.issue_session_until(now, limits, Bound::default())
    }

    /// A session that also ends at `bound`'s cap and with its key.
    pub(crate) fn issue_session_until(
        &self,
        now: Now,
        limits: &SessionLimits,
        bound: Bound,
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
                    bound,
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
            value: Mutex::new(Some((Secret(random_value()), Bound::default()))),
            bound_port: AtomicU16::new(0),
            sessions: Mutex::new(HashMap::new()),
            #[cfg(feature = "webui")]
            handoff: Mutex::new(None),
            #[cfg(feature = "webui")]
            stream: crate::gateway::ui::stream::StreamHub::new(),
        }
    }

    /// The UI live stream's hub.
    #[cfg(feature = "webui")]
    pub(crate) fn stream_hub(&self) -> &crate::gateway::ui::stream::StreamHub {
        &self.stream
    }

    /// The value to print, while it remains unused.
    #[must_use]
    pub fn peek(&self) -> Option<String> {
        self.value
            .lock()
            .ok()
            .and_then(|v| v.as_ref().map(|(value, _)| value.reveal().to_owned()))
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

    /// Consume the value if it matches, returning what it was minted bound
    /// to. A wall clock before 1970 refuses every candidate unspent, decided
    /// before any compare, so the answer is the same for the live value and a
    /// guess: the session could not be dated, and the operator keeps a
    /// working link (MIK-8202). A link whose minting key `keys` no longer
    /// holds as a live admin key is spent and refused.
    pub(crate) fn consume_capped(
        &self,
        candidate: &str,
        keys: &crate::gateway::auth::ResolvedAuthConfig,
    ) -> Redeem {
        let now = Now::read();
        if wall_unreadable(now) {
            tracing::warn!(
                "dashboard bootstrap refused: the host clock reads before 1970; the link is kept"
            );
            return Redeem::ClockUnreadable;
        }
        match self.take_matching(candidate) {
            Some((_, bound)) if bound.key_dead(keys, now) => Redeem::Refused,
            Some((_, bound)) => Redeem::Issued(Redemption { bound, now }),
            None => Redeem::Refused,
        }
    }

    /// Take the value and its cap if `candidate` matches it. An empty slot
    /// still runs the compare, against a dummy, so whether a live link is
    /// outstanding cannot be timed.
    fn take_matching(&self, candidate: &str) -> Option<(Secret, Bound)> {
        let mut guard = self.value.lock().ok()?;
        let matches = if let Some((expected, _)) = guard.as_ref() {
            expected.matches(candidate)
        } else {
            let _ = secret_eq(&EMPTY_SLOT_DUMMY, candidate);
            false
        };
        if matches { guard.take() } else { None }
    }

    /// Whether some live session at `now` has a handle whose SHA-256 is
    /// `digest`: the delivery re-check of an events subscription made from a
    /// dashboard session (MIK-7769), which keeps only the digest. Never
    /// extends a session; a logout, expiry or the minting key leaving `keys`
    /// answers `false`.
    pub(crate) fn live_digest(
        &self,
        digest: &str,
        now: Now,
        limits: &SessionLimits,
        keys: &crate::gateway::auth::ResolvedAuthConfig,
    ) -> bool {
        let Ok(sessions) = self.sessions.lock() else {
            return false;
        };
        sessions.iter().any(|(handle, times)| {
            !times.expired(now, limits)
                && !times.bound.key_dead(keys, now)
                && crate::hashing::sha256_hex(handle.as_bytes()) == digest
        })
    }

    /// Whether `handle` is a live session at `now`.
    ///
    /// An expired handle is removed by the check that finds it. `Touch::Yes`
    /// restarts the idle clock of a valid session; `Touch::No` checks without
    /// extending, for background refreshes and delivery re-checks.
    /// Test fixtures, whose sessions carry no minting key: production checks
    /// through [`Self::check_session_with`], against a key table.
    #[cfg(test)]
    pub(crate) fn check_session(
        &self,
        handle: &str,
        now: Now,
        limits: &SessionLimits,
        touch: Touch,
    ) -> SessionCheck {
        self.check(handle, now, limits, touch, None)
    }

    /// [`Self::check_session`], and a session minted by an API key ends when
    /// `keys` no longer holds that key as a live admin key (K13): `keys` is
    /// the request's pinned table, or the one current at a delivery.
    pub(crate) fn check_session_with(
        &self,
        handle: &str,
        now: Now,
        limits: &SessionLimits,
        touch: Touch,
        keys: &crate::gateway::auth::ResolvedAuthConfig,
    ) -> SessionCheck {
        self.check(handle, now, limits, touch, Some(keys))
    }

    fn check(
        &self,
        handle: &str,
        now: Now,
        limits: &SessionLimits,
        touch: Touch,
        keys: Option<&crate::gateway::auth::ResolvedAuthConfig>,
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
        if times.expired(now, limits) || keys.is_some_and(|keys| times.bound.key_dead(keys, now)) {
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
    #[cfg(test)]
    pub(crate) fn rearm_until(&self, not_after: Option<SystemTime>) -> String {
        self.rearm_bound(Bound::until(not_after))
    }

    /// Like [`Self::rearm`], bound to `bound`: its cap and the API key that
    /// minted the link, which must still be a live admin key when the link
    /// and the session it opens are used (K13).
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn rearm_bound(&self, bound: Bound) -> String {
        let fresh = random_value();
        if let Ok(mut value) = self.value.lock() {
            *value = Some((Secret(fresh.clone()), bound));
        }
        fresh
    }

    /// Mint the code a loopback redemption shows, replacing any unused one. It
    /// carries `cap`, the redeemed link's credential cap, to the session.
    #[cfg(feature = "webui")]
    pub(crate) fn mint_handoff(&self, now: Now, cap: Bound) -> String {
        let value = random_value();
        if let Ok(mut slot) = self.handoff.lock() {
            *slot = Some(Handoff {
                value: Secret(value.clone()),
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
    pub(crate) fn take_handoff(
        &self,
        candidate: &str,
        now: Now,
        keys: &crate::gateway::auth::ResolvedAuthConfig,
    ) -> Option<Redemption> {
        let mut slot = self.handoff.lock().ok()?;
        let (expired, matches) = {
            let Some(live) = slot.as_ref() else {
                // No code outstanding: pay for the compare anyway.
                let _ = secret_eq(&EMPTY_SLOT_DUMMY, candidate);
                return None;
            };
            (
                wall_unreadable(now)
                    || exceeds(live.minted, now, HANDOFF_TTL)
                    || live.cap.not_after.is_some_and(|cap| cap_reached(now, cap))
                    || live.cap.key_dead(keys, now),
                live.value.matches(candidate),
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
            bound: live.cap,
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

    /// Whether the wall reading is usable: at or after the epoch (MIK-8202
    /// P4b). Judged through `crate::clock`, so no epoch comparison lives
    /// outside the clock module.
    pub(crate) fn wall_readable(&self) -> bool {
        crate::clock::wall_readable(self.wall)
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

/// The outcome of spending a bootstrap value, decided so that no branch
/// depends on comparing the candidate except `Issued` versus `Refused`.
pub(crate) enum Redeem {
    /// The candidate was the live value; it is spent.
    Issued(Redemption),
    /// The clock reads before 1970: every candidate is refused, none spent.
    ClockUnreadable,
    /// Not the live value, or none is outstanding.
    Refused,
}

/// A bootstrap value or handoff code the gateway holds. It has no `==`: the
/// only comparison is [`Secret::matches`], in constant time, so the compiler
/// refuses a plain compare that would leak timing or pick a branch by value.
struct Secret(String);

impl Secret {
    fn matches(&self, candidate: &str) -> bool {
        secret_eq(self.0.as_bytes(), candidate)
    }

    /// The value, to print the link for the operator. Never to compare.
    fn reveal(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// The one compare of a candidate with a secret: constant time for equal
/// lengths (every value and code is 43 base64url characters).
fn secret_eq(secret: &[u8], candidate: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    #[cfg(test)]
    CT_COMPARES.with(|n| n.set(n.get() + 1));
    bool::from(secret.ct_eq(candidate.as_bytes()))
}

/// Compared against when no value is outstanding, so an empty slot costs
/// the same as a full one: the length of `random_value`'s output.
const EMPTY_SLOT_DUMMY: [u8; 43] = [b'A'; 43];

#[cfg(test)]
thread_local! {
    /// Constant-time compares of a candidate with a secret on this thread.
    static CT_COMPARES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many constant-time secret compares ran on this thread (R14).
#[cfg(test)]
pub(crate) fn ct_compares_for_test() -> usize {
    CT_COMPARES.with(std::cell::Cell::get)
}
