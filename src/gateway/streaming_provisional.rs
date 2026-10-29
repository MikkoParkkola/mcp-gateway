// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Provisional sessions (MIK-8504).
//!
//! A legacy request that is not `initialize` and presents no live session of
//! its own still gets one, because a 2025 client may adopt the id from the
//! answer (MIK-7215.STATELESS.3a). Kept for `session_ttl`, a session minted per
//! sessionless call made the store grow with the request rate. Such a session
//! is now provisional: reaped once idle for [`PROVISIONAL_SESSION_TTL`], or
//! for `session_ttl` if that is shorter, with no request in flight and no open
//! stream, and counted against
//! [`MAX_PROVISIONAL_SESSIONS`] until it is presented again (promoted) or
//! leaves the store. At the cap a new provisional session is refused.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;

use super::{ClientSession, NotificationMultiplexer};
use crate::gateway::session_id::SessionOwner;

/// The longest a provisional session with nothing in flight and no open
/// stream stays idle before it is reaped: the window a client has to adopt
/// the id. A configured `session_ttl` below it shortens it (the reaper takes
/// the smaller); it is also the `Retry-After` a capacity refusal names.
pub(crate) const PROVISIONAL_SESSION_TTL: Duration = Duration::from_secs(60);

/// Live provisional sessions minted by POST at most. Past it a POST is
/// served without a session rather than refused (MIK-8533). A POST mint
/// opens no notification channel, so each costs about 1.1 KB.
pub(crate) const MAX_PROVISIONAL_SESSIONS: usize = 10_000;

/// Live provisional sessions minted by a sessionless GET stream at most;
/// a stream past it is refused, since a stream cannot run without one.
/// Lower than the POST share because a subscribed stream opens its
/// broadcast channel: about 30 KB at the default buffer size (MIK-8533).
pub(crate) const MAX_PROVISIONAL_STREAM_SESSIONS: usize = 1_000;

/// What kind of session a request may mint when it resumes none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MintKind {
    /// `initialize`: kept for `session_ttl`, never refused by the cap.
    Ordinary,
    /// Any other POST: provisional, counted against the POST share.
    Provisional,
    /// A sessionless GET stream: provisional, counted against the stream
    /// share (MIK-8533).
    ProvisionalStream,
}

/// The provisional cap is full: the request is refused before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionCapacity;

/// A request running under a session. While any is held, a provisional
/// session is not reaped; dropping the last one starts its idle clock.
pub(crate) struct InFlightHold(Arc<ClientSession>);

impl InFlightHold {
    fn take(session: &Arc<ClientSession>) -> Self {
        session.in_flight.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(session))
    }
}

impl Drop for InFlightHold {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl NotificationMultiplexer {
    /// Resume `owner`'s live session named `session_id`, or open a provisional
    /// one under a fresh id, holding it for the request. `kind` picks the
    /// share it counts against. `Err` when a new provisional session would
    /// pass that share's cap; nothing is inserted then.
    pub(super) fn open_provisional_for(
        &self,
        session_id: Option<&str>,
        owner: &SessionOwner,
        kind: MintKind,
    ) -> Result<(Arc<ClientSession>, InFlightHold), SessionCapacity> {
        let stream = kind == MintKind::ProvisionalStream;
        let mut sessions = self.sessions.write();
        if let Some(session) = self.resume_live(&sessions, session_id, owner) {
            let hold = InFlightHold::take(&session);
            return Ok((session, hold));
        }
        // Checked and counted under the write lock that inserts, so
        // concurrent admissions cannot pass the cap together.
        let (live, cap) = self.provisional_share(stream);
        if live.load(Ordering::SeqCst) >= cap {
            return Err(SessionCapacity);
        }
        let session = self.mint(&mut sessions, owner);
        session.provisional_stream.store(stream, Ordering::SeqCst);
        session.provisional.store(true, Ordering::SeqCst);
        live.fetch_add(1, Ordering::SeqCst);
        let hold = InFlightHold::take(&session);
        Ok((session, hold))
    }

    /// Hold an existing session for a request that resumed it.
    pub(super) fn hold(session: &Arc<ClientSession>) -> InFlightHold {
        InFlightHold::take(session)
    }

    /// A session presented again by its owner is ordinary from now on.
    pub(super) fn promote(&self, session: &ClientSession) {
        self.forget_provisional(session);
    }

    /// Drop `session`'s provisional count, once, when it is promoted or
    /// leaves the store.
    pub(super) fn forget_provisional(&self, session: &ClientSession) {
        if session.provisional.swap(false, Ordering::SeqCst) {
            let (live, _) =
                self.provisional_share(session.provisional_stream.load(Ordering::SeqCst));
            live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// The counter and cap of the POST share, or of the stream share.
    fn provisional_share(&self, stream: bool) -> (&std::sync::atomic::AtomicUsize, usize) {
        if stream {
            (
                &self.provisional_stream_live,
                MAX_PROVISIONAL_STREAM_SESSIONS,
            )
        } else {
            (&self.provisional_live, MAX_PROVISIONAL_SESSIONS)
        }
    }

    /// Whether the reaper takes `session` now: idle past `ttl` (past the
    /// provisional limit for a provisional one, and then only with nothing in
    /// flight), with no open stream either way.
    pub(super) fn reapable(session: &ClientSession, now: Instant, ttl: Duration) -> bool {
        Self::reapable_observed(session, now, ttl, || {})
    }

    /// [`Self::reapable`], with `between` run between reading what is in
    /// flight and reading when the session was last active: the window a
    /// hold's drop can land in. Tests put a drop there; production runs
    /// nothing.
    fn reapable_observed(
        session: &ClientSession,
        now: Instant,
        ttl: Duration,
        between: impl FnOnce(),
    ) -> bool {
        let no_stream = session.receiver_count() == 0;
        if !session.provisional.load(Ordering::SeqCst) {
            return no_stream && now.duration_since(*session.last_active.read()) >= ttl;
        }
        // In flight first: a hold's drop refreshes `last_active` before it
        // decrements, so once none is seen in flight the refresh is seen too,
        // and a request that just ended keeps its adoption window.
        let quiet = session.in_flight.load(Ordering::SeqCst) == 0;
        between();
        let idle = now.duration_since(*session.last_active.read());
        // Never longer than an ordinary session: a configured `session_ttl`
        // below the provisional limit shortens it too.
        no_stream && quiet && idle >= PROVISIONAL_SESSION_TTL.min(ttl)
    }
}

#[cfg(test)]
#[path = "streaming_provisional_tests.rs"]
mod tests;

#[cfg(test)]
impl NotificationMultiplexer {
    /// Count the cap as full, without minting ten thousand sessions.
    pub(crate) fn fill_provisional_cap_for_test(&self) {
        self.provisional_live
            .store(MAX_PROVISIONAL_SESSIONS, Ordering::SeqCst);
    }

    /// Count the stream share as full.
    pub(crate) fn fill_stream_cap_for_test(&self) {
        self.provisional_stream_live
            .store(MAX_PROVISIONAL_STREAM_SESSIONS, Ordering::SeqCst);
    }

    /// Live provisional sessions in the POST share and the stream share.
    pub(crate) fn provisional_shares_for_test(&self) -> (usize, usize) {
        (
            self.provisional_live.load(Ordering::SeqCst),
            self.provisional_stream_live.load(Ordering::SeqCst),
        )
    }

    /// Requests and streams holding session `id` now; `None` when it is gone.
    pub(crate) fn in_flight_for_test(&self, id: &str) -> Option<usize> {
        self.sessions
            .read()
            .get(id)
            .map(|session| session.in_flight.load(Ordering::SeqCst))
    }
}
