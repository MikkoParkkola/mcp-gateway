// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI login rate limits, each a key cap beside a gateway cap.
//!
//! Every cap is an events `HostLimiter`; a gateway cap is one under a single
//! fixed key. A start is counted only when both its caps admit it, so a call
//! one cap refuses never spends the other. Lookups and polls are checked
//! before the work and counted only when they fail. Ceiling: that check and
//! the later count are two steps, so concurrent failures from one key can
//! pass its cap by the calls in flight; against a 50-bit code that is a few
//! guesses.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::events::limiter::HostLimiter;

pub(crate) const STARTS_PER_PEER: u32 = 5;
pub(crate) const STARTS_PER_GATEWAY: u32 = 100;
pub(crate) const LOOKUPS_PER_SESSION: u32 = 5;
pub(crate) const LOOKUPS_PER_GATEWAY: u32 = 100;
pub(crate) const INVALID_POLLS_PER_PEER: u32 = 5;
pub(crate) const INVALID_POLLS_PER_GATEWAY: u32 = 100;
/// The start and invalid-poll window.
pub(crate) const MINUTE: Duration = Duration::from_secs(60);
/// The failed-lookup window.
pub(crate) const LOOKUP_WINDOW: Duration = Duration::from_secs(600);
/// Keys one limiter tracks; above every gateway cap, so the bound never
/// refuses a key the gateway cap would admit.
pub(crate) const MAX_TRACKED_KEYS: usize = 128;

/// The six caps.
pub(crate) struct Limits {
    starts_peer: HostLimiter,
    starts_gateway: HostLimiter,
    lookups_session: HostLimiter,
    lookups_gateway: HostLimiter,
    polls_peer: HostLimiter,
    polls_gateway: HostLimiter,
}

impl Limits {
    pub(crate) fn new() -> Self {
        Self {
            starts_peer: HostLimiter::new(STARTS_PER_PEER, MINUTE, MAX_TRACKED_KEYS),
            starts_gateway: HostLimiter::new(STARTS_PER_GATEWAY, MINUTE, 1),
            lookups_session: HostLimiter::new(LOOKUPS_PER_SESSION, LOOKUP_WINDOW, MAX_TRACKED_KEYS),
            lookups_gateway: HostLimiter::new(LOOKUPS_PER_GATEWAY, LOOKUP_WINDOW, 1),
            polls_peer: HostLimiter::new(INVALID_POLLS_PER_PEER, MINUTE, MAX_TRACKED_KEYS),
            polls_gateway: HostLimiter::new(INVALID_POLLS_PER_GATEWAY, MINUTE, 1),
        }
    }

    /// Counts a start from `peer` if both caps admit it.
    pub(crate) fn admit_start(&self, peer: IpAddr, now: Instant) -> bool {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = (&self.starts_peer, &self.starts_gateway, peer, now);
        false
    }

    /// Whether `session` may try a code now; counts nothing.
    pub(crate) fn may_look_up(&self, session: &str, now: Instant) -> bool {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = (&self.lookups_session, &self.lookups_gateway, session, now);
        false
    }

    /// Counts one failed lookup against `session` and the gateway.
    pub(crate) fn note_failed_lookup(&self, session: &str, now: Instant) {
        // SCAFFOLD: counts nothing until the implementation commit.
        let _ = (session, now);
    }

    /// Whether `peer` may poll now; counts nothing.
    pub(crate) fn may_poll(&self, peer: IpAddr, now: Instant) -> bool {
        // SCAFFOLD: refuses until the implementation commit.
        let _ = (&self.polls_peer, &self.polls_gateway, peer, now);
        false
    }

    /// Counts one invalid poll against `peer` and the gateway.
    pub(crate) fn note_invalid_poll(&self, peer: IpAddr, now: Instant) {
        // SCAFFOLD: counts nothing until the implementation commit.
        let _ = (peer, now);
    }

    /// Keys each per-key cap tracks now: start peers, lookup sessions,
    /// invalid-poll peers.
    #[cfg(test)]
    pub(crate) fn tracked_keys(&self) -> [usize; 3] {
        [
            self.starts_peer.tracked(),
            self.lookups_session.tracked(),
            self.polls_peer.tracked(),
        ]
    }
}
