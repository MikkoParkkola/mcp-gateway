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

use parking_lot::Mutex;

use crate::events::limiter::HostLimiter;

/// The one key of every gateway-wide cap.
const GATEWAY: &str = "gateway";

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
    /// Held across a start's two checks and two counts, so concurrent starts
    /// cannot both take a cap's last slot.
    start_lock: Mutex<()>,
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
            start_lock: Mutex::new(()),
        }
    }

    /// Counts a start from `peer` if both caps admit it.
    pub(crate) fn admit_start(&self, peer: IpAddr, now: Instant) -> bool {
        let peer = peer.to_string();
        let _both = self.start_lock.lock();
        let admitted = self.starts_peer.would_admit(&peer, now)
            && self.starts_gateway.would_admit(GATEWAY, now);
        if admitted {
            self.starts_peer.admit(&peer, now);
            self.starts_gateway.admit(GATEWAY, now);
        }
        admitted
    }

    /// Whether `session` may try a code now; counts nothing.
    pub(crate) fn may_look_up(&self, session: &str, now: Instant) -> bool {
        self.lookups_session.would_admit(session, now)
            && self.lookups_gateway.would_admit(GATEWAY, now)
    }

    /// Counts one failed lookup against `session` and the gateway.
    pub(crate) fn note_failed_lookup(&self, session: &str, now: Instant) {
        self.lookups_session.admit(session, now);
        self.lookups_gateway.admit(GATEWAY, now);
    }

    /// Whether `peer` may poll now; counts nothing.
    pub(crate) fn may_poll(&self, peer: IpAddr, now: Instant) -> bool {
        self.polls_peer.would_admit(&peer.to_string(), now)
            && self.polls_gateway.would_admit(GATEWAY, now)
    }

    /// Counts one invalid poll against `peer` and the gateway.
    pub(crate) fn note_invalid_poll(&self, peer: IpAddr, now: Instant) {
        self.polls_peer.admit(&peer.to_string(), now);
        self.polls_gateway.admit(GATEWAY, now);
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
