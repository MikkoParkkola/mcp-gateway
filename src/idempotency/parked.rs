// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key held for the continuation of an input-required round.
//!
//! When a backend stops to ask, the key is neither released (a fresh same-key
//! call would run the tool again) nor completed (the continuation carries a
//! different fingerprint and would be refused as a mismatch). It is parked:
//! a same-key call is answered "in progress", and the continuation that
//! presents the envelope minted for this round claims the key and runs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::OccupiedEntry;
use serde_json::Value;

use super::{AdmitOutcome, Entry, IdempotencyCache, IdempotencyState, OwnerToken};
use crate::gateway::gateway_writes::WriteRecord;

/// The retry suffix every continuation's fingerprint carries.
const RETRY_SUFFIX: &str = "|mrtr:";

/// What a parked key holds.
#[derive(Debug, Clone)]
pub struct Park {
    /// sha256 of the minted envelope: a continuation claims the park by
    /// presenting exactly that envelope.
    state_digest: String,
    /// The envelope's own expiry, in unix seconds.
    expires_at: u64,
    /// When it was parked, on the cache clock.
    parked_at: Instant,
    /// The monotonic cap: twice the envelope's lifetime, so a continuation
    /// clock that cannot be read, or reads backwards, never parks forever.
    backstop: Duration,
    /// The may-have-run answer the park becomes once it expires.
    expired_answer: Value,
}

impl Park {
    /// Expired once the backstop has passed on the cache clock, or once the
    /// continuation clock reads past the envelope's expiry. Strictly past: the
    /// keyring still opens an envelope at its expiry second.
    fn is_expired(&self, now: Instant, now_unix: Option<u64>) -> bool {
        now.saturating_duration_since(self.parked_at) > self.backstop
            || now_unix.is_some_and(|unix| unix > self.expires_at)
    }
}

/// The continuation clock, or `None` when it cannot be read.
fn now_unix() -> Option<u64> {
    crate::protocol::continuation::clock_now().ok()
}

/// A fingerprint without its retry suffix: the part every round of one
/// exchange shares.
pub(super) fn base_of(fingerprint: &str) -> &str {
    fingerprint
        .split_once(RETRY_SUFFIX)
        .map_or(fingerprint, |(base, _)| base)
}

/// Whether `entry` is a park still waiting for its continuation.
pub(super) fn is_live(park: &Park, now: Instant) -> bool {
    !park.is_expired(now, now_unix())
}

/// An expired park becomes the may-have-run answer, still bound to the
/// exchange's base, so a retry of any round of it gets the notice. In place,
/// under whatever lock holds `entry`.
pub(super) fn settle_if_expired(entry: &mut Entry, now: Instant) {
    if let IdempotencyState::Parked(park) = &entry.state
        && park.is_expired(now, now_unix())
    {
        entry.state = IdempotencyState::Completed(park.expired_answer.clone(), now);
    }
}

/// Admit a call against a parked key. Decided before the mismatch gate: a
/// continuation's fingerprint always differs from round 1's.
/// - expired: answered as the may-have-run entry it becomes, for any round
///   of the exchange (a fingerprint starting with the base);
/// - claimed (the envelope's digest, a fingerprint of this exchange): the
///   continuation takes the key, in flight under its own fingerprint;
/// - anything else (no claim, another exchange's envelope): in progress.
pub(super) fn admit(
    mut occupied: OccupiedEntry<'_, String, Entry>,
    fingerprint: &str,
    claim: Option<&str>,
    owner: &Arc<OwnerToken>,
    now: Instant,
) -> AdmitOutcome {
    settle_if_expired(occupied.get_mut(), now);
    let entry = occupied.get();
    let of_exchange = fingerprint.starts_with(&entry.fingerprint);
    let outcome = match &entry.state {
        IdempotencyState::Parked(park)
            if of_exchange && claim == Some(park.state_digest.as_str()) =>
        {
            AdmitOutcome::Proceed
        }
        IdempotencyState::Parked(_) => AdmitOutcome::InFlight,
        IdempotencyState::Completed(answer, _) if of_exchange => {
            AdmitOutcome::Completed(answer.clone(), None, WriteRecord::default())
        }
        _ => AdmitOutcome::Mismatch,
    };
    if matches!(outcome, AdmitOutcome::Proceed) {
        occupied.insert(Entry::in_flight(fingerprint, owner, now));
    }
    outcome
}

impl IdempotencyCache {
    /// Park `key` for the continuation of `envelope`, bound to the base of
    /// the admitted `fingerprint`. `expires_at` and `issued_at` are the
    /// envelope's own (unix seconds); `expired_answer` is what the key
    /// answers once the park expires.
    pub(super) fn park(
        &self,
        key: &str,
        fingerprint: &str,
        envelope: &str,
        (issued_at, expires_at): (u64, u64),
        expired_answer: Value,
    ) {
        let lifetime = Duration::from_secs(expires_at.saturating_sub(issued_at));
        let park = Park {
            state_digest: crate::hashing::sha256_hex(envelope.as_bytes()),
            expires_at,
            parked_at: self.now(),
            backstop: lifetime.saturating_mul(2),
            expired_answer,
        };
        let mut entry = Entry::new(IdempotencyState::Parked(park), base_of(fingerprint));
        entry.bound_to_base = true;
        self.entries.insert(key.to_string(), entry);
    }
}

/// The claim a call makes on a parked key: the digest of the `requestState`
/// it presents, the envelope's own digest when it is the one minted.
#[must_use]
pub(crate) fn claim_of(request_state: Option<&str>) -> Option<String> {
    request_state.map(|state| crate::hashing::sha256_hex(state.as_bytes()))
}
