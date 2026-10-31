// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The reservation an admitted idempotency key hands its caller, and how it
//! settles on every exit path.

use std::sync::Arc;

use serde_json::Value;
use tracing::debug;

use super::{IdempotencyCache, OwnerToken};
use crate::gateway::gateway_writes::WriteRecord;
use crate::security::tenant_reads::ReadAttribution;

/// Owned reservation of an admitted idempotency key.
///
/// Holding one is the right to execute the protected side effect exactly once.
/// Every exit path after admission reaches a terminal state, so no early return
/// can strand an entry as in-flight until [`super::IN_FLIGHT_TIMEOUT`]. Which terminal
/// state depends on whether the side effect has run: before
/// [`commit`](Self::commit) a drop releases the key so the call can be retried;
/// after it, a drop stores the committed result, because once the backend has
/// acted a retry must not execute it again. A call that was dispatched and
/// answered with an error settles through [`fail`](Self::fail) instead — the
/// backend may have acted, and from here that is indistinguishable from not
/// having acted (ADR-012).
pub struct IdempotencyReservation {
    cache: Arc<IdempotencyCache>,
    key: String,
    /// The fingerprint the key was admitted for, so a result stored after the
    /// entry is gone stays bound to this request instead of matching any.
    fingerprint: String,
    pub(super) settled: bool,
    /// Parked for a continuation: no later completion may overwrite the park.
    parked: bool,
    pub(super) on_drop: OnDrop,
    /// The liveness token this reservation keeps alive. Held, never read: the
    /// cache entry's weak handle goes dead when this field is dropped, which
    /// happens only after `Drop::drop` has finished settling the key
    /// (ADR-012 A2).
    _owner: Arc<OwnerToken>,
}

// Not derived: the key ends in the caller's stored principal (MIK-8697).
impl std::fmt::Debug for IdempotencyReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyReservation")
            .field("key", &"<redacted>")
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

/// What an unsettled [`IdempotencyReservation`] does when it is dropped.
#[derive(Debug)]
pub(super) enum OnDrop {
    /// Nothing has been executed yet — free the key so the call can be retried.
    Release,
    /// The protected side effect has committed — settle with this result so a
    /// retry is served the cached value instead of re-executing.
    Complete(Value),
}

impl IdempotencyReservation {
    pub(super) fn new(
        cache: Arc<IdempotencyCache>,
        key: &str,
        fingerprint: &str,
        owner: Arc<OwnerToken>,
    ) -> Self {
        Self {
            cache,
            key: key.to_string(),
            fingerprint: fingerprint.to_string(),
            settled: false,
            parked: false,
            on_drop: OnDrop::Release,
            _owner: owner,
        }
    }

    /// The key this reservation owns.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Whether a settling call already stored or released the key.
    #[must_use]
    pub(crate) fn is_settled(&self) -> bool {
        self.settled
    }

    /// Settle by storing `result`. Returns whether it was cached — a non-final
    /// result is refused by [`IdempotencyCache::mark_completed`] and the key is
    /// released instead, so the call stays retryable.
    ///
    /// Callable after [`release`](Self::release): a failed dispatch releases the
    /// key first and may still store a structured error result afterwards, which
    /// is the behaviour the invoke path already relied on.
    pub fn complete(&mut self, result: &Value) -> bool {
        self.complete_read(result, (None, WriteRecord::default()))
    }

    /// [`Self::complete`] with the dispatch's reading (MIN.2) and the
    /// gateway's write record (MIK-7991) kept in the entry.
    pub(crate) fn complete_read(
        &mut self,
        result: &Value,
        read: (Option<ReadAttribution>, WriteRecord),
    ) -> bool {
        // Parked for a continuation: nothing later may overwrite the park,
        // least of all a non-final result, which would free the key.
        if self.parked {
            return false;
        }
        self.settled = true;
        self.cache
            .mark_completed_read(&self.key, result.clone(), &self.fingerprint, read)
    }

    /// Park the key for the continuation of `envelope`, the envelope minted
    /// for the input-required round this reservation's call answered.
    /// `deadlines` are the envelope's `(issued_at, expires_at)`;
    /// `expired_answer` is what the key answers once the park expires.
    /// Returns `false`, changing nothing, once the reservation is settled.
    pub(crate) fn park(
        &mut self,
        envelope: &str,
        deadlines: (u64, u64),
        expired_answer: Value,
    ) -> bool {
        if self.settled {
            return false;
        }
        self.settled = true;
        self.parked = true;
        self.cache.park(
            &self.key,
            &self.fingerprint,
            envelope,
            deadlines,
            expired_answer,
        );
        true
    }

    /// Record that the protected side effect has committed.
    ///
    /// After this, dropping the reservation unsettled stores `result` as the
    /// terminal state instead of releasing the key. Once a backend has acted, a
    /// post-dispatch early return must not readmit the retry that would execute
    /// it a second time. No-op once the reservation is already settled.
    pub fn commit(&mut self, result: &Value) {
        if !self.settled {
            self.on_drop = OnDrop::Complete(result.clone());
        }
    }

    /// Settle by storing `error` as the terminal outcome, so a retry of the
    /// same key is served the same JSON-RPC error rather than readmitted.
    ///
    /// `error` is the error object the caller would otherwise have seen
    /// (`{"code", "message"}`). Use this — not [`release`](Self::release) — for
    /// any failure after dispatch: the backend may already have acted, and the
    /// two cases are indistinguishable from here (ADR-012 consequence 1).
    pub fn fail(&mut self, error: &Value) {
        self.settled = true;
        self.cache
            .mark_failed_bound(&self.key, error.clone(), &self.fingerprint);
    }

    /// Settle by releasing the key so the call can be retried.
    pub fn release(&mut self) {
        self.settled = true;
        self.cache.remove(&self.key);
    }
}

impl Drop for IdempotencyReservation {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        match std::mem::replace(&mut self.on_drop, OnDrop::Release) {
            OnDrop::Release => {
                self.cache.remove(&self.key);
                debug!(
                    // The pre-split module path, kept as the log target.
                    target: "mcp_gateway::idempotency",
                    // Not the key: it ends in the caller's stored principal.
                    "Released abandoned idempotency reservation"
                );
            }
            OnDrop::Complete(result) => {
                if self
                    .cache
                    .mark_completed_bound(&self.key, result, &self.fingerprint)
                {
                    debug!(
                        // The pre-split module path, kept as the log target.
                        target: "mcp_gateway::idempotency",
                        "Settled abandoned idempotency reservation"
                    );
                } else {
                    // A non-final result is refused by `mark_completed`. Leaving
                    // the entry in flight is the one outcome this guard exists to
                    // prevent, so fall back to releasing the key.
                    self.cache.remove(&self.key);
                }
            }
        }
    }
}
