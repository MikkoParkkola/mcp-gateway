// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-client rate-limit buckets and circuit breakers, kept apart from the
//! resolved key list: one store for the process, shared by every resolved
//! auth config built over it, so a reload that rebuilds the key list does not
//! reset any client's usage or breaker.
//!
//! The buckets are not `governor` limiters: a reload may change a key's
//! `rate_limit`, and the design keeps the usage already spent under the new
//! rate, which needs a bucket whose rate can change in place. `governor`
//! exposes neither. [`ClientBucket`] runs the same GCRA as
//! `governor::Quota::per_minute(rate)` (burst = rate), pinned to it by the
//! equivalence rows.

use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use dashmap::DashMap;

use crate::config::CircuitBreakerConfig;
use crate::failsafe::CircuitBreaker;

/// Nanoseconds in the one-minute period a `rate_limit` counts over.
const MINUTE_NS: u128 = 60_000_000_000;

/// The shared per-client store, keyed by the credential's state key, never by
/// a display name.
#[derive(Debug, Default)]
pub(crate) struct AuthRuntime {
    buckets: DashMap<String, Arc<ClientBucket>>,
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    /// When each configured key last authenticated, in unix seconds, keyed by
    /// the key's principal, so a rotation under one principal keeps it and a
    /// reload never clears it. In memory only: empty after a restart.
    // ponytail: one entry per principal ever matched since start; a derived
    // principal adds one per rotation. Prune to the current table if it grows.
    last_used: DashMap<String, i64>,
}

impl AuthRuntime {
    /// Whether one more request fits `key`'s bucket at `rate` per minute. A
    /// bucket made at another rate is first re-priced to `rate`, keeping what
    /// was spent.
    pub(crate) fn admit(&self, key: String, rate: NonZeroU32) -> bool {
        let bucket = self
            .buckets
            .entry(key)
            .or_insert_with(|| Arc::new(ClientBucket::new(rate)))
            .clone();
        bucket.check_at(rate, now_ns())
    }

    /// `key`'s breaker, made under `config` on first use and labelled for logs
    /// with the client's `name`. A breaker keeps the policy it was made with:
    /// `client_circuit_breaker` is restart-only.
    pub(crate) fn breaker(
        &self,
        key: String,
        name: &str,
        config: &CircuitBreakerConfig,
    ) -> Arc<CircuitBreaker> {
        self.breakers
            .entry(key)
            .or_insert_with(|| Arc::new(CircuitBreaker::new(&format!("client:{name}"), config)))
            .clone()
    }

    /// Records an accepted match of the key with `principal` at `at` (unix
    /// seconds). The newer reading wins, under the entry's shard lock, so an
    /// older reading arriving last never moves the time back.
    pub(crate) fn note_used(&self, principal: &str, at: i64) {
        self.last_used
            .entry(principal.to_owned())
            .and_modify(|seen| *seen = (*seen).max(at))
            .or_insert(at);
    }

    /// When the key with `principal` last authenticated in this process.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn last_used(&self, principal: &str) -> Option<i64> {
        self.last_used.get(principal).map(|seen| *seen)
    }

    /// `key`'s breaker, if one was made.
    pub(crate) fn existing_breaker(&self, key: &str) -> Option<Arc<CircuitBreaker>> {
        self.breakers.get(key).map(|breaker| Arc::clone(&breaker))
    }
}

/// One client's bucket: GCRA in integer nanoseconds, as `governor` runs
/// `Quota::per_minute(rate)`, with a rate that can change in place.
#[derive(Debug)]
pub(crate) struct ClientBucket {
    state: parking_lot::Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    rate: NonZeroU32,
    /// One request's cost and the burst tolerance at `rate`, in nanoseconds,
    /// computed when the rate is set rather than on every check.
    pricing: Pricing,
    /// The theoretical arrival time of the next request, in nanoseconds on
    /// [`now_ns`]'s clock; `None` until the first request.
    tat: Option<u64>,
}

impl ClientBucket {
    pub(crate) fn new(rate: NonZeroU32) -> Self {
        Self {
            state: parking_lot::Mutex::new(BucketState {
                rate,
                pricing: Pricing::of(rate),
                tat: None,
            }),
        }
    }

    /// Whether a request at `t0` fits at `rate`. A changed rate re-prices the
    /// requests still owed: the same count of them, at the new interval. Both
    /// steps run under the one lock, which is never held across an await.
    pub(crate) fn check_at(&self, rate: NonZeroU32, t0: u64) -> bool {
        let mut state = self.state.lock();
        if state.rate != rate {
            let pricing = Pricing::of(rate);
            if let Some(tat) = state.tat.filter(|&tat| tat > t0) {
                let owed =
                    u128::from(tat - t0) * u128::from(pricing.t) / u128::from(state.pricing.t);
                state.tat = Some(t0.saturating_add(u64::try_from(owed).unwrap_or(u64::MAX)));
            }
            state.rate = rate;
            state.pricing = pricing;
        }
        let Pricing { t, tau } = state.pricing;
        let tat = state.tat.unwrap_or(t0);
        if t0 < tat.saturating_sub(tau) {
            return false;
        }
        state.tat = Some(tat.max(t0).saturating_add(t));
        true
    }
}

/// One request's cost (`t`) and the burst tolerance (`tau`, the cost of
/// `rate - 1` requests) at a rate, in nanoseconds.
#[derive(Debug, Clone, Copy)]
struct Pricing {
    t: u64,
    tau: u64,
}

impl Pricing {
    fn of(rate: NonZeroU32) -> Self {
        let t = interval(rate);
        Self {
            t,
            tau: t.saturating_mul(u64::from(rate.get()) - 1),
        }
    }
}

/// One request's cost in nanoseconds at `rate` per minute, truncated as
/// `governor::Quota::per_minute` truncates it, and never zero.
fn interval(rate: NonZeroU32) -> u64 {
    u64::try_from(MINUTE_NS / u128::from(rate.get()))
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Nanoseconds since the first bucket check in this process.
fn now_ns() -> u64 {
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    u64::try_from(ANCHOR.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "auth_runtime_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "auth_bucket_tests.rs"]
mod bucket_tests;
