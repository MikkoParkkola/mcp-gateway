// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rate limiting implementation
//!
//! The clock is `std::time::Instant` (governor's `MonotonicClock`), not
//! governor's default, which on some hosts reads a raw hardware counter. A
//! bucket whose stored state runs ahead of its clock would refuse every call
//! until the clock caught up, so a refusal that asks for a wait no legitimate
//! refusal can ask for rebuilds the bucket instead.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use governor::clock::{Clock, MonotonicClock, Reference};
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovernorLimiter};
use parking_lot::Mutex;

use crate::config::RateLimitConfig;

/// The least time, by the limiter's own clock, between two refusals that ask
/// for a WARN.
const WARN_EVERY: Duration = Duration::from_secs(60);

type Bucket<C> = GovernorLimiter<NotKeyed, InMemoryState, C, NoOpMiddleware<<C as Clock>::Instant>>;

/// What one [`RateLimiter::acquire`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Acquire {
    /// A token was taken.
    Admitted,
    /// The stored state was ahead of the clock by more than one replenish
    /// interval, which only a clock that went back produces. The bucket was
    /// rebuilt and this call took a token from it.
    AdmittedAfterClockStep {
        /// The wait the old state would have imposed. Not the size of the
        /// step: unused burst capacity can make it shorter or longer.
        stale_wait: Duration,
    },
    /// No token. `wait` is the time until the next one; `warn` is true for at
    /// most one refusal per [`WARN_EVERY`].
    Refused { wait: Duration, warn: bool },
}

struct State<C: Clock> {
    bucket: Bucket<C>,
    last_warn: Option<C::Instant>,
}

/// Rate limiter for request throttling
pub struct RateLimiter<C: Clock + Clone + Send + Sync = MonotonicClock> {
    /// Whether rate limiting is enabled
    enabled: AtomicBool,
    /// The bucket (built on first use) and the last WARN, behind one lock so
    /// a rebuild and the calls racing it see one bucket.
    inner: Mutex<Option<State<C>>>,
    clock: C,
    /// The quota each rebuilt bucket takes.
    quota: Quota,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: &RateLimitConfig) -> Self {
        Self::with_clock(config, MonotonicClock)
    }
}

impl<C: Clock + Clone + Send + Sync> RateLimiter<C> {
    fn with_clock(config: &RateLimitConfig, clock: C) -> Self {
        Self {
            enabled: AtomicBool::new(config.enabled),
            inner: Mutex::new(None),
            clock,
            quota: Quota::per_second(
                NonZeroU32::new(config.requests_per_second).unwrap_or(NonZeroU32::MIN),
            )
            .allow_burst(NonZeroU32::new(config.burst_size).unwrap_or(NonZeroU32::MIN)),
        }
    }

    /// A limiter that is always on, for one fixed `quota`: no config, no
    /// enable switch. It shares [`Self::acquire`]'s clock-step handling and
    /// wait calculation.
    #[cfg(feature = "webui")]
    pub(crate) fn always_on(quota: Quota, clock: C) -> Self {
        Self {
            enabled: AtomicBool::new(true),
            inner: Mutex::new(None),
            clock,
            quota,
        }
    }

    /// Forget the bucket, so the next call starts from a full one: for rows
    /// that make more calls than one budget allows.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) fn reset_for_test(&self) {
        *self.inner.lock() = None;
    }

    fn bucket(&self) -> Bucket<C> {
        GovernorLimiter::direct_with_clock(self.quota, self.clock.clone())
    }

    /// Try to acquire a permit
    pub fn try_acquire(&self) -> bool {
        matches!(
            self.acquire(),
            Acquire::Admitted | Acquire::AdmittedAfterClockStep { .. }
        )
    }

    /// Take a token, or say why not.
    pub(crate) fn acquire(&self) -> Acquire {
        if !self.enabled.load(Ordering::Relaxed) {
            return Acquire::Admitted;
        }

        let mut inner = self.inner.lock();
        let state = inner.get_or_insert_with(|| State {
            bucket: self.bucket(),
            last_warn: None,
        });

        let Err(refused) = state.bucket.check() else {
            return Acquire::Admitted;
        };
        let now = self.clock.now();
        let mut wait = refused.wait_time_from(now);
        // An admission at `a` leaves the next allowed time at most one
        // interval after `a` (GCRA), so a longer wait means the state is from
        // the future: the clock went back.
        let interval = refused.quota().replenish_interval();
        if wait > interval {
            state.bucket = self.bucket();
            match state.bucket.check() {
                Ok(()) => return Acquire::AdmittedAfterClockStep { stale_wait: wait },
                Err(refused) => wait = refused.wait_time_from(now),
            }
        }

        // A stamp from the future (the clock went back) is due, too.
        let warn = state.last_warn.is_none_or(|last| {
            now < last || Duration::from(now.duration_since(last)) >= WARN_EVERY
        });
        if warn {
            state.last_warn = Some(now);
        }
        Acquire::Refused { wait, warn }
    }

    /// Enable or disable rate limiting
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[path = "rate_limiter_tests.rs"]
mod tests;
