// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The process-wide budget of the admin email lookup: a stolen admin
//! credential can still guess candidate emails, so every authorized attempt
//! is charged to one shared bucket before anything is hashed or read.
//!
//! Always on: no config switch, no enable flag. It is a sustained refill of
//! one permit per six seconds with capacity two, not a sliding window of ten
//! a minute: two attempts at once, then one every six seconds. Per process:
//! with several replicas the capacity multiplies by the replica count.

use std::num::NonZeroU32;

use governor::Quota;
use governor::clock::{Clock, MonotonicClock};

use crate::failsafe::rate_limiter::{Acquire, RateLimiter};

/// The sustained rate: ten a minute, one every six seconds.
const PERMITS_PER_MINUTE: NonZeroU32 = NonZeroU32::new(10).expect("10 is nonzero");
/// The burst: two attempts back to back.
const BURST: NonZeroU32 = NonZeroU32::new(2).expect("2 is nonzero");

/// What one charge came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charge {
    /// The attempt may go on.
    Admitted,
    /// The budget is spent; retry after this many whole seconds (at least 1).
    Throttled { retry_after_secs: u64 },
}

/// The shared bucket.
pub(crate) struct LookupBudget<C: Clock + Clone + Send + Sync = MonotonicClock> {
    limiter: RateLimiter<C>,
}

impl<C: Clock + Clone + Send + Sync> std::fmt::Debug for LookupBudget<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupBudget").finish_non_exhaustive()
    }
}

impl LookupBudget {
    /// The budget a process starts with.
    pub(crate) fn new() -> Self {
        Self::with_clock(MonotonicClock)
    }
}

impl<C: Clock + Clone + Send + Sync> LookupBudget<C> {
    /// The same budget on `clock`, for rows that move time by hand.
    pub(crate) fn with_clock(clock: C) -> Self {
        Self {
            limiter: RateLimiter::always_on(
                Quota::per_minute(PERMITS_PER_MINUTE).allow_burst(BURST),
                clock,
            ),
        }
    }

    /// Take one permit, or say how long until one frees.
    pub(crate) fn charge(&self) -> Charge {
        match self.limiter.acquire() {
            Acquire::Admitted | Acquire::AdmittedAfterClockStep { .. } => Charge::Admitted,
            Acquire::Refused { wait, warn } => {
                if warn {
                    tracing::warn!("the admin email lookup budget is spent; refusing lookups");
                }
                let whole = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
                Charge::Throttled {
                    retry_after_secs: whole.max(1),
                }
            }
        }
    }
}
