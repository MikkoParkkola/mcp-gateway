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

use crate::failsafe::{Acquire, RateLimiter};

/// The sustained rate: ten a minute, one every six seconds.
const PERMITS_PER_MINUTE: NonZeroU32 = NonZeroU32::MIN.saturating_add(9);
/// The burst: two attempts back to back.
const BURST: NonZeroU32 = NonZeroU32::MIN.saturating_add(1);

/// `wait` in whole seconds, rounded up, and never below one.
fn whole_seconds(wait: std::time::Duration) -> u64 {
    (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1)
}

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

    /// A full bucket again, for rows that make more calls than one budget allows.
    #[cfg(test)]
    pub(crate) fn reset_for_test(&self) {
        self.limiter.reset_for_test();
    }

    /// Take one permit, or say how long until one frees.
    pub(crate) fn charge(&self) -> Charge {
        match self.limiter.acquire() {
            Acquire::Admitted | Acquire::AdmittedAfterClockStep { .. } => Charge::Admitted,
            Acquire::Refused { wait, warn } => {
                if warn {
                    tracing::warn!("the admin email lookup budget is spent; refusing lookups");
                }
                Charge::Throttled {
                    retry_after_secs: whole_seconds(wait),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use governor::clock::FakeRelativeClock;

    use super::*;

    fn retry(charge: Charge) -> u64 {
        match charge {
            Charge::Throttled { retry_after_secs } => retry_after_secs,
            Charge::Admitted => panic!("expected a refusal, got {charge:?}"),
        }
    }

    /// The pinned schedule: two permits at once, the third refused until one
    /// refills (six seconds), then one every six seconds. It is a refill, not
    /// ten in any minute: a fresh budget never admits a third at once.
    /// Mutant: a burst of three, or a refill of one per ten seconds.
    #[test]
    fn two_permits_then_one_every_six_seconds() {
        let clock = FakeRelativeClock::default();
        let budget = LookupBudget::with_clock(clock.clone());
        assert_eq!(budget.charge(), Charge::Admitted);
        assert_eq!(budget.charge(), Charge::Admitted);
        assert_eq!(retry(budget.charge()), 6, "the third waits one refill");
        clock.advance(Duration::from_secs(5));
        assert_eq!(retry(budget.charge()), 1, "one second left rounds up to 1");
        clock.advance(Duration::from_secs(1));
        assert_eq!(budget.charge(), Charge::Admitted, "a permit refilled");
        assert_eq!(retry(budget.charge()), 6, "and only one");
        clock.advance(Duration::from_secs(12));
        assert_eq!(budget.charge(), Charge::Admitted);
        assert_eq!(budget.charge(), Charge::Admitted);
        assert_eq!(retry(budget.charge()), 6, "capacity is two, not more");
    }

    /// Rounded up, never zero: even a wait of nothing says one second.
    /// Mutant: truncate, or drop the floor.
    #[test]
    fn waits_round_up_and_never_say_zero() {
        use std::time::Duration;
        assert_eq!(whole_seconds(Duration::ZERO), 1);
        assert_eq!(whole_seconds(Duration::from_millis(1)), 1);
        assert_eq!(whole_seconds(Duration::from_secs(6)), 6);
        assert_eq!(whole_seconds(Duration::from_millis(5_001)), 6);
    }

    /// A wait of a fraction of a second still says at least one second.
    /// Mutant: report the truncated wait (0).
    #[test]
    fn a_fractional_wait_reports_at_least_one_second() {
        let clock = FakeRelativeClock::default();
        let budget = LookupBudget::with_clock(clock.clone());
        budget.charge();
        budget.charge();
        clock.advance(Duration::from_millis(5_900));
        assert_eq!(retry(budget.charge()), 1);
    }
}
