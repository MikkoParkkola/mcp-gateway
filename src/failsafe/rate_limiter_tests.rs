// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The limiter after its clock steps back, and its WARN cadence.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use governor::clock::{Clock, MonotonicClock};

use super::{Acquire, RateLimiter};
use crate::config::RateLimitConfig;

/// A clock the test sets, in nanoseconds.
#[derive(Clone, Default)]
struct StepClock(Arc<AtomicU64>);

impl StepClock {
    fn set(&self, at: Duration) {
        self.0
            .store(u64::try_from(at.as_nanos()).unwrap(), Ordering::SeqCst);
    }
}

impl Clock for StepClock {
    type Instant = Duration;

    fn now(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

const T: Duration = Duration::from_millis(10);

fn limiter(at: Duration) -> (RateLimiter<StepClock>, StepClock) {
    let clock = StepClock::default();
    clock.set(at);
    let config = RateLimitConfig {
        enabled: true,
        requests_per_second: 100,
        burst_size: 50,
    };
    (RateLimiter::with_clock(&config, clock.clone()), clock)
}

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn admitted(outcome: Acquire) -> bool {
    !matches!(outcome, Acquire::Refused { .. })
}

/// Takes every token left at the clock's current time: how many, and the
/// refusal that stopped it.
fn drain_to(l: &RateLimiter<StepClock>) -> (usize, Acquire) {
    // No bucket here holds more than its burst of 50: more admissions mean
    // a bucket that never empties, which fails here instead of hanging.
    for n in 0..=50 {
        let outcome = l.acquire();
        if !admitted(outcome) {
            return (n, outcome);
        }
    }
    panic!("more than one burst admitted at one instant");
}

fn drain(l: &RateLimiter<StepClock>) -> usize {
    drain_to(l).0
}

/// R1, red on a limiter without the reset: after a burst, the clock steps
/// back an hour; the next call is admitted on a rebuilt bucket instead of
/// waiting an hour.
#[test]
fn a_clock_stepped_back_an_hour_admits_the_next_call() {
    let (l, clock) = limiter(secs(3610));
    assert_eq!(drain(&l), 50);
    clock.set(secs(10));
    assert!(
        matches!(l.acquire(), Acquire::AdmittedAfterClockStep { stale_wait } if stale_wait > secs(3599)),
        "a refusal asking for an hour's wait is a clock step"
    );
}

/// R1b: the rebuilt bucket holds one burst and refills at the quota's rate.
#[test]
fn the_rebuilt_bucket_holds_one_burst_and_refills_at_the_quota() {
    let (l, clock) = limiter(secs(3610));
    drain(&l);
    clock.set(secs(10));
    assert!(matches!(
        l.acquire(),
        Acquire::AdmittedAfterClockStep { .. }
    ));
    assert_eq!(drain(&l), 49, "50 with the call that saw the step");
    assert!(matches!(l.acquire(), Acquire::Refused { wait, .. } if wait <= T));
    clock.set(secs(10) + T);
    assert_eq!(drain(&l), 1);
}

/// R2: legitimate refusals never reset, and the wait is exactly one interval.
#[test]
fn refusals_at_one_instant_never_reset_the_bucket() {
    let (l, clock) = limiter(secs(1000));
    drain(&l);
    for _ in 0..10_000 {
        assert!(matches!(l.acquire(), Acquire::Refused { .. }));
    }
    clock.set(secs(1000) + T);
    assert_eq!(drain(&l), 1);
}

/// R3: a step back to before the limiter's first use is caught the same way.
#[test]
fn a_step_back_before_the_first_use_admits() {
    let (l, clock) = limiter(secs(1000));
    drain(&l);
    clock.set(Duration::ZERO);
    assert!(matches!(
        l.acquire(),
        Acquire::AdmittedAfterClockStep { .. }
    ));
}

/// R4: one WARN-asking refusal per 60 s of the limiter's clock, the bucket
/// re-exhausted at every step.
#[test]
fn a_refusing_limiter_asks_for_a_warn_once_a_minute() {
    let (l, clock) = limiter(Duration::ZERO);
    assert!(matches!(
        drain_to(&l).1,
        Acquire::Refused { warn: true, .. }
    ));
    for s in 1..60 {
        clock.set(secs(s));
        assert!(
            matches!(drain_to(&l).1, Acquire::Refused { warn: false, .. }),
            "at {s} s"
        );
    }
    clock.set(secs(60));
    assert!(matches!(
        drain_to(&l).1,
        Acquire::Refused { warn: true, .. }
    ));
}

/// R4c: a WARN stamp left ahead of the clock by a step back does not mute
/// the refusals after the step until the clock reaches it again.
#[test]
fn a_warn_stamp_from_the_future_is_due() {
    let (l, clock) = limiter(secs(3600));
    assert!(matches!(
        drain_to(&l).1,
        Acquire::Refused { warn: true, .. }
    ));
    clock.set(secs(10));
    let (taken, refusal) = drain_to(&l);
    assert_eq!(taken, 50, "the reset call and the rebuilt bucket's 49");
    assert!(matches!(refusal, Acquire::Refused { warn: true, .. }));
}

/// R5: the default clock is `std::time::Instant`: the bare `RateLimiter`
/// binding takes the default, so the second compiles only while that default
/// is `MonotonicClock`.
#[test]
fn the_default_clock_is_std_instant() {
    fn send_sync<T: Send + Sync>() {}
    fn any_clock<C: Clock + Clone + Send + Sync>() {
        send_sync::<RateLimiter<C>>();
    }
    let l: RateLimiter = RateLimiter::new(&RateLimitConfig::default());
    let _: RateLimiter<MonotonicClock> = l;
    any_clock::<MonotonicClock>();
    any_clock::<StepClock>();
}

/// R6: callers racing the step share one rebuilt bucket.
#[test]
fn racing_callers_after_a_step_share_one_rebuilt_bucket() {
    let (l, clock) = limiter(secs(3610));
    drain(&l);
    clock.set(secs(10));
    let l = Arc::new(l);
    let start = Arc::new(std::sync::Barrier::new(8));
    let outcomes: Vec<Acquire> = (0..8)
        .map(|_| {
            let l = Arc::clone(&l);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                (0..20).map(|_| l.acquire()).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let resets = outcomes
        .iter()
        .filter(|o| matches!(o, Acquire::AdmittedAfterClockStep { .. }))
        .count();
    assert_eq!(resets, 1);
    assert_eq!(outcomes.iter().filter(|o| admitted(**o)).count(), 50);
}

/// R7: a step back of half an interval on an empty bucket, and a step back
/// with tokens left, both admit within one interval.
#[test]
fn small_steps_back_admit_within_one_interval() {
    let (l, clock) = limiter(secs(1000));
    drain(&l);
    clock.set(Duration::from_micros(999_995_000));
    assert!(admitted(l.acquire()), "a wait of 1.5 intervals is a step");

    let (l, clock) = limiter(secs(1000));
    for _ in 0..10 {
        assert!(admitted(l.acquire()));
    }
    clock.set(secs(999));
    assert!(admitted(l.acquire()));
}

/// The public `try_acquire` keeps its answers, and a disabled limiter admits
/// without a bucket.
#[test]
fn try_acquire_and_a_disabled_limiter_keep_their_answers() {
    let (l, clock) = limiter(secs(3610));
    for _ in 0..50 {
        assert!(l.try_acquire());
    }
    assert!(!l.try_acquire());
    clock.set(secs(10));
    assert!(
        l.try_acquire(),
        "a step back admits through try_acquire too"
    );

    l.set_enabled(false);
    for _ in 0..1000 {
        assert_eq!(l.acquire(), Acquire::Admitted);
    }
}
