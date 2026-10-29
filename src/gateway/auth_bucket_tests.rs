// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `ClientBucket` against `governor`: the same allow and deny sequence as
//! `Quota::per_minute(rate)` for a burst, a steady stream and a refill across a
//! minute, on an injected clock (no sleeps); then the resize rules, and the
//! cap under concurrent callers.

use std::num::NonZeroU32;
use std::time::Duration;

use governor::clock::FakeRelativeClock;
use governor::{Quota, RateLimiter};

use super::{AuthRuntime, ClientBucket, interval};

const MINUTE: u64 = 60_000_000_000;

/// Rates that divide 60 and rates that do not, from one a minute up.
const RATES: [u32; 5] = [1, 7, 13, 60, 1000];

fn rate(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("a test rate is non-zero")
}

/// Each request time in `schedule` (non-decreasing nanoseconds), judged by
/// `governor` and by the bucket: the two allow and deny sequences.
fn both(n: u32, schedule: &[u64]) -> (Vec<bool>, Vec<bool>) {
    let clock = FakeRelativeClock::default();
    let limiter = RateLimiter::direct_with_clock(Quota::per_minute(rate(n)), clock.clone());
    let bucket = ClientBucket::new(rate(n));
    let mut last = 0;
    let mut theirs = Vec::new();
    let mut ours = Vec::new();
    for &at in schedule {
        clock.advance(Duration::from_nanos(at - last));
        last = at;
        theirs.push(limiter.check().is_ok());
        ours.push(bucket.check_at(rate(n), at));
    }
    (theirs, ours)
}

#[test]
fn a_burst_matches_governor() {
    for n in RATES {
        let schedule = vec![0; n as usize + 2];
        let (theirs, ours) = both(n, &schedule);
        assert_eq!(ours, theirs, "rate {n}");
        assert_eq!(
            ours.iter().filter(|ok| **ok).count(),
            n as usize,
            "rate {n}: burst = rate"
        );
    }
}

#[test]
fn a_steady_stream_at_twice_the_rate_matches_governor() {
    for n in RATES {
        let step = (interval(rate(n)) / 2).max(1);
        let schedule: Vec<u64> = (0..=3 * MINUTE / step).map(|i| i * step).collect();
        let (theirs, ours) = both(n, &schedule);
        assert_eq!(ours, theirs, "rate {n}");
    }
}

#[test]
fn a_refill_across_a_minute_matches_governor() {
    for n in RATES {
        let t = interval(rate(n));
        let mut schedule = vec![0; n as usize + 1];
        schedule.extend(std::iter::repeat_n(MINUTE, n as usize + 1));
        schedule.extend([MINUTE + t - 1, MINUTE + t, MINUTE + 2 * t]);
        let (theirs, ours) = both(n, &schedule);
        assert_eq!(ours, theirs, "rate {n}");
    }
}

/// Integer units: a rate that does not divide a minute truncates exactly as
/// `governor` does, so the two clocks never drift apart.
#[test]
fn a_rate_that_does_not_divide_a_minute_truncates_as_governor_does() {
    assert_eq!(interval(rate(7)), 8_571_428_571);
    assert_eq!(
        Duration::from_nanos(interval(rate(7))),
        Quota::per_minute(rate(7)).replenish_interval()
    );
    let (theirs, ours) = both(7, &[0, 0, 0, 0, 0, 0, 0, 0, 8_571_428_570, 8_571_428_571]);
    assert_eq!(ours, theirs);
    assert_eq!(&ours[7..], &[false, false, true]);
}

/// Tightened below what was spent: the next request waits for the refill.
#[test]
fn a_rate_tightened_below_usage_denies_until_refill() {
    let bucket = ClientBucket::new(rate(3));
    assert!(bucket.check_at(rate(3), 0) && bucket.check_at(rate(3), 0));
    assert!(!bucket.check_at(rate(1), 0), "two owed at 1/min");
    assert!(
        !bucket.check_at(rate(1), MINUTE),
        "one still owed after a minute"
    );
    assert!(bucket.check_at(rate(1), 2 * MINUTE), "both refilled");
}

/// Loosened: what was spent stays spent.
#[test]
fn a_rate_loosened_keeps_the_usage() {
    let bucket = ClientBucket::new(rate(3));
    assert!((0..3).all(|_| bucket.check_at(rate(3), 0)));
    assert!(bucket.check_at(rate(5), 0) && bucket.check_at(rate(5), 0));
    assert!(
        !bucket.check_at(rate(5), 0),
        "three of five were already spent"
    );
}

/// The same rate changes nothing: the bucket decides as one never re-priced.
#[test]
fn the_same_rate_changes_nothing() {
    // 2/min: 30 s a request, a burst of two. Two at 0 fill it; the next fits
    // at exactly 30 s, not a nanosecond before.
    let bucket = ClientBucket::new(rate(2));
    let decisions: Vec<bool> = [0, 0, 1, 29_999_999_999, 30_000_000_000]
        .into_iter()
        .map(|at| bucket.check_at(rate(2), at))
        .collect();
    assert_eq!(decisions, [true, true, false, false, true]);
}

/// The theoretical arrival time a bucket holds.
fn tat(bucket: &ClientBucket) -> Option<u64> {
    bucket.state.lock().tat
}

/// Re-priced mid-interval and back. 3/min with two spent at 0 owes 40 s.
/// At 7 s, 5/min re-prices the 33 s owed to 19.8 s and admits one more
/// (owed 31.8 s, so the arrival time is 38.8 s). At 10 s, 3/min re-prices the
/// 28.8 s owed to 48 s, past the 40 s tolerance: denied until 18 s.
#[test]
fn a_rate_changed_mid_interval_and_back_reprices_what_is_owed() {
    let bucket = ClientBucket::new(rate(3));
    assert!(bucket.check_at(rate(3), 0) && bucket.check_at(rate(3), 0));
    assert_eq!(tat(&bucket), Some(40_000_000_000));
    assert!(bucket.check_at(rate(5), 7_000_000_000));
    assert_eq!(tat(&bucket), Some(38_800_000_000));
    assert!(!bucket.check_at(rate(3), 10_000_000_000));
    assert_eq!(tat(&bucket), Some(58_000_000_000));
    assert!(!bucket.check_at(rate(3), 17_999_999_999));
    assert!(bucket.check_at(rate(3), 18_000_000_000));
}

/// Re-priced after idle time: 3/min with three spent at 0 owes 60 s; by 50 s
/// it owes 10 s, half a request; tightened to 1/min that is 30 s, so the next
/// request waits until 80 s.
#[test]
fn a_rate_tightened_after_idle_reprices_only_what_is_still_owed() {
    let bucket = ClientBucket::new(rate(3));
    assert!((0..3).all(|_| bucket.check_at(rate(3), 0)));
    assert!(
        !bucket.check_at(rate(1), 50_000_000_000),
        "half a request still owed"
    );
    assert_eq!(tat(&bucket), Some(80_000_000_000));
    assert!(!bucket.check_at(rate(1), 79_999_999_999));
    assert!(bucket.check_at(rate(1), 80_000_000_000));
}

/// The largest rates: the interval truncates to 13 ns at `u32::MAX`, the
/// tolerance does not overflow, and a burst matches `governor`.
#[test]
fn the_largest_rates_match_governor_and_do_not_overflow() {
    for n in [u32::MAX, u32::MAX - 1, 1_000_000_000] {
        assert_eq!(
            Duration::from_nanos(interval(rate(n))),
            Quota::per_minute(rate(n)).replenish_interval(),
            "rate {n}"
        );
        let (theirs, ours) = both(n, &[0; 1000]);
        assert_eq!(ours, theirs, "rate {n}");
    }
    assert_eq!(interval(rate(u32::MAX)), 13);
}

/// Many callers at once never exceed the bucket.
#[test]
fn concurrent_callers_never_exceed_the_bucket() {
    let bucket = std::sync::Arc::new(ClientBucket::new(rate(50)));
    let admitted: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let bucket = &bucket;
                scope.spawn(move || (0..100).filter(|_| bucket.check_at(rate(50), 0)).count())
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a caller finishes"))
            .sum()
    });
    assert_eq!(admitted, 50);
}

/// Cost against `governor`, run once in release (`--release -- --ignored`):
/// 1M checks per limiter, uncontended and from 8 threads on one bucket. It
/// prints the four figures and asserts nothing about time.
#[test]
#[ignore = "a timing comparison, run once in release; it asserts nothing about time"]
fn cost_against_governor() {
    const CHECKS: u32 = 1_000_000;
    const THREADS: u32 = 8;
    let max = NonZeroU32::MAX;
    let ns_per = |elapsed: Duration| elapsed.as_nanos() / u128::from(CHECKS);

    let theirs = RateLimiter::direct(Quota::per_minute(max));
    let start = std::time::Instant::now();
    let admitted = (0..CHECKS).filter(|_| theirs.check().is_ok()).count();
    let governor_alone = ns_per(start.elapsed());
    assert_eq!(admitted, CHECKS as usize, "premise: nothing denied");

    let ours = ClientBucket::new(max);
    let start = std::time::Instant::now();
    let admitted = (0..CHECKS)
        .filter(|_| ours.check_at(max, super::now_ns()))
        .count();
    let bucket_alone = ns_per(start.elapsed());
    assert_eq!(admitted, CHECKS as usize, "premise: nothing denied");

    let theirs = RateLimiter::direct(Quota::per_minute(max));
    let start = std::time::Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                (0..CHECKS / THREADS).for_each(|_| {
                    let _ = theirs.check();
                });
            });
        }
    });
    let governor_shared = ns_per(start.elapsed());

    let ours = ClientBucket::new(max);
    let start = std::time::Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                (0..CHECKS / THREADS).for_each(|_| {
                    let _ = ours.check_at(max, super::now_ns());
                });
            });
        }
    });
    let bucket_shared = ns_per(start.elapsed());

    // The request path as it runs: the store lookup by a freshly built key,
    // at a rate that admits everything and at one that denies nearly all.
    let runtime = AuthRuntime::default();
    let start = std::time::Instant::now();
    (0..CHECKS).for_each(|_| {
        let _ = runtime.admit("a-client-state-key".to_owned(), max);
    });
    let admit_allowed = ns_per(start.elapsed());
    let start = std::time::Instant::now();
    (0..CHECKS).for_each(|_| {
        let _ = runtime.admit("a-limited-client".to_owned(), rate(60));
    });
    let admit_denied = ns_per(start.elapsed());

    println!(
        "ns per check: governor {governor_alone} alone, {governor_shared} from {THREADS} threads; \
         bucket {bucket_alone} alone, {bucket_shared} from {THREADS} threads; \
         AuthRuntime::admit {admit_allowed} allowed, {admit_denied} mostly denied"
    );
}
