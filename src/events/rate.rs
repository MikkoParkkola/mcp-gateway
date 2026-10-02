// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-subscription pacing (design §3.7) and the sustained-failure window
//! that suspends a subscription (design §6.5). In memory: a restart starts
//! both afresh, which only ever errs towards sending.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::EventsRateLimit;

/// One token bucket per subscription: `burst` deep, refilled at
/// `per_minute`. Over the limit an attempt waits; it is never dropped.
pub(crate) struct RateLimits {
    capacity: f64,
    per_second: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
    throttled: bool,
}

impl RateLimits {
    pub(crate) fn new(limit: &EventsRateLimit) -> Self {
        Self {
            capacity: f64::from(limit.burst.max(1)),
            per_second: f64::from(limit.per_minute.max(1)) / 60.0,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Keep only the buckets of subscriptions `keep` names.
    pub(crate) fn retain(&self, keep: &HashSet<String>) {
        self.buckets.lock().retain(|id, _| keep.contains(id));
    }

    /// Take a token for `id`, or say how long until one is free.
    pub(crate) fn take(&self, id: &str, now: Instant) -> Result<(), Duration> {
        let mut buckets = self.buckets.lock();
        let bucket = buckets.entry(id.to_owned()).or_insert(Bucket {
            tokens: self.capacity,
            at: now,
            throttled: false,
        });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.capacity);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            bucket.throttled = false;
            Ok(())
        } else {
            bucket.throttled = true;
            Err(Duration::from_secs_f64(
                (1.0 - bucket.tokens) / self.per_second,
            ))
        }
    }

    /// Whether `id` has a due delivery waiting on a token now.
    pub(crate) fn throttled(&self, id: &str) -> bool {
        self.buckets.lock().get(id).is_some_and(|b| b.throttled)
    }
}

/// Attempt outcomes per subscription over a sliding window.
pub(crate) struct FailureWindows {
    window: Duration,
    min_attempts: usize,
    seen: Mutex<HashMap<String, VecDeque<(Instant, bool)>>>,
}

impl FailureWindows {
    pub(crate) fn new(window: Duration, min_attempts: u32) -> Self {
        Self {
            window,
            min_attempts: usize::try_from(min_attempts).unwrap_or(usize::MAX),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Keep only the windows of subscriptions `keep` names.
    pub(crate) fn retain(&self, keep: &HashSet<String>) {
        self.seen.lock().retain(|id, _| keep.contains(id));
    }

    /// Record one attempt; `true` when the subscription must now be
    /// suspended: more than 95 % failures over at least `min_attempts`.
    pub(crate) fn record(&self, id: &str, delivered: bool, now: Instant) -> bool {
        let mut seen = self.seen.lock();
        let window = seen.entry(id.to_owned()).or_default();
        while window
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= self.window)
        {
            window.pop_front();
        }
        window.push_back((now, delivered));
        let failures = window.iter().filter(|(_, ok)| !ok).count();
        let suspend = window.len() >= self.min_attempts && failures * 100 > window.len() * 95;
        if suspend {
            // A reactivated subscription starts with a clean window.
            seen.remove(id);
        }
        suspend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_paced_and_reports_throttled() {
        let limits = RateLimits::new(&EventsRateLimit {
            per_minute: 60,
            burst: 2,
        });
        let t0 = Instant::now();
        assert!(limits.take("s", t0).is_ok());
        assert!(limits.take("s", t0).is_ok());
        let wait = limits.take("s", t0).expect_err("bucket empty");
        assert!(wait <= Duration::from_secs(1));
        assert!(limits.throttled("s"));
        assert!(limits.take("s", t0 + Duration::from_secs(1)).is_ok());
        assert!(!limits.throttled("s"));
    }

    #[test]
    fn suspends_only_past_the_minimum_attempts() {
        let windows = FailureWindows::new(Duration::from_secs(60), 5);
        let t0 = Instant::now();
        for _ in 0..4 {
            assert!(!windows.record("s", false, t0), "below the minimum");
        }
        assert!(windows.record("s", false, t0), "fifth failure suspends");
        assert!(!windows.record("s", false, t0), "window cleared");
    }

    #[test]
    fn retain_forgets_subscriptions_that_are_gone() {
        let limits = RateLimits::new(&EventsRateLimit {
            per_minute: 60,
            burst: 1,
        });
        let windows = FailureWindows::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        for id in ["kept", "gone"] {
            assert!(limits.take(id, t0).is_ok());
            assert!(!windows.record(id, false, t0));
        }
        let keep = HashSet::from(["kept".to_owned()]);
        limits.retain(&keep);
        windows.retain(&keep);
        assert!(limits.take("kept", t0).is_err(), "kept its spent bucket");
        assert!(limits.take("gone", t0).is_ok(), "a fresh bucket");
        assert!(windows.record("kept", false, t0), "kept its failure");
        assert!(!windows.record("gone", false, t0), "a fresh window");
    }
}
