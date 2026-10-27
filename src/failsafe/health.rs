// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend health tracking with latency metrics
//!
//! Tracks per-backend health metrics including:
//! - Success/failure counts
//! - Request latency percentiles (p50, p95, p99)
//! - Last success/failure timestamps
//! - Overall health status

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use serde::Serialize;
use tracing::{debug, info, warn};

/// Default capacity for latency histogram
const DEFAULT_HISTOGRAM_CAPACITY: usize = 1000;

/// Successful calls in one batch: the recent window, and one baseline update.
const SLOW_BATCH: usize = 100;
/// Batches the baseline absorbs before any Slow verdict (500 calls), so a
/// restart or a quiet server never flags noise.
// The verdict's only reader is the web UI's status row.
#[cfg(any(test, feature = "webui"))]
const SLOW_WARM_BATCHES: u32 = 5;
/// The recent p95 must exceed this many times the baseline.
// The verdict's only reader is the web UI's status row.
#[cfg(any(test, feature = "webui"))]
const SLOW_FACTOR: u64 = 3;
/// Below this recent p95 nothing is slow: a few-ms swing is slow to nobody.
// The verdict's only reader is the web UI's status row.
#[cfg(any(test, feature = "webui"))]
const SLOW_FLOOR_MS: u64 = 50;
/// The baseline is an average of batch p95s with weight 1 / `SLOW_DECAY`,
/// held times `SLOW_DECAY` so steps under `SLOW_DECAY` ms still move it.
const SLOW_DECAY: u64 = 64;

/// Whether a reply counts toward the Slow window. A throttled reply proves
/// the server answered, not how fast it serves a call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    Answered,
    Throttled,
}

/// A running server's recent p95 against its usual one, both in ms.
#[cfg(any(test, feature = "webui"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slow {
    pub recent_ms: u64,
    pub usual_ms: u64,
}

/// Backend health tracker
pub struct HealthTracker {
    /// Backend name
    name: String,
    /// Whether backend is currently healthy
    healthy: AtomicBool,
    /// Total successful requests
    success_count: AtomicU64,
    /// Total failed requests
    failure_count: AtomicU64,
    /// Consecutive failures
    consecutive_failures: AtomicU64,
    /// Last successful request timestamp (millis since epoch)
    last_success: AtomicU64,
    /// Last failed request timestamp (millis since epoch)
    last_failure: AtomicU64,
    /// Latency histogram (for percentile calculation)
    latencies: RwLock<LatencyHistogram>,
}

impl HealthTracker {
    /// Create a new health tracker
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            healthy: AtomicBool::new(true),
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            last_success: AtomicU64::new(0),
            last_failure: AtomicU64::new(0),
            latencies: RwLock::new(LatencyHistogram::new(DEFAULT_HISTOGRAM_CAPACITY)),
        }
    }

    /// Record a successful request. On a clock before 1970 the success
    /// still counts, but the last-success time is left unchanged (MIK-8202).
    pub fn record_success(&self, latency: Duration) {
        self.record_reply(latency, Reply::Answered);
    }

    /// Record a throttled reply: counted as [`Self::record_success`] counts
    /// one, and kept out of the Slow window.
    pub(crate) fn record_throttled(&self, latency: Duration) {
        self.record_reply(latency, Reply::Throttled);
    }

    fn record_reply(&self, latency: Duration, reply: Reply) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if let Ok(now_ms) = crate::clock::unix_millis() {
            self.last_success.store(now_ms, Ordering::Relaxed);
        }

        // Record latency
        self.latencies.write().record(latency, reply);

        // Mark as healthy after success
        if !self.healthy.load(Ordering::Relaxed) {
            self.healthy.store(true, Ordering::Relaxed);
            info!(backend = %self.name, "Backend recovered");
        }
    }

    /// Record a failed request. On a clock before 1970 the failure
    /// still counts, but the last-failure time is left unchanged (MIK-8202).
    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(now_ms) = crate::clock::unix_millis() {
            self.last_failure.store(now_ms, Ordering::Relaxed);
        }

        // Mark as unhealthy after threshold
        if consecutive >= 3 && self.healthy.load(Ordering::Relaxed) {
            self.healthy.store(false, Ordering::Relaxed);
            warn!(
                backend = %self.name,
                consecutive_failures = consecutive,
                "Backend marked unhealthy"
            );
        }
    }

    /// Check if backend is currently healthy
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Get current health metrics
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // latency millis fits u64
    pub fn metrics(&self) -> HealthMetrics {
        let latencies = self.latencies.read();

        HealthMetrics {
            backend: self.name.clone(),
            healthy: self.healthy.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
            failure_count: self.failure_count.load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            last_success_ms: self.last_success.load(Ordering::Relaxed),
            last_failure_ms: self.last_failure.load(Ordering::Relaxed),
            latency_p50_ms: latencies.percentile(0.50).map(|d| d.as_millis() as u64),
            latency_p95_ms: latencies.percentile(0.95).map(|d| d.as_millis() as u64),
            latency_p99_ms: latencies.percentile(0.99).map(|d| d.as_millis() as u64),
        }
    }

    /// Its recent p95 and its usual p95 in ms, when the recent one is over
    /// three times the usual and at least 50 ms; `None` until 500 answered
    /// calls have warmed the usual one.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn slow(&self) -> Option<Slow> {
        self.latencies.read().slow()
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.success_count.store(0, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success.store(0, Ordering::Relaxed);
        self.last_failure.store(0, Ordering::Relaxed);
        self.latencies.write().clear();
        self.healthy.store(true, Ordering::Relaxed);

        debug!(backend = %self.name, "Health metrics reset");
    }
}

/// Health metrics snapshot
#[derive(Debug, Clone, Serialize)]
pub struct HealthMetrics {
    /// Backend name
    pub backend: String,
    /// Current health status
    pub healthy: bool,
    /// Total successful requests
    pub success_count: u64,
    /// Total failed requests
    pub failure_count: u64,
    /// Consecutive failures
    pub consecutive_failures: u64,
    /// Last success timestamp (millis since epoch)
    pub last_success_ms: u64,
    /// Last failure timestamp (millis since epoch)
    pub last_failure_ms: u64,
    /// 50th percentile latency (milliseconds)
    pub latency_p50_ms: Option<u64>,
    /// 95th percentile latency (milliseconds)
    pub latency_p95_ms: Option<u64>,
    /// 99th percentile latency (milliseconds)
    pub latency_p99_ms: Option<u64>,
}

/// Which sorted sample is the `p` percentile of `len` samples: floor(len × p),
/// capped at the last. The one rule the latency panel and the Slow window both
/// read, so their p95s can differ only by the samples each window holds.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn percentile_index(len: usize, p: f64) -> usize {
    (((len as f64) * p).floor() as usize).min(len.saturating_sub(1))
}

/// Latency histogram for percentile calculation
struct LatencyHistogram {
    /// Recent latency samples (in milliseconds)
    samples: Vec<u64>,
    /// Maximum number of samples to keep
    capacity: usize,
    /// Sorted flag to avoid repeated sorting
    sorted: bool,
    /// The baseline p95 in ms, times `SLOW_DECAY`.
    baseline_x64: u64,
    /// Complete batches folded into the baseline.
    batches: u32,
    /// The last `SLOW_BATCH` answered calls, oldest first: the Slow window,
    /// apart from `samples`, which throttled replies also feed.
    window: std::collections::VecDeque<u64>,
    /// Answered calls since the last complete batch.
    in_batch: usize,
}

impl LatencyHistogram {
    /// Create a new histogram
    fn new(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
            capacity,
            sorted: true,
            baseline_x64: 0,
            batches: 0,
            window: std::collections::VecDeque::with_capacity(SLOW_BATCH),
            in_batch: 0,
        }
    }

    /// Record a latency sample
    #[allow(clippy::cast_possible_truncation)] // latency millis fits u64
    fn record(&mut self, latency: Duration, reply: Reply) {
        let millis = latency.as_millis() as u64;

        if self.samples.len() >= self.capacity {
            // Remove oldest sample (FIFO)
            self.samples.remove(0);
        }

        self.samples.push(millis);
        self.sorted = false;

        if reply == Reply::Throttled {
            return;
        }
        if self.window.len() == SLOW_BATCH {
            self.window.pop_front();
        }
        self.window.push_back(millis);
        // Every full batch folds its p95 into the baseline; the first seeds it.
        // The window and the batch are both SLOW_BATCH long, so at this point
        // the window holds exactly the batch just completed.
        self.in_batch += 1;
        if self.in_batch == SLOW_BATCH {
            self.in_batch = 0;
            let batch = self.recent_p95();
            self.baseline_x64 = if self.batches == 0 {
                batch.saturating_mul(SLOW_DECAY)
            } else {
                // Never underflows: the subtracted part is at most the whole.
                (self.baseline_x64 - self.baseline_x64 / SLOW_DECAY).saturating_add(batch)
            };
            self.batches = self.batches.saturating_add(1);
        }
    }

    /// Calculate percentile (0.0 to 1.0)
    fn percentile(&self, p: f64) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }

        // Ensure samples are sorted
        if !self.sorted {
            // We need mutable access to sort, but we're in an immutable method
            // This is a design tradeoff - we'll need to sort on every read if not sorted
            // In practice, this is acceptable for health metrics which are read infrequently
            let mut sorted_samples = self.samples.clone();
            sorted_samples.sort_unstable();

            let index = percentile_index(sorted_samples.len(), p);
            return Some(Duration::from_millis(sorted_samples[index]));
        }

        let index = percentile_index(self.samples.len(), p);
        Some(Duration::from_millis(self.samples[index]))
    }

    /// The p95 of the Slow window (the last `SLOW_BATCH` answered calls, or
    /// fewer before that many), by [`percentile_index`] as the panel's is.
    fn recent_p95(&self) -> u64 {
        let mut recent: Vec<u64> = self.window.iter().copied().collect();
        recent.sort_unstable();
        recent
            .get(percentile_index(recent.len(), 0.95))
            .copied()
            .unwrap_or(0)
    }

    /// The recent p95 and the baseline, when the baseline is warm and the
    /// recent one is over `SLOW_FACTOR` times it and at least `SLOW_FLOOR_MS`.
    #[cfg(any(test, feature = "webui"))]
    fn slow(&self) -> Option<Slow> {
        if self.batches < SLOW_WARM_BATCHES {
            return None;
        }
        let recent_ms = self.recent_p95();
        let usual_ms = self.baseline_x64 / SLOW_DECAY;
        (recent_ms >= SLOW_FLOOR_MS && recent_ms > SLOW_FACTOR.saturating_mul(usual_ms)).then_some(
            Slow {
                recent_ms,
                usual_ms,
            },
        )
    }

    /// Clear all samples, and the baseline with them: a reset warms up again.
    fn clear(&mut self) {
        self.samples.clear();
        self.sorted = true;
        self.baseline_x64 = 0;
        self.batches = 0;
        self.window.clear();
        self.in_batch = 0;
    }
}

#[cfg(test)]
#[path = "health_slow_tests.rs"]
mod slow_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tracker_success() {
        let tracker = HealthTracker::new("test-backend");

        assert!(tracker.is_healthy());
        assert_eq!(tracker.success_count.load(Ordering::Relaxed), 0);

        tracker.record_success(Duration::from_millis(50));

        assert!(tracker.is_healthy());
        assert_eq!(tracker.success_count.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.failure_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_health_tracker_failure() {
        let tracker = HealthTracker::new("test-backend");

        assert!(tracker.is_healthy());

        // First failure - still healthy
        tracker.record_failure();
        assert!(tracker.is_healthy());

        // Second failure - still healthy
        tracker.record_failure();
        assert!(tracker.is_healthy());

        // Third failure - now unhealthy
        tracker.record_failure();
        assert!(!tracker.is_healthy());

        assert_eq!(tracker.failure_count.load(Ordering::Relaxed), 3);
        assert_eq!(tracker.consecutive_failures.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_health_tracker_recovery() {
        let tracker = HealthTracker::new("test-backend");

        // Make unhealthy
        tracker.record_failure();
        tracker.record_failure();
        tracker.record_failure();
        assert!(!tracker.is_healthy());

        // Recover with success
        tracker.record_success(Duration::from_millis(50));
        assert!(tracker.is_healthy());
        assert_eq!(tracker.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_latency_histogram() {
        let mut histogram = LatencyHistogram::new(10);

        // Record some latencies
        histogram.record(Duration::from_millis(10), Reply::Answered);
        histogram.record(Duration::from_millis(20), Reply::Answered);
        histogram.record(Duration::from_millis(30), Reply::Answered);
        histogram.record(Duration::from_millis(40), Reply::Answered);
        histogram.record(Duration::from_millis(50), Reply::Answered);

        // Check percentiles
        let p50 = histogram.percentile(0.50).unwrap();
        assert_eq!(p50.as_millis(), 30);

        let p95 = histogram.percentile(0.95).unwrap();
        assert!(p95.as_millis() >= 45);
    }

    #[test]
    fn test_latency_histogram_capacity() {
        let mut histogram = LatencyHistogram::new(5);

        // Record more than capacity
        for i in 1..=10 {
            histogram.record(Duration::from_millis(i * 10), Reply::Answered);
        }

        // Should only keep last 5
        assert_eq!(histogram.samples.len(), 5);

        // Should have kept 60, 70, 80, 90, 100
        let p50 = histogram.percentile(0.50).unwrap();
        assert!(p50.as_millis() >= 70 && p50.as_millis() <= 90);
    }

    #[test]
    fn test_health_metrics() {
        let tracker = HealthTracker::new("test-backend");

        tracker.record_success(Duration::from_millis(50));
        tracker.record_success(Duration::from_millis(100));
        tracker.record_failure();

        let metrics = tracker.metrics();

        assert_eq!(metrics.backend, "test-backend");
        assert!(metrics.healthy);
        assert_eq!(metrics.success_count, 2);
        assert_eq!(metrics.failure_count, 1);
        assert_eq!(metrics.consecutive_failures, 1);
        assert!(metrics.last_success_ms > 0);
        assert!(metrics.last_failure_ms > 0);
        assert!(metrics.latency_p50_ms.is_some());
    }
}

#[cfg(test)]
#[path = "health_clock_tests.rs"]
mod clock_tests;
