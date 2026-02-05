//! Backend health tracking with latency metrics
//!
//! Tracks per-backend health metrics including:
//! - Success/failure counts
//! - Request latency percentiles (p50, p95, p99)
//! - Last success/failure timestamps
//! - Overall health status

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::Serialize;
use tracing::{debug, info, warn};

/// Default capacity for latency histogram
const DEFAULT_HISTOGRAM_CAPACITY: usize = 1000;

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

    /// Record a successful request
    pub fn record_success(&self, latency: Duration) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            Ordering::Relaxed,
        );

        // Record latency
        self.latencies.write().record(latency);

        // Mark as healthy after success
        if !self.healthy.load(Ordering::Relaxed) {
            self.healthy.store(true, Ordering::Relaxed);
            info!(backend = %self.name, "Backend recovered");
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.last_failure.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            Ordering::Relaxed,
        );

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

/// Latency histogram for percentile calculation
struct LatencyHistogram {
    /// Recent latency samples (in milliseconds)
    samples: Vec<u64>,
    /// Maximum number of samples to keep
    capacity: usize,
    /// Sorted flag to avoid repeated sorting
    sorted: bool,
}

impl LatencyHistogram {
    /// Create a new histogram
    fn new(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
            capacity,
            sorted: true,
        }
    }

    /// Record a latency sample
    fn record(&mut self, latency: Duration) {
        let millis = latency.as_millis() as u64;

        if self.samples.len() >= self.capacity {
            // Remove oldest sample (FIFO)
            self.samples.remove(0);
        }

        self.samples.push(millis);
        self.sorted = false;
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

            let index = ((sorted_samples.len() as f64) * p).floor() as usize;
            let index = index.min(sorted_samples.len() - 1);
            return Some(Duration::from_millis(sorted_samples[index]));
        }

        let index = ((self.samples.len() as f64) * p).floor() as usize;
        let index = index.min(self.samples.len() - 1);
        Some(Duration::from_millis(self.samples[index]))
    }

    /// Clear all samples
    fn clear(&mut self) {
        self.samples.clear();
        self.sorted = true;
    }
}

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
        histogram.record(Duration::from_millis(10));
        histogram.record(Duration::from_millis(20));
        histogram.record(Duration::from_millis(30));
        histogram.record(Duration::from_millis(40));
        histogram.record(Duration::from_millis(50));

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
            histogram.record(Duration::from_millis(i * 10));
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
