use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A browser-automation task descriptor.
#[derive(Debug, Clone)]
pub struct TaskDescriptor {
    /// Type of task (e.g. "scrape", "navigate").
    pub task_type: String,
    /// Target URL for the browser automation.
    pub target_url: String,
    /// Named parameters for the task.
    pub parameters: BTreeMap<String, Value>,
}

impl TaskDescriptor {
    /// Create a new task descriptor.
    pub fn new(
        task_type: impl Into<String>,
        target_url: impl Into<String>,
    ) -> Self {
        Self {
            task_type: task_type.into(),
            target_url: target_url.into(),
            parameters: BTreeMap::new(),
        }
    }

    /// Add a parameter to the descriptor (builder-style).
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }
}

/// Result of a completed browser-automation task.
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// JSON data produced by the task.
    pub data: Value,
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Captured DOM snapshot, if any.
    pub dom_snapshot: Option<String>,
    /// Paths to screenshots taken during the task.
    pub screenshot_paths: Vec<String>,
    /// JSON-encoded model trace, if captured.
    pub model_trace: Option<String>,
}

impl TaskResult {
    /// Whether the task completed successfully.
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Hebb-embedded task memory cache (zero-IPC, in-process).
///
/// Provides recall-based short-circuiting for repeat browser-automation tasks.
/// On a cache hit, the cached [`TaskResult`] is returned without re-executing
/// the browser automation, giving a measurable short-circuit on the second run
/// of the same task.
///
/// Follows the `TransitionTracker` / `ResponseCache` patterns: `DashMap` for
/// concurrent access, `AtomicU64` for lock-free stats counters, lazy TTL
/// expiry on recall.
pub struct TaskMemory {
    entries: DashMap<String, MemoryEntry>,
    hits: AtomicU64,
    misses: AtomicU64,
    stores: AtomicU64,
}

struct MemoryEntry {
    result: TaskResult,
    cached_at: Instant,
    ttl: Duration,
    recall_count: AtomicU64,
}

impl TaskMemory {
    /// Create a new, empty task memory cache.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stores: AtomicU64::new(0),
        }
    }

    /// Build a deterministic cache key from a task descriptor.
    ///
    /// Key = `SHA-256(task_type || \0 || target_url || \0 || canonical_params_json)`.
    pub fn build_key(descriptor: &TaskDescriptor) -> String {
        let mut hasher = Sha256::new();
        hasher.update(descriptor.task_type.as_bytes());
        hasher.update(b"\0");
        hasher.update(descriptor.target_url.as_bytes());
        hasher.update(b"\0");
        let params_json = serde_json::to_string(&descriptor.parameters)
            .unwrap_or_default();
        hasher.update(params_json.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Recall a cached task result. Returns `Some` on cache hit (short-circuit),
    /// `None` on miss or expired entry. Returns a clone to avoid lifetime
    /// issues with the concurrent map guard.
    pub fn recall(&self, descriptor: &TaskDescriptor) -> Option<TaskResult> {
        let key = Self::build_key(descriptor);
        if let Some(entry) = self.entries.get(&key) {
            if entry.cached_at.elapsed() > entry.ttl {
                drop(entry);
                self.entries.remove(&key);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            entry.recall_count.fetch_add(1, Ordering::Relaxed);
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.result.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Store a task result in the cache.
    pub fn store(&self, descriptor: &TaskDescriptor, result: TaskResult, ttl: Duration) {
        let key = Self::build_key(descriptor);
        let entry = MemoryEntry {
            result,
            cached_at: Instant::now(),
            ttl,
            recall_count: AtomicU64::new(0),
        };
        self.entries.insert(key, entry);
        self.stores.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total cache hits (monotonic).
    pub fn total_hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Total cache misses (monotonic).
    pub fn total_misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Total stores (monotonic).
    pub fn total_stores(&self) -> u64 {
        self.stores.load(Ordering::Relaxed)
    }

    /// Snapshot of recall statistics.
    pub fn recall_stats(&self) -> RecallStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        #[allow(clippy::cast_precision_loss)]
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };
        RecallStats {
            hits,
            misses,
            total,
            stores: self.stores.load(Ordering::Relaxed),
            hit_rate,
        }
    }
}

impl Default for TaskMemory {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of hebb-recall statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecallStats {
    /// Total cache hits (monotonic).
    pub hits: u64,
    /// Total cache misses (monotonic).
    pub misses: u64,
    /// Total recall attempts (hits + misses).
    pub total: u64,
    /// Total cache stores (monotonic).
    pub stores: u64,
    /// Cache hit rate (hits / total), 0.0 when no attempts.
    pub hit_rate: f64,
}

/// Hebb decision-pin: a browser-task checkpoint durable under tag 'webwright-spike'.
///
/// Records the outcome of a single task decision (cache hit vs miss, success vs
/// failure) for audit and durability verification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HebbDecisionPin {
    /// Unique identifier for this pin (UUID v4).
    pub pin_id: String,
    /// Tag grouping pins (always "webwright-spike" for this spike).
    pub tag: String,
    /// Task type that was executed.
    pub task_type: String,
    /// Target URL of the browser automation.
    pub target_url: String,
    /// Decision outcome (e.g. `"cache_hit"`, `"cache_miss"`).
    pub decision: String,
    /// RFC3339 timestamp when the pin was recorded.
    pub timestamp: String,
    /// Attestation token ID linking this pin to a validated run.
    pub attestation_token_id: Option<String>,
}

impl HebbDecisionPin {
    /// Create a new decision pin under the given tag.
    pub fn new(
        tag: impl Into<String>,
        descriptor: &TaskDescriptor,
        decision: impl Into<String>,
    ) -> Self {
        Self {
            pin_id: uuid::Uuid::new_v4().to_string(),
            tag: tag.into(),
            task_type: descriptor.task_type.clone(),
            target_url: descriptor.target_url.clone(),
            decision: decision.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            attestation_token_id: None,
        }
    }

    /// Attach an attestation token ID to this pin.
    #[must_use]
    pub fn with_attestation(mut self, token_id: impl Into<String>) -> Self {
        self.attestation_token_id = Some(token_id.into());
        self
    }
}

/// Collection of hebb decision-pins for a spike run.
pub struct HebbDecisionPins {
    pins: Mutex<Vec<HebbDecisionPin>>,
}

impl HebbDecisionPins {
    /// Create an empty pin collection.
    pub fn new() -> Self {
        Self {
            pins: Mutex::new(Vec::new()),
        }
    }

    /// Record a decision pin.
    pub fn pin(&self, pin: HebbDecisionPin) {
        self.pins.lock().push(pin);
    }

    /// Snapshot all pins.
    pub fn snapshot(&self) -> Vec<HebbDecisionPin> {
        self.pins.lock().clone()
    }

    /// Number of recorded pins.
    pub fn len(&self) -> usize {
        self.pins.lock().len()
    }

    /// Whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.pins.lock().is_empty()
    }

    /// Count pins matching the given tag.
    pub fn count_by_tag(&self, tag: &str) -> usize {
        self.pins.lock().iter().filter(|p| p.tag == tag).count()
    }
}

impl Default for HebbDecisionPins {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn task_memory_recall_miss_then_hit() {
        let mem = TaskMemory::new();
        let desc = TaskDescriptor::new("scrape", "https://example.com");

        assert!(mem.recall(&desc).is_none());
        assert_eq!(mem.total_misses(), 1);
        assert_eq!(mem.total_hits(), 0);
    }

    #[test]
    fn task_memory_store_then_recall() {
        let mem = TaskMemory::new();
        let desc = TaskDescriptor::new("scrape", "https://example.com");
        let result = TaskResult {
            data: json!({"rows": 42}),
            exit_code: 0,
            dom_snapshot: None,
            screenshot_paths: vec![],
            model_trace: None,
        };

        mem.store(&desc, result, Duration::from_secs(300));
        assert_eq!(mem.len(), 1);
        assert_eq!(mem.total_stores(), 1);

        let recalled = mem.recall(&desc);
        assert!(recalled.is_some());
        assert_eq!(mem.total_hits(), 1);
        assert_eq!(mem.total_misses(), 0);
    }

    #[test]
    fn task_memory_different_descriptors_different_keys() {
        let d1 = TaskDescriptor::new("scrape", "https://a.com");
        let d2 = TaskDescriptor::new("scrape", "https://b.com");

        assert_ne!(TaskMemory::build_key(&d1), TaskMemory::build_key(&d2));
    }

    #[test]
    fn decision_pin_carries_tag() {
        let desc = TaskDescriptor::new("scrape", "https://example.com");
        let pin = HebbDecisionPin::new("webwright-spike", &desc, "cache_miss");
        assert_eq!(pin.tag, "webwright-spike");
        assert!(pin.attestation_token_id.is_none());
    }

    #[test]
    fn decision_pin_with_attestation() {
        let desc = TaskDescriptor::new("scrape", "https://example.com");
        let pin = HebbDecisionPin::new("webwright-spike", &desc, "cache_hit")
            .with_attestation("tok-123");
        assert_eq!(pin.attestation_token_id.as_deref(), Some("tok-123"));
    }

    #[test]
    fn decision_pins_count_by_tag() {
        let pins = HebbDecisionPins::new();
        let desc = TaskDescriptor::new("scrape", "https://example.com");
        pins.pin(HebbDecisionPin::new("webwright-spike", &desc, "miss"));
        pins.pin(HebbDecisionPin::new("webwright-spike", &desc, "hit"));
        pins.pin(HebbDecisionPin::new("other-tag", &desc, "miss"));

        assert_eq!(pins.count_by_tag("webwright-spike"), 2);
        assert_eq!(pins.count_by_tag("other-tag"), 1);
        assert_eq!(pins.count_by_tag("nonexistent"), 0);
        assert_eq!(pins.len(), 3);
    }
}
