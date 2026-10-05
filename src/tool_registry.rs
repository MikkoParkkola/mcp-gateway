// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Engram-inspired deterministic O(1) tool registry with prefetching.
//!
//! Three layers: (1) `HashMap<String, Tool>` keyed by `"server:tool"` for O(1)
//! exact-match resolution; (2) schema prefetching via [`TransitionTracker`] that
//! warms predicted-next entries after each invocation; (3) metrics tracking hit
//! rate, prefetch accuracy, and resolution latency.
//!
//! Fallback chain: hash hit → (miss) → fuzzy search → full discovery.
//!
//! `tool_id` is `fnv1a_64("server:tool_name")` — stable and deterministic across
//! restarts.  All methods take `&self`; mutation is guarded by `parking_lot::RwLock`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

use crate::protocol::Tool;
use crate::transition::TransitionTracker;

// ============================================================================
// FNV-1a hash (64-bit, no-dep)
// ============================================================================

/// FNV-1a 64-bit hash of `input`.
///
/// Produces a stable, deterministic `u64` identifier for a tool key.
/// Collision probability is negligible at the expected cardinality (< 100 K).
#[must_use]
fn fnv1a_64(input: &str) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

// ============================================================================
// RegistryEntry
// ============================================================================

/// An entry in the tool registry.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Fully-qualified key: `"server:tool_name"`.
    pub key: String,
    /// Deterministic, stable identifier (`fnv1a_64(key)`).
    pub tool_id: u64,
    /// Complete MCP tool definition (name, description, inputSchema, …).
    pub tool: Tool,
}

// ============================================================================
// RegistryMetrics
// ============================================================================

/// Counters for the tool registry.
///
/// All counters are `u64` atomics; reads are `Relaxed` (approximate is fine
/// for monitoring).
#[derive(Debug, Default)]
pub struct RegistryMetrics {
    /// Total registry lookups attempted.
    pub lookups: AtomicU64,
    /// Lookups that found an entry (hash hits).
    pub hits: AtomicU64,
    /// Lookups that fell through to fuzzy search (hash misses).
    pub misses: AtomicU64,
    /// Prefetch operations triggered.
    pub prefetch_requests: AtomicU64,
    /// Prefetched entries that were subsequently used (prefetch hit).
    pub prefetch_hits: AtomicU64,
    /// Total resolution latency accumulated (nanoseconds).
    pub total_latency_ns: AtomicU64,
    /// Number of latency samples recorded.
    pub latency_samples: AtomicU64,
}

impl RegistryMetrics {
    /// Create zeroed metrics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful hash lookup.
    ///
    /// `latency_ns` is the wall-clock time between lookup start and entry
    /// return, measured in nanoseconds.
    pub fn record_hit(&self, latency_ns: u64) {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a miss (entry not in the hash map).
    pub fn record_miss(&self) {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a prefetch request (schemas scheduled for warming).
    pub fn record_prefetch(&self, count: u64) {
        self.prefetch_requests.fetch_add(count, Ordering::Relaxed);
    }

    /// Record a prefetch hit (a pre-warmed entry was requested and found).
    pub fn record_prefetch_hit(&self) {
        self.prefetch_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Current hit rate in `[0.0, 1.0]`.  Returns `0.0` when no lookups have
    /// been made yet.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.lookups.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let rate = self.hits.load(Ordering::Relaxed) as f64 / total as f64;
        rate
    }

    /// Prefetch accuracy in `[0.0, 1.0]`.  Returns `0.0` when no prefetch
    /// requests have been made.
    #[must_use]
    pub fn prefetch_accuracy(&self) -> f64 {
        let reqs = self.prefetch_requests.load(Ordering::Relaxed);
        if reqs == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let accuracy = self.prefetch_hits.load(Ordering::Relaxed) as f64 / reqs as f64;
        accuracy
    }

    /// Average resolution latency in nanoseconds.  Returns `0.0` when no
    /// samples have been recorded.
    #[must_use]
    pub fn avg_latency_ns(&self) -> f64 {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let avg = self.total_latency_ns.load(Ordering::Relaxed) as f64 / samples as f64;
        avg
    }

    /// Snapshot of all metrics as a plain struct (for serialisation /
    /// reporting).
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            lookups: self.lookups.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            prefetch_requests: self.prefetch_requests.load(Ordering::Relaxed),
            prefetch_hits: self.prefetch_hits.load(Ordering::Relaxed),
            hit_rate: self.hit_rate(),
            prefetch_accuracy: self.prefetch_accuracy(),
            avg_latency_ns: self.avg_latency_ns(),
        }
    }
}

/// A point-in-time snapshot of `RegistryMetrics` for reporting.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    /// Total lookups.
    pub lookups: u64,
    /// Hash hits.
    pub hits: u64,
    /// Hash misses.
    pub misses: u64,
    /// Prefetch operations triggered.
    pub prefetch_requests: u64,
    /// Prefetch hits (pre-warmed entry was used).
    pub prefetch_hits: u64,
    /// Hit rate `[0.0, 1.0]`.
    pub hit_rate: f64,
    /// Prefetch accuracy `[0.0, 1.0]`.
    pub prefetch_accuracy: f64,
    /// Average resolution latency in nanoseconds.
    pub avg_latency_ns: f64,
}

// ============================================================================
// ToolRegistry
// ============================================================================

/// Deterministic O(1) tool registry with schema prefetching.
///
/// # Insertion
///
/// Call [`ToolRegistry::insert`] for each `(server, tool)` pair when tools are
/// discovered or refreshed.  Duplicate keys overwrite existing entries.
///
/// # Lookup
///
/// Call [`ToolRegistry::get`] with a `"server:tool"` key.  A returned
/// `Some(&RegistryEntry)` indicates a hash hit; `None` means fall through to
/// the fuzzy search path.
///
/// # Prefetch
///
/// After invoking a tool, call [`ToolRegistry::prefetch_after`] with the
/// current `tool_key` and the `TransitionTracker`.  The registry schedules
/// warming (i.e. confirms schema presence) for the top-N predicted successors.
pub struct ToolRegistry {
    /// Primary index: `"server:tool"` → `RegistryEntry`.
    index: RwLock<HashMap<String, RegistryEntry>>,
    /// Set of keys that were prefetch-warmed (used for accuracy tracking).
    prefetched: RwLock<std::collections::HashSet<String>>,
    /// Registry metrics.
    pub metrics: RegistryMetrics,
    /// Maximum number of successors to prefetch after each invocation.
    pub prefetch_depth: usize,
}

impl ToolRegistry {
    /// Create an empty registry.
    ///
    /// `prefetch_depth` controls how many predicted-next tools are scheduled
    /// for prefetch warming after each invocation (default: 3).
    #[must_use]
    pub fn new(prefetch_depth: usize) -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
            prefetched: RwLock::new(std::collections::HashSet::new()),
            metrics: RegistryMetrics::new(),
            prefetch_depth,
        }
    }

    /// Insert or replace a tool entry for `server:tool_name`.
    ///
    /// The deterministic `tool_id` is derived from the key via FNV-1a.
    pub fn insert(&self, server: &str, tool: Tool) {
        let key = format!("{}:{}", server, tool.name);
        let tool_id = fnv1a_64(&key);
        let entry = RegistryEntry {
            key: key.clone(),
            tool_id,
            tool,
        };
        self.index.write().insert(key, entry);
    }

    /// Bulk-insert all tools from a `(server, tools)` pair, replacing any
    /// existing entries for that server.
    ///
    /// Existing entries for *other* servers are preserved.  This is the
    /// preferred API for refreshing a backend's tool list.
    pub fn replace_server(&self, server: &str, tools: Vec<Tool>) {
        let mut idx = self.index.write();
        // Remove stale entries for this server.
        idx.retain(|k, _| !k.starts_with(&format!("{server}:")));
        // Insert fresh entries.
        for tool in tools {
            let key = format!("{server}:{}", tool.name);
            let tool_id = fnv1a_64(&key);
            idx.insert(key.clone(), RegistryEntry { key, tool_id, tool });
        }
    }

    /// Remove all entries for a server (e.g. when a backend is shut down).
    pub fn remove_server(&self, server: &str) {
        let prefix = format!("{server}:");
        self.index.write().retain(|k, _| !k.starts_with(&prefix));
    }

    /// O(1) lookup by `"server:tool"` key.
    ///
    /// Returns a cloned `RegistryEntry` on hit; `None` on miss.
    /// Records hit/miss metrics and the lookup latency.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<RegistryEntry> {
        let start = Instant::now();
        let result = self.index.read().get(key).cloned();

        #[allow(clippy::cast_possible_truncation)]
        let latency_ns = start.elapsed().as_nanos() as u64;

        if result.is_some() {
            // If this key was prefetched, count it as a prefetch hit.
            if self.prefetched.read().contains(key) {
                self.metrics.record_prefetch_hit();
            }
            self.metrics.record_hit(latency_ns);
        } else {
            self.metrics.record_miss();
        }

        result
    }

    /// Warm schema entries for the top-N predicted successors of `current_key`.
    ///
    /// Uses `TransitionTracker::predict_next` to identify candidates, then
    /// verifies they are present in the registry (no-op if already warm).
    /// Records how many were scheduled via `metrics.record_prefetch`.
    ///
    /// # Arguments
    /// * `current_key` — `"server:tool"` key of the just-invoked tool
    /// * `tracker` — the session transition tracker
    /// * `min_confidence` — minimum probability threshold (e.g. `0.20`)
    /// * `min_count` — minimum observation count (e.g. `2`)
    pub fn prefetch_after(
        &self,
        current_key: &str,
        tracker: &TransitionTracker,
        min_confidence: f64,
        min_count: u64,
    ) {
        let predictions = tracker.predict_next(current_key, min_confidence, min_count);
        if predictions.is_empty() {
            return;
        }

        let top_n = predictions.into_iter().take(self.prefetch_depth);
        let index = self.index.read();
        let mut prefetched = self.prefetched.write();
        let mut warmed: u64 = 0;

        for pred in top_n {
            if index.contains_key(&pred.tool) {
                // Mark as prefetched so a subsequent get() can credit accuracy.
                prefetched.insert(pred.tool);
                warmed += 1;
            }
        }

        if warmed > 0 {
            self.metrics.record_prefetch(warmed);
        }
    }

    /// Total number of tools in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.read().len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.read().is_empty()
    }

    /// Returns `true` if `key` is present in the registry.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.index.read().contains_key(key)
    }

    /// All registered keys (server:tool), sorted alphabetically.
    ///
    /// Intended for diagnostics and tests only — O(n log n).
    #[must_use]
    pub fn all_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.index.read().keys().cloned().collect();
        keys.sort();
        keys
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new(3)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "tool_registry_tests.rs"]
mod tests;
