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
mod tests {
    use super::*;
    use serde_json::json;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: Some(format!("Tool {name}")),
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: None,
            annotations: None,
        }
    }

    // ── fnv1a_64 ─────────────────────────────────────────────────────────────

    #[test]
    fn fnv1a_64_is_deterministic() {
        // GIVEN: the same input
        // WHEN: hashed twice
        // THEN: identical output
        let h1 = fnv1a_64("server:my_tool");
        let h2 = fnv1a_64("server:my_tool");
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a_64_differs_for_distinct_inputs() {
        // GIVEN: two different keys
        // THEN: distinct hashes (no trivial collision for typical tool names)
        let h1 = fnv1a_64("srv_a:tool_read");
        let h2 = fnv1a_64("srv_a:tool_write");
        assert_ne!(h1, h2);
    }

    #[test]
    fn fnv1a_64_empty_string_does_not_panic() {
        // Edge case: empty input
        let _ = fnv1a_64("");
    }

    // ── insert + get (O(1) hash path) ────────────────────────────────────────

    #[test]
    fn insert_then_get_returns_entry() {
        // GIVEN: a fresh registry and a tool
        let reg = ToolRegistry::default();
        reg.insert("srv", make_tool("my_tool"));

        // WHEN: looking up the key
        let entry = reg.get("srv:my_tool");

        // THEN: entry is returned
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.tool.name, "my_tool");
    }

    #[test]
    fn get_missing_key_returns_none() {
        // GIVEN: an empty registry
        let reg = ToolRegistry::default();

        // WHEN: looking up a non-existent key
        let result = reg.get("srv:nonexistent");

        // THEN: None
        assert!(result.is_none());
    }

    #[test]
    fn insert_assigns_stable_tool_id() {
        // GIVEN: same tool inserted twice (idempotent)
        let reg = ToolRegistry::default();
        reg.insert("srv", make_tool("stable_id_tool"));
        let e1 = reg.get("srv:stable_id_tool").unwrap();
        reg.insert("srv", make_tool("stable_id_tool"));
        let e2 = reg.get("srv:stable_id_tool").unwrap();

        // THEN: tool_id is identical on both reads
        assert_eq!(e1.tool_id, e2.tool_id);
    }

    #[test]
    fn tool_id_matches_fnv1a_of_key() {
        // GIVEN: an inserted tool
        let reg = ToolRegistry::default();
        reg.insert("my_server", make_tool("my_tool"));
        let entry = reg.get("my_server:my_tool").unwrap();

        // THEN: tool_id equals fnv1a_64("my_server:my_tool")
        assert_eq!(entry.tool_id, fnv1a_64("my_server:my_tool"));
    }

    #[test]
    fn insert_overwrites_existing_entry() {
        // GIVEN: a tool already in the registry
        let reg = ToolRegistry::default();
        reg.insert("s", make_tool("t"));

        // WHEN: inserting the same key with different description
        let mut updated = make_tool("t");
        updated.description = Some("updated".to_string());
        reg.insert("s", updated);

        // THEN: the new description is returned
        let entry = reg.get("s:t").unwrap();
        assert_eq!(entry.tool.description.as_deref(), Some("updated"));
    }

    // ── replace_server ───────────────────────────────────────────────────────

    #[test]
    fn replace_server_replaces_only_target_server_tools() {
        // GIVEN: two servers with tools
        let reg = ToolRegistry::default();
        reg.insert("srv_a", make_tool("tool1"));
        reg.insert("srv_b", make_tool("shared"));

        // WHEN: replacing srv_a with a new tool list
        reg.replace_server("srv_a", vec![make_tool("new_tool")]);

        // THEN: srv_a's old tool is gone, new one present; srv_b is untouched
        assert!(reg.get("srv_a:tool1").is_none(), "old tool must be removed");
        assert!(reg.get("srv_a:new_tool").is_some(), "new tool must exist");
        assert!(reg.get("srv_b:shared").is_some(), "other server unaffected");
    }

    #[test]
    fn replace_server_with_empty_list_removes_all_tools() {
        // GIVEN: a server with tools
        let reg = ToolRegistry::default();
        reg.insert("srv", make_tool("a"));
        reg.insert("srv", make_tool("b"));

        // WHEN: replace with empty list
        reg.replace_server("srv", vec![]);

        // THEN: all tools removed
        assert_eq!(reg.len(), 0);
    }

    // ── remove_server ────────────────────────────────────────────────────────

    #[test]
    fn remove_server_removes_only_that_server() {
        // GIVEN: two servers
        let reg = ToolRegistry::default();
        reg.insert("a", make_tool("t1"));
        reg.insert("b", make_tool("t2"));

        // WHEN: removing server "a"
        reg.remove_server("a");

        // THEN: "a" tools gone, "b" tools remain
        assert!(reg.get("a:t1").is_none());
        assert!(reg.get("b:t2").is_some());
    }

    // ── metrics: hit rate ─────────────────────────────────────────────────────

    #[test]
    fn metrics_hit_rate_zero_when_no_lookups() {
        let reg = ToolRegistry::default();
        assert_eq!(reg.metrics.hit_rate(), 0.0);
    }

    #[test]
    fn metrics_hit_rate_one_after_all_hits() {
        // GIVEN: a tool in the registry
        let reg = ToolRegistry::default();
        reg.insert("s", make_tool("t"));

        // WHEN: three successful lookups
        for _ in 0..3 {
            let _ = reg.get("s:t");
        }

        // THEN: hit rate = 1.0
        assert!((reg.metrics.hit_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metrics_miss_increments_on_unknown_key() {
        let reg = ToolRegistry::default();
        let _ = reg.get("nope:nope");
        assert_eq!(reg.metrics.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn metrics_hit_rate_mixed_lookups() {
        // GIVEN: 3 hits + 1 miss
        let reg = ToolRegistry::default();
        reg.insert("s", make_tool("t"));
        let _ = reg.get("s:t");
        let _ = reg.get("s:t");
        let _ = reg.get("s:t");
        let _ = reg.get("s:missing");

        // THEN: hit rate = 3/4 = 0.75
        let rate = reg.metrics.hit_rate();
        assert!((rate - 0.75).abs() < 1e-9);
    }

    // ── metrics: latency ──────────────────────────────────────────────────────

    #[test]
    fn metrics_avg_latency_zero_when_no_samples() {
        let reg = ToolRegistry::default();
        assert_eq!(reg.metrics.avg_latency_ns(), 0.0);
    }

    #[test]
    fn metrics_records_latency_on_hit() {
        let reg = ToolRegistry::default();
        reg.insert("s", make_tool("t"));
        let _ = reg.get("s:t");
        // latency should be a very small positive number (sub-millisecond)
        let avg = reg.metrics.avg_latency_ns();
        assert!(avg >= 0.0, "avg_latency_ns must be non-negative");
        assert!(
            avg < 1_000_000.0,
            "avg_latency_ns should be sub-millisecond for in-memory lookup"
        );
    }

    // ── metrics: snapshot ────────────────────────────────────────────────────

    #[test]
    fn metrics_snapshot_reflects_current_state() {
        let reg = ToolRegistry::default();
        reg.insert("s", make_tool("t"));
        let _ = reg.get("s:t");
        let _ = reg.get("s:missing");

        let snap = reg.metrics.snapshot();
        assert_eq!(snap.lookups, 2);
        assert_eq!(snap.hits, 1);
        assert_eq!(snap.misses, 1);
        assert!((snap.hit_rate - 0.5).abs() < 1e-9);
    }

    // ── prefetch ─────────────────────────────────────────────────────────────

    #[test]
    fn prefetch_after_does_not_panic_on_cold_tracker() {
        // GIVEN: an empty tracker and registry
        let reg = ToolRegistry::new(3);
        let tracker = TransitionTracker::new();

        // WHEN: prefetching after a tool with no history
        reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

        // THEN: no panic, no prefetch recorded
        assert_eq!(reg.metrics.prefetch_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn prefetch_after_warms_predicted_successors_that_exist_in_registry() {
        // GIVEN: A→B observed 5 times, B is in the registry
        let tracker = TransitionTracker::new();
        for _ in 0..5 {
            tracker.record_transition("sess", "s:tool_a");
            tracker.record_transition("sess", "s:tool_b");
        }

        let reg = ToolRegistry::new(3);
        reg.insert("s", make_tool("tool_b")); // B is in registry

        // WHEN: prefetch after A
        reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

        // THEN: exactly 1 prefetch request recorded (for B)
        assert_eq!(reg.metrics.prefetch_requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn prefetch_after_skips_candidates_not_in_registry() {
        // GIVEN: A→C observed 5 times, C is NOT in the registry
        let tracker = TransitionTracker::new();
        for _ in 0..5 {
            tracker.record_transition("s", "s:tool_a");
            tracker.record_transition("s", "s:tool_c");
        }

        let reg = ToolRegistry::new(3);
        // tool_c intentionally not inserted

        // WHEN: prefetch after A
        reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

        // THEN: no prefetch recorded (candidate missing from registry)
        assert_eq!(reg.metrics.prefetch_requests.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn prefetch_hit_credited_when_prefetched_key_is_accessed() {
        // GIVEN: A→B seen 5 times; B is in registry; prefetch is run
        let tracker = TransitionTracker::new();
        for _ in 0..5 {
            tracker.record_transition("s", "s:tool_a");
            tracker.record_transition("s", "s:tool_b");
        }

        let reg = ToolRegistry::new(3);
        reg.insert("s", make_tool("tool_b"));
        reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

        // WHEN: tool_b is then looked up
        let _ = reg.get("s:tool_b");

        // THEN: a prefetch hit is credited
        assert_eq!(reg.metrics.prefetch_hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn prefetch_depth_limits_number_of_warming_candidates() {
        // GIVEN: A→B, A→C, A→D all observed; depth = 2
        let tracker = TransitionTracker::new();
        for _ in 0..5 {
            tracker.record_transition("s1", "s:a");
            tracker.record_transition("s1", "s:b");
        }
        for _ in 0..4 {
            tracker.record_transition("s2", "s:a");
            tracker.record_transition("s2", "s:c");
        }
        for _ in 0..3 {
            tracker.record_transition("s3", "s:a");
            tracker.record_transition("s3", "s:d");
        }

        let reg = ToolRegistry::new(2); // depth = 2
        reg.insert("s", make_tool("b"));
        reg.insert("s", make_tool("c"));
        reg.insert("s", make_tool("d"));

        // WHEN: prefetch after a
        reg.prefetch_after("s:a", &tracker, 0.0, 1);

        // THEN: only up to 2 candidates are warmed (depth limit)
        assert!(
            reg.metrics.prefetch_requests.load(Ordering::Relaxed) <= 2,
            "Prefetch depth must cap at 2"
        );
    }

    // ── prefetch accuracy ────────────────────────────────────────────────────

    #[test]
    fn prefetch_accuracy_zero_when_no_prefetch_requests() {
        let reg = ToolRegistry::default();
        assert_eq!(reg.metrics.prefetch_accuracy(), 0.0);
    }

    #[test]
    fn prefetch_accuracy_is_hits_over_requests() {
        // GIVEN: 4 prefetch requests, 2 hits
        let reg = ToolRegistry::default();
        reg.metrics.record_prefetch(4);
        reg.metrics.record_prefetch_hit();
        reg.metrics.record_prefetch_hit();

        let accuracy = reg.metrics.prefetch_accuracy();
        assert!((accuracy - 0.5).abs() < 1e-9);
    }

    // ── contains / len / is_empty ─────────────────────────────────────────────

    #[test]
    fn len_and_is_empty_reflect_contents() {
        let reg = ToolRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);

        reg.insert("s", make_tool("t1"));
        reg.insert("s", make_tool("t2"));
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn contains_returns_true_for_inserted_key() {
        let reg = ToolRegistry::default();
        reg.insert("s", make_tool("t"));
        assert!(reg.contains("s:t"));
        assert!(!reg.contains("s:other"));
    }

    // ── all_keys ──────────────────────────────────────────────────────────────

    #[test]
    fn all_keys_returns_sorted_keys() {
        let reg = ToolRegistry::default();
        reg.insert("b", make_tool("z"));
        reg.insert("a", make_tool("a"));
        reg.insert("a", make_tool("z"));

        let keys = reg.all_keys();
        assert_eq!(keys, vec!["a:a", "a:z", "b:z"]);
    }

    // ── default prefetch_depth ───────────────────────────────────────────────

    #[test]
    fn default_prefetch_depth_is_three() {
        let reg = ToolRegistry::default();
        assert_eq!(reg.prefetch_depth, 3);
    }
}
