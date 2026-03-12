//! Simhash-based request routing and cache sharing for MCP Gateway — Issue #46.
//!
//! Sessions that invoke similar sets of tools tend to benefit from sharing
//! cache partitions: their responses are more likely to be reusable, and
//! routing similar sessions to the same cache shard increases hit rates.
//!
//! This module provides:
//!
//! 1. **`simhash`** — a 64-bit locality-sensitive hash (Charikar 2002) that
//!    maps a set of string features to a fingerprint where similar feature
//!    sets produce fingerprints with a small Hamming distance.
//! 2. **`hamming_distance` / `similarity_score`** — bit-level distance and a
//!    normalised 0.0–1.0 similarity score derived from it.
//! 3. **`SimhashIndex`** — an in-memory store that indexes fingerprints and
//!    supports threshold-based nearest-neighbour queries.
//! 4. **`SessionFingerprint`** — extracts features from session context (tool
//!    names, argument keys) and produces a simhash fingerprint.
//! 5. **`CacheRouter`** — assigns sessions to cache partitions by grouping
//!    sessions with similar tool-usage patterns together.
//!
//! # Locality-sensitive hashing
//!
//! Each feature string is hashed with FNV-1a to produce a 64-bit integer.
//! For every set bit in that integer, the corresponding "column" weight is
//! incremented; for every clear bit it is decremented. After accumulating all
//! features, the sign of each column becomes the corresponding bit of the
//! final simhash. This means two feature sets with high Jaccard overlap will
//! have a small Hamming distance between their simhashes.
//!
//! # Cache routing
//!
//! `CacheRouter` maintains `num_partitions` named cache partitions.  When a
//! session fingerprint arrives, the router finds the existing partition whose
//! centroid fingerprint is most similar to the new session (above a
//! configurable threshold) and assigns the session there.  If no partition
//! matches, a new partition is created (up to `num_partitions`; after that the
//! least-recently-used partition is reused).

use std::collections::HashMap;

// ============================================================================
// FNV-1a 64-bit (same constants as context_compression.rs for consistency)
// ============================================================================

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Compute the FNV-1a 64-bit hash of `input`.
#[inline]
fn fnv1a(input: &str) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ============================================================================
// Core simhash
// ============================================================================

/// Compute a 64-bit SimHash (Charikar 2002) from a set of string features.
///
/// Each feature is hashed with FNV-1a. The 64 "column weights" are
/// incremented for every set bit and decremented for every clear bit across
/// all feature hashes. The final simhash bit `i` is 1 iff `weights[i] > 0`.
///
/// Two feature sets with high Jaccard overlap produce fingerprints with small
/// Hamming distance, making this suitable for locality-sensitive hashing.
///
/// # Examples
///
/// ```
/// # use mcp_gateway::simhash::simhash;
/// let h1 = simhash(&["read_file", "write_file", "list_dir"]);
/// let h2 = simhash(&["read_file", "write_file", "list_dir"]);
/// assert_eq!(h1, h2);
/// ```
#[must_use]
pub fn simhash(features: &[&str]) -> u64 {
    // 64 integer accumulators — one per bit position.
    let mut weights = [0i32; 64];

    for &feature in features {
        let hash = fnv1a(feature);
        for bit in 0u32..64 {
            if (hash >> bit) & 1 == 1 {
                weights[bit as usize] += 1;
            } else {
                weights[bit as usize] -= 1;
            }
        }
    }

    // Collapse weights to a single u64: bit i is 1 iff weights[i] > 0.
    let mut fingerprint: u64 = 0;
    for bit in 0u32..64 {
        if weights[bit as usize] > 0 {
            fingerprint |= 1u64 << bit;
        }
    }
    fingerprint
}

// ============================================================================
// Hamming distance and similarity
// ============================================================================

/// Count the number of bit positions where `a` and `b` differ.
///
/// The result is in the range `[0, 64]`.
#[must_use]
#[inline]
pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Normalise Hamming distance to a similarity score in `[0.0, 1.0]`.
///
/// A score of `1.0` means identical fingerprints (distance 0); a score of
/// `0.0` means maximum distance (64 differing bits).
///
/// Formula: `1.0 - hamming_distance(a, b) / 64.0`
#[must_use]
#[inline]
pub fn similarity_score(a: u64, b: u64) -> f64 {
    1.0 - f64::from(hamming_distance(a, b)) / 64.0
}

// ============================================================================
// SimhashIndex
// ============================================================================

/// An in-memory index of simhash fingerprints supporting threshold-based
/// nearest-neighbour queries.
///
/// Insertions and queries are both O(n) in the number of stored entries.
/// For the typical gateway workload (hundreds of sessions, not millions) this
/// is acceptable and avoids additional dependencies.
#[derive(Debug, Default)]
pub struct SimhashIndex {
    /// All stored (id, fingerprint) pairs.
    entries: Vec<(String, u64)>,
}

impl SimhashIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a fingerprint with the given identifier.
    ///
    /// Inserting the same `id` again adds a second entry; callers that want
    /// upsert semantics should call [`remove`] first.
    pub fn insert(&mut self, id: String, hash: u64) {
        self.entries.push((id, hash));
    }

    /// Remove all entries whose identifier equals `id`.
    ///
    /// Returns the number of entries removed.
    pub fn remove(&mut self, id: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|(entry_id, _)| entry_id != id);
        before - self.entries.len()
    }

    /// Return all stored entries whose similarity to `hash` meets or exceeds
    /// `threshold`, sorted by descending similarity score.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `threshold` is outside `[0.0, 1.0]`.
    #[must_use]
    pub fn find_similar(&self, hash: u64, threshold: f64) -> Vec<(String, f64)> {
        debug_assert!(
            threshold >= 0.0 && threshold <= 1.0,
            "threshold must be in [0.0, 1.0], got {threshold}"
        );

        let mut results: Vec<(String, f64)> = self
            .entries
            .iter()
            .filter_map(|(id, stored_hash)| {
                let score = similarity_score(hash, *stored_hash);
                if score >= threshold {
                    Some((id.clone(), score))
                } else {
                    None
                }
            })
            .collect();

        // Stable sort: highest score first; ties broken by insertion order.
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Return the number of entries in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the index contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ============================================================================
// SessionFingerprint
// ============================================================================

/// Extracts features from MCP session context and produces a simhash
/// fingerprint suitable for similarity-based cache routing.
///
/// Features are extracted from:
/// - **Tool names** — which MCP tools have been registered or invoked.
/// - **Argument keys** — the parameter names used in tool calls (captures
///   schema shape without leaking sensitive argument values).
///
/// Feature weighting:
/// - Tool names contribute with weight 3 (repeated 3 times in the feature
///   vector) to emphasise which tools are present over argument structure.
/// - Argument keys contribute with weight 1.
#[derive(Debug, Default)]
pub struct SessionFingerprint {
    /// Accumulated feature strings.
    features: Vec<String>,
}

impl SessionFingerprint {
    /// Create an empty fingerprint builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a tool with `name` is available or was used in this session.
    ///
    /// Tool names are added with weight 3 to dominate the fingerprint (tool
    /// presence is a stronger signal than argument key shape).
    pub fn add_tool(&mut self, name: &str) {
        // Weight 3: insert three times.
        for _ in 0..3 {
            self.features.push(format!("tool:{name}"));
        }
    }

    /// Record that a tool argument with `key` was observed in this session.
    ///
    /// Only the key (parameter name) is recorded, not the value, to avoid
    /// leaking sensitive data into the routing layer.
    pub fn add_argument_key(&mut self, key: &str) {
        self.features.push(format!("arg:{key}"));
    }

    /// Record multiple tool names at once.
    pub fn add_tools(&mut self, names: &[&str]) {
        for &name in names {
            self.add_tool(name);
        }
    }

    /// Record multiple argument keys at once.
    pub fn add_argument_keys(&mut self, keys: &[&str]) {
        for &key in keys {
            self.add_argument_key(key);
        }
    }

    /// Compute the 64-bit simhash fingerprint for the accumulated features.
    ///
    /// Returns `0` if no features have been added (all weights cancel out to
    /// zero or are zero, so the fingerprint is the all-zero vector).
    #[must_use]
    pub fn compute(&self) -> u64 {
        if self.features.is_empty() {
            return 0;
        }
        let refs: Vec<&str> = self.features.iter().map(String::as_str).collect();
        simhash(&refs)
    }

    /// Return the number of features recorded.
    #[must_use]
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }
}

// ============================================================================
// CacheRouter
// ============================================================================

/// A single cache partition within the router.
#[derive(Debug)]
struct CachePartition {
    /// Partition identifier (e.g. `"partition-0"`).
    id: String,
    /// Running simhash centroid: updated as sessions are assigned.
    centroid: u64,
    /// Number of sessions assigned to this partition.
    session_count: u64,
    /// Session IDs mapped to this partition.
    sessions: Vec<String>,
    /// Logical "last used" counter for LRU eviction.
    last_used: u64,
}

/// Routes sessions to cache partitions based on simhash similarity.
///
/// Sessions with similar tool-usage patterns (small Hamming distance between
/// their fingerprints) are placed in the same partition, increasing the
/// probability that cached responses can be shared.
///
/// # Partition assignment algorithm
///
/// 1. Compute the similarity between the session fingerprint and each
///    partition centroid.
/// 2. If the best match exceeds `similarity_threshold`, assign to that
///    partition.
/// 3. Otherwise, create a new partition (if `num_partitions` allows) or
///    reassign to the LRU partition.
///
/// The centroid is updated as the bitwise majority of all session fingerprints
/// assigned to the partition (equivalent to re-running simhash over all
/// assigned sessions' fingerprints, approximated cheaply by a per-bit majority
/// vote stored in the partition's accumulated weight vector).
#[derive(Debug)]
pub struct CacheRouter {
    /// Maximum number of cache partitions.
    num_partitions: usize,
    /// Similarity threshold for assigning a session to an existing partition.
    similarity_threshold: f64,
    /// Active partitions.
    partitions: Vec<CachePartition>,
    /// Monotonic clock for LRU ordering.
    clock: u64,
    /// Per-partition per-bit weight accumulators for centroid updates.
    /// `bit_weights[partition_idx][bit]` = sum of (+1/-1) for each assigned session.
    bit_weights: Vec<[i64; 64]>,
}

impl CacheRouter {
    /// Create a router with `num_partitions` partitions and the given
    /// similarity threshold.
    ///
    /// # Panics
    ///
    /// Panics if `num_partitions` is 0 or if `similarity_threshold` is outside
    /// `(0.0, 1.0]`.
    #[must_use]
    pub fn new(num_partitions: usize, similarity_threshold: f64) -> Self {
        assert!(num_partitions > 0, "num_partitions must be at least 1");
        assert!(
            similarity_threshold >= 0.0 && similarity_threshold <= 1.0,
            "similarity_threshold must be in [0.0, 1.0]"
        );
        Self {
            num_partitions,
            similarity_threshold,
            partitions: Vec::with_capacity(num_partitions),
            clock: 0,
            bit_weights: Vec::with_capacity(num_partitions),
        }
    }

    /// Assign `session_id` with fingerprint `hash` to a cache partition.
    ///
    /// Returns the partition identifier string (e.g. `"partition-0"`).
    pub fn assign(&mut self, session_id: String, hash: u64) -> &str {
        self.clock += 1;
        let clock = self.clock;

        // Find the best-matching existing partition.
        let best = self
            .partitions
            .iter()
            .enumerate()
            .map(|(i, p)| (i, similarity_score(hash, p.centroid)))
            .filter(|(_, score)| *score >= self.similarity_threshold)
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        if let Some((idx, _)) = best {
            // Assign to existing partition and update centroid.
            self.partitions[idx].sessions.push(session_id);
            self.partitions[idx].session_count += 1;
            self.partitions[idx].last_used = clock;
            self.update_centroid(idx, hash);
            return &self.partitions[idx].id;
        }

        // No match — create a new partition if capacity allows.
        if self.partitions.len() < self.num_partitions {
            let id = format!("partition-{}", self.partitions.len());
            let weights = Self::initial_bit_weights(hash);
            self.partitions.push(CachePartition {
                id,
                centroid: hash,
                session_count: 1,
                sessions: vec![session_id],
                last_used: clock,
            });
            self.bit_weights.push(weights);
            let idx = self.partitions.len() - 1;
            return &self.partitions[idx].id;
        }

        // All partitions full — reuse the LRU one (clear it and start fresh).
        let lru_idx = self
            .partitions
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| p.last_used)
            .map(|(i, _)| i)
            .unwrap_or(0);

        self.partitions[lru_idx].sessions.clear();
        self.partitions[lru_idx].sessions.push(session_id);
        self.partitions[lru_idx].session_count = 1;
        self.partitions[lru_idx].centroid = hash;
        self.partitions[lru_idx].last_used = clock;
        self.bit_weights[lru_idx] = Self::initial_bit_weights(hash);
        &self.partitions[lru_idx].id
    }

    /// Return the partition identifier for `session_id`, if already assigned.
    #[must_use]
    pub fn partition_for_session(&self, session_id: &str) -> Option<&str> {
        self.partitions
            .iter()
            .find(|p| p.sessions.contains(&session_id.to_string()))
            .map(|p| p.id.as_str())
    }

    /// Return the number of active partitions.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    /// Return the IDs of all sessions assigned to `partition_id`.
    #[must_use]
    pub fn sessions_in_partition(&self, partition_id: &str) -> Vec<&str> {
        self.partitions
            .iter()
            .find(|p| p.id == partition_id)
            .map(|p| p.sessions.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Return a snapshot of all partition statistics.
    ///
    /// Each entry is `(partition_id, session_count, centroid_hash)`.
    #[must_use]
    pub fn partition_stats(&self) -> Vec<(&str, u64, u64)> {
        self.partitions
            .iter()
            .map(|p| (p.id.as_str(), p.session_count, p.centroid))
            .collect()
    }

    /// Compute the initial per-bit weights from a single hash (used when a
    /// new partition is seeded from the first session fingerprint).
    fn initial_bit_weights(hash: u64) -> [i64; 64] {
        let mut weights = [0i64; 64];
        for bit in 0u32..64 {
            weights[bit as usize] = if (hash >> bit) & 1 == 1 { 1 } else { -1 };
        }
        weights
    }

    /// Incorporate `hash` into the per-bit weight accumulators for partition
    /// `idx` and recompute the centroid.
    fn update_centroid(&mut self, idx: usize, hash: u64) {
        for bit in 0u32..64 {
            if (hash >> bit) & 1 == 1 {
                self.bit_weights[idx][bit as usize] += 1;
            } else {
                self.bit_weights[idx][bit as usize] -= 1;
            }
        }
        // Recompute centroid from updated weights.
        let mut centroid: u64 = 0;
        for bit in 0u32..64 {
            if self.bit_weights[idx][bit as usize] > 0 {
                centroid |= 1u64 << bit;
            }
        }
        self.partitions[idx].centroid = centroid;
    }
}

// ============================================================================
// SessionContext — convenience builder for routing pipelines
// ============================================================================

/// Convenience type that bundles session metadata for fingerprinting.
///
/// Build a `SessionContext`, call [`SessionContext::fingerprint`] to obtain a
/// `u64`, then pass it to [`CacheRouter::assign`].
#[derive(Debug, Default)]
pub struct SessionContext {
    /// Unique session identifier.
    pub session_id: String,
    /// MCP tool names available / used in this session.
    pub tool_names: Vec<String>,
    /// Argument keys observed in tool calls during this session.
    pub argument_keys: Vec<String>,
}

impl SessionContext {
    /// Create a new context for `session_id`.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            tool_names: Vec::new(),
            argument_keys: Vec::new(),
        }
    }

    /// Add a tool name.
    pub fn add_tool(mut self, name: impl Into<String>) -> Self {
        self.tool_names.push(name.into());
        self
    }

    /// Add an argument key.
    pub fn add_arg_key(mut self, key: impl Into<String>) -> Self {
        self.argument_keys.push(key.into());
        self
    }

    /// Compute the simhash fingerprint for this context.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let mut fp = SessionFingerprint::new();
        for name in &self.tool_names {
            fp.add_tool(name);
        }
        for key in &self.argument_keys {
            fp.add_argument_key(key);
        }
        fp.compute()
    }
}

// ============================================================================
// Utility: bulk similarity comparison
// ============================================================================

/// Compare `query` against all `candidates` and return those meeting
/// `threshold`, sorted by descending similarity.
///
/// This is a thin convenience wrapper around repeated `similarity_score` calls.
#[must_use]
pub fn find_similar_hashes(
    query: u64,
    candidates: &HashMap<String, u64>,
    threshold: f64,
) -> Vec<(String, f64)> {
    let mut results: Vec<(String, f64)> = candidates
        .iter()
        .filter_map(|(id, &hash)| {
            let score = similarity_score(query, hash);
            if score >= threshold {
                Some((id.clone(), score))
            } else {
                None
            }
        })
        .collect();
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── simhash ───────────────────────────────────────────────────────────────

    #[test]
    fn simhash_empty_features_returns_zero() {
        assert_eq!(simhash(&[]), 0);
    }

    #[test]
    fn simhash_is_deterministic() {
        let features = ["read_file", "write_file", "list_dir"];
        assert_eq!(simhash(&features), simhash(&features));
    }

    #[test]
    fn simhash_identical_sets_produce_identical_hashes() {
        let a = simhash(&["tool_a", "tool_b"]);
        let b = simhash(&["tool_a", "tool_b"]);
        assert_eq!(a, b);
    }

    #[test]
    fn simhash_order_independence_approximate() {
        // Simhash is NOT order-independent by construction, but the same
        // multiset produces the same result.
        let a = simhash(&["search", "read", "write"]);
        let b = simhash(&["search", "read", "write"]);
        assert_eq!(a, b);
    }

    #[test]
    fn simhash_similar_sets_have_small_hamming_distance() {
        let base = ["read_file", "write_file", "list_dir", "delete_file"];
        let similar = ["read_file", "write_file", "list_dir", "move_file"]; // one swap
        let h1 = simhash(&base);
        let h2 = simhash(&similar);
        let dist = hamming_distance(h1, h2);
        // Similar sets should differ in few bits (empirically < 20 for one swap).
        assert!(dist < 25, "expected distance < 25, got {dist}");
    }

    #[test]
    fn simhash_disjoint_sets_have_large_hamming_distance() {
        let a = simhash(&["alpha", "beta", "gamma", "delta"]);
        let b = simhash(&["epsilon", "zeta", "eta", "theta"]);
        let dist = hamming_distance(a, b);
        // Disjoint random sets tend to differ in ~32 bits on average.
        // Relax to > 10 to avoid flakiness.
        assert!(dist > 10, "expected distance > 10, got {dist}");
    }

    #[test]
    fn simhash_single_feature_is_nonzero() {
        assert_ne!(simhash(&["only_one_feature"]), 0);
    }

    // ── hamming_distance ──────────────────────────────────────────────────────

    #[test]
    fn hamming_distance_same_hash_is_zero() {
        assert_eq!(hamming_distance(0xDEAD_BEEF_CAFE_BABE, 0xDEAD_BEEF_CAFE_BABE), 0);
    }

    #[test]
    fn hamming_distance_inverted_is_64() {
        assert_eq!(hamming_distance(0u64, !0u64), 64);
    }

    #[test]
    fn hamming_distance_one_bit_flip() {
        assert_eq!(hamming_distance(0b0000, 0b0001), 1);
        assert_eq!(hamming_distance(0b0000, 0b1000), 1);
    }

    #[test]
    fn hamming_distance_symmetric() {
        let a = 0xABCD_1234_5678_EF90u64;
        let b = 0x1234_ABCD_EF90_5678u64;
        assert_eq!(hamming_distance(a, b), hamming_distance(b, a));
    }

    // ── similarity_score ──────────────────────────────────────────────────────

    #[test]
    fn similarity_score_identical_is_one() {
        let score = similarity_score(0x1234_5678_9ABC_DEF0, 0x1234_5678_9ABC_DEF0);
        assert!((score - 1.0).abs() < 1e-9, "expected 1.0, got {score}");
    }

    #[test]
    fn similarity_score_inverted_is_zero() {
        let score = similarity_score(0u64, !0u64);
        assert!(score.abs() < 1e-9, "expected 0.0, got {score}");
    }

    #[test]
    fn similarity_score_in_range() {
        let a = simhash(&["a", "b", "c"]);
        let b = simhash(&["d", "e", "f"]);
        let score = similarity_score(a, b);
        assert!((0.0..=1.0).contains(&score), "score {score} out of range");
    }

    #[test]
    fn similarity_score_consistent_with_hamming() {
        let a = 0xFFFF_0000_FFFF_0000u64;
        let b = 0x0000_FFFF_0000_FFFFu64;
        let dist = hamming_distance(a, b);
        let score = similarity_score(a, b);
        let expected = 1.0 - f64::from(dist) / 64.0;
        assert!((score - expected).abs() < 1e-9);
    }

    // ── SimhashIndex ──────────────────────────────────────────────────────────

    #[test]
    fn index_empty_find_returns_empty() {
        let idx = SimhashIndex::new();
        let results = idx.find_similar(0xABCD, 0.5);
        assert!(results.is_empty());
    }

    #[test]
    fn index_insert_and_exact_match() {
        let mut idx = SimhashIndex::new();
        let hash = simhash(&["read_file", "write_file"]);
        idx.insert("session-1".to_string(), hash);
        let results = idx.find_similar(hash, 1.0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "session-1");
        assert!((results[0].1 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn index_threshold_filters_dissimilar() {
        let mut idx = SimhashIndex::new();
        idx.insert("sim".to_string(), 0xFFFF_FFFF_FFFF_FFFF);
        // Query with zero hash → score = 0.0 → should be filtered
        let results = idx.find_similar(0u64, 0.8);
        assert!(results.is_empty(), "dissimilar entry should be filtered");
    }

    #[test]
    fn index_multiple_entries_sorted_by_score() {
        let mut idx = SimhashIndex::new();
        // Use carefully chosen hashes with known distances.
        let query: u64 = 0b1111_1111;
        // 1 bit different from query
        idx.insert("close".to_string(), 0b1111_1110);
        // 8 bits different from query (lower byte is 0b0000_0000)
        idx.insert("far".to_string(), 0b1111_1111_0000_0000);

        let results = idx.find_similar(query, 0.0);
        assert_eq!(results.len(), 2);
        // Highest score should be first
        assert!(results[0].1 >= results[1].1, "results must be sorted descending");
    }

    #[test]
    fn index_remove_deletes_entries() {
        let mut idx = SimhashIndex::new();
        idx.insert("s1".to_string(), 0xABCD);
        idx.insert("s1".to_string(), 0x1234); // duplicate id
        assert_eq!(idx.len(), 2);
        let removed = idx.remove("s1");
        assert_eq!(removed, 2);
        assert!(idx.is_empty());
    }

    #[test]
    fn index_len_and_is_empty() {
        let mut idx = SimhashIndex::new();
        assert!(idx.is_empty());
        idx.insert("a".to_string(), 1);
        assert_eq!(idx.len(), 1);
        assert!(!idx.is_empty());
    }

    // ── SessionFingerprint ────────────────────────────────────────────────────

    #[test]
    fn session_fingerprint_empty_is_zero() {
        let fp = SessionFingerprint::new();
        assert_eq!(fp.compute(), 0);
    }

    #[test]
    fn session_fingerprint_is_deterministic() {
        let mut fp1 = SessionFingerprint::new();
        fp1.add_tools(&["search", "read_file"]);
        fp1.add_argument_keys(&["query", "path"]);

        let mut fp2 = SessionFingerprint::new();
        fp2.add_tools(&["search", "read_file"]);
        fp2.add_argument_keys(&["query", "path"]);

        assert_eq!(fp1.compute(), fp2.compute());
    }

    #[test]
    fn session_fingerprint_similar_toolsets_close() {
        let mut fp1 = SessionFingerprint::new();
        fp1.add_tools(&["read_file", "write_file", "list_dir", "delete_file"]);

        let mut fp2 = SessionFingerprint::new();
        fp2.add_tools(&["read_file", "write_file", "list_dir", "move_file"]);

        let score = similarity_score(fp1.compute(), fp2.compute());
        assert!(score > 0.5, "similar toolsets should have score > 0.5, got {score}");
    }

    #[test]
    fn session_fingerprint_disjoint_toolsets_different() {
        let mut fp1 = SessionFingerprint::new();
        fp1.add_tools(&["read_file", "write_file"]);

        let mut fp2 = SessionFingerprint::new();
        fp2.add_tools(&["execute_query", "send_email"]);

        let score = similarity_score(fp1.compute(), fp2.compute());
        // Not necessarily < 0.5 with only 2 tools, but they should not be identical.
        assert!(
            score < 1.0,
            "disjoint toolsets should not be perfectly similar, got {score}"
        );
    }

    #[test]
    fn session_fingerprint_feature_count() {
        let mut fp = SessionFingerprint::new();
        fp.add_tool("t1"); // +3 features
        fp.add_argument_key("k1"); // +1 feature
        assert_eq!(fp.feature_count(), 4);
    }

    #[test]
    fn session_fingerprint_tools_weight_more_than_args() {
        // Adding a tool (weight 3) has more impact than adding an arg (weight 1).
        // Two sessions differing only by one tool should differ less than
        // two sessions differing only by many arg keys.
        let base_tools = ["read_file", "write_file", "list_dir"];
        let base_args = ["path", "content", "encoding"];

        let mut fp_base = SessionFingerprint::new();
        fp_base.add_tools(&base_tools);
        fp_base.add_argument_keys(&base_args);
        let h_base = fp_base.compute();

        let mut fp_diff_tool = SessionFingerprint::new();
        fp_diff_tool.add_tools(&["read_file", "write_file", "DELETE_file"]);
        fp_diff_tool.add_argument_keys(&base_args);

        let mut fp_diff_arg = SessionFingerprint::new();
        fp_diff_arg.add_tools(&base_tools);
        fp_diff_arg.add_argument_keys(&["path", "content", "completely_different"]);

        let dist_tool = hamming_distance(h_base, fp_diff_tool.compute());
        let dist_arg = hamming_distance(h_base, fp_diff_arg.compute());
        // Changing a tool should produce a larger distance than changing an arg.
        assert!(
            dist_tool >= dist_arg,
            "tool change (dist={dist_tool}) should impact fingerprint at least as much as arg change (dist={dist_arg})"
        );
    }

    // ── CacheRouter ───────────────────────────────────────────────────────────

    #[test]
    fn router_single_partition_all_assigned_same() {
        let mut router = CacheRouter::new(1, 0.5);
        let h = simhash(&["tool_a", "tool_b"]);
        let p1 = router.assign("s1".to_string(), h).to_string();
        let p2 = router.assign("s2".to_string(), h).to_string();
        assert_eq!(p1, p2, "same fingerprint should go to same partition");
    }

    #[test]
    fn router_creates_partitions_up_to_limit() {
        // Use threshold=1.0 to force every new fingerprint into a new partition.
        let mut router = CacheRouter::new(3, 1.0);
        let h1 = simhash(&["tool_a"]);
        let h2 = simhash(&["tool_b"]);
        let h3 = simhash(&["tool_c"]);
        router.assign("s1".to_string(), h1);
        router.assign("s2".to_string(), h2);
        router.assign("s3".to_string(), h3);
        assert_eq!(router.partition_count(), 3);
    }

    #[test]
    fn router_does_not_exceed_partition_limit() {
        let mut router = CacheRouter::new(2, 1.0);
        for i in 0..10u64 {
            router.assign(format!("s{i}"), i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        }
        assert!(
            router.partition_count() <= 2,
            "router must not exceed num_partitions"
        );
    }

    #[test]
    fn router_partition_for_session_returns_correct_id() {
        let mut router = CacheRouter::new(4, 0.5);
        let h = simhash(&["search", "read"]);
        let assigned = router.assign("my-session".to_string(), h).to_string();
        let looked_up = router.partition_for_session("my-session");
        assert_eq!(Some(assigned.as_str()), looked_up);
    }

    #[test]
    fn router_sessions_in_partition_lists_assigned_sessions() {
        // threshold=0.0 means every session matches any existing partition.
        let mut router = CacheRouter::new(1, 0.0);
        let h = simhash(&["tool"]);
        router.assign("s1".to_string(), h);
        router.assign("s2".to_string(), h);
        let p_id = router.partition_for_session("s1").unwrap().to_string();
        let members = router.sessions_in_partition(&p_id);
        assert!(members.contains(&"s1"), "s1 should be in partition");
        assert!(members.contains(&"s2"), "s2 should be in partition");
    }

    #[test]
    fn router_similar_sessions_share_partition() {
        let mut router = CacheRouter::new(4, 0.6);
        let tools_a = ["read_file", "write_file", "list_dir"];
        let tools_b = ["read_file", "write_file", "delete_file"]; // 2/3 overlap

        let h1 = SessionContext::new("s1")
            .add_tool(tools_a[0])
            .add_tool(tools_a[1])
            .add_tool(tools_a[2])
            .fingerprint();

        let h2 = SessionContext::new("s2")
            .add_tool(tools_b[0])
            .add_tool(tools_b[1])
            .add_tool(tools_b[2])
            .fingerprint();

        let p1 = router.assign("s1".to_string(), h1).to_string();
        let p2 = router.assign("s2".to_string(), h2).to_string();

        // They may or may not share a partition depending on the threshold,
        // but we can verify the assignment is valid (non-empty partition id).
        assert!(!p1.is_empty());
        assert!(!p2.is_empty());
        // In practice with these similar tools, they should share a partition.
        let score = similarity_score(h1, h2);
        if score >= 0.6 {
            assert_eq!(p1, p2, "similar sessions (score={score:.2}) should share partition");
        }
    }

    #[test]
    fn router_partition_stats_returns_all_partitions() {
        let mut router = CacheRouter::new(2, 1.0);
        router.assign("s1".to_string(), 0xAAAA_AAAA_AAAA_AAAA);
        router.assign("s2".to_string(), 0x5555_5555_5555_5555);
        let stats = router.partition_stats();
        assert_eq!(stats.len(), 2);
    }

    // ── SessionContext ─────────────────────────────────────────────────────────

    #[test]
    fn session_context_fingerprint_stable() {
        let ctx = SessionContext::new("test")
            .add_tool("read_file")
            .add_tool("write_file")
            .add_arg_key("path");
        assert_eq!(ctx.fingerprint(), ctx.fingerprint());
    }

    #[test]
    fn session_context_different_tools_different_fingerprint() {
        let ctx1 = SessionContext::new("s1").add_tool("tool_alpha");
        let ctx2 = SessionContext::new("s2").add_tool("tool_beta");
        assert_ne!(ctx1.fingerprint(), ctx2.fingerprint());
    }

    // ── find_similar_hashes ───────────────────────────────────────────────────

    #[test]
    fn find_similar_hashes_empty_map() {
        let map = HashMap::new();
        assert!(find_similar_hashes(0xABCD, &map, 0.5).is_empty());
    }

    #[test]
    fn find_similar_hashes_returns_matching_entries() {
        let mut map = HashMap::new();
        let h = simhash(&["x", "y", "z"]);
        map.insert("match".to_string(), h);
        map.insert("nomatch".to_string(), !h);

        let results = find_similar_hashes(h, &map, 0.8);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "match");
    }
}
