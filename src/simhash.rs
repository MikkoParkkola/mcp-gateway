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
#[path = "simhash_tests.rs"]
mod tests;
