//! DSA-inspired context compression for proxied conversations — Issue #79.
//!
//! When the gateway proxies conversations that include tool definitions, the
//! full set of tool schemas can consume significant context window space.
//! This module reduces that cost by:
//!
//! 1. **Semantic hashing** — tools with identical or near-identical
//!    `description` + `inputSchema` fingerprints are deduplicated.
//! 2. **Usage tracking** — a per-session set tracks which tools are actually
//!    called; after a configurable warm-up period, unobserved tools are pruned
//!    from outbound tool lists.
//! 3. **Similarity grouping** — tools whose descriptions share a common prefix
//!    (same "category") are grouped so a single representative description can
//!    be sent instead of N near-identical ones.
//!
//! # Semantic hash
//!
//! The hash is an FNV-1a 64-bit digest of the concatenated lower-cased
//! description tokens + JSON-serialised `inputSchema`. Two tools collide only
//! if their schemas are identical byte-for-byte; near-duplicates are detected
//! separately via the Jaccard token-overlap coefficient.
//!
//! # Pruning policy
//!
//! - Tools used at least once during the session are always retained.
//! - Tools never used are pruned after `min_requests` requests to the session
//!   (default: 3). This lets the model "discover" tools during the warm-up
//!   window.

use std::collections::{HashMap, HashSet};

use crate::protocol::Tool;

// ============================================================================
// FNV-1a 64-bit
// ============================================================================

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(input: &str) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ============================================================================
// Semantic hash
// ============================================================================

/// Compute a stable semantic fingerprint for `tool`.
///
/// The fingerprint combines:
/// - Lower-cased description tokens (word-level, sorted for stability).
/// - Canonical JSON serialization of `inputSchema`.
///
/// The result is a hex-encoded FNV-1a 64-bit digest.
#[must_use]
pub fn semantic_hash(tool: &Tool) -> String {
    let desc_tokens = {
        let raw = tool.description.as_deref().unwrap_or("");
        let mut tokens: Vec<&str> = raw.split_whitespace().collect();
        tokens.sort_unstable();
        tokens.join(" ").to_lowercase()
    };
    let schema_repr =
        serde_json::to_string(&tool.input_schema).unwrap_or_else(|_| "{}".to_string());
    let combined = format!("{desc_tokens}||{schema_repr}");
    format!("{:016x}", fnv1a(&combined))
}

// ============================================================================
// Token-Jaccard similarity
// ============================================================================

/// Word-level Jaccard similarity between two description strings.
///
/// Returns a value in `[0.0, 1.0]`.  Two identical strings → 1.0.
/// Two completely disjoint strings → 0.0.
#[must_use]
pub fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let set_a: HashSet<&str> = a.split_whitespace().collect();
    let set_b: HashSet<&str> = b.split_whitespace().collect();
    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)] // tool counts are small (< 2^53)
    {
        intersection as f64 / union as f64
    }
}

// ============================================================================
// Tool group
// ============================================================================

/// A group of semantically similar tools.
///
/// The first tool in `members` is the **representative** whose definition is
/// kept in compressed output; remaining members are aliases.
#[derive(Debug, Clone)]
pub struct ToolGroup {
    /// Shared category label (common name prefix or description prefix word).
    pub category: String,
    /// Member tool names; `members[0]` is the representative.
    pub members: Vec<String>,
    /// Semantic hash of the representative tool.
    pub hash: String,
}

// ============================================================================
// CompressionConfig
// ============================================================================

/// Configuration for the context compressor.
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Jaccard similarity threshold above which two tools are considered
    /// duplicates.  Default: 0.85.
    pub dedup_threshold: f64,
    /// Minimum number of requests before unused tools are pruned.
    /// Default: 3.
    pub min_requests_before_prune: u32,
    /// Whether to enable description deduplication.
    /// Default: true.
    pub dedup_enabled: bool,
    /// Whether to enable usage-based pruning.
    /// Default: true.
    pub prune_unused: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            dedup_threshold: 0.85,
            min_requests_before_prune: 3,
            dedup_enabled: true,
            prune_unused: true,
        }
    }
}

// ============================================================================
// SessionCompressor
// ============================================================================

/// Per-session compressor that tracks tool usage and applies compression.
///
/// One `SessionCompressor` should be created per proxied conversation session.
/// Call [`compress`] before forwarding tool definitions to the model; call
/// [`record_usage`] whenever the model invokes a tool.
pub struct SessionCompressor {
    config: CompressionConfig,
    /// Number of times [`compress`] has been called for this session.
    request_count: u32,
    /// Tools observed to be used in this session.
    used_tools: HashSet<String>,
    /// Canonical deduplicated tool set (name → Tool), populated on first call.
    canonical: HashMap<String, Tool>,
    /// Semantic hash → canonical tool name.
    hash_to_canonical: HashMap<String, String>,
    /// Alias → canonical name mapping.
    aliases: HashMap<String, String>,
    /// Groups identified during deduplication.
    groups: Vec<ToolGroup>,
}

impl SessionCompressor {
    /// Create a new compressor with the given configuration.
    #[must_use]
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            request_count: 0,
            used_tools: HashSet::new(),
            canonical: HashMap::new(),
            hash_to_canonical: HashMap::new(),
            aliases: HashMap::new(),
            groups: Vec::new(),
        }
    }

    /// Record that the model used `tool_name` in this session.
    pub fn record_usage(&mut self, tool_name: &str) {
        self.used_tools.insert(tool_name.to_string());
        // Also record the canonical name in case this is an alias
        if let Some(canonical) = self.aliases.get(tool_name) {
            self.used_tools.insert(canonical.clone());
        }
    }

    /// Compress the given tool list for inclusion in an outbound request.
    ///
    /// Steps:
    /// 1. Deduplicate by semantic hash (if `dedup_enabled`).
    /// 2. Prune unused tools after warm-up (if `prune_unused`).
    /// 3. Return the filtered list.
    ///
    /// The original `tools` slice is never mutated.
    pub fn compress(&mut self, tools: &[Tool]) -> Vec<Tool> {
        self.request_count += 1;
        // Step 1: deduplication
        let deduped = if self.config.dedup_enabled {
            self.deduplicate(tools)
        } else {
            tools.to_vec()
        };
        // Step 2: usage-based pruning
        if self.config.prune_unused && self.request_count > self.config.min_requests_before_prune {
            deduped
                .into_iter()
                .filter(|t| self.used_tools.contains(&t.name))
                .collect()
        } else {
            deduped
        }
    }

    /// Deduplicate `tools` by semantic hash and near-duplicate Jaccard.
    ///
    /// Returns a new Vec containing only representative tools.
    /// Alias mappings are stored in `self.aliases`.
    fn deduplicate(&mut self, tools: &[Tool]) -> Vec<Tool> {
        let mut output: Vec<Tool> = Vec::new();

        for tool in tools {
            let hash = semantic_hash(tool);

            // Exact-hash dedup: already seen this schema
            if let Some(canonical_name) = self.hash_to_canonical.get(&hash) {
                self.aliases
                    .insert(tool.name.clone(), canonical_name.clone());
                // Update group membership
                if let Some(grp) = self
                    .groups
                    .iter_mut()
                    .find(|g| g.members.contains(canonical_name))
                {
                    if !grp.members.contains(&tool.name) {
                        grp.members.push(tool.name.clone());
                    }
                }
                continue;
            }

            // Near-duplicate check via Jaccard
            let tool_desc = tool.description.as_deref().unwrap_or("");
            let mut merged = false;
            for existing in &output {
                let existing_desc = existing.description.as_deref().unwrap_or("");
                let sim = jaccard_similarity(tool_desc, existing_desc);
                if sim >= self.config.dedup_threshold {
                    // Treat `tool` as an alias of `existing`
                    self.aliases
                        .insert(tool.name.clone(), existing.name.clone());
                    let existing_hash = semantic_hash(existing);
                    if let Some(grp) = self.groups.iter_mut().find(|g| g.hash == existing_hash) {
                        if !grp.members.contains(&tool.name) {
                            grp.members.push(tool.name.clone());
                        }
                    }
                    merged = true;
                    break;
                }
            }

            if !merged {
                // New unique tool — register it
                self.hash_to_canonical
                    .insert(hash.clone(), tool.name.clone());
                self.canonical.insert(tool.name.clone(), tool.clone());
                let category = derive_category(&tool.name);
                self.groups.push(ToolGroup {
                    category,
                    members: vec![tool.name.clone()],
                    hash,
                });
                output.push(tool.clone());
            }
        }

        output
    }

    /// Return tool groups identified during deduplication.
    #[must_use]
    pub fn groups(&self) -> &[ToolGroup] {
        &self.groups
    }

    /// Return the set of tools used in this session.
    #[must_use]
    pub fn used_tools(&self) -> &HashSet<String> {
        &self.used_tools
    }

    /// Return alias mappings (alias → canonical name).
    #[must_use]
    pub fn aliases(&self) -> &HashMap<String, String> {
        &self.aliases
    }

    /// Number of `compress()` calls so far.
    #[must_use]
    pub fn request_count(&self) -> u32 {
        self.request_count
    }

    /// Compute compression statistics.
    ///
    /// `original_count` is the number of tools before compression;
    /// `output_count` is the number of tools after compression (returned by
    /// [`compress`]).
    #[must_use]
    pub fn stats(&self, original_count: usize, output_count: usize) -> CompressionStats {
        let alias_count = self.aliases.len();
        let dedup_savings = alias_count;
        let prune_savings = original_count.saturating_sub(output_count + alias_count);
        CompressionStats {
            original_count,
            output_count,
            dedup_savings,
            prune_savings,
            alias_count,
            group_count: self.groups.len(),
        }
    }
}

/// Category label derived from the tool name prefix.
fn derive_category(name: &str) -> String {
    // Take the first underscore-separated segment as the category.
    name.split('_').next().unwrap_or(name).to_string()
}

// ============================================================================
// CompressionStats
// ============================================================================

/// Summary statistics for a compression pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionStats {
    /// Tools in the original list.
    pub original_count: usize,
    /// Tools in the compressed output.
    pub output_count: usize,
    /// Tools removed by exact/near-duplicate deduplication.
    pub dedup_savings: usize,
    /// Tools removed by usage-based pruning.
    pub prune_savings: usize,
    /// Total alias mappings registered.
    pub alias_count: usize,
    /// Number of distinct groups.
    pub group_count: usize,
}

impl CompressionStats {
    /// Compression ratio: `output_count / original_count`.
    ///
    /// Returns `1.0` if `original_count` is zero (no compression possible).
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.original_count == 0 {
            return 1.0;
        }
        #[allow(clippy::cast_precision_loss)] // tool counts are small (< 2^53)
        {
            self.output_count as f64 / self.original_count as f64
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn make_tool(name: &str, description: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: Some(description.to_string()),
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: None,
            annotations: None,
        }
    }

    fn make_tool_with_schema(name: &str, description: &str, schema: Value) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: Some(description.to_string()),
            input_schema: schema,
            output_schema: None,
            annotations: None,
        }
    }

    // ── fnv1a ─────────────────────────────────────────────────────────

    #[test]
    fn fnv1a_is_deterministic() {
        assert_eq!(fnv1a("hello"), fnv1a("hello"));
    }

    #[test]
    fn fnv1a_differs_for_different_inputs() {
        assert_ne!(fnv1a("hello"), fnv1a("world"));
    }

    // ── semantic_hash ─────────────────────────────────────────────────

    #[test]
    fn semantic_hash_is_16_hex_chars() {
        let tool = make_tool("search", "Search the web for information");
        let h = semantic_hash(&tool);
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn semantic_hash_identical_tools_match() {
        let a = make_tool("search", "Search the web");
        let b = make_tool("search", "Search the web");
        assert_eq!(semantic_hash(&a), semantic_hash(&b));
    }

    #[test]
    fn semantic_hash_different_descriptions_differ() {
        let a = make_tool("tool", "Do something useful");
        let b = make_tool("tool", "Do something completely different");
        assert_ne!(semantic_hash(&a), semantic_hash(&b));
    }

    #[test]
    fn semantic_hash_different_schemas_differ() {
        let a = make_tool_with_schema(
            "tool",
            "Same description",
            json!({"type": "object", "properties": {"q": {"type": "string"}}}),
        );
        let b = make_tool_with_schema(
            "tool",
            "Same description",
            json!({"type": "object", "properties": {"query": {"type": "string"}}}),
        );
        assert_ne!(semantic_hash(&a), semantic_hash(&b));
    }

    #[test]
    fn semantic_hash_name_does_not_affect_hash() {
        // Two tools with different names but identical desc+schema should hash the same
        let a = make_tool("tool_v1", "Search the web for information");
        let b = make_tool("tool_v2", "Search the web for information");
        assert_eq!(semantic_hash(&a), semantic_hash(&b));
    }

    // ── jaccard_similarity ────────────────────────────────────────────

    #[test]
    fn jaccard_identical_strings_is_one() {
        assert!((jaccard_similarity("hello world", "hello world") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn jaccard_disjoint_strings_is_zero() {
        assert!((jaccard_similarity("hello", "world") - 0.0).abs() < 1e-9);
    }

    #[test]
    fn jaccard_empty_strings_is_one() {
        assert!((jaccard_similarity("", "") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn jaccard_partial_overlap() {
        // {"hello", "world"} ∩ {"hello", "there"} = {"hello"}  |union| = 3
        let sim = jaccard_similarity("hello world", "hello there");
        assert!((sim - 1.0 / 3.0).abs() < 1e-9);
    }

    // ── derive_category ───────────────────────────────────────────────

    #[test]
    fn derive_category_uses_first_segment() {
        assert_eq!(derive_category("search_web"), "search");
        assert_eq!(derive_category("write_file"), "write");
        assert_eq!(derive_category("no_underscore"), "no");
    }

    #[test]
    fn derive_category_no_underscore_returns_whole_name() {
        assert_eq!(derive_category("search"), "search");
    }

    // ── SessionCompressor deduplication ───────────────────────────────

    #[test]
    fn compress_dedup_exact_duplicates_kept_once() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        let t1 = make_tool("search_v1", "Search the web for information");
        let t2 = make_tool("search_v2", "Search the web for information");
        let out = c.compress(&[t1, t2]);
        // Both have same desc+schema, so only the first should survive
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "search_v1");
        assert!(c.aliases().contains_key("search_v2"));
    }

    #[test]
    fn compress_near_duplicates_above_threshold_merged() {
        let mut c = SessionCompressor::new(CompressionConfig {
            dedup_threshold: 0.8,
            ..Default::default()
        });
        // Very similar descriptions — Jaccard will be high
        let t1 = make_tool("tool_a", "Search the web for relevant information");
        let t2 = make_tool("tool_b", "Search the web for relevant information quickly");
        let out = c.compress(&[t1, t2]);
        // "tool_b" has 7 words, "tool_a" has 6 — intersection=6, union=7 → 0.857 > 0.8
        assert_eq!(out.len(), 1, "near-dups should be merged");
    }

    #[test]
    fn compress_distinct_tools_all_kept() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        let t1 = make_tool("search", "Search the web for information");
        let t2 = make_tool("write_file", "Write content to a file on disk");
        let t3 = make_tool("run_command", "Execute a shell command");
        let out = c.compress(&[t1, t2, t3]);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn compress_dedup_disabled_keeps_all() {
        let mut c = SessionCompressor::new(CompressionConfig {
            dedup_enabled: false,
            ..Default::default()
        });
        let t1 = make_tool("tool_a", "Do the thing");
        let t2 = make_tool("tool_b", "Do the thing");
        let out = c.compress(&[t1, t2]);
        assert_eq!(out.len(), 2);
    }

    // ── SessionCompressor pruning ──────────────────────────────────────

    #[test]
    fn compress_prunes_unused_after_warmup() {
        let mut c = SessionCompressor::new(CompressionConfig {
            min_requests_before_prune: 2,
            prune_unused: true,
            dedup_enabled: false,
            ..Default::default()
        });
        let t1 = make_tool("search", "Search");
        let t2 = make_tool("write_file", "Write");

        // Warm-up: request 1 and 2
        c.compress(&[t1.clone(), t2.clone()]);
        c.compress(&[t1.clone(), t2.clone()]);
        // Only use t1
        c.record_usage("search");

        // Request 3: prune kicks in
        let out = c.compress(&[t1.clone(), t2.clone()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "search");
    }

    #[test]
    fn compress_does_not_prune_during_warmup() {
        let mut c = SessionCompressor::new(CompressionConfig {
            min_requests_before_prune: 5,
            prune_unused: true,
            dedup_enabled: false,
            ..Default::default()
        });
        let t1 = make_tool("search", "Search");
        let t2 = make_tool("write_file", "Write");
        // Only 2 requests — still in warm-up
        c.compress(&[t1.clone(), t2.clone()]);
        let out = c.compress(&[t1.clone(), t2.clone()]);
        assert_eq!(out.len(), 2, "pruning should not fire during warm-up");
    }

    #[test]
    fn compress_prune_disabled_keeps_unused() {
        let mut c = SessionCompressor::new(CompressionConfig {
            min_requests_before_prune: 1,
            prune_unused: false,
            dedup_enabled: false,
            ..Default::default()
        });
        let t1 = make_tool("search", "Search");
        let t2 = make_tool("write_file", "Write");
        c.compress(&[t1.clone(), t2.clone()]);
        c.record_usage("search");
        let out = c.compress(&[t1.clone(), t2.clone()]);
        assert_eq!(out.len(), 2);
    }

    // ── record_usage ───────────────────────────────────────────────────

    #[test]
    fn record_usage_marks_tool_as_used() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        c.record_usage("my_tool");
        assert!(c.used_tools().contains("my_tool"));
    }

    #[test]
    fn record_usage_alias_also_marks_canonical() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        let t1 = make_tool("tool_a", "Do the thing");
        let t2 = make_tool("tool_b", "Do the thing");
        c.compress(&[t1, t2]);
        // tool_b is alias for tool_a
        c.record_usage("tool_b");
        // The canonical should also be marked
        assert!(c.used_tools().contains("tool_a"));
    }

    // ── groups ─────────────────────────────────────────────────────────

    #[test]
    fn groups_created_for_unique_tools() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        let t1 = make_tool("search_web", "Search the web");
        let t2 = make_tool("write_file", "Write content to a file");
        c.compress(&[t1, t2]);
        assert_eq!(c.groups().len(), 2);
    }

    #[test]
    fn groups_include_aliases() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        let t1 = make_tool("tool_a", "Same description text here");
        let t2 = make_tool("tool_b", "Same description text here");
        c.compress(&[t1, t2]);
        assert_eq!(c.groups().len(), 1);
        assert_eq!(c.groups()[0].members.len(), 2);
        assert!(c.groups()[0].members.contains(&"tool_a".to_string()));
        assert!(c.groups()[0].members.contains(&"tool_b".to_string()));
    }

    // ── CompressionStats ────────────────────────────────────────────────

    #[test]
    fn stats_ratio_no_compression_is_one() {
        let mut c = SessionCompressor::new(CompressionConfig {
            dedup_enabled: false,
            prune_unused: false,
            ..Default::default()
        });
        let t1 = make_tool("a", "Tool A");
        let t2 = make_tool("b", "Tool B");
        let out = c.compress(&[t1, t2]);
        let s = c.stats(2, out.len());
        // 2 unique tools, 0 aliases → output_count = 2, ratio = 1.0
        assert!((s.ratio() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn stats_ratio_with_dedup() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        let t1 = make_tool("tool_a", "Identical description for both tools");
        let t2 = make_tool("tool_b", "Identical description for both tools");
        let out = c.compress(&[t1, t2]);
        let s = c.stats(2, out.len());
        // 1 canonical, 1 alias → output_count=1, ratio = 0.5
        assert!((s.ratio() - 0.5).abs() < 1e-9);
        assert_eq!(s.dedup_savings, 1);
    }

    #[test]
    fn stats_ratio_empty_is_one() {
        let c = SessionCompressor::new(CompressionConfig::default());
        let s = c.stats(0, 0);
        assert!((s.ratio() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn request_count_increments() {
        let mut c = SessionCompressor::new(CompressionConfig::default());
        assert_eq!(c.request_count(), 0);
        c.compress(&[]);
        assert_eq!(c.request_count(), 1);
        c.compress(&[]);
        assert_eq!(c.request_count(), 2);
    }
}
