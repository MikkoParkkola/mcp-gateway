//! Smart search ranking based on usage frequency
//!
//! Ranks search results by combining text relevance with usage-based popularity.
//! Synonym expansion allows semantically related words to match with a slight
//! score discount (0.8×) relative to exact matches.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Synonym expansion
// ============================================================================

/// Return the synonym group for a given word (all lowercase).
///
/// Each word maps to the *other* members of its group. Matches against synonyms
/// score at 0.8× of an exact match to prefer literal terms. Returns an empty
/// slice when the word has no known synonyms.
///
/// # Extending the synonym map
///
/// Add a new `match` arm with the canonical and alternate spellings:
/// ```text
/// "send" | "deliver" | "publish" | "emit" => &["send", "deliver", "publish", "emit"],
/// ```
/// Every word in the group must map to the full group (bidirectional).
#[must_use]
pub fn expand_synonyms(word: &str) -> &'static [&'static str] {
    match word {
        // search group
        "search" | "find" | "discover" | "locate" | "lookup" | "query" => {
            &["search", "find", "discover", "locate", "lookup", "query"]
        }
        // monitor group
        "monitor" | "watch" | "track" | "observe" | "alert" => {
            &["monitor", "watch", "track", "observe", "alert"]
        }
        // extract group
        "extract" | "scrape" | "parse" | "pull" | "fetch" => {
            &["extract", "scrape", "parse", "pull", "fetch"]
        }
        // create group
        "create" | "generate" | "make" | "build" | "produce" => {
            &["create", "generate", "make", "build", "produce"]
        }
        // analyze group
        "analyze" | "examine" | "inspect" | "audit" | "review" => {
            &["analyze", "examine", "inspect", "audit", "review"]
        }
        // batch group
        "batch" | "bulk" | "mass" | "parallel" | "concurrent" => {
            &["batch", "bulk", "mass", "parallel", "concurrent"]
        }
        // entity group
        "entity" | "record" | "item" | "object" | "resource" => {
            &["entity", "record", "item", "object", "resource"]
        }
        // research group
        "research" | "investigate" | "study" | "explore" => {
            &["research", "investigate", "study", "explore"]
        }
        // send group
        "send" | "deliver" | "publish" | "emit" | "notify" => {
            &["send", "deliver", "publish", "emit", "notify"]
        }
        // delete group
        "delete" | "remove" | "purge" | "clear" | "destroy" => {
            &["delete", "remove", "purge", "clear", "destroy"]
        }
        // list group
        "list" | "enumerate" | "browse" | "catalog" | "index" => {
            &["list", "enumerate", "browse", "catalog", "index"]
        }
        // convert group
        "convert" | "transform" | "translate" | "format" | "encode" => {
            &["convert", "transform", "translate", "format", "encode"]
        }
        _ => &[],
    }
}

/// Score multiplier applied to synonym-expanded matches.
///
/// Exact matches retain their full score; synonym matches are discounted
/// to prefer literal term alignment over semantic expansion.
const SYNONYM_MULTIPLIER: f64 = 0.8;

// ============================================================================
// Scoring helpers
// ============================================================================

/// Return `true` if `text` contains `word` as a substring, or contains any
/// synonym of `word`.  The `synonym_hit` output flag is set to `true` when a
/// synonym (not the word itself) produced the match — callers can apply the
/// `SYNONYM_MULTIPLIER` in that case.
fn text_contains_with_synonyms(text: &str, word: &str) -> (bool, bool) {
    if text.contains(word) {
        return (true, false);
    }
    for syn in expand_synonyms(word) {
        if *syn != word && text.contains(*syn) {
            return (true, true);
        }
    }
    (false, false)
}

/// Keyword-tag scoring: returns `(score, via_synonym)`.
///
/// Tier: `6 + 2N` where N is the number of matched keyword tags.
#[allow(clippy::cast_precision_loss)]
fn keyword_tag_score(desc_lower: &str, words: &[&str]) -> (f64, bool) {
    if !desc_lower.contains("[keywords:") {
        return (0.0, false);
    }
    let exact_kw = count_keyword_matches(desc_lower, words);
    if exact_kw > 0 {
        return (6.0 + (exact_kw as f64) * 2.0, false);
    }
    let syn_kw = count_keyword_matches_with_synonyms(desc_lower, words);
    if syn_kw > 0 {
        (6.0 + (syn_kw as f64) * 2.0, true)
    } else {
        (0.0, false)
    }
}

/// Text-coverage scoring for multi-word queries: returns `(score, via_synonym)`.
///
/// Counts query words found anywhere in `combined` (tool name + description).
/// Tiers: `10+2N` (all N matched), `3+2M` (M of N partial), `0` (no match).
#[allow(clippy::cast_precision_loss)]
fn text_coverage_score(combined: &str, words: &[&str]) -> (f64, bool) {
    if words.len() <= 1 {
        return (0.0, false);
    }
    let exact_matched = words.iter().filter(|w| combined.contains(**w)).count();
    if exact_matched == words.len() {
        return (10.0 + (exact_matched as f64) * 2.0, false);
    }
    let syn_matched = words
        .iter()
        .filter(|w| text_contains_with_synonyms(combined, w).0)
        .count();
    let any_syn = words
        .iter()
        .any(|w| text_contains_with_synonyms(combined, w).1);
    if syn_matched == words.len() {
        (10.0 + (syn_matched as f64) * 2.0, any_syn)
    } else if syn_matched > 0 {
        (3.0 + (syn_matched as f64) * 2.0, any_syn)
    } else {
        (0.0, false)
    }
}

/// Select the winning `(score, via_synonym)` from the three scoring paths.
///
/// Schema scores are never synonym-discounted (field names are exact identifiers).
fn best_coverage_score(kw: (f64, bool), schema: f64, text: (f64, bool)) -> (f64, bool) {
    let (kw_best, kw_syn) = if kw.0 >= text.0 { kw } else { text };
    if schema > kw_best {
        (schema, false)
    } else {
        (kw_best, kw_syn)
    }
}

/// Compute text relevance score for a single result against a pre-lowercased query.
///
/// `words` must be `query.split_whitespace().collect()` — passed in to avoid
/// re-splitting for every result in a batch.
///
/// Synonym-expanded matches use the same scoring tiers but with a
/// `SYNONYM_MULTIPLIER` (0.8×) applied to the base text-relevance score before
/// the usage multiplier is applied.
fn score_text_relevance(tool: &str, description: &str, query: &str, words: &[&str]) -> f64 {
    let tool_lower = tool.to_lowercase();
    let desc_lower = description.to_lowercase();

    // Tier 1: single-word exact name match
    if tool_lower == query {
        return 10.0;
    }

    // Tier 2: all words found in tool name alone
    if words.len() > 1 {
        if words.iter().all(|w| tool_lower.contains(w)) {
            return 15.0;
        }
        let syn_all_in_name = words
            .iter()
            .all(|w| text_contains_with_synonyms(&tool_lower, w).0);
        let any_synonym = words
            .iter()
            .any(|w| text_contains_with_synonyms(&tool_lower, w).1);
        if syn_all_in_name && any_synonym {
            return 15.0 * SYNONYM_MULTIPLIER;
        }
    }

    // Coverage tiers: keyword-tag, schema-field, text-coverage — take the best.
    let combined = format!("{tool_lower} {desc_lower}");
    let (best, via_syn) = best_coverage_score(
        keyword_tag_score(&desc_lower, words),
        schema_field_score(&desc_lower, words),
        text_coverage_score(&combined, words),
    );
    if best > 0.0 {
        return if via_syn {
            best * SYNONYM_MULTIPLIER
        } else {
            best
        };
    }

    // Single-word substring fallbacks (exact, then schema-field, then desc, then synonyms)
    if tool_lower.contains(query) {
        return 5.0;
    }
    if words.len() == 1 && is_schema_field_match(&desc_lower, query) {
        return 6.0;
    }
    if desc_lower.contains(query) {
        return 2.0;
    }
    if words.len() == 1 {
        for syn in expand_synonyms(query) {
            if *syn != query {
                if tool_lower.contains(syn) {
                    return 5.0 * SYNONYM_MULTIPLIER;
                }
                if desc_lower.contains(syn) {
                    return 2.0 * SYNONYM_MULTIPLIER;
                }
            }
        }
    }

    0.0
}

/// Extract a bracketed tag section from a lowercased description by its prefix.
///
/// Returns the content between `[{prefix}:` and the matching `]`, or `None`
/// if the section is absent.  Used by both keyword and schema tag lookups.
fn extract_tag_section<'a>(desc_lower: &'a str, prefix: &str) -> Option<&'a str> {
    let marker = format!("[{prefix}:");
    let start = desc_lower.find(marker.as_str())?;
    let after_marker = &desc_lower[start + marker.len()..];
    let end = after_marker.find(']').unwrap_or(after_marker.len());
    Some(&after_marker[..end])
}

/// Check whether `word` appears as a discrete keyword inside the
/// `[keywords: tag1, tag2, ...]` suffix of a lowercased description.
/// Also matches against hyphen-split parts (e.g., "entity" matches "entity-discovery").
fn is_keyword_match(desc_lower: &str, word: &str) -> bool {
    let Some(section) = extract_tag_section(desc_lower, "keywords") else {
        return false;
    };
    section.split(',').any(|tag| {
        let tag = tag.trim();
        tag == word || tag.split('-').any(|part| part == word)
    })
}

/// Check whether `word` appears as a token inside the `[schema: ...]` suffix.
///
/// Schema tokens are plain lowercase identifiers separated by commas.
#[must_use]
pub fn is_schema_field_match(desc_lower: &str, word: &str) -> bool {
    let Some(section) = extract_tag_section(desc_lower, "schema") else {
        return false;
    };
    section.split(',').any(|token| token.trim() == word)
}

/// Count how many query words match schema fields in the description.
fn count_schema_field_matches(desc_lower: &str, words: &[&str]) -> usize {
    words
        .iter()
        .filter(|w| is_schema_field_match(desc_lower, w))
        .count()
}

/// Compute the schema-field scoring tier for a query against a description.
///
/// Returns `(score, via_synonym=false)` — schema tokens are exact identifiers
/// so synonym expansion is never applied here.
///
/// Tier: `4 + 2N` where N is the count of matched schema fields.
/// A single match scores 6.0 (above description-substring at 2.0, below
/// keyword-tag at 8.0). When no schema section is present, returns 0.0.
#[allow(clippy::cast_precision_loss)]
fn schema_field_score(desc_lower: &str, words: &[&str]) -> f64 {
    if !desc_lower.contains("[schema:") {
        return 0.0;
    }
    let n = count_schema_field_matches(desc_lower, words);
    if n > 0 { 4.0 + (n as f64) * 2.0 } else { 0.0 }
}

/// Check whether `word` or any of its synonyms appears as a keyword tag in the description.
fn is_keyword_match_with_synonyms(desc_lower: &str, word: &str) -> bool {
    if is_keyword_match(desc_lower, word) {
        return true;
    }
    expand_synonyms(word)
        .iter()
        .any(|syn| *syn != word && is_keyword_match(desc_lower, syn))
}

/// Count how many query words match keywords in the description (exact only).
fn count_keyword_matches(desc_lower: &str, words: &[&str]) -> usize {
    words
        .iter()
        .filter(|w| is_keyword_match(desc_lower, w))
        .count()
}

/// Count how many query words match keywords in the description (exact or synonym).
fn count_keyword_matches_with_synonyms(desc_lower: &str, words: &[&str]) -> usize {
    words
        .iter()
        .filter(|w| is_keyword_match_with_synonyms(desc_lower, w))
        .count()
}

/// Search result with relevance score
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Server name
    pub server: String,
    /// Tool name
    pub tool: String,
    /// Description
    pub description: String,
    /// Relevance score (higher = more relevant)
    pub score: f64,
}

/// Search ranker with usage-based weighting
pub struct SearchRanker {
    /// Usage counts per tool (key = "server:tool")
    usage_counts: DashMap<String, AtomicU64>,
}

impl SearchRanker {
    /// Create a new ranker
    #[must_use]
    pub fn new() -> Self {
        Self {
            usage_counts: DashMap::new(),
        }
    }

    /// Record a tool usage
    pub fn record_use(&self, server: &str, tool: &str) {
        let key = format!("{server}:{tool}");
        self.usage_counts
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get usage count for a tool
    #[must_use]
    pub fn usage_count(&self, server: &str, tool: &str) -> u64 {
        let key = format!("{server}:{tool}");
        self.usage_counts
            .get(&key)
            .map_or(0, |entry| entry.load(Ordering::Relaxed))
    }

    /// Rank search results by relevance and usage.
    ///
    /// # Scoring Algorithm
    ///
    /// `score = text_relevance * (1 + usage_factor)`
    ///
    /// Usage is **multiplicative** so it amplifies good matches but cannot
    /// promote irrelevant tools above highly relevant ones.
    ///
    /// Text relevance tiers (multi-word queries split on whitespace):
    /// - 15: all words match tool name
    /// - 10+2N: all N words found in name+description combined (2w=14, 3w=16)
    /// - 10: exact single-word name match
    /// - 6+2N: N query words match keyword tags in `[keywords: …]` (1=8, 2=10, 3=12)
    /// - 4+2N: N query words match schema field names in `[schema: …]` (1=6, 2=8, 3=10)
    /// - 3+2M: M of N words found in name+description (partial, 1/3=5, 2/3=7)
    /// - 6: single-word query matches a schema field name exactly
    /// - 5: name contains the full query as a substring
    /// - 2: description contains the full query as a substring
    ///
    /// Usage factor: `log2(usage_count + 1) * 0.15` (multiplicative)
    /// - 0 uses → ×1.0, 4 uses → ×1.35, 10 uses → ×1.52, 100 uses → ×2.0
    #[must_use]
    pub fn rank(&self, mut results: Vec<SearchResult>, query: &str) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let words: Vec<&str> = query_lower.split_whitespace().collect();

        for result in &mut results {
            let text_relevance =
                score_text_relevance(&result.tool, &result.description, &query_lower, &words);

            let usage = self.usage_count(&result.server, &result.tool);
            #[allow(clippy::cast_precision_loss)]
            let usage_factor = if usage > 0 {
                ((usage + 1) as f64).log2() * 0.15
            } else {
                0.0
            };

            // Multiplicative: usage amplifies relevance, can't promote irrelevant tools
            result.score = text_relevance * (1.0 + usage_factor);
        }

        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results
    }

    /// Save usage counts to JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the file cannot be written.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let counts: Vec<UsageEntry> = self
            .usage_counts
            .iter()
            .map(|entry| {
                let parts: Vec<&str> = entry.key().split(':').collect();
                UsageEntry {
                    server: parts.first().unwrap_or(&"").to_string(),
                    tool: parts.get(1).unwrap_or(&"").to_string(),
                    count: entry.value().load(Ordering::Relaxed),
                }
            })
            .collect();

        let json = serde_json::to_string_pretty(&counts)?;
        std::fs::write(path, json)
    }

    /// Load usage counts from JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or JSON is invalid.
    pub fn load(&self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<UsageEntry> = serde_json::from_str(&content)?;

        for entry in entries {
            let key = format!("{}:{}", entry.server, entry.tool);
            self.usage_counts.insert(key, AtomicU64::new(entry.count));
        }

        Ok(())
    }

    /// Clear all usage counts
    pub fn clear(&self) {
        self.usage_counts.clear();
    }
}

impl Default for SearchRanker {
    fn default() -> Self {
        Self::new()
    }
}

/// Usage entry for serialization
#[derive(Debug, Serialize, Deserialize)]
struct UsageEntry {
    server: String,
    tool: String,
    count: u64,
}

/// Convert a JSON search result to a `SearchResult`
#[must_use]
pub fn json_to_search_result(value: &Value) -> Option<SearchResult> {
    Some(SearchResult {
        server: value.get("server")?.as_str()?.to_string(),
        tool: value.get("tool")?.as_str()?.to_string(),
        description: value.get("description")?.as_str()?.to_string(),
        score: 0.0,
    })
}

#[cfg(test)]
mod tests;
