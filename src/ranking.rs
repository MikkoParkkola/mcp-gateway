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

    // Single-word exact name match
    if tool_lower == query {
        return 10.0;
    }

    // Multi-word: all words found in name alone (strongest signal)
    // Check exact first, then synonym-expanded.
    if words.len() > 1 {
        if words.iter().all(|w| tool_lower.contains(w)) {
            return 15.0;
        }
        let syn_all_in_name = words.iter().all(|w| {
            let (hit, _) = text_contains_with_synonyms(&tool_lower, w);
            hit
        });
        let any_synonym = words.iter().any(|w| {
            let (_, is_syn) = text_contains_with_synonyms(&tool_lower, w);
            is_syn
        });
        if syn_all_in_name && any_synonym {
            return 15.0 * SYNONYM_MULTIPLIER;
        }
    }

    // ── Coverage-aware scoring for multi-word queries ──
    // Compute how many query words match via keywords and via text independently,
    // then take the best composite score. This ensures 3/3 matches always
    // dominate 1/3 matches regardless of which mechanism matched.

    // Keyword tag matches (exact, then synonym-expanded)
    #[allow(clippy::cast_precision_loss)]
    let (kw_score, kw_via_synonym) = if desc_lower.contains("[keywords:") {
        let exact_kw = count_keyword_matches(&desc_lower, words);
        if exact_kw > 0 {
            (6.0 + (exact_kw as f64) * 2.0, false)
        } else {
            let syn_kw = count_keyword_matches_with_synonyms(&desc_lower, words);
            if syn_kw > 0 {
                (6.0 + (syn_kw as f64) * 2.0, true)
            } else {
                (0.0, false)
            }
        }
    } else {
        (0.0, false)
    };

    // Text coverage: count words found anywhere in name + description
    let combined = format!("{tool_lower} {desc_lower}");
    #[allow(clippy::cast_precision_loss)]
    let (text_score, text_via_synonym) = if words.len() > 1 {
        // Count exact matches first
        let exact_matched = words.iter().filter(|w| combined.contains(**w)).count();
        if exact_matched == words.len() {
            (10.0 + (exact_matched as f64) * 2.0, false)
        } else {
            // Count synonym-expanded matches for words that didn't match exactly
            let syn_matched = words
                .iter()
                .filter(|w| {
                    let (hit, _) = text_contains_with_synonyms(&combined, w);
                    hit
                })
                .count();
            let any_syn = words.iter().any(|w| {
                let (_, is_syn) = text_contains_with_synonyms(&combined, w);
                is_syn
            });
            if syn_matched == words.len() {
                (10.0 + (syn_matched as f64) * 2.0, any_syn)
            } else if syn_matched > 0 {
                (3.0 + (syn_matched as f64) * 2.0, any_syn)
            } else {
                (0.0, false)
            }
        }
    } else {
        (0.0, false)
    };

    // Take the best of keyword-tag and coverage-text scores, applying the
    // synonym discount when the winning path was synonym-expanded.
    let (best, via_syn) = if kw_score >= text_score {
        (kw_score, kw_via_synonym)
    } else {
        (text_score, text_via_synonym)
    };

    if best > 0.0 {
        return if via_syn { best * SYNONYM_MULTIPLIER } else { best };
    }

    // Single-word substring fallbacks (exact, then synonym-expanded)
    if tool_lower.contains(query) {
        return 5.0;
    }
    if desc_lower.contains(query) {
        return 2.0;
    }
    // Synonym substring fallbacks for single-word queries
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

/// Check whether `word` appears as a discrete keyword inside the
/// `[keywords: tag1, tag2, ...]` suffix of a lowercased description.
/// Also matches against hyphen-split parts (e.g., "entity" matches "entity-discovery").
fn is_keyword_match(desc_lower: &str, word: &str) -> bool {
    let Some(kw_start) = desc_lower.find("[keywords:") else {
        return false;
    };
    let kw_section = &desc_lower[kw_start..];
    kw_section
        .trim_start_matches("[keywords:")
        .trim_end_matches(']')
        .split(',')
        .any(|tag| {
            let tag = tag.trim();
            // Exact tag match
            tag == word
            // Or word matches a hyphen-split part of the tag
            || tag.split('-').any(|part| part == word)
        })
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
    words.iter().filter(|w| is_keyword_match(desc_lower, w)).count()
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
    /// - 3+2M: M of N words found in name+description (partial, 1/3=5, 2/3=7)
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
            let text_relevance = score_text_relevance(&result.tool, &result.description, &query_lower, &words);

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
            self.usage_counts
                .insert(key, AtomicU64::new(entry.count));
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
mod tests {
    use super::*;

    #[test]
    fn test_record_and_retrieve_usage() {
        let ranker = SearchRanker::new();
        ranker.record_use("server1", "tool1");
        ranker.record_use("server1", "tool1");
        ranker.record_use("server2", "tool2");

        assert_eq!(ranker.usage_count("server1", "tool1"), 2);
        assert_eq!(ranker.usage_count("server2", "tool2"), 1);
        assert_eq!(ranker.usage_count("server3", "tool3"), 0);
    }

    #[test]
    fn test_ranking_with_text_relevance() {
        let search_ranker = SearchRanker::new();
        let results = vec![
            SearchResult {
                server: "s1".to_string(),
                tool: "weather".to_string(), // Exact match
                description: "Get weather".to_string(),
                score: 0.0,
            },
            SearchResult {
                server: "s2".to_string(),
                tool: "get_weather_forecast".to_string(), // Contains
                description: "Forecast".to_string(),
                score: 0.0,
            },
            SearchResult {
                server: "s3".to_string(),
                tool: "forecast".to_string(),
                description: "Get weather data".to_string(), // Desc contains
                score: 0.0,
            },
        ];

        let ranked = search_ranker.rank(results, "weather");

        assert_eq!(ranked[0].tool, "weather"); // Exact match first
        assert_eq!(ranked[1].tool, "get_weather_forecast"); // Contains second
        assert_eq!(ranked[2].tool, "forecast"); // Desc contains last
    }

    #[test]
    fn test_ranking_with_usage_boost() {
        let usage_ranker = SearchRanker::new();

        // Popular tool
        for _ in 0..100 {
            usage_ranker.record_use("s1", "popular");
        }

        let results = vec![
            SearchResult {
                server: "s1".to_string(),
                tool: "popular".to_string(),
                description: "Contains search term".to_string(),
                score: 0.0,
            },
            SearchResult {
                server: "s2".to_string(),
                tool: "exact".to_string(), // Exact match but no usage
                description: "Something".to_string(),
                score: 0.0,
            },
        ];

        let ranked = usage_ranker.rank(results, "search");

        // "popular" has desc match (2 pts) × (1 + log2(101)*0.15) ≈ 2 × 2.0 = 4.0
        // "exact" has no match (0 points, usage irrelevant with multiplicative)
        assert_eq!(ranked[0].tool, "popular");
    }

    #[test]
    fn test_save_and_load() {
        let ranker = SearchRanker::new();
        ranker.record_use("s1", "t1");
        ranker.record_use("s1", "t1");
        ranker.record_use("s2", "t2");

        let temp = std::env::temp_dir().join("test_ranking.json");

        ranker.save(&temp).unwrap();

        let new_ranker = SearchRanker::new();
        new_ranker.load(&temp).unwrap();

        assert_eq!(new_ranker.usage_count("s1", "t1"), 2);
        assert_eq!(new_ranker.usage_count("s2", "t2"), 1);

        std::fs::remove_file(temp).ok();
    }

    #[test]
    fn test_default_impl() {
        let ranker = SearchRanker::default();
        assert_eq!(ranker.usage_count("s1", "t1"), 0);
    }

    #[test]
    fn test_clear() {
        let ranker = SearchRanker::new();
        ranker.record_use("s1", "t1");
        ranker.record_use("s2", "t2");

        ranker.clear();

        assert_eq!(ranker.usage_count("s1", "t1"), 0);
        assert_eq!(ranker.usage_count("s2", "t2"), 0);
    }

    #[test]
    fn test_json_to_search_result() {
        let value = serde_json::json!({
            "server": "test-server",
            "tool": "test-tool",
            "description": "Test description"
        });

        let result = json_to_search_result(&value).unwrap();
        assert_eq!(result.server, "test-server");
        assert_eq!(result.tool, "test-tool");
        assert_eq!(result.description, "Test description");
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_json_to_search_result_missing_fields() {
        let value = serde_json::json!({
            "server": "test-server"
        });

        let result = json_to_search_result(&value);
        assert!(result.is_none());
    }

    #[test]
    fn test_ranking_empty_results() {
        let ranker = SearchRanker::new();
        let results = vec![];

        let ranked = ranker.rank(results, "test");
        assert_eq!(ranked.len(), 0);
    }

    #[test]
    fn test_ranking_preserves_unmatched() {
        let ranker = SearchRanker::new();
        let results = vec![
            SearchResult {
                server: "s1".to_string(),
                tool: "unrelated".to_string(),
                description: "No match".to_string(),
                score: 0.0,
            },
            SearchResult {
                server: "s2".to_string(),
                tool: "also_unrelated".to_string(),
                description: "Still no match".to_string(),
                score: 0.0,
            },
        ];

        let ranked = ranker.rank(results, "test");
        assert_eq!(ranked.len(), 2);
        // Both should have score 0.0 (no text match, no usage)
        assert_eq!(ranked[0].score, 0.0);
        assert_eq!(ranked[1].score, 0.0);
    }

    // ── score_text_relevance ─────────────────────────────────────────────

    fn sr(tool: &str, description: &str) -> SearchResult {
        SearchResult {
            server: "s".to_string(),
            tool: tool.to_string(),
            description: description.to_string(),
            score: 0.0,
        }
    }

    #[test]
    fn score_text_relevance_exact_name_match_scores_10() {
        // GIVEN: single-word query exactly equals tool name
        // WHEN: scoring
        // THEN: score is 10
        let words = vec!["weather"];
        let score = score_text_relevance("weather", "Get weather data", "weather", &words);
        assert!((score - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_text_relevance_all_words_in_name_scores_15() {
        // GIVEN: multi-word query where ALL words are in tool name
        // WHEN: scoring
        // THEN: score is 15 (highest tier)
        let words = vec!["batch", "search"];
        let score = score_text_relevance("batch_search_tool", "Does stuff", "batch search", &words);
        assert!((score - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_text_relevance_all_words_in_combined_scores_by_word_count() {
        // GIVEN: "batch" in name, "research" only in description
        // WHEN: scoring with "batch research" (2 words)
        // THEN: score is 10 + 2*2 = 14 (all words found, scaled by count)
        let words = vec!["batch", "research"];
        let score = score_text_relevance(
            "batch_runner",
            "Executes deep research tasks",
            "batch research",
            &words,
        );
        assert!((score - 14.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_text_relevance_keyword_exact_match_scores_8() {
        // GIVEN: description has [keywords: search, web, brave] and query word is "brave"
        // WHEN: scoring with single word "brave"
        // THEN: score is 8 (keyword exact match)
        let words = vec!["brave"];
        let score = score_text_relevance(
            "query_tool",
            "Query the web [keywords: search, web, brave]",
            "brave",
            &words,
        );
        assert!((score - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_text_relevance_partial_match_scores_by_matched_count() {
        // GIVEN: multi-word query "batch search", only "search" matches
        // WHEN: scoring
        // THEN: score is 3 + 2*1 = 5 (partial coverage, 1 word matched)
        let words = vec!["batch", "search"];
        let score = score_text_relevance("search_engine", "Search the web", "batch search", &words);
        assert!((score - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_text_relevance_full_query_in_name_scores_5() {
        // GIVEN: single-word query as substring of tool name (not exact)
        // WHEN: scoring
        // THEN: score is 5
        let words = vec!["search"];
        let score = score_text_relevance("search_engine", "Find things", "search", &words);
        assert!((score - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_text_relevance_full_query_in_description_scores_2() {
        // GIVEN: query only in description
        // WHEN: scoring
        // THEN: score is 2
        let words = vec!["forecast"];
        let score = score_text_relevance("weather_api", "Get weather forecast data", "forecast", &words);
        assert!((score - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_text_relevance_no_match_scores_0() {
        let words = vec!["unrelated"];
        let score = score_text_relevance("weather_api", "Get current temperature", "unrelated", &words);
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ranking_multi_word_query_all_words_in_name_beats_partial() {
        // GIVEN: "batch search" query, two results
        let ranker = SearchRanker::new();
        let results = vec![
            sr("search_only", "Does searching"),             // only "search" in name -> score 7
            sr("batch_search_runner", "Multi-batch tool"),   // both words in name -> score 15
        ];
        // WHEN: ranking
        let ranked = ranker.rank(results, "batch search");
        // THEN: full-name match wins
        assert_eq!(ranked[0].tool, "batch_search_runner");
    }

    #[test]
    fn ranking_keyword_tag_scores_above_description_substring() {
        // GIVEN: "brave" query, one tool with keyword tag, one with desc substring
        let ranker = SearchRanker::new();
        let results = vec![
            sr("query_tool", "Use brave API to query stuff"),          // desc contains -> 2
            sr("web_tool", "Web search [keywords: search, web, brave]"), // keyword match -> 8
        ];
        let ranked = ranker.rank(results, "brave");
        assert_eq!(ranked[0].tool, "web_tool");
        assert!(ranked[0].score > ranked[1].score);
    }

    #[test]
    fn is_keyword_match_finds_exact_tag() {
        // GIVEN: description with [keywords: search, web, brave]
        let desc = "does stuff [keywords: search, web, brave]";
        // WHEN: checking each tag
        // THEN: all exact tags match, non-tags do not
        assert!(is_keyword_match(desc, "search"));
        assert!(is_keyword_match(desc, "web"));
        assert!(is_keyword_match(desc, "brave"));
        assert!(!is_keyword_match(desc, "stuff"));
        assert!(!is_keyword_match(desc, "does"));
    }

    #[test]
    fn is_keyword_match_no_keywords_section_returns_false() {
        assert!(!is_keyword_match("plain description with no tags", "search"));
    }

    // ── expand_synonyms ──────────────────────────────────────────────────

    #[test]
    fn expand_synonyms_returns_group_for_known_word() {
        // GIVEN: "find" is in the search synonym group
        // WHEN: expanding
        // THEN: the full group is returned
        let syns = expand_synonyms("find");
        assert!(syns.contains(&"search"));
        assert!(syns.contains(&"find"));
        assert!(syns.contains(&"discover"));
        assert!(syns.contains(&"locate"));
    }

    #[test]
    fn expand_synonyms_is_bidirectional() {
        // GIVEN: "search" and "find" are synonyms
        // WHEN: expanding both
        // THEN: each group contains the other word
        let from_search = expand_synonyms("search");
        let from_find = expand_synonyms("find");
        assert!(from_search.contains(&"find"));
        assert!(from_find.contains(&"search"));
    }

    #[test]
    fn expand_synonyms_returns_empty_for_unknown_word() {
        assert!(expand_synonyms("xyzzy").is_empty());
        assert!(expand_synonyms("weather").is_empty());
    }

    #[test]
    fn expand_synonyms_all_groups_are_bidirectional() {
        // Every word in a returned group should map back to the same group.
        let seeds = [
            "search", "monitor", "extract", "create", "analyze", "batch", "entity", "research",
            "send", "delete", "list", "convert",
        ];
        for seed in seeds {
            let group = expand_synonyms(seed);
            assert!(!group.is_empty(), "seed '{seed}' has empty group");
            for member in group {
                let back = expand_synonyms(member);
                assert!(
                    back.contains(&seed),
                    "'{member}' does not map back to '{seed}'"
                );
            }
        }
    }

    // ── synonym scoring ──────────────────────────────────────────────────

    #[test]
    fn score_text_relevance_synonym_name_match_scores_below_exact() {
        // GIVEN: query "find" and tool name "search_engine" (synonym of "find")
        // WHEN: scoring both an exact match and a synonym match
        // THEN: exact match scores higher
        let words_exact = vec!["search"];
        let words_syn = vec!["find"];
        let exact_score = score_text_relevance("search_engine", "Finds things", "search", &words_exact);
        let syn_score = score_text_relevance("search_engine", "Finds things", "find", &words_syn);
        // Both should be positive (synonym hit gives a score)
        assert!(syn_score > 0.0, "synonym should produce a positive score");
        // But exact beats synonym
        assert!(
            exact_score > syn_score,
            "exact ({exact_score}) should beat synonym ({syn_score})"
        );
    }

    #[test]
    fn score_text_relevance_synonym_multiplier_is_applied() {
        // GIVEN: query "find" resolves via synonym to a name-contains match (score 5)
        // WHEN: scoring
        // THEN: score is 5 * 0.8 = 4.0
        let words = vec!["find"];
        let score = score_text_relevance("search_engine", "Retrieves data", "find", &words);
        let expected = 5.0 * SYNONYM_MULTIPLIER;
        assert!(
            (score - expected).abs() < 0.01,
            "expected {expected}, got {score}"
        );
    }

    #[test]
    fn score_text_relevance_synonym_keyword_match_applies_discount() {
        // GIVEN: tool has [keywords: search] and query is "find" (synonym)
        // WHEN: scoring
        // THEN: 1-word keyword match = 8, discounted to 8 * 0.8 = 6.4
        let words = vec!["find"];
        let score = score_text_relevance(
            "tool",
            "Does stuff [keywords: search, web]",
            "find",
            &words,
        );
        let expected = 8.0 * SYNONYM_MULTIPLIER;
        assert!(
            (score - expected).abs() < 0.01,
            "expected {expected}, got {score}"
        );
    }

    #[test]
    fn score_text_relevance_exact_keyword_beats_synonym_keyword() {
        // GIVEN: tool has [keywords: search] and two queries: "search" (exact) and "find" (synonym)
        let words_exact = vec!["search"];
        let words_syn = vec!["find"];
        let desc = "Does stuff [keywords: search, web]";
        let exact = score_text_relevance("tool", desc, "search", &words_exact);
        let syn = score_text_relevance("tool", desc, "find", &words_syn);
        assert!(exact > syn, "exact ({exact}) should beat synonym ({syn})");
    }

    #[test]
    fn ranking_synonym_query_finds_matching_tools() {
        // GIVEN: query "find companies" where "find" is a synonym for "search"
        // WHEN: ranking against a tool with "search" in its name
        let ranker = SearchRanker::new();
        let results = vec![
            sr("company_search", "Search for companies [keywords: search, company]"),
            sr("weather_api", "Get current temperature"),
        ];
        let ranked = ranker.rank(results, "find companies");
        // THEN: the search tool should score above 0 due to synonym expansion
        assert!(
            ranked.iter().find(|r| r.tool == "company_search").unwrap().score > 0.0,
            "synonym-expanded query should match"
        );
        assert_eq!(ranked[0].tool, "company_search");
    }

    #[test]
    fn ranking_exact_match_beats_synonym_match() {
        // GIVEN: one tool has exact word "search", another only matches via "find" synonym
        let ranker = SearchRanker::new();
        let results = vec![
            sr("find_companies", "Discovers companies"),  // exact "find" in name
            sr("search_companies", "Searches companies"), // synonym of "find"
        ];
        let ranked = ranker.rank(results, "find");
        // The tool with exact "find" in its name should score at least as high
        assert!(
            ranked[0].score >= ranked[1].score,
            "exact match should score >= synonym match"
        );
    }

    #[test]
    fn is_keyword_match_with_synonyms_finds_synonym_tag() {
        // GIVEN: description has [keywords: search] and we check "find" (synonym)
        let desc = "does stuff [keywords: search, web]";
        assert!(
            is_keyword_match_with_synonyms(desc, "find"),
            "'find' should match via synonym 'search'"
        );
    }

    #[test]
    fn is_keyword_match_with_synonyms_still_finds_exact() {
        let desc = "does stuff [keywords: search, web]";
        assert!(is_keyword_match_with_synonyms(desc, "search"));
    }

    #[test]
    fn is_keyword_match_with_synonyms_returns_false_for_no_match() {
        let desc = "does stuff [keywords: weather, temperature]";
        assert!(!is_keyword_match_with_synonyms(desc, "find"));
    }
}
