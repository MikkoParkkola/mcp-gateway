//! Smart search ranking based on usage frequency
//!
//! Ranks search results by combining text relevance with usage-based popularity.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

    /// Rank search results by relevance and usage
    ///
    /// # Scoring Algorithm
    ///
    /// `score = text_relevance + usage_boost`
    ///
    /// Where:
    /// - `text_relevance`: 10 (name exact), 5 (name contains), 2 (desc contains)
    /// - `usage_boost`: `log2(usage_count + 1) * 3`
    #[must_use]
    pub fn rank(&self, mut results: Vec<SearchResult>, query: &str) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();

        for result in &mut results {
            // Calculate text relevance
            let text_relevance = if result.tool.to_lowercase() == query_lower {
                10.0
            } else if result.tool.to_lowercase().contains(&query_lower) {
                5.0
            } else if result.description.to_lowercase().contains(&query_lower) {
                2.0
            } else {
                0.0
            };

            // Calculate usage boost
            let usage = self.usage_count(&result.server, &result.tool);
            #[allow(clippy::cast_precision_loss)]
            let usage_boost = if usage > 0 {
                ((usage + 1) as f64).log2() * 3.0
            } else {
                0.0
            };

            result.score = text_relevance + usage_boost;
        }

        // Sort by score descending
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

        // "popular" has desc match (2 points) + usage boost (log2(101) * 3 ≈ 20)
        // "exact" has no match (0 points)
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
}
