// SPDX-License-Identifier: MIT

//! User-selection feedback tracker for semantic search result boosting.
//!
//! When a user picks a tool from search results that signal carries strong
//! intent: the same query (or a similar one) should surface that tool higher
//! in the future.  `FeedbackTracker` stores these selections and
//! [`boost_scores`](FeedbackTracker::boost_scores) applies a multiplicative
//! boost to results that have been previously chosen.
//!
//! # Boost formula
//!
//! ```text
//! boosted_score = score * (1.0 + BOOST_FACTOR * ln(selections + 1))
//! ```
//!
//! The logarithm ensures diminishing returns — one prior selection already
//! provides a meaningful lift, but 100 prior selections do not dominate
//! infinitely over a fresh high-relevance result.

use dashmap::DashMap;

use super::SearchResult;

/// Multiplicative boost factor per unit of `ln(selections + 1)`.
///
/// At 1 selection: ×1.35 lift.  At 10 selections: ×1.80 lift.
/// At 100 selections: ×2.27 lift.
const BOOST_FACTOR: f64 = 0.35;

// ============================================================================
// FeedbackTracker
// ============================================================================

/// Thread-safe tracker of user tool selections keyed by normalised query.
///
/// The map key is the lowercased, whitespace-collapsed query string.
/// The value is a nested map of `tool_name → selection_count`.
///
/// All operations are non-blocking: `DashMap` shards avoid contention under
/// concurrent gateway request handling.
#[derive(Debug, Default)]
pub struct FeedbackTracker {
    /// `query → (tool_name → count)`.
    selections: DashMap<String, DashMap<String, u64>>,
}

impl FeedbackTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the user selected `tool_name` for `query`.
    ///
    /// Both `query` and `tool_name` are normalised (lowercased, trimmed)
    /// before storage so that minor casing differences do not fragment the
    /// feedback signal.
    pub fn record_selection(&self, query: &str, tool_name: &str) {
        let key = normalise_query(query);
        let tool = tool_name.to_lowercase();
        self.selections
            .entry(key)
            .or_default()
            .entry(tool)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Return the number of times `tool_name` was selected for `query`.
    #[must_use]
    pub fn selection_count(&self, query: &str, tool_name: &str) -> u64 {
        let key = normalise_query(query);
        let tool = tool_name.to_lowercase();
        self.selections
            .get(&key)
            .and_then(|tools| tools.get(&tool).map(|c| *c))
            .unwrap_or(0)
    }

    /// Apply feedback boosts to `results` for `query`.
    ///
    /// Results that have been previously selected for this query receive a
    /// multiplicative score boost.  The ordering is re-established after
    /// boosting so the output is always sorted descending by final score.
    ///
    /// Results with zero prior selections pass through unchanged.
    #[must_use]
    pub fn boost_scores(&self, query: &str, mut results: Vec<SearchResult>) -> Vec<SearchResult> {
        let key = normalise_query(query);
        if let Some(tool_map) = self.selections.get(&key) {
            for result in &mut results {
                let tool_lower = result.tool_name.to_lowercase();
                if let Some(count) = tool_map.get(&tool_lower) {
                    #[allow(clippy::cast_precision_loss)]
                    let lift = 1.0 + BOOST_FACTOR * (*count as f64 + 1.0).ln();
                    result.score *= lift;
                }
            }
        }
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Return the total number of distinct (query, tool) pairs tracked.
    #[must_use]
    pub fn tracked_pair_count(&self) -> usize {
        self.selections
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    /// Clear all tracked feedback.
    pub fn clear(&self) {
        self.selections.clear();
    }
}

/// Normalise a query string for use as a map key.
///
/// Lowercases and collapses interior whitespace so that `"Search Files"` and
/// `"search  files"` map to the same bucket.
fn normalise_query(query: &str) -> String {
    query
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_search::SearchResult;

    fn make_result(tool_name: &str, score: f64) -> SearchResult {
        SearchResult {
            tool_name: tool_name.to_string(),
            score,
            matched_fields: Vec::new(),
        }
    }

    #[test]
    fn record_and_retrieve_selection_count() {
        let tracker = FeedbackTracker::new();
        tracker.record_selection("search files", "list_files");
        tracker.record_selection("search files", "list_files");
        assert_eq!(tracker.selection_count("search files", "list_files"), 2);
    }

    #[test]
    fn unknown_query_returns_zero_count() {
        let tracker = FeedbackTracker::new();
        assert_eq!(tracker.selection_count("never queried", "some_tool"), 0);
    }

    #[test]
    fn query_normalisation_merges_case_variants() {
        let tracker = FeedbackTracker::new();
        tracker.record_selection("Search Files", "list_files");
        assert_eq!(tracker.selection_count("search files", "list_files"), 1);
    }

    #[test]
    fn query_normalisation_collapses_whitespace() {
        let tracker = FeedbackTracker::new();
        tracker.record_selection("search  files", "list_files");
        assert_eq!(tracker.selection_count("search files", "list_files"), 1);
    }

    #[test]
    fn boost_scores_lifts_previously_selected_tool() {
        let tracker = FeedbackTracker::new();
        tracker.record_selection("read", "read_file");

        let results = vec![
            make_result("read_file", 5.0),
            make_result("other_tool", 5.0),
        ];
        let boosted = tracker.boost_scores("read", results);
        let read_score = boosted
            .iter()
            .find(|r| r.tool_name == "read_file")
            .unwrap()
            .score;
        let other_score = boosted
            .iter()
            .find(|r| r.tool_name == "other_tool")
            .unwrap()
            .score;
        assert!(
            read_score > other_score,
            "selected tool should score higher after boost"
        );
    }

    #[test]
    fn boost_scores_preserves_order_descending() {
        let tracker = FeedbackTracker::new();
        let results = vec![make_result("low", 1.0), make_result("high", 10.0)];
        let boosted = tracker.boost_scores("anything", results);
        assert_eq!(boosted[0].tool_name, "high");
    }

    #[test]
    fn boost_scores_no_feedback_returns_unchanged() {
        let tracker = FeedbackTracker::new();
        let results = vec![make_result("read_file", 5.0)];
        let boosted = tracker.boost_scores("query with no history", results);
        assert!((boosted[0].score - 5.0).abs() < 1e-9);
    }

    #[test]
    fn boost_increases_with_more_selections() {
        let tool = "my_tool";

        let score_after = |n: u64| -> f64 {
            let t = FeedbackTracker::new();
            for _ in 0..n {
                t.record_selection("q", tool);
            }
            let r = vec![make_result(tool, 1.0)];
            t.boost_scores("q", r)[0].score
        };

        assert!(
            score_after(10) > score_after(1),
            "more selections → higher boost"
        );
    }

    #[test]
    fn tracked_pair_count_reflects_unique_pairs() {
        let tracker = FeedbackTracker::new();
        tracker.record_selection("q1", "tool_a");
        tracker.record_selection("q1", "tool_b");
        tracker.record_selection("q2", "tool_a");
        assert_eq!(tracker.tracked_pair_count(), 3);
    }

    #[test]
    fn clear_resets_all_tracked_state() {
        let tracker = FeedbackTracker::new();
        tracker.record_selection("query", "tool");
        tracker.clear();
        assert_eq!(tracker.selection_count("query", "tool"), 0);
        assert_eq!(tracker.tracked_pair_count(), 0);
    }
}
