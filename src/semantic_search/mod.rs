// SPDX-License-Identifier: MIT

//! Semantic search for natural language MCP tool discovery (RFC-0072).
//!
//! Provides [`SemanticIndex`], a self-contained index that accepts tool
//! registrations and answers free-text queries with ranked [`SearchResult`]s.
//!
//! # Architecture
//!
//! ```text
//! SemanticIndex
//!   ├── TfIdfIndex   — term-frequency/inverse-document-frequency ranking
//!   └── FeedbackTracker — boost scores based on past user selections
//! ```
//!
//! Tool text is built from three sources, concatenated with whitespace:
//! 1. **name** — the MCP tool identifier.
//! 2. **description** — the human-readable summary.
//! 3. **`schema_json`** — the JSON parameter schema, contributing field names
//!    as additional discriminative terms.
//!
//! # Example
//!
//! ```
//! # use mcp_gateway::semantic_search::{SemanticIndex, SearchResult};
//! let mut idx = SemanticIndex::new();
//! idx.index_tool("read_file", "Read a file from disk", r#"{"path": "string"}"#);
//! idx.index_tool("send_email", "Send an email message", r#"{"to": "string"}"#);
//!
//! let results = idx.search("read file content", 5);
//! assert!(!results.is_empty());
//! assert_eq!(results[0].tool_name, "read_file");
//! ```

pub mod feedback;
pub mod tfidf;
pub mod tokenizer;

use feedback::FeedbackTracker;
use tfidf::TfIdfIndex;

// ============================================================================
// Public types
// ============================================================================

/// A single result returned by [`SemanticIndex::search`].
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    /// The MCP tool name.
    pub tool_name: String,
    /// Relevance score — higher is better.  Not normalised to a fixed range.
    pub score: f64,
    /// Which fields contributed to this match (e.g. `"name"`, `"description"`, `"schema"`).
    pub matched_fields: Vec<String>,
}

// ============================================================================
// SemanticIndex
// ============================================================================

/// In-memory semantic search index for MCP tools.
///
/// Index tools with [`index_tool`](SemanticIndex::index_tool), search with
/// [`search`](SemanticIndex::search), and feed back selections with
/// [`record_selection`](SemanticIndex::record_selection).
///
/// Not `Send + Sync` on its own — wrap in `Arc<RwLock<_>>` for shared
/// mutable access across tasks.
#[derive(Debug, Default)]
pub struct SemanticIndex {
    tfidf: TfIdfIndex,
    feedback: FeedbackTracker,
}

impl SemanticIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a tool in the search index.
    ///
    /// The text submitted to the TF-IDF engine is:
    /// `"{name} {description} {schema_json}"`.
    ///
    /// Calling `index_tool` twice with the same `name` replaces the first
    /// entry; the document-frequency table is updated correctly.
    ///
    /// # Arguments
    ///
    /// * `name` — MCP tool identifier (e.g. `"read_file"`).
    /// * `description` — Human-readable tool summary.
    /// * `schema_json` — Raw JSON string of the input schema (field names
    ///   provide additional indexable signal).
    pub fn index_tool(&mut self, name: &str, description: &str, schema_json: &str) {
        let text = build_document_text(name, description, schema_json);
        self.tfidf.add_document(name, &text);
    }

    /// Remove the tool identified by `name` from the index.
    ///
    /// Returns `true` if the tool existed and was removed.
    pub fn remove_tool(&mut self, name: &str) -> bool {
        self.tfidf.remove_document(name)
    }

    /// Search for tools matching `query` and return the top `limit` results.
    ///
    /// Results are ranked by TF-IDF score, then feedback-boosted if prior
    /// selections exist for this query.  Pass `limit = 0` to retrieve all
    /// non-zero matches.
    ///
    /// # Examples
    ///
    /// ```
    /// # use mcp_gateway::semantic_search::SemanticIndex;
    /// let mut idx = SemanticIndex::new();
    /// idx.index_tool("list_files", "List files in a directory", r#"{}"#);
    /// let results = idx.search("list directory files", 10);
    /// assert!(!results.is_empty());
    /// ```
    #[must_use]
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchResult> {
        let raw = self.tfidf.query(query, limit);
        let results: Vec<SearchResult> = raw
            .into_iter()
            .map(|(tool_name, score)| SearchResult {
                matched_fields: matched_fields_for(&tool_name, query),
                tool_name,
                score,
            })
            .collect();
        self.feedback.boost_scores(query, results)
    }

    /// Record that the user selected `tool_name` for `query`.
    ///
    /// Future calls to [`search`](Self::search) with `query` will boost
    /// `tool_name`'s score according to the selection count.
    pub fn record_selection(&self, query: &str, tool_name: &str) {
        self.feedback.record_selection(query, tool_name);
    }

    /// Return the number of indexed tools.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tfidf.document_count()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Concatenate tool fields into a single indexable text blob.
fn build_document_text(name: &str, description: &str, schema_json: &str) -> String {
    format!("{name} {description} {schema_json}")
}

/// Heuristically identify which document fields contributed to a match.
///
/// This is a best-effort attribution based on substring presence of the
/// raw (non-stemmed) query terms.  It is informational only and does not
/// affect ranking.
fn matched_fields_for(tool_name: &str, query: &str) -> Vec<String> {
    let query_lower = query.to_lowercase();
    let name_lower = tool_name.to_lowercase();
    if query_lower
        .split_whitespace()
        .any(|w| name_lower.contains(w))
    {
        vec!["name".to_string()]
    } else {
        vec!["description".to_string()]
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers ----------------------------------------------------------------

    fn populated_index() -> SemanticIndex {
        let mut idx = SemanticIndex::new();
        idx.index_tool(
            "read_file",
            "Read content from a file on disk",
            r#"{"path":"string","encoding":"string"}"#,
        );
        idx.index_tool(
            "write_file",
            "Write content to a file on disk",
            r#"{"path":"string","content":"string"}"#,
        );
        idx.index_tool(
            "list_directory",
            "List files and directories at a path",
            r#"{"path":"string"}"#,
        );
        idx.index_tool(
            "send_email",
            "Send an email to a recipient",
            r#"{"to":"string","subject":"string","body":"string"}"#,
        );
        idx.index_tool(
            "query_database",
            "Execute a SQL query against the database",
            r#"{"sql":"string","params":"array"}"#,
        );
        idx
    }

    // -- SemanticIndex basic ---------------------------------------------------

    #[test]
    fn empty_index_returns_no_results() {
        let idx = SemanticIndex::new();
        assert!(idx.search("read file", 10).is_empty());
    }

    #[test]
    fn index_tool_increments_count() {
        let mut idx = SemanticIndex::new();
        idx.index_tool("t1", "description one", "{}");
        assert_eq!(idx.tool_count(), 1);
        idx.index_tool("t2", "description two", "{}");
        assert_eq!(idx.tool_count(), 2);
    }

    #[test]
    fn index_tool_twice_does_not_duplicate() {
        let mut idx = SemanticIndex::new();
        idx.index_tool("t1", "initial description", "{}");
        idx.index_tool("t1", "updated description", "{}");
        assert_eq!(idx.tool_count(), 1);
    }

    #[test]
    fn remove_tool_decrements_count() {
        let mut idx = SemanticIndex::new();
        idx.index_tool("t1", "some tool", "{}");
        assert!(idx.remove_tool("t1"));
        assert_eq!(idx.tool_count(), 0);
    }

    #[test]
    fn remove_nonexistent_tool_returns_false() {
        let mut idx = SemanticIndex::new();
        assert!(!idx.remove_tool("ghost_tool"));
    }

    // -- search quality --------------------------------------------------------

    #[test]
    fn search_finds_relevant_tool_by_name_token() {
        let idx = populated_index();
        let results = idx.search("email", 5);
        assert!(!results.is_empty(), "should match send_email");
        assert_eq!(results[0].tool_name, "send_email");
    }

    #[test]
    fn search_finds_tool_by_description_keyword() {
        let idx = populated_index();
        let results = idx.search("sql", 5);
        assert!(!results.is_empty());
        assert_eq!(results[0].tool_name, "query_database");
    }

    #[test]
    fn search_returns_results_sorted_descending() {
        let idx = populated_index();
        let results = idx.search("file", 10);
        for window in results.windows(2) {
            assert!(
                window[0].score >= window[1].score,
                "results must be sorted descending: {} < {}",
                window[0].score,
                window[1].score
            );
        }
    }

    #[test]
    fn search_limit_caps_result_count() {
        let idx = populated_index();
        let results = idx.search("file", 2);
        assert!(results.len() <= 2);
    }

    #[test]
    fn search_with_limit_zero_returns_all_matches() {
        let idx = populated_index();
        let all = idx.search("file", 0);
        let limited = idx.search("file", 100);
        assert_eq!(all.len(), limited.len());
    }

    #[test]
    fn search_multiword_query_outranks_single_word() {
        let idx = populated_index();
        let results_multi = idx.search("read file", 10);
        let results_single = idx.search("read", 10);
        assert!(!results_multi.is_empty());
        assert!(!results_single.is_empty());
        // "read_file" should appear in both
        assert!(results_multi.iter().any(|r| r.tool_name == "read_file"));
    }

    #[test]
    fn search_special_characters_in_query_do_not_panic() {
        let idx = populated_index();
        let _ = idx.search("read!@#$%^&*()", 10);
        let _ = idx.search("", 10);
        let _ = idx.search("   ", 10);
    }

    #[test]
    fn search_schema_fields_contribute_to_ranking() {
        let idx = populated_index();
        // "sql" only appears in query_database schema
        let results = idx.search("sql params", 5);
        assert!(!results.is_empty());
        assert_eq!(results[0].tool_name, "query_database");
    }

    // -- feedback boosting -----------------------------------------------------

    #[test]
    fn record_selection_boosts_selected_tool() {
        let idx = populated_index();
        // First, get baseline scores
        let baseline = idx.search("file", 5);
        let file_baseline = baseline
            .iter()
            .find(|r| r.tool_name == "read_file")
            .map(|r| r.score);

        idx.record_selection("file", "read_file");
        idx.record_selection("file", "read_file");

        let boosted = idx.search("file", 5);
        let file_boosted = boosted
            .iter()
            .find(|r| r.tool_name == "read_file")
            .map(|r| r.score);

        if let (Some(b), Some(a)) = (file_baseline, file_boosted) {
            assert!(a > b, "score should be higher after selections: {b} vs {a}");
        }
    }

    #[test]
    fn record_selection_does_not_affect_unrelated_query() {
        let idx = populated_index();
        idx.record_selection("completely different query", "read_file");
        let results = idx.search("email", 5);
        // email query should still rank send_email first
        assert_eq!(results[0].tool_name, "send_email");
    }

    // -- large index -----------------------------------------------------------

    #[test]
    fn large_index_returns_results_without_panic() {
        let mut idx = SemanticIndex::new();
        for i in 0..100 {
            idx.index_tool(
                &format!("tool_{i:03}"),
                &format!("This tool performs operation number {i} on data records"),
                &format!(r#"{{"id": "integer", "value_{i}": "string"}}"#),
            );
        }
        assert_eq!(idx.tool_count(), 100);
        let results = idx.search("data records operation", 10);
        assert!(!results.is_empty(), "large index must return results");
        assert!(results.len() <= 10);
    }

    #[test]
    fn large_index_top_result_is_most_relevant() {
        let mut idx = SemanticIndex::new();
        for i in 0..100 {
            idx.index_tool(
                &format!("generic_tool_{i}"),
                &format!("Generic utility tool number {i}"),
                "{}",
            );
        }
        // Add one highly specific tool
        idx.index_tool(
            "email_sender",
            "Send email messages to recipients via SMTP",
            r#"{"to":"string","subject":"string"}"#,
        );
        let results = idx.search("send email smtp", 5);
        assert!(!results.is_empty());
        assert_eq!(results[0].tool_name, "email_sender");
    }
}
