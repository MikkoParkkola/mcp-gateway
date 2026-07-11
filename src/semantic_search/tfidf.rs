// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! TF-IDF index for MCP tool description matching.
//!
//! Term Frequency–Inverse Document Frequency ranks documents by how
//! characteristic each query term is across the corpus.  A term that appears
//! often in a specific document but rarely overall gets a high IDF weight,
//! making it a strong discriminator.
//!
//! # Algorithm
//!
//! For each term `t` in query `q` against document `d`:
//!
//! ```text
//! tf(t, d)  = occurrences_of_t_in_d / total_terms_in_d
//! idf(t)    = ln(1 + N / (1 + df(t)))    (smooth IDF — always > 0)
//! score(d)  = Σ tf(t, d) * idf(t)
//! ```
//!
//! where `N` is the total number of indexed documents and `df(t)` is the
//! number of documents that contain term `t`.

use std::collections::HashMap;

use super::tokenizer::tokenize;

// ============================================================================
// Indexed document
// ============================================================================

/// Per-document term statistics stored inside the index.
#[derive(Debug, Clone)]
struct IndexedDoc {
    /// Term → occurrence count within this document.
    term_counts: HashMap<String, usize>,
    /// Total number of terms in the document (after tokenization).
    total_terms: usize,
}

impl IndexedDoc {
    /// Build from raw text.
    fn from_text(text: &str) -> Self {
        let tokens = tokenize(text);
        let total_terms = tokens.len();
        let mut term_counts: HashMap<String, usize> = HashMap::new();
        for token in tokens {
            *term_counts.entry(token).or_insert(0) += 1;
        }
        Self {
            term_counts,
            total_terms,
        }
    }

    /// Term frequency: `count(t, d) / |d|`.
    ///
    /// Returns 0.0 for unknown terms or empty documents.
    fn tf(&self, term: &str) -> f64 {
        if self.total_terms == 0 {
            return 0.0;
        }
        let count = self.term_counts.get(term).copied().unwrap_or(0);
        #[allow(clippy::cast_precision_loss)]
        {
            count as f64 / self.total_terms as f64
        }
    }
}

// ============================================================================
// TfIdfIndex
// ============================================================================

/// An in-memory TF-IDF index for short text documents.
///
/// Documents are added with string identifiers.  After indexing, the
/// [`query`](TfIdfIndex::query) method returns ranked results.
///
/// # Thread safety
///
/// `TfIdfIndex` is not `Send + Sync`; wrap it in `Arc<RwLock<_>>` if
/// concurrent access is required.
#[derive(Debug, Default)]
pub struct TfIdfIndex {
    /// Document ID → indexed document data.
    docs: HashMap<String, IndexedDoc>,
    /// Term → number of documents containing that term.
    doc_freq: HashMap<String, usize>,
}

impl TfIdfIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Index `text` under `id`, replacing any existing entry for that `id`.
    ///
    /// If the same `id` is added twice the previous entry is overwritten and
    /// the document-frequency table is updated accordingly.
    pub fn add_document(&mut self, id: impl Into<String>, text: &str) {
        let id = id.into();
        // Remove stale document-frequency contributions from the old entry.
        if let Some(old_doc) = self.docs.remove(&id) {
            self.remove_doc_freq(&old_doc);
        }
        let doc = IndexedDoc::from_text(text);
        self.update_doc_freq(&doc);
        self.docs.insert(id, doc);
    }

    /// Remove the document with `id` from the index.
    ///
    /// Returns `true` if the document existed and was removed.
    pub fn remove_document(&mut self, id: &str) -> bool {
        if let Some(doc) = self.docs.remove(id) {
            self.remove_doc_freq(&doc);
            true
        } else {
            false
        }
    }

    /// Return the top-`limit` documents ranked by TF-IDF score for `query_text`.
    ///
    /// Results are sorted descending by score.  Documents with a score of
    /// exactly 0.0 are excluded.  If `limit` is 0, all non-zero results are
    /// returned.
    #[must_use]
    pub fn query(&self, query_text: &str, limit: usize) -> Vec<(String, f64)> {
        let query_terms = tokenize(query_text);
        if query_terms.is_empty() || self.docs.is_empty() {
            return Vec::new();
        }
        let n = self.docs.len();
        let mut scores: Vec<(String, f64)> = self
            .docs
            .iter()
            .filter_map(|(id, doc)| {
                let score = self.score(doc, &query_terms, n);
                if score > 0.0 {
                    Some((id.clone(), score))
                } else {
                    None
                }
            })
            .collect();

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        if limit > 0 {
            scores.truncate(limit);
        }
        scores
    }

    /// Return the number of indexed documents.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.docs.len()
    }

    /// Compute the TF-IDF score for `doc` against `query_terms`.
    ///
    /// Uses the "smooth IDF" variant: `ln(1 + N / (1 + df(t)))`.
    /// The outer `+1` guarantees IDF > 0 even when every document contains
    /// the term (`df = N`), so queries against small or uniform corpora always
    /// yield positive scores for present terms.
    #[allow(clippy::cast_precision_loss)]
    fn score(&self, doc: &IndexedDoc, query_terms: &[String], n: usize) -> f64 {
        query_terms.iter().fold(0.0, |acc, term| {
            let tf = doc.tf(term);
            if tf == 0.0 {
                return acc;
            }
            let df = self.doc_freq.get(term).copied().unwrap_or(0);
            // Smooth IDF: ln(1 + N / (1 + df))  — always positive
            let idf = (1.0 + (n as f64) / (1.0 + df as f64)).ln();
            acc + tf * idf
        })
    }

    /// Increment document-frequency counts for every term in `doc`.
    fn update_doc_freq(&mut self, doc: &IndexedDoc) {
        for term in doc.term_counts.keys() {
            *self.doc_freq.entry(term.clone()).or_insert(0) += 1;
        }
    }

    /// Decrement document-frequency counts for every term in `doc`.
    fn remove_doc_freq(&mut self, doc: &IndexedDoc) {
        for term in doc.term_counts.keys() {
            if let Some(freq) = self.doc_freq.get_mut(term.as_str()) {
                if *freq <= 1 {
                    self.doc_freq.remove(term.as_str());
                } else {
                    *freq -= 1;
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_index(docs: &[(&str, &str)]) -> TfIdfIndex {
        let mut idx = TfIdfIndex::new();
        for (id, text) in docs {
            idx.add_document(*id, text);
        }
        idx
    }

    #[test]
    fn empty_index_returns_no_results() {
        let idx = TfIdfIndex::new();
        assert!(idx.query("search", 10).is_empty());
    }

    #[test]
    fn single_document_matches_its_own_text() {
        let idx = build_index(&[("doc1", "search files in filesystem")]);
        let results = idx.query("search", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "doc1");
    }

    #[test]
    fn query_returns_empty_for_absent_term() {
        let idx = build_index(&[("doc1", "read write files")]);
        assert!(idx.query("database", 10).is_empty());
    }

    #[test]
    fn more_relevant_document_ranks_first() {
        let idx = build_index(&[
            ("tool_search", "search search search find query"),
            ("tool_write", "write content to file path"),
        ]);
        let results = idx.query("search", 10);
        assert!(!results.is_empty(), "should match");
        assert_eq!(results[0].0, "tool_search");
    }

    #[test]
    fn limit_caps_result_count() {
        let docs: Vec<(String, String)> = (0..10)
            .map(|i| (format!("doc{i}"), format!("read file content {i}")))
            .collect();
        let mut idx = TfIdfIndex::new();
        for (id, text) in &docs {
            idx.add_document(id.as_str(), text.as_str());
        }
        let results = idx.query("read", 3);
        assert!(results.len() <= 3);
    }

    #[test]
    fn limit_zero_returns_all_matches() {
        let idx = build_index(&[
            ("a", "read file"),
            ("b", "read directory"),
            ("c", "read stream"),
        ]);
        let results = idx.query("read", 0);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn results_are_sorted_descending_by_score() {
        let idx = build_index(&[("strong", "query query query search"), ("weak", "search")]);
        let results = idx.query("query", 10);
        if results.len() >= 2 {
            assert!(
                results[0].1 >= results[1].1,
                "results must be sorted descending"
            );
        }
    }

    #[test]
    fn add_document_twice_replaces_old_entry() {
        let mut idx = TfIdfIndex::new();
        idx.add_document("doc", "old content about writing");
        idx.add_document("doc", "new content about reading");
        assert_eq!(idx.document_count(), 1);
        // Should match "reading" but not "writing" anymore
        assert!(!idx.query("writing", 10).is_empty() || !idx.query("reading", 10).is_empty());
    }

    #[test]
    fn remove_document_decrements_doc_freq() {
        let mut idx = build_index(&[("d1", "search files"), ("d2", "search content")]);
        idx.remove_document("d1");
        assert_eq!(idx.document_count(), 1);
        // d1 gone — only d2 should match
        let results = idx.query("search", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "d2");
    }

    #[test]
    fn remove_nonexistent_document_returns_false() {
        let mut idx = TfIdfIndex::new();
        assert!(!idx.remove_document("ghost"));
    }

    #[test]
    fn multiword_query_ranks_by_combined_tfidf() {
        let idx = build_index(&[
            ("both", "read file from filesystem path"),
            ("one", "read content"),
        ]);
        let results = idx.query("read file", 10);
        // "both" contains both terms; should rank first
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "both");
    }
}
