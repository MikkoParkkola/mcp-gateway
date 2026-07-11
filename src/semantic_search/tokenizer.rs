// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Text tokenization for semantic search.
//!
//! Provides lowercasing, stopword removal, and basic suffix-stripping
//! (stemming) so that TF-IDF can match morphological variants of the same
//! root term without external dependencies.

/// Common English words that carry no discriminative signal.
///
/// Tokens that appear in this set are dropped during tokenization.
pub const STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by",
    "from", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does",
    "did", "will", "would", "could", "should", "may", "might", "shall", "can", "that", "this",
    "these", "those", "it", "its", "as", "not", "no", "if", "then", "than", "so", "up", "out",
    "about", "into", "over", "after",
];

/// Tokenize `text` into a list of normalised, non-stopword tokens.
///
/// Processing pipeline:
/// 1. Lowercase the entire input.
/// 2. Split on any character that is not ASCII alphanumeric or `'_'`.
/// 3. Discard tokens shorter than 2 characters.
/// 4. Remove stopwords.
/// 5. Apply [`normalize`] (basic suffix stripping).
///
/// # Examples
///
/// ```
/// # use mcp_gateway::semantic_search::tokenizer::tokenize;
/// let tokens = tokenize("Read files from the filesystem");
/// assert!(tokens.contains(&"read".to_string()));
/// assert!(tokens.contains(&"file".to_string()));     // "files" -> "file"
/// assert!(!tokens.contains(&"the".to_string()));     // stopword removed
/// assert!(!tokens.contains(&"from".to_string()));    // stopword removed
/// ```
#[must_use]
pub fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|t| t.len() >= 2)
        .filter(|t| !STOPWORDS.contains(t))
        .filter_map(normalize)
        .collect()
}

/// Strip common English suffixes to reduce morphological variants to a root.
///
/// Returns `None` for tokens that collapse to fewer than 2 characters, so
/// they are discarded by the caller rather than producing noise.
///
/// Suffixes stripped (in priority order):
/// - `"ing"` — e.g. `"searching"` → `"search"`
/// - `"ed"` — e.g. `"searched"` → `"search"`
/// - `"s"` — e.g. `"files"` → `"file"`
///
/// This is intentionally lightweight: a full Porter stemmer would add
/// implementation complexity without meaningful accuracy gain for the
/// short technical descriptions found in MCP tool schemas.
#[must_use]
pub fn normalize(token: &str) -> Option<String> {
    let root = strip_suffix(token);
    if root.len() < 2 {
        None
    } else {
        Some(root.to_owned())
    }
}

/// Apply the longest matching suffix rule and return the stripped slice.
fn strip_suffix(token: &str) -> &str {
    if let Some(stem) = token.strip_suffix("ing") {
        return stem;
    }
    if let Some(stem) = token.strip_suffix("ed") {
        return stem;
    }
    if let Some(stem) = token.strip_suffix('s') {
        return stem;
    }
    token
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_lowercases_input() {
        let tokens = tokenize("READ_FILE");
        assert!(tokens.contains(&"read_file".to_string()));
    }

    #[test]
    fn tokenize_removes_stopwords() {
        let tokens = tokenize("the a an is");
        assert!(tokens.is_empty(), "all stopwords should be removed");
    }

    #[test]
    fn tokenize_strips_ing_suffix() {
        let tokens = tokenize("searching");
        assert!(tokens.contains(&"search".to_string()));
    }

    #[test]
    fn tokenize_strips_ed_suffix() {
        let tokens = tokenize("searched");
        assert!(tokens.contains(&"search".to_string()));
    }

    #[test]
    fn tokenize_strips_trailing_s() {
        let tokens = tokenize("files");
        assert!(tokens.contains(&"file".to_string()));
    }

    #[test]
    fn tokenize_splits_on_punctuation() {
        let tokens = tokenize("read.file,and;write");
        assert!(tokens.contains(&"read".to_string()));
        assert!(tokens.contains(&"write".to_string()));
    }

    #[test]
    fn tokenize_drops_single_char_tokens() {
        let tokens = tokenize("a b c read");
        assert!(!tokens.contains(&"b".to_string()));
        assert!(!tokens.contains(&"c".to_string()));
        assert!(tokens.contains(&"read".to_string()));
    }

    #[test]
    fn tokenize_empty_string_returns_empty() {
        assert!(tokenize("").is_empty());
    }

    #[test]
    fn normalize_ing_produces_stem() {
        assert_eq!(normalize("running"), Some("runn".to_string()));
    }

    #[test]
    fn normalize_short_stem_returns_none() {
        // "is" -> strip 's' -> "i" (len 1) -> None
        assert_eq!(normalize("is"), None);
    }

    #[test]
    fn normalize_no_suffix_returns_unchanged() {
        assert_eq!(normalize("read"), Some("read".to_string()));
    }

    #[test]
    fn stopwords_contains_common_articles() {
        assert!(STOPWORDS.contains(&"the"));
        assert!(STOPWORDS.contains(&"a"));
        assert!(STOPWORDS.contains(&"an"));
    }
}
