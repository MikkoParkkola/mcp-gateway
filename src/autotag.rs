//! Automatic keyword extraction for MCP tool descriptions.
//!
//! Enriches tool descriptions from MCP backends with a `[keywords: ...]` suffix
//! so they participate in the same keyword-matching pipeline as capability tools.
//!
//! # Design
//!
//! - Idempotent: descriptions that already contain `[keywords:` are returned as-is.
//! - Deterministic: given the same input, always produces the same output.
//! - Zero-allocation fast-path: returns the original string unchanged when no
//!   keywords are extracted.
//! - Top-7 keywords, preferring longer (more specific) words, deduplicated.
//!
//! # Example
//!
//! ```rust
//! use mcp_gateway::autotag::enrich_description;
//!
//! let result = enrich_description("Reads a file from the local filesystem.");
//! assert!(result.contains("[keywords:"));
//! assert!(result.contains("file") || result.contains("filesystem") || result.contains("reads"));
//!
//! // Already-tagged descriptions are returned unchanged.
//! let tagged = "A tool. [keywords: file, read]";
//! assert_eq!(enrich_description(tagged), tagged);
//! ```

// ============================================================================
// Public API
// ============================================================================

/// Enrich a tool description with auto-extracted keyword tags.
///
/// If the description already contains a `[keywords: ...]` section, it is
/// returned unchanged. Otherwise, meaningful words are extracted and appended
/// as `[keywords: tag1, tag2, ...]`.
///
/// Returns the original description (owned) when no keywords can be extracted.
///
/// # Examples
///
/// ```rust
/// use mcp_gateway::autotag::enrich_description;
///
/// // Appends keywords
/// let result = enrich_description("Fetches weather data for a city.");
/// assert!(result.contains("[keywords:"));
///
/// // Idempotent — already-tagged descriptions pass through unchanged
/// let tagged = "My tool. [keywords: weather, fetch]";
/// assert_eq!(enrich_description(tagged), tagged);
///
/// // Empty description
/// assert_eq!(enrich_description(""), "");
/// ```
#[must_use]
pub fn enrich_description(description: &str) -> String {
    if description.contains("[keywords:") {
        return description.to_string();
    }

    let tags = extract_keywords(description);
    if tags.is_empty() {
        return description.to_string();
    }

    format!("{} [keywords: {}]", description.trim_end(), tags.join(", "))
}

// ============================================================================
// Keyword extraction internals
// ============================================================================

use std::cmp::Reverse;

/// Maximum number of keywords appended per description.
const MAX_KEYWORDS: usize = 7;

/// Minimum word length to consider (inclusive).
const MIN_WORD_LEN: usize = 3;

/// Extract up to [`MAX_KEYWORDS`] meaningful keywords from `text`.
///
/// Pipeline:
/// 1. Tokenise on non-alphabetic boundaries (hyphens treated as word separators)
/// 2. Lowercase
/// 3. Filter stopwords and tool-generic words
/// 4. Filter words shorter than [`MIN_WORD_LEN`]
/// 5. Deduplicate, preserving first-occurrence order
/// 6. Sort stable by descending length (longer = more specific) within the deduped set
/// 7. Truncate to [`MAX_KEYWORDS`]
fn extract_keywords(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut words: Vec<String> = Vec::new();

    for raw_word in tokenize(text) {
        let word = raw_word.to_lowercase();
        if word.len() < MIN_WORD_LEN {
            continue;
        }
        if is_stopword(&word) {
            continue;
        }
        if seen.insert(word.clone()) {
            words.push(word);
        }
    }

    // Stable sort descending by length — longer words are more specific.
    words.sort_by_key(|w| Reverse(w.len()));
    words.truncate(MAX_KEYWORDS);
    words
}

/// Tokenise `text` by splitting on any non-ASCII-alphabetic character.
///
/// Hyphens and underscores are treated as separators, so `"entity-discovery"`
/// yields `["entity", "discovery"]`.
fn tokenize(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|s| !s.is_empty())
}

/// Return `true` if `word` (already lowercase) is a stopword or tool-generic term
/// that provides no search value.
fn is_stopword(word: &str) -> bool {
    STOPWORDS.binary_search(&word).is_ok()
}

// ============================================================================
// Stopword table (sorted — enables O(log n) binary_search)
// ============================================================================

/// Combined English stopwords and tool-generic terms.
///
/// MUST remain sorted (ASCII lexicographic) for `binary_search` to be correct.
/// Run `src/autotag/verify_sorted` or the test below to validate.
const STOPWORDS: &[&str] = &[
    "about",
    "above",
    "after",
    "again",
    "against",
    "all",
    "allow",
    "allows",
    "also",
    "am",
    "and",
    "annotations",
    "any",
    "are",
    "as",
    "at",
    "available",
    "based",
    "be",
    "because",
    "been",
    "before",
    "being",
    "below",
    "between",
    "both",
    "but",
    "by",
    "can",
    "current",
    "data",
    "default",
    "did",
    "do",
    "does",
    "down",
    "during",
    "each",
    "enable",
    "enables",
    "etc",
    "every",
    "examples",
    "few",
    "for",
    "from",
    "function",
    "functions",
    "further",
    "get",
    "gets",
    "given",
    "had",
    "has",
    "have",
    "here",
    "how",
    "if",
    "in",
    "include",
    "includes",
    "including",
    "information",
    "input",
    "into",
    "is",
    "it",
    "its",
    "just",
    "may",
    "method",
    "methods",
    "might",
    "more",
    "most",
    "multiple",
    "must",
    "new",
    "no",
    "not",
    "note",
    "of",
    "off",
    "on",
    "once",
    "one",
    "only",
    "optional",
    "or",
    "other",
    "out",
    "output",
    "over",
    "own",
    "parameter",
    "parameters",
    "per",
    "provide",
    "provides",
    "required",
    "result",
    "results",
    "return",
    "returns",
    "same",
    "see",
    "set",
    "sets",
    "shall",
    "should",
    "single",
    "so",
    "some",
    "specific",
    "specified",
    "such",
    "support",
    "supports",
    "than",
    "that",
    "the",
    "then",
    "there",
    "these",
    "this",
    "those",
    "through",
    "too",
    "tool",
    "tools",
    "two",
    "type",
    "types",
    "under",
    "until",
    "up",
    "use",
    "used",
    "uses",
    "using",
    "value",
    "values",
    "various",
    "very",
    "via",
    "was",
    "well",
    "were",
    "what",
    "when",
    "where",
    "which",
    "while",
    "who",
    "whom",
    "will",
    "with",
    "would",
    "you",
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── enrich_description ──────────────────────────────────────────────

    #[test]
    fn enrich_description_appends_keywords_to_plain_description() {
        // GIVEN: a plain description with no keyword tags
        // WHEN: enriched
        // THEN: a [keywords: ...] suffix is appended
        let result = enrich_description("Fetches weather forecasts from an external service.");
        assert!(
            result.contains("[keywords:"),
            "Expected keywords suffix, got: {result}"
        );
    }

    #[test]
    fn enrich_description_is_idempotent_when_already_tagged() {
        // GIVEN: a description that already has [keywords: ...]
        let input = "Searches the web. [keywords: search, web]";
        // WHEN / THEN: returned unchanged
        assert_eq!(enrich_description(input), input);
    }

    #[test]
    fn enrich_description_returns_unchanged_when_no_keywords_extracted() {
        // GIVEN: a description consisting only of stopwords
        let input = "use the tool to get data";
        // WHEN: enriched
        let result = enrich_description(input);
        // THEN: no keywords suffix is added (all words filtered)
        assert!(!result.contains("[keywords:"), "Got: {result}");
    }

    #[test]
    fn enrich_description_returns_empty_string_unchanged() {
        assert_eq!(enrich_description(""), "");
    }

    #[test]
    fn enrich_description_trims_trailing_whitespace_before_appending() {
        // GIVEN: description with trailing whitespace
        let result = enrich_description("Manages calendar events.   ");
        // THEN: no double-space before [keywords:
        assert!(
            !result.contains("   [keywords:"),
            "Unexpected whitespace before tag: {result}"
        );
        assert!(result.contains(" [keywords:"));
    }

    #[test]
    fn enrich_description_preserves_original_description_text() {
        let desc = "Resolves DNS hostnames into IP addresses.";
        let result = enrich_description(desc);
        assert!(
            result.starts_with(desc),
            "Original text not preserved. Got: {result}"
        );
    }

    #[test]
    fn enrich_description_keywords_are_comma_separated() {
        let result = enrich_description("Authenticates users with OAuth tokens.");
        if result.contains("[keywords:") {
            let kw_part = result
                .split("[keywords:")
                .nth(1)
                .unwrap()
                .trim_end_matches(']');
            // Keyword list should contain commas separating multiple words
            // (at least one comma when more than one keyword exists)
            let keywords: Vec<&str> = kw_part.split(',').map(str::trim).collect();
            for kw in &keywords {
                assert!(!kw.is_empty(), "Empty keyword in list");
            }
        }
    }

    // ── extract_keywords ────────────────────────────────────────────────

    #[test]
    fn extract_keywords_filters_stopwords() {
        // GIVEN: text containing only stopwords
        let keywords = extract_keywords("use the tool to get data from it");
        // THEN: empty (all filtered)
        assert!(
            keywords.is_empty(),
            "Expected empty keywords, got: {keywords:?}"
        );
    }

    #[test]
    fn extract_keywords_filters_words_shorter_than_min_len() {
        // GIVEN: text with very short words that aren't stopwords
        let keywords = extract_keywords("an is a of to go");
        assert!(keywords.is_empty(), "Got: {keywords:?}");
    }

    #[test]
    fn extract_keywords_deduplicates_repeated_words() {
        // GIVEN: "calendar calendar calendar"
        let keywords = extract_keywords("calendar events calendar schedule calendar");
        let calendar_count = keywords.iter().filter(|k| k.as_str() == "calendar").count();
        assert_eq!(calendar_count, 1, "Duplicate 'calendar' found: {keywords:?}");
    }

    #[test]
    fn extract_keywords_limits_to_max_keywords() {
        // GIVEN: a long description with many distinct keywords
        let desc = "authenticates resolves transforms aggregates monitors publishes \
                    archives broadcasts encrypts compresses validates normalizes";
        let keywords = extract_keywords(desc);
        assert!(
            keywords.len() <= MAX_KEYWORDS,
            "Got {} keywords, expected ≤{MAX_KEYWORDS}: {keywords:?}",
            keywords.len()
        );
    }

    #[test]
    fn extract_keywords_prefers_longer_words() {
        // GIVEN: mix of short and long meaningful words
        let keywords = extract_keywords("authenticates resolves dns ip");
        // 'authenticates' (13 chars) should be in result before short ones
        if keywords.len() >= 2 {
            assert!(
                keywords[0].len() >= keywords[1].len(),
                "Expected descending length order, got: {keywords:?}"
            );
        }
    }

    #[test]
    fn extract_keywords_splits_hyphenated_words() {
        // GIVEN: hyphenated word "entity-discovery"
        let keywords = extract_keywords("entity-discovery workflow");
        assert!(
            keywords.contains(&"entity".to_string())
                || keywords.contains(&"discovery".to_string()),
            "Hyphen not split: {keywords:?}"
        );
    }

    #[test]
    fn extract_keywords_splits_underscore_separated_words() {
        // GIVEN: underscore-separated tokens (common in tool names embedded in descriptions)
        let keywords = extract_keywords("oauth_token refresh_token");
        assert!(
            keywords.contains(&"oauth".to_string())
                || keywords.contains(&"token".to_string())
                || keywords.contains(&"refresh".to_string()),
            "Underscore not split: {keywords:?}"
        );
    }

    #[test]
    fn extract_keywords_lowercases_all_output() {
        let keywords = extract_keywords("Authenticates OAuth Calendar");
        for kw in &keywords {
            assert_eq!(kw.as_str(), kw.to_lowercase(), "Non-lowercase keyword: {kw}");
        }
    }

    #[test]
    fn extract_keywords_from_realistic_tool_description() {
        let desc = "Search for code repositories on GitHub using keyword queries. \
                    Returns repository names, descriptions, star counts, and topics.";
        let keywords = extract_keywords(desc);
        // Should pick up domain-relevant words like "repositories", "github", "keyword",
        // "repository", "descriptions", "topics" — not "search", "returns"
        assert!(
            !keywords.is_empty(),
            "Expected keywords from realistic description"
        );
        assert!(keywords.len() <= MAX_KEYWORDS);
        // "data" is a stopword — must not appear
        assert!(!keywords.contains(&"data".to_string()));
        // "returns" is a stopword — must not appear
        assert!(!keywords.contains(&"returns".to_string()));
    }

    // ── tokenize ────────────────────────────────────────────────────────

    #[test]
    fn tokenize_splits_on_spaces() {
        let tokens: Vec<&str> = tokenize("hello world rust").collect();
        assert_eq!(tokens, ["hello", "world", "rust"]);
    }

    #[test]
    fn tokenize_splits_on_punctuation() {
        let tokens: Vec<&str> = tokenize("reads, writes, and deletes.").collect();
        assert!(tokens.contains(&"reads"));
        assert!(tokens.contains(&"writes"));
        assert!(tokens.contains(&"deletes"));
        // "and" is a stopword but tokenization itself should include it
        assert!(tokens.contains(&"and"));
    }

    #[test]
    fn tokenize_splits_on_hyphens() {
        let tokens: Vec<&str> = tokenize("entity-discovery").collect();
        assert_eq!(tokens, ["entity", "discovery"]);
    }

    #[test]
    fn tokenize_produces_no_empty_tokens() {
        for token in tokenize("  hello   world  ") {
            assert!(!token.is_empty());
        }
    }

    // ── is_stopword ─────────────────────────────────────────────────────

    #[test]
    fn stopwords_list_is_sorted() {
        // INVARIANT: STOPWORDS must be sorted for binary_search correctness
        let is_sorted = STOPWORDS.windows(2).all(|w| w[0] <= w[1]);
        assert!(
            is_sorted,
            "STOPWORDS is not sorted — binary_search will produce incorrect results"
        );
    }

    #[test]
    fn stopwords_contains_common_english_words() {
        for word in &["the", "and", "for", "with", "from", "this", "that"] {
            assert!(is_stopword(word), "'{word}' should be a stopword");
        }
    }

    #[test]
    fn stopwords_contains_tool_generic_words() {
        for word in &["tool", "tools", "returns", "parameter", "parameters", "data"] {
            assert!(is_stopword(word), "'{word}' should be a tool-generic stopword");
        }
    }

    #[test]
    fn stopwords_does_not_contain_domain_keywords() {
        for word in &[
            "calendar",
            "oauth",
            "github",
            "kubernetes",
            "bitcoin",
            "forecast",
        ] {
            assert!(!is_stopword(word), "'{word}' should NOT be a stopword");
        }
    }

    // ── edge cases ──────────────────────────────────────────────────────

    #[test]
    fn enrich_description_handles_description_with_only_numbers() {
        let result = enrich_description("42 100 3.14");
        // Numbers don't contain ASCII alphabetics, so no keywords — returns unchanged
        assert_eq!(result, "42 100 3.14");
    }

    #[test]
    fn enrich_description_handles_single_meaningful_word() {
        let result = enrich_description("Authenticates.");
        assert!(
            result.contains("[keywords: authenticates]"),
            "Got: {result}"
        );
    }

    #[test]
    fn enrich_description_handles_unicode_text() {
        // Non-ASCII chars are split boundaries; the ASCII portions should tokenize fine
        let result = enrich_description("Manages calendar entries (créer).");
        // "manages", "calendar", "entries" should be extracted; "cr" + "er" filtered by len
        assert!(result.contains("[keywords:"));
        let kws_part = result.split("[keywords:").nth(1).unwrap_or("");
        assert!(kws_part.contains("calendar") || kws_part.contains("manages") || kws_part.contains("entries"));
    }

    #[test]
    fn enrich_description_max_keywords_from_dense_description() {
        // A very long description should still produce at most MAX_KEYWORDS tags
        let desc = "Subscribes authenticates resolves normalizes aggregates \
                    broadcasts archives encrypts compresses validates transforms \
                    schedules deploys monitors analyzes generates publishes";
        let result = enrich_description(desc);
        if let Some(kw_part) = result.split("[keywords:").nth(1) {
            let count = kw_part.trim_end_matches(']').split(',').count();
            assert!(
                count <= MAX_KEYWORDS,
                "Got {count} keywords, max is {MAX_KEYWORDS}"
            );
        }
    }
}
