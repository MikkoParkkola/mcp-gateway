//! Differential descriptions for tool families in search results.
//!
//! When a search returns multiple tools from the same "family" (common name prefix,
//! e.g. `gmail_search`, `gmail_send`, `gmail_batch_modify`), the descriptions are
//! often so similar that an LLM cannot distinguish them.  This module computes a
//! **differential description** for each family member that emphasises what makes
//! *that specific tool* different from its siblings, rather than repeating shared
//! context.
//!
//! # Algorithm
//!
//! 1. **Family detection** — tools are in the same family when they share the same
//!    server AND a common snake_case prefix (the first segment before the first `_`).
//!    A family must have ≥ 2 members to qualify for differential treatment.
//!
//! 2. **Common-word extraction** — the descriptions of all family members are split
//!    into words (lowercased, punctuation stripped).  Words that appear in *every*
//!    member's description are considered "shared context" and carry no differential
//!    signal.
//!
//! 3. **Unique-word selection** — words that appear in a member's description but
//!    NOT in every sibling's description are "discriminating words".  The first
//!    8 such words (preserving original order) form the differential description.
//!
//! 4. **Fallback** — when the unique-word set is empty (all descriptions are
//!    identical) the original description is returned unchanged so callers never
//!    receive an empty string.
//!
//! The original `description` field is always preserved alongside
//! `differential_description` in the search result JSON.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

// ============================================================================
// Public API
// ============================================================================

/// Annotate a slice of search-match JSON objects with `differential_description`
/// fields where applicable.
///
/// Matches that belong to a family of ≥ 2 tools (same server, same prefix) have
/// an extra `"differential_description"` key added.  All other matches are
/// returned unchanged.  The original `"description"` is never modified.
///
/// # Arguments
///
/// * `matches` – mutable slice of JSON objects as produced by
///   [`build_match_json`][crate::gateway::meta_mcp_helpers::build_match_json].
pub fn annotate_differential(matches: &mut [Value]) {
    let families = detect_families(matches);

    for (_, indices) in &families {
        if indices.len() < 2 {
            continue;
        }
        apply_differential_descriptions(matches, indices);
    }
}

// ============================================================================
// Family detection
// ============================================================================

/// Family key: (server, name_prefix).
type FamilyKey = (String, String);

/// Detect tool families in a list of search matches.
///
/// Returns a map from `(server, prefix)` to the indices into `matches` that
/// belong to that family.  Only families with ≥ 2 members are meaningful, but
/// all are returned so callers can filter as needed.
fn detect_families(matches: &[Value]) -> HashMap<FamilyKey, Vec<usize>> {
    let mut families: HashMap<FamilyKey, Vec<usize>> = HashMap::new();

    for (idx, m) in matches.iter().enumerate() {
        let server = match m.get("server").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let tool = match m.get("tool").and_then(Value::as_str) {
            Some(t) => t,
            None => continue,
        };
        let prefix = tool_prefix(tool);
        families.entry((server, prefix)).or_default().push(idx);
    }

    families
}

/// Extract the name prefix: everything before the first `_` in a tool name.
///
/// Tools with no `_` are their own prefix (single-member family, no diff needed).
///
/// # Examples
///
/// ```
/// assert_eq!(tool_prefix("gmail_search"), "gmail");
/// assert_eq!(tool_prefix("gmail_batch_modify"), "gmail");
/// assert_eq!(tool_prefix("search"), "search");
/// ```
fn tool_prefix(name: &str) -> String {
    name.split_once('_')
        .map(|(prefix, _)| prefix.to_string())
        .unwrap_or_else(|| name.to_string())
}

// ============================================================================
// Differential description generation
// ============================================================================

/// Compute and apply differential descriptions for a single family.
///
/// `indices` must point to at least 2 elements of `matches`.
fn apply_differential_descriptions(matches: &mut [Value], indices: &[usize]) {
    // Collect original descriptions (before mutation) so computation is pure.
    let descriptions: Vec<String> = indices
        .iter()
        .map(|&i| {
            matches[i]
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        })
        .collect();

    let common = common_words(&descriptions);

    for (pos, &idx) in indices.iter().enumerate() {
        let diff = differential_text(&descriptions[pos], &common);
        matches[idx]["differential_description"] = Value::String(diff);
    }
}

/// Return the set of words that appear in **every** description.
///
/// Words are lowercased and stripped of leading/trailing punctuation before
/// comparison.  An empty set is returned when descriptions share no common
/// words (unlikely in practice but handled gracefully).
fn common_words(descriptions: &[String]) -> HashSet<String> {
    if descriptions.is_empty() {
        return HashSet::new();
    }

    // Build word sets per description.
    let word_sets: Vec<HashSet<String>> = descriptions
        .iter()
        .map(|d| tokenise(d))
        .collect();

    // Intersection: start from the first set and retain only words present in all.
    let mut common = word_sets[0].clone();
    for set in &word_sets[1..] {
        common.retain(|w| set.contains(w));
    }
    common
}

/// Build the differential text for one tool by removing common words.
///
/// Preserves original word order and capitalises the first word.  Falls back
/// to the full original description when the diff would be empty (all words are
/// shared).
///
/// At most 8 discriminating words are kept to produce concise diffs.
fn differential_text(description: &str, common: &HashSet<String>) -> String {
    const MAX_DIFF_WORDS: usize = 8;

    let words: Vec<&str> = description.split_whitespace().collect();
    let unique: Vec<&str> = words
        .iter()
        .filter(|&&w| {
            let normalised = normalise_word(w);
            !normalised.is_empty() && !common.contains(&normalised)
        })
        .copied()
        .take(MAX_DIFF_WORDS)
        .collect();

    if unique.is_empty() {
        return description.to_string();
    }

    let joined = unique.join(" ");
    // Capitalise first character of the result.
    let mut chars = joined.chars();
    match chars.next() {
        None => joined,
        Some(first) => {
            let upper: String = first.to_uppercase().collect();
            upper + chars.as_str()
        }
    }
}

/// Tokenise a description into a set of normalised words.
fn tokenise(description: &str) -> HashSet<String> {
    description
        .split_whitespace()
        .map(normalise_word)
        .filter(|w| !w.is_empty())
        .collect()
}

/// Lowercase a word and strip surrounding punctuation.
fn normalise_word(word: &str) -> String {
    word.trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── tool_prefix ────────────────────────────────────────────────────

    #[test]
    fn tool_prefix_splits_on_first_underscore() {
        // GIVEN: tool name with multiple underscores
        // WHEN: extracting prefix
        // THEN: only the first segment is returned
        assert_eq!(tool_prefix("gmail_batch_modify"), "gmail");
    }

    #[test]
    fn tool_prefix_single_segment_returns_full_name() {
        // GIVEN: tool name with no underscore
        // WHEN: extracting prefix
        // THEN: full name returned
        assert_eq!(tool_prefix("search"), "search");
    }

    #[test]
    fn tool_prefix_two_segment_name() {
        // GIVEN: "gmail_search"
        // WHEN: extracting prefix
        // THEN: "gmail"
        assert_eq!(tool_prefix("gmail_search"), "gmail");
    }

    #[test]
    fn tool_prefix_brave_family() {
        assert_eq!(tool_prefix("brave_search"), "brave");
        assert_eq!(tool_prefix("brave_news"), "brave");
        assert_eq!(tool_prefix("brave_images"), "brave");
    }

    // ── detect_families ────────────────────────────────────────────────

    #[test]
    fn detect_families_groups_same_server_and_prefix() {
        // GIVEN: three gmail tools on the same server
        // WHEN: detecting families
        // THEN: one family with three members
        let matches = vec![
            json!({"server": "fulcrum", "tool": "gmail_search", "description": "Search Gmail"}),
            json!({"server": "fulcrum", "tool": "gmail_send", "description": "Send Gmail"}),
            json!({"server": "fulcrum", "tool": "gmail_batch_modify", "description": "Batch Gmail"}),
        ];
        let families = detect_families(&matches);
        let key = ("fulcrum".to_string(), "gmail".to_string());
        assert!(families.contains_key(&key));
        assert_eq!(families[&key].len(), 3);
    }

    #[test]
    fn detect_families_separates_different_servers() {
        // GIVEN: same tool prefix but different servers
        // WHEN: detecting families
        // THEN: two separate single-member families (no diff applied)
        let matches = vec![
            json!({"server": "server_a", "tool": "brave_search", "description": "A"}),
            json!({"server": "server_b", "tool": "brave_news", "description": "B"}),
        ];
        let families = detect_families(&matches);
        let key_a = ("server_a".to_string(), "brave".to_string());
        let key_b = ("server_b".to_string(), "brave".to_string());
        assert_eq!(families[&key_a].len(), 1);
        assert_eq!(families[&key_b].len(), 1);
    }

    #[test]
    fn detect_families_single_tool_makes_own_family() {
        // GIVEN: one tool
        // WHEN: detecting families
        // THEN: single-member family (too small for differential)
        let matches = vec![
            json!({"server": "srv", "tool": "unique_tool", "description": "Unique"}),
        ];
        let families = detect_families(&matches);
        assert_eq!(families.len(), 1);
        let key = ("srv".to_string(), "unique".to_string());
        assert_eq!(families[&key].len(), 1);
    }

    #[test]
    fn detect_families_skips_missing_server_or_tool() {
        // GIVEN: malformed JSON objects
        // WHEN: detecting families
        // THEN: skips gracefully, no panic
        let matches = vec![
            json!({"tool": "gmail_search"}),   // missing server
            json!({"server": "fulcrum"}),       // missing tool
        ];
        let families = detect_families(&matches);
        // Only the entry with both fields forms a family
        assert_eq!(families.len(), 0);
    }

    // ── common_words ───────────────────────────────────────────────────

    #[test]
    fn common_words_finds_shared_words() {
        // GIVEN: descriptions all containing "gmail" and "messages"
        // WHEN: computing common words
        // THEN: both words in the result
        let descs = vec![
            "Search Gmail messages by query".to_string(),
            "Send Gmail messages to recipients".to_string(),
            "Delete Gmail messages in bulk".to_string(),
        ];
        let common = common_words(&descs);
        assert!(common.contains("gmail"), "expected 'gmail' in common");
        assert!(common.contains("messages"), "expected 'messages' in common");
    }

    #[test]
    fn common_words_excludes_non_universal_words() {
        // GIVEN: "search" appears in only one description
        // WHEN: computing common words
        // THEN: "search" is NOT in common set
        let descs = vec![
            "Search Gmail messages".to_string(),
            "Send Gmail messages".to_string(),
        ];
        let common = common_words(&descs);
        assert!(!common.contains("search"), "'search' should not be common");
        assert!(!common.contains("send"), "'send' should not be common");
    }

    #[test]
    fn common_words_empty_for_empty_input() {
        // GIVEN: no descriptions
        // WHEN: computing common words
        // THEN: empty set
        let common = common_words(&[]);
        assert!(common.is_empty());
    }

    #[test]
    fn common_words_single_description_all_words_common() {
        // GIVEN: only one description
        // WHEN: computing common words
        // THEN: every word in the description is "common"
        let descs = vec!["Send email".to_string()];
        let common = common_words(&descs);
        assert!(common.contains("send"));
        assert!(common.contains("email"));
    }

    // ── differential_text ──────────────────────────────────────────────

    #[test]
    fn differential_text_keeps_unique_words() {
        // GIVEN: description "Search Gmail messages by query", common = {gmail, messages}
        // WHEN: computing differential text
        // THEN: "Search by query" (unique words only)
        let common: HashSet<String> = ["gmail".to_string(), "messages".to_string()]
            .into_iter()
            .collect();
        let diff = differential_text("Search Gmail messages by query", &common);
        assert!(diff.to_lowercase().contains("search"));
        assert!(diff.to_lowercase().contains("query"));
        assert!(!diff.to_lowercase().contains("gmail"));
        assert!(!diff.to_lowercase().contains("messages"));
    }

    #[test]
    fn differential_text_capitalises_first_word() {
        // GIVEN: unique words that start with lowercase
        // WHEN: differential_text is called
        // THEN: first character of result is uppercase
        let common: HashSet<String> = ["shared".to_string()].into_iter().collect();
        let diff = differential_text("shared unique words here", &common);
        assert!(diff.chars().next().unwrap().is_uppercase());
    }

    #[test]
    fn differential_text_falls_back_when_all_words_common() {
        // GIVEN: all words in description are in the common set
        // WHEN: differential_text is called
        // THEN: original description returned verbatim
        let common: HashSet<String> = ["search".to_string(), "gmail".to_string()]
            .into_iter()
            .collect();
        let original = "Search Gmail";
        let diff = differential_text(original, &common);
        assert_eq!(diff, original);
    }

    #[test]
    fn differential_text_limits_to_eight_words() {
        // GIVEN: description with 12 unique words
        // WHEN: computing differential text
        // THEN: at most 8 words in the result
        let common: HashSet<String> = HashSet::new();
        let desc = "one two three four five six seven eight nine ten eleven twelve";
        let diff = differential_text(desc, &common);
        assert!(diff.split_whitespace().count() <= 8);
    }

    // ── annotate_differential ──────────────────────────────────────────

    #[test]
    fn annotate_differential_adds_field_to_family_members() {
        // GIVEN: three gmail tools that form a family
        // WHEN: annotate_differential is called
        // THEN: all three have a "differential_description" field
        let mut matches = vec![
            json!({"server": "fulcrum", "tool": "gmail_search", "description": "Search Gmail messages by query, date, labels"}),
            json!({"server": "fulcrum", "tool": "gmail_send", "description": "Send Gmail messages to recipients"}),
            json!({"server": "fulcrum", "tool": "gmail_batch_modify", "description": "Modify Gmail messages in bulk operations"}),
        ];
        annotate_differential(&mut matches);
        for m in &matches {
            assert!(
                m.get("differential_description").is_some(),
                "tool {} missing differential_description",
                m["tool"]
            );
        }
    }

    #[test]
    fn annotate_differential_preserves_original_description() {
        // GIVEN: two tools forming a family
        // WHEN: annotate_differential is called
        // THEN: original "description" field is unchanged
        let original_desc = "Search Gmail messages by query, date, labels";
        let mut matches = vec![
            json!({"server": "fulcrum", "tool": "gmail_search", "description": original_desc}),
            json!({"server": "fulcrum", "tool": "gmail_send", "description": "Send Gmail messages"}),
        ];
        annotate_differential(&mut matches);
        assert_eq!(matches[0]["description"], original_desc);
    }

    #[test]
    fn annotate_differential_no_change_for_single_tool() {
        // GIVEN: one tool with a unique prefix (no family)
        // WHEN: annotate_differential is called
        // THEN: no "differential_description" field added
        let mut matches = vec![
            json!({"server": "srv", "tool": "weather_get", "description": "Get current weather"}),
        ];
        annotate_differential(&mut matches);
        assert!(
            matches[0].get("differential_description").is_none(),
            "single tool should not get differential_description"
        );
    }

    #[test]
    fn annotate_differential_no_change_for_tools_on_different_servers() {
        // GIVEN: two brave tools but on different servers
        // WHEN: annotate_differential is called
        // THEN: no differential_description (different servers = different families)
        let mut matches = vec![
            json!({"server": "server_a", "tool": "brave_search", "description": "Search the web"}),
            json!({"server": "server_b", "tool": "brave_news", "description": "Search news"}),
        ];
        annotate_differential(&mut matches);
        assert!(matches[0].get("differential_description").is_none());
        assert!(matches[1].get("differential_description").is_none());
    }

    #[test]
    fn annotate_differential_diff_contains_unique_terms() {
        // GIVEN: gmail family with "search", "send", "batch_modify"
        // WHEN: annotate_differential is called
        // THEN: each diff description highlights something unique to that tool
        let mut matches = vec![
            json!({"server": "cap", "tool": "gmail_search", "description": "Search Gmail messages by query date labels"}),
            json!({"server": "cap", "tool": "gmail_send",   "description": "Send Gmail messages compose new email"}),
            json!({"server": "cap", "tool": "gmail_batch_modify", "description": "Modify Gmail messages bulk archive trash"}),
        ];
        annotate_differential(&mut matches);

        let search_diff = matches[0]["differential_description"].as_str().unwrap().to_lowercase();
        let send_diff   = matches[1]["differential_description"].as_str().unwrap().to_lowercase();
        let batch_diff  = matches[2]["differential_description"].as_str().unwrap().to_lowercase();

        // Each diff should not contain "gmail" or "messages" (universal across all)
        for diff in &[&search_diff, &send_diff, &batch_diff] {
            assert!(!diff.contains("gmail"), "common word 'gmail' should be removed: {diff}");
            assert!(!diff.contains("messages"), "common word 'messages' should be removed: {diff}");
        }

        // Each diff should contain at least one distinctive word
        assert!(
            search_diff.contains("search") || search_diff.contains("query") || search_diff.contains("labels"),
            "search diff should mention search-specific terms: {search_diff}"
        );
        assert!(
            send_diff.contains("send") || send_diff.contains("compose") || send_diff.contains("email"),
            "send diff should mention send-specific terms: {send_diff}"
        );
        assert!(
            batch_diff.contains("bulk") || batch_diff.contains("archive") || batch_diff.contains("trash") || batch_diff.contains("modify"),
            "batch diff should mention bulk-specific terms: {batch_diff}"
        );
    }

    #[test]
    fn annotate_differential_two_member_family() {
        // GIVEN: exactly two tools sharing a prefix
        // WHEN: annotate_differential is called
        // THEN: both get differential_description
        let mut matches = vec![
            json!({"server": "s", "tool": "linear_get_teams", "description": "Get all teams in Linear workspace"}),
            json!({"server": "s", "tool": "linear_create_issue", "description": "Create a new issue in Linear workspace"}),
        ];
        annotate_differential(&mut matches);
        assert!(matches[0].get("differential_description").is_some());
        assert!(matches[1].get("differential_description").is_some());
    }

    #[test]
    fn annotate_differential_handles_empty_matches() {
        // GIVEN: empty matches slice
        // WHEN: annotate_differential is called
        // THEN: no panic
        let mut matches: Vec<Value> = vec![];
        annotate_differential(&mut matches);
        assert!(matches.is_empty());
    }

    #[test]
    fn annotate_differential_mixed_families_and_singles() {
        // GIVEN: two gmail tools (family) and one weather tool (singleton)
        // WHEN: annotate_differential is called
        // THEN: gmail tools get diff, weather tool does not
        let mut matches = vec![
            json!({"server": "cap", "tool": "gmail_search", "description": "Search Gmail messages"}),
            json!({"server": "cap", "tool": "gmail_send",   "description": "Send Gmail messages"}),
            json!({"server": "cap", "tool": "weather_get",  "description": "Get current weather conditions"}),
        ];
        annotate_differential(&mut matches);
        assert!(matches[0].get("differential_description").is_some(), "gmail_search should have diff");
        assert!(matches[1].get("differential_description").is_some(), "gmail_send should have diff");
        assert!(matches[2].get("differential_description").is_none(), "weather_get should not have diff");
    }

    #[test]
    fn annotate_differential_five_member_family() {
        // GIVEN: 5 brave tools forming a large family
        // WHEN: annotate_differential is called
        // THEN: all 5 get differential_description without panic
        let mut matches: Vec<Value> = ["search", "news", "images", "videos", "suggest"]
            .iter()
            .map(|kind| {
                json!({
                    "server": "cap",
                    "tool": format!("brave_{kind}"),
                    "description": format!("Brave {kind} search engine results for your query")
                })
            })
            .collect();
        annotate_differential(&mut matches);
        for m in &matches {
            assert!(
                m.get("differential_description").is_some(),
                "tool {} should have diff",
                m["tool"]
            );
        }
    }

    // ── normalise_word ──────────────────────────────────────────────────

    #[test]
    fn normalise_word_strips_punctuation_and_lowercases() {
        // GIVEN: words with trailing/leading punctuation
        // WHEN: normalising
        // THEN: clean lowercase tokens
        assert_eq!(normalise_word("Gmail,"), "gmail");
        assert_eq!(normalise_word("(messages)"), "messages");
        assert_eq!(normalise_word("READ-ONLY"), "read-only");
    }
}
