// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Edit distance and the "did you mean" suggestions built on it.

use super::*;

// ── levenshtein ─────────────────────────────────────────────────────

#[test]
fn levenshtein_identical_strings_is_zero() {
    assert_eq!(levenshtein("gateway_invoke", "gateway_invoke"), 0);
}

#[test]
fn levenshtein_empty_strings_is_zero() {
    assert_eq!(levenshtein("", ""), 0);
}

#[test]
fn levenshtein_empty_vs_nonempty_is_length() {
    assert_eq!(levenshtein("", "abc"), 3);
    assert_eq!(levenshtein("abc", ""), 3);
}

#[test]
fn levenshtein_single_insertion() {
    // "gateway_invokee" has one extra 'e'
    assert_eq!(levenshtein("gateway_invokee", "gateway_invoke"), 1);
}

#[test]
fn levenshtein_single_deletion() {
    // "gatway_invoke" is missing 'e'
    assert_eq!(levenshtein("gatway_invoke", "gateway_invoke"), 1);
}

#[test]
fn levenshtein_single_substitution() {
    // "gateway_xnvoke" has 'x' instead of 'i'
    assert_eq!(levenshtein("gateway_xnvoke", "gateway_invoke"), 1);
}

#[test]
fn levenshtein_transposition_costs_two() {
    // Standard Levenshtein (not Damerau): "ab" -> "ba" requires 2 ops
    assert_eq!(levenshtein("ba", "ab"), 2);
}

#[test]
fn levenshtein_completely_different_strings() {
    assert_eq!(levenshtein("abc", "xyz"), 3);
}

#[test]
fn levenshtein_non_ascii_char_vs_byte_length() {
    // "café" has 4 chars but 5 bytes (é is 2 bytes in UTF-8). The buggy
    // version sized and indexed the final row by `b.len()` (bytes) while
    // the inner loop only ever wrote up to `b.chars().count()` (chars),
    // so it returned a stale cell the algorithm never computed for `b`.
    assert_eq!(levenshtein("cafe", "café"), 1);
}

// ── did_you_mean ────────────────────────────────────────────────────

#[test]
fn did_you_mean_exact_match_returns_that_name() {
    // GIVEN: the exact tool name is in the candidates
    let candidates = ["gateway_invoke", "gateway_search_tools"];
    let hint = did_you_mean("gateway_invoke", &candidates, 3, 3);
    // THEN: returns a suggestion containing the exact match
    assert!(hint.is_some());
    assert!(hint.unwrap().contains("gateway_invoke"));
}

#[test]
fn did_you_mean_one_char_typo_returns_suggestion() {
    // GIVEN: "gateway_invokee" is off by one character
    let candidates = [
        "gateway_search_tools",
        "gateway_list_tools",
        "gateway_list_servers",
        "gateway_invoke",
    ];
    let hint = did_you_mean("gateway_invokee", &candidates, 3, 3);
    assert!(hint.is_some_and(|m| m.contains("gateway_invoke")));
}

#[test]
fn did_you_mean_far_typo_returns_none() {
    // GIVEN: "completely_wrong" has no close match
    let candidates = ["gateway_invoke", "gateway_search_tools"];
    let hint = did_you_mean("completely_wrong", &candidates, 3, 3);
    assert!(hint.is_none());
}

#[test]
fn did_you_mean_returns_at_most_max_suggestions() {
    // GIVEN: three close candidates (all distance 1) and max=2
    let candidates = ["gateway_a", "gateway_b", "gateway_c"];
    let hint = did_you_mean("gateway_x", &candidates, 2, 2);
    if let Some(msg) = hint {
        // The message should mention at most 2 names separated by ", "
        let names: Vec<&str> = msg
            .strip_prefix("Did you mean: ")
            .unwrap_or(&msg)
            .strip_suffix('?')
            .unwrap_or(&msg)
            .split(", ")
            .collect();
        assert!(names.len() <= 2);
    }
}

#[test]
fn did_you_mean_sorts_by_ascending_distance() {
    // GIVEN: two candidates — one is an exact match (dist 0), one is farther
    let candidates = ["gateway_invoke", "gateway_invoke_extra"];
    let hint = did_you_mean("gateway_invoke", &candidates, 6, 3).unwrap();
    // The exact match must appear first
    let first = hint
        .strip_prefix("Did you mean: ")
        .unwrap_or(&hint)
        .split(", ")
        .next()
        .unwrap()
        .trim_end_matches('?');
    assert_eq!(first, "gateway_invoke");
}
