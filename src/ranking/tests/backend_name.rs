// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

#[test]
fn a_backend_name_score_sits_between_a_mention_and_a_name_match() {
    let full = backend_name_score("CodeSearch", &["codesearch"]);
    assert!((full - 4.0).abs() < f64::EPSILON, "{full}");
    let mention = score_text_relevance("guide", "about codesearch", "codesearch", &["codesearch"]);
    let named = score_text_relevance("codesearch_index", "", "codesearch", &["codesearch"]);
    assert!(mention < full && full < named, "{mention} {full} {named}");
}

#[test]
fn a_backend_name_score_counts_the_share_of_words_found() {
    let half = backend_name_score("codesearch", &["codesearch", "weather"]);
    assert!((half - 2.0).abs() < f64::EPSILON, "{half}");
    assert!(backend_name_score("docs", &["codesearch"]).abs() < f64::EPSILON);
    assert!(backend_name_score("docs", &[]).abs() < f64::EPSILON);
}

#[test]
fn a_backend_name_found_through_a_synonym_or_abbreviation_scores_at_the_discount() {
    let discounted = 4.0 * SYNONYM_MULTIPLIER;
    let synonym = backend_name_score("finder", &["search"]);
    assert!((synonym - discounted).abs() < f64::EPSILON, "{synonym}");
    let abbreviation = backend_name_score("k8s-ops", &["kubernetes"]);
    assert!(
        (abbreviation - discounted).abs() < f64::EPSILON,
        "{abbreviation}"
    );
}

/// Usage is multiplicative, so feedback cannot promote an irrelevant tool:
/// a candidate with no match in its name, description or backend stays at
/// zero however heavily it is used. (No search route admits such a candidate
/// now that a backend-name match scores, so this is pinned on the ranker.)
#[test]
fn usage_cannot_lift_a_zero_relevance_candidate() {
    let ranker = SearchRanker::new();
    for _ in 0..1_000 {
        ranker.record_use("other", "sprocket_sorter");
    }
    let order = ranker.rank(
        vec![
            SearchResult::new("other", "sprocket_sorter", "sorting sprockets by colour"),
            SearchResult::new("hub", "weak_match", "a zebracorn adjacent helper"),
        ],
        "zebracorn",
    );
    assert_eq!(order[0].tool, "weak_match");
    let sorter = order
        .iter()
        .find(|r| r.tool == "sprocket_sorter")
        .expect("a zero-relevance candidate is kept, not dropped");
    assert!(sorter.score.abs() < f64::EPSILON, "{}", sorter.score);
}
