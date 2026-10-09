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
