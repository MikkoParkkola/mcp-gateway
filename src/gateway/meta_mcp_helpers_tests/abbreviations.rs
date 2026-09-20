// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance tests for MIK-3274.RANKING.1 — fuzzy ranking for abbreviations
//! and word boundaries.
//!
//! Design: `docs/design/2026-09-12-mik-3274-ranking-abbreviations.md`, §5 is
//! the acceptance mapping and this file is one test per row of it.
//!
//! The corpus is read from a fixture frozen in its own commit before the
//! abbreviation table existed (§3.2). It carries no supported/unsupported
//! labels, so the held-out test asserts a bounded fraction rather than a
//! perfect score: resolving every case is leakage, not a pass.

use super::*;
use crate::ranking::{SearchRanker, SearchResult};

const CORPUS: &str = include_str!("../../ranking/fixtures/abbreviation-corpus.tsv");
const CATALOGUE: &str = include_str!("../../ranking/fixtures/abbreviation-catalogue.tsv");

/// Parse a frozen fixture into `(first, second)` pairs, skipping comments.
fn fixture_rows(raw: &str) -> Vec<(&str, &str)> {
    raw.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| line.split_once('\t'))
        .collect()
}

/// The frozen catalogue as candidate tools.
fn catalogue() -> Vec<Tool> {
    fixture_rows(CATALOGUE)
        .into_iter()
        .map(|(name, desc)| make_tool(name, Some(desc)))
        .collect()
}

/// Run a query through the real discovery path: candidate filter first, then
/// the ranker. A scorer-only or filter-only change cannot satisfy this.
fn discover(query: &str) -> Vec<SearchResult> {
    let ranker = SearchRanker::new();
    let candidates: Vec<SearchResult> = catalogue()
        .iter()
        .filter(|t| tool_matches_query(t, query))
        .map(|t| {
            SearchResult::new(
                "cat",
                t.name.as_str(),
                t.description.clone().unwrap_or_default(),
            )
        })
        .collect();
    ranker
        .rank(candidates, query)
        .into_iter()
        .filter(|result| result.score > 0.0)
        .collect()
}

// ── §5: Code Mode glob control ──────────────────────────────────────

/// Glob queries skip `ranker.rank` entirely and never reach the candidate
/// filter (§3.6), so their results are byte-identical before and after this
/// change. The expected lists are written out in full: a leak of abbreviation
/// expansion into glob matching shows up as a diff here.
#[test]
fn glob_queries_are_byte_identical_across_the_ranking_change() {
    let names = |pattern: &str| -> Vec<String> {
        catalogue()
            .iter()
            .filter(|t| tool_matches_glob(t, pattern))
            .map(|t| t.name.clone())
            .collect()
    };

    assert_eq!(
        names("kubernetes_*"),
        vec!["kubernetes_list_pods", "kubernetes_drain_node"]
    );
    assert_eq!(names("*_rotate"), vec!["credentials_rotate"]);
    assert_eq!(names("config_e?port"), vec!["config_export"]);
    // `k8s` is the flagship abbreviation. A glob query must not gain a
    // Kubernetes tool from the table.
    assert_eq!(names("k8s*"), Vec::<String>::new());
    assert_eq!(names("*k8s*"), Vec::<String>::new());
}

// ── §5: Unicode control ─────────────────────────────────────────────

/// Non-ASCII queries traverse the filter and the ranker without panicking and
/// without inventing matches. All new matching code works on whole `&str`
/// values, never byte-offset slices (§3.5).
#[test]
fn non_ascii_queries_rank_without_panicking() {
    assert!(discover("éé").is_empty());
    assert!(discover("配置").is_empty());
    // A non-ASCII word beside a supported abbreviation still resolves.
    assert_eq!(
        discover("k8s éé").first().map(|r| r.tool.as_str()),
        Some("kubernetes_list_pods")
    );
}

/// The zero-result suggestion path is the Unicode control's other half: it
/// runs only when `matches` is empty, which is exactly what a non-ASCII query
/// produces. `MIN_PREFIX_LEN` is a byte count, so a two-char four-byte word
/// slices through a character boundary (§3.5).
///
/// The tag must not contain the query word, or the substring arm
/// short-circuits before the prefix rule is reached.
#[test]
fn build_suggestions_does_not_panic_on_a_multi_byte_query_word() {
    let tags = vec!["email".to_string(), "kubernetes".to_string()];
    assert!(build_suggestions("éé", &tags).is_empty());
    assert!(build_suggestions("配置文件", &tags).is_empty());
    // ASCII behaviour is byte-identical: three-char prefix rule still fires.
    assert_eq!(build_suggestions("ema", &tags), vec!["email".to_string()]);
}

/// The prefix rule must still *produce* a suggestion for a multi-byte query,
/// not merely stop panicking on one. Absence of a panic cannot tell a working
/// character cut apart from a rule that never fires, and the zero-result path
/// exists to return something.
///
/// `éémailbox` cuts at byte 3, inside the second `é`, so the byte slice this
/// replaced panicked before it could return anything at all.
#[test]
fn a_multi_byte_query_word_still_earns_a_prefix_suggestion() {
    let tags = vec!["éémail-service".to_string(), "kubernetes".to_string()];
    assert_eq!(
        build_suggestions("éémailbox", &tags),
        vec!["éémail-service".to_string()]
    );
}

// ── §5: held-out abbreviations, and the unsupported-match control ───

/// Frozen corpus rows as `(query, intended tool)`.
type CorpusRows = Vec<(&'static str, &'static str)>;

/// Split the frozen corpus into cases the shipped table resolves and cases it
/// does not. No fixture row is labelled: the partition is whatever the table
/// turns out to cover, computed at run time.
fn corpus_partition() -> (CorpusRows, CorpusRows) {
    fixture_rows(CORPUS)
        .into_iter()
        .partition(|(query, intended)| {
            discover(query).first().map(|r| r.tool.as_str()) == Some(*intended)
        })
}

/// Held-out abbreviation queries return their intended tool at rank 1, with a
/// non-zero score — a filter-only change admits the tool at score 0.0 and is
/// caught here, which is the failure §3.2 rule 2 exists to prevent.
///
/// The corpus was frozen before the table, so it necessarily carries
/// abbreviations the table does not. A perfect score means the table was
/// fitted to the corpus and is reported as leakage, not as a pass (§3.2).
#[test]
fn held_out_abbreviations_resolve_to_their_intended_tool() {
    let (resolved, unresolved) = corpus_partition();
    let total = resolved.len() + unresolved.len();

    assert!(
        !resolved.is_empty(),
        "no held-out abbreviation resolved; the table admits nothing"
    );
    assert!(
        !unresolved.is_empty(),
        "every one of {total} held-out cases resolved: the table was fitted to \
         the corpus that grades it — leakage, not a pass"
    );

    for (query, intended) in resolved {
        let ranked = discover(query);
        assert_eq!(ranked[0].tool, intended, "rank 1 for {query}");
        assert!(ranked[0].score > 0.0, "score for {query}");
    }
}

/// An abbreviation the table does not carry returns no new result. The control
/// is drawn from the same frozen corpus (§3.2 rule 4), so it cannot be a
/// control against a table written knowing how to dodge it.
#[test]
fn unsupported_abbreviations_return_no_new_result() {
    let (_, unresolved) = corpus_partition();

    for (query, intended) in unresolved {
        let ranked = discover(query);
        let tools: Vec<&str> = ranked.iter().map(|r| r.tool.as_str()).collect();
        assert!(
            !tools.contains(&intended),
            "unsupported {query} must not surface {intended}, got {tools:?}"
        );
    }
}

// ── §5: word boundaries over conflicting sibling names ──────────────

/// Rank a bespoke sibling set. `(tool, description, uses)` in the order the
/// collectors would have produced, so a tie resolved by stable sort keeps the
/// first entry — which is what makes the tie-break observable.
fn rank_siblings(query: &str, siblings: &[(&str, &str, u64)]) -> Vec<SearchResult> {
    let ranker = SearchRanker::new();
    let mut results = Vec::new();
    for (tool, description, uses) in siblings {
        for _ in 0..*uses {
            ranker.record_use("gmail", tool);
        }
        results.push(SearchResult::new("gmail", *tool, *description));
    }
    ranker.rank(results, query)
}

/// At equal final score, a match starting at a token boundary sorts above a
/// mid-token one (§3.3). Both candidates reach the same tier, so nothing but
/// the tie-break can separate them.
#[test]
fn boundary_aligned_match_outranks_a_mid_token_one_at_equal_score() {
    let ranked = rank_siblings(
        "send",
        &[
            ("resend_webhook", "Replay a stored webhook delivery", 0),
            ("gmail_send", "Send a Gmail message", 0),
            ("gmail_batch_modify", "Apply label changes in bulk", 0),
        ],
    );

    assert_eq!(ranked[0].tool, "gmail_send");
    assert_eq!(ranked[1].tool, "resend_webhook");
    assert!((ranked[0].score - ranked[1].score).abs() < f64::EPSILON);
}

/// A multi-word query is boundary-aligned only when **every** query word that
/// matched the name is aligned (§3.3). `gmail_resend_log` aligns on `gmail`
/// and not on `send`, so it loses to the candidate that aligns on both.
#[test]
fn multi_word_boundary_requires_every_matched_word_to_align() {
    let ranked = rank_siblings(
        "gmail send",
        &[
            ("gmail_resend_log", "Audit log of Gmail resend attempts", 0),
            ("gmail_send", "Send a Gmail message", 0),
        ],
    );

    assert_eq!(ranked[0].tool, "gmail_send");
    assert!((ranked[0].score - ranked[1].score).abs() < f64::EPSILON);
}

// ── §5: exact identifier control ────────────────────────────────────

/// An exact tool name returns that tool first even against a sibling whose
/// usage multiplier carries it past the exact match's text score (§3.4).
/// Testing this with neutral usage would not exercise the control: the sibling
/// reaches `8.0 × ~2.0 ≈ 16` against the exact match's `10.0 × 1.0`.
#[test]
fn exact_identifier_outranks_a_highly_used_competing_sibling() {
    let ranked = rank_siblings(
        "gmail_send",
        &[
            (
                "gmail_send_draft",
                "Send an existing draft [keywords: gmail_send, draft]",
                100,
            ),
            ("gmail_send", "Send a Gmail message", 0),
        ],
    );

    assert_eq!(ranked[0].tool, "gmail_send");
    assert!(
        ranked[1].score > ranked[0].score,
        "the control is only real while the sibling outscores the exact match"
    );
}

// ── §3.4: the one constant left in the blast radius ─────────────────

/// Abbreviation matches reuse `SYNONYM_MULTIPLIER` rather than introducing a
/// second constant (§3.2 rule 3), and the discount is applied once. The
/// absolute scores are asserted, not their ratio: a test written as
/// `abbrev == literal * SYNONYM_MULTIPLIER` passes at every value of the
/// constant and is not coverage of it.
#[test]
fn abbreviation_matches_carry_the_synonym_discount_exactly_once() {
    let literal = discover("kubernetes");
    let abbreviated = discover("k8s");

    assert_eq!(literal[0].tool, "kubernetes_list_pods");
    assert_eq!(abbreviated[0].tool, "kubernetes_list_pods");
    assert!((literal[0].score - 5.0).abs() < f64::EPSILON);
    assert!((abbreviated[0].score - 4.0).abs() < f64::EPSILON);
}
