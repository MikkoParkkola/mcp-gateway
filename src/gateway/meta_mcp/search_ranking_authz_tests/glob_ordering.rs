// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! INVARIANT B of MIK-3274.RANKING.2 — the documented glob carve-out.
use super::*;

/// Two equally relevant capabilities whose names share a glob-able prefix.
///
/// Neither name equals `QUERY`, so `score_text_relevance` gives them the SAME
/// non-zero score and usage is the only thing that can reorder them. `_alpha`
/// is collected first (see `capability_backend_named`), so collection order and
/// ranked order disagree once `_beta` carries the usage.
const GLOB_FIXTURES: &[(&str, &str)] = &[
    ("zebracorn_alpha", "first zebracorn helper"),
    ("zebracorn_beta", "second zebracorn helper"),
];

/// CONTROL for the glob carve-out below — ranking must be able to reorder
/// these two, or the carve-out test would pass whether or not it was applied.
#[tokio::test]
async fn code_mode_usage_reorders_these_fixtures_on_a_keyword_query() {
    let (meta, _dirs) = glob_fixture_meta().await;

    let response = meta
        .code_mode_search_anon(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{CAP_BACKEND}:zebracorn_beta")],
        "ranking must promote the later-collected tool on a keyword query, or \
         the glob test below cannot tell ranking apart from collection order"
    );
}

/// The gateway both glob tests share: Code Mode on, usage loaded on the
/// later-collected `zebracorn_beta`, no denials.
async fn glob_fixture_meta() -> (MetaMcp, Vec<TempDir>) {
    let (cap_backend, dirs) = capability_backend_named(CAP_BACKEND, GLOB_FIXTURES).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(ranker_with_heavy_usage("zebracorn_beta")),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
    .with_profile_registry(registry_with_default("open", poisoned_profile(false)));
    meta.set_capabilities(cap_backend);
    (meta, dirs)
}

/// INVARIANT B, the documented glob exception —
/// `src/gateway/meta_mcp/search.rs:412` (`if !use_glob && let Some(ref ranker)`,
/// rationale at :411).
///
/// The criterion says both routes rank before truncation and names no glob
/// carve-out, so the exception lives only in a comment. This pins it: a glob
/// query truncates in COLLECTION order, not ranked order. The control above
/// proves the ranker is potent against this very pair — on a KEYWORD query it
/// promotes the later-collected tool — so the carve-out is what holds the glob
/// order still, not an inert fixture. It does NOT prove ranking would reorder
/// the GLOB query; see the next paragraph for why nothing could.
///
/// The SCORE is what discriminates, not the order. Ranking a glob query does
/// not reorder these fixtures: `score_text_relevance` scores the literal
/// pattern `zebracorn_*` at 0.0 for both, and the usage factor is
/// multiplicative, so `0.0 * (1 + factor)` leaves the 10^12 uses inert and the
/// collection order intact. Order alone therefore cannot tell the carve-out
/// apart — verified by removing `!use_glob &&`, which left the order assertion
/// green. `finalize_search_matches` stamps `score: 1.0` on matches that arrive
/// unscored, so a glob match scoring 1.0 proves the ranker never touched it;
/// with the carve-out removed the same match comes back at 0.0.
///
/// Fails in both directions on purpose — if a future change starts ranking glob
/// results, or stops ranking keyword ones, exactly one of this pair goes red.
#[tokio::test]
async fn code_mode_glob_results_are_not_reranked() {
    let (meta, _dirs) = glob_fixture_meta().await;

    let response = meta
        .code_mode_search(
            &json!({ "query": "zebracorn_*", "limit": 1 }),
            None,
            &crate::gateway::meta_mcp::anonymous_caller(),
        )
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{CAP_BACKEND}:zebracorn_alpha")],
        "a glob query must truncate in collection order: the ranker is skipped \
         for globs, so 10^12 uses on the later tool must not promote it"
    );
    assert_eq!(
        response["matches"][0]["score"], 1.0,
        "glob matches must carry the flat score `finalize_search_matches` stamps \
         on unscored matches; a real relevance score here means the ranker ran"
    );
}
