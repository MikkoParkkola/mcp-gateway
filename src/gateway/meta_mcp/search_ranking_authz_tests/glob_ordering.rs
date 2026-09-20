// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! INVARIANT B of MIK-3274.RANKING.2 — the documented glob carve-out.
use super::*;

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
        .code_mode_search(&json!({ "query": "zebracorn_*", "limit": 1 }), None)
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
