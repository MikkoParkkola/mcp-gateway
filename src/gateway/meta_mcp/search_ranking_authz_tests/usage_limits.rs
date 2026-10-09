// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Code Mode twin of the usage potency control. Split out for the
//! file-size ceiling. The zero-relevance limit is pinned in the ranker's own
//! tests (`ranking::tests::backend_name`): a backend-name match now scores, so
//! no search route admits a zero-relevance candidate any more.
use super::*;

/// USAGE CLAUSE, boost potency on the Code Mode route — the twin of
/// `heavy_usage_outranks_the_exact_match_when_nothing_is_denied`.
///
/// That control runs the CLASSIC route, which serialises through
/// `json_to_search_result`; Code Mode uses `json_to_code_mode_search_result`.
/// If the Code Mode conversion ever dropped the server/tool keying the ranker
/// looks usage up by, the boost would silently zero, `zebracorn_tool` would win
/// on its bare 5.0 (design §3.4 retired the exact-name premise this control was
/// founded on — see `POTENCY_FIXTURES`), and
/// `code_mode_forbidden_heavily_used_tool_loses_to_an_allowed_one` would pass
/// without `tool_allowed` doing anything. This pins the premise that test needs.
///
/// On `POTENCY_FIXTURES` for the reason given there: the heavily-used tool is
/// collected SECOND, so skipping the ranker outright also fails this test.
#[tokio::test]
async fn code_mode_heavy_usage_outranks_the_exact_match_when_nothing_is_denied() {
    let (cap_backend, _dirs) = capability_backend(POTENCY_FIXTURES).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(ranker_with_heavy_usage("weak_match")),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
    .with_profile_registry(registry_with_default("open", poisoned_profile(false)));
    meta.set_capabilities(cap_backend);

    let response = meta
        .code_mode_search_anon(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{CAP_BACKEND}:weak_match")],
        "the Code Mode control has stopped controlling: usage feedback no longer \
         promotes a weaker match on this route, so the Code Mode denial test \
         proves nothing"
    );
}
