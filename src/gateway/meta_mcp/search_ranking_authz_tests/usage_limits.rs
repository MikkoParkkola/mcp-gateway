// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The usage clause's limits: a zero-relevance candidate stays at zero, and the
//! Code Mode twin of the potency control. Split out for the file-size ceiling.
use super::*;

/// USAGE CLAUSE, the form of the boost — `src/ranking/mod.rs:371`.
///
/// The three potency tests in the parent would all stay green if the usage
/// factor became additive rather than multiplicative, because every tool they
/// score has non-zero relevance. This one does not: `sprocket_sorter` is
/// admitted by the Code Mode backend-name match while scoring 0.0 relevance, so
/// `0.0 * (1 + factor)` keeps it at zero and `weak_match` survives `limit` 1.
/// Under `relevance + factor` the zero-relevance tool would score about 6.0
/// against `weak_match`'s 2.0 and take the slot. This is the test that pins
/// "usage feedback cannot promote an irrelevant tool" to the construct that
/// makes it true.
#[tokio::test]
async fn a_zero_relevance_candidate_cannot_be_lifted_by_usage() {
    let (cap_backend, _dirs) =
        capability_backend_named(QUERY_NAMED_BACKEND, ZERO_RELEVANCE_FIXTURES).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(ranker_with_heavy_usage_on(
            QUERY_NAMED_BACKEND,
            "sprocket_sorter",
        )),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
    .with_profile_registry(registry_with_default(
        "open",
        RoutingProfileConfig {
            description: "no backend or tool restrictions".to_string(),
            ..Default::default()
        },
    ));
    meta.set_capabilities(cap_backend);

    let all = meta
        .code_mode_search_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();
    // Guards the assertion below: if the backend-name match stopped admitting
    // the zero-relevance tool, the test would pass by absence rather than by
    // the multiplicative form holding it at zero.
    assert!(
        tool_names(&all)
            .iter()
            .any(|n| n == &format!("{QUERY_NAMED_BACKEND}:sprocket_sorter")),
        "fixture premise broken: the zero-relevance tool is no longer admitted, \
         so this test cannot observe what it claims: got {:?}",
        tool_names(&all)
    );

    let response = meta
        .code_mode_search_anon(&json!({ "query": QUERY, "limit": 1 }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{QUERY_NAMED_BACKEND}:weak_match")],
        "a zero-relevance candidate must stay at zero however heavily used: the \
         usage factor is multiplicative, not additive"
    );
}

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
