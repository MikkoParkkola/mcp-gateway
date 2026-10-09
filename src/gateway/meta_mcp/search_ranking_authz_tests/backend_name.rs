// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `gateway_search_tools` matches a query against the serving backend's name.
use super::*;

/// The backend under test. Only `codesearch_index` carries this name itself;
/// every other tool can match it through the serving backend alone.
const BACKEND: &str = "codesearch";

async fn named_meta(caps: &[(&str, &str)], registry: ProfileRegistry) -> (MetaMcp, Vec<TempDir>) {
    let (cap_backend, dirs) = capability_backend_named(BACKEND, caps).await;
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_profile_registry(registry);
    meta.set_capabilities(cap_backend);
    (meta, dirs)
}

fn profile(deny: Option<Vec<String>>) -> ProfileRegistry {
    registry_with_default(
        "under_test",
        RoutingProfileConfig {
            description: "backend-name search".to_string(),
            deny_backends: deny,
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn a_query_naming_the_backend_finds_its_tools() {
    let (meta, _dirs) = named_meta(
        &[("lookup_snippet", "returns exact snippets")],
        profile(None),
    )
    .await;
    let response = meta
        .search_tools_anon(&json!({ "query": BACKEND }), None)
        .await
        .unwrap();
    assert_eq!(tool_names(&response), vec!["lookup_snippet".to_string()]);
}

#[tokio::test]
async fn a_denied_backend_is_not_found_by_its_name() {
    let (meta, _dirs) = named_meta(
        &[("lookup_snippet", "returns exact snippets")],
        profile(Some(vec![BACKEND.to_string()])),
    )
    .await;
    let response = meta
        .search_tools_anon(&json!({ "query": BACKEND }), None)
        .await
        .unwrap();
    assert_eq!(tool_names(&response), Vec::<String>::new());
    assert_eq!(response["total_available"], 0);
}

#[tokio::test]
async fn a_direct_tool_match_ranks_above_a_backend_name_match() {
    // The backend-only match is collected first, so only ranking can put the
    // direct match ahead of it under `limit: 1`.
    let (meta, _dirs) = named_meta(
        &[
            ("lookup_snippet", "returns exact snippets"),
            ("codesearch_index", "rebuilds the index"),
        ],
        profile(None),
    )
    .await;
    let response = meta
        .search_tools_anon(&json!({ "query": BACKEND, "limit": 1 }), None)
        .await
        .unwrap();
    assert_eq!(tool_names(&response), vec!["codesearch_index".to_string()]);
    assert_eq!(response["total_available"], 2);
}

/// The reported case: an MCP backend whose tools never mention its name.
#[tokio::test]
async fn a_query_naming_an_mcp_backend_finds_its_tools() {
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(mcp_backend(BACKEND, &[("search_code", "returns exact snippets")]).await),
        "fixture backend failed to register"
    );
    let meta = MetaMcp::with_features(
        backends,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(false)
    .with_profile_registry(profile(None));
    let response = meta
        .search_tools_anon(&json!({ "query": BACKEND }), None)
        .await
        .unwrap();
    assert_eq!(tool_names(&response), vec!["search_code".to_string()]);
}

/// With the ranker on, a tool found only by its backend's name must not score
/// zero: under `limit: 1` it has to beat a tool elsewhere whose description
/// merely mentions the query, which is collected first.
#[tokio::test]
async fn a_backend_name_match_ranks_above_a_description_mention() {
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(mcp_backend(BACKEND, &[("search_code", "returns exact snippets")]).await),
        "fixture backend failed to register"
    );
    let (docs, _dirs) =
        capability_backend_named("docs", &[("guide_page", "explains how codesearch indexes")])
            .await;
    let meta = MetaMcp::with_features(
        backends,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(false)
    .with_profile_registry(profile(None));
    meta.set_capabilities(docs);
    let response = meta
        .search_tools_anon(&json!({ "query": BACKEND, "limit": 1 }), None)
        .await
        .unwrap();
    assert_eq!(tool_names(&response), vec!["search_code".to_string()]);
    assert_eq!(response["total_available"], 2);
}
