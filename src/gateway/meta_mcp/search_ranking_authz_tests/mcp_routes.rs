// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! INVARIANT A and the usage clause on the MCP-backend routes; the fixtures
//! and their rationale stay in the parent. Split out for the file-size ceiling.
use super::*;

/// A gateway whose only backend is a warm MCP backend (no capabilities).
async fn meta_with_mcp_backend(registry: ProfileRegistry, code_mode: bool) -> MetaMcp {
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(mcp_backend(MCP_BACKEND, MCP_TOOLS).await),
        "fixture backend failed to register"
    );
    MetaMcp::with_features(
        backends,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(code_mode)
    .with_profile_registry(registry)
}

/// CONTROL — the warm MCP backend is discoverable when the profile allows it.
///
/// Without this, a cold cache and a working guard are indistinguishable: both
/// yield an empty match list, and the two denial tests below would pass for the
/// wrong reason.
#[tokio::test]
async fn permissive_profile_sees_the_mcp_backend_tools() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "open",
            RoutingProfileConfig {
                description: "no backend or tool restrictions".to_string(),
                ..Default::default()
            },
        ),
        false,
    )
    .await;

    let response = meta
        .search_tools_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    let mut names = tool_names(&response);
    names.sort();
    assert_eq!(
        names,
        vec!["weak_match".to_string(), QUERY.to_string()],
        "both MCP backend tools must be discoverable when the profile allows them"
    );
    assert_eq!(
        response["total_available"], 2,
        "both MCP backend tools must be counted as candidates"
    );
}

/// INVARIANT A on the classic MCP-backend route —
/// `src/gateway/meta_mcp/search.rs:329` (`collect_search_backend_matches`, the
/// `profile.backend_allowed(&backend.name)` guard).
///
/// `total_available` is the pre-truncation candidate count, so zero here means
/// the tools were never collected, not collected then filtered.
#[tokio::test]
async fn denied_mcp_backend_never_enters_the_candidate_set() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "locked",
            RoutingProfileConfig {
                description: "denies the MCP backend wholesale".to_string(),
                deny_backends: Some(vec![MCP_BACKEND.to_string()]),
                ..Default::default()
            },
        ),
        false,
    )
    .await;

    let response = meta
        .search_tools_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a denied MCP backend must contribute no matches"
    );
    assert_eq!(
        response["total_available"], 0,
        "denied MCP backend tools must not be counted as candidates, so the \
         denial is not a late filter over an already-counted set"
    );
}

/// INVARIANT A on the Code Mode MCP-backend route —
/// `src/gateway/meta_mcp/search.rs:238` (`collect_code_mode_backend_matches`).
///
/// The pre-truncation candidate count is taken at `search.rs:409` and reported
/// as `total_available`, so this asserts absence from the count as well as from
/// the survivors.
#[tokio::test]
async fn code_mode_denied_mcp_backend_contributes_no_matches() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "locked",
            RoutingProfileConfig {
                description: "denies the MCP backend wholesale".to_string(),
                deny_backends: Some(vec![MCP_BACKEND.to_string()]),
                ..Default::default()
            },
        ),
        true,
    )
    .await;

    let response = meta
        .code_mode_search_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        Vec::<String>::new(),
        "a denied MCP backend must contribute no Code Mode matches"
    );
    assert_eq!(
        response["total_available"], 0,
        "denied MCP backend tools must not be counted as Code Mode candidates, \
         so the denial is not a late filter over an already-counted set"
    );
}

/// INVARIANT A, mixed authorization on the MCP-backend route — the
/// `profile.tool_allowed(&t.name)` filter that follows the backend guard
/// (`src/gateway/meta_mcp/search.rs:341`).
///
/// The backend stays ALLOWED and one tool is denied, so a denied tool competes
/// against an allowed relevant one rather than against an empty result. The
/// permissive control above proves both are otherwise discoverable.
#[tokio::test]
async fn a_forbidden_mcp_tool_loses_to_an_allowed_one() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "partial",
            RoutingProfileConfig {
                description: "allows the backend, denies one tool".to_string(),
                deny_tools: Some(vec![QUERY.to_string()]),
                ..Default::default()
            },
        ),
        false,
    )
    .await;

    let response = meta
        .search_tools_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec!["weak_match".to_string()],
        "the denied tool must be absent while its allowed sibling survives"
    );
    assert_eq!(
        response["total_available"], 1,
        "the denied tool must not be counted as a candidate"
    );
}

/// INVARIANT A, mixed authorization on the Code Mode MCP-backend route — the
/// `profile.tool_allowed(&t.name)` filter inside
/// `collect_code_mode_backend_matches` (`src/gateway/meta_mcp/search.rs:254`).
///
/// The sibling of the `search.rs:341` filter pinned above. Both collectors carry
/// their own copy, so pinning one leaves the other free to drop its filter.
///
/// `tool_allowed` is asked about the BARE name the backend served, while Code
/// Mode emits the qualified `server:tool`, so this also pins that the filter
/// reads the unqualified name.
///
/// Self-falsifying against a cold cache: the surviving sibling is asserted
/// present, so an empty collection fails the test rather than passing it. The
/// denial-only tests above need the permissive control for that; this one does
/// not.
#[tokio::test]
async fn code_mode_forbidden_mcp_tool_loses_to_an_allowed_one() {
    let meta = meta_with_mcp_backend(
        registry_with_default(
            "partial",
            RoutingProfileConfig {
                description: "allows the backend, denies one tool".to_string(),
                deny_tools: Some(vec![QUERY.to_string()]),
                ..Default::default()
            },
        ),
        true,
    )
    .await;

    let response = meta
        .code_mode_search_anon(&json!({ "query": QUERY }), None)
        .await
        .unwrap();

    assert_eq!(
        tool_names(&response),
        vec![format!("{MCP_BACKEND}:weak_match")],
        "the denied tool must be absent from Code Mode while its allowed \
         sibling survives"
    );
}
