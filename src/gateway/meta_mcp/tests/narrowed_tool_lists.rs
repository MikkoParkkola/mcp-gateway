// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Profile-narrowed tool lists shared across modern connections.

use super::*;

// ============================================================================
// MIK-7272.ORDER.2 — Cluster B connection invariance (B-01, B-02, B-06)
// ============================================================================

/// The profile connection A asks for.
///
/// Registered by the fixture below. `handle_initialize` skips a profile name
/// the registry does not contain (`mod.rs`, `profile_registry.contains`), so
/// an unregistered name would leave A and B identical for a reason that has
/// nothing to do with the invariant, and B-01 would pass with the defect
/// present.
const NARROW_PROFILE: &str = "narrow";

/// The substring both staged capability names carry.
///
/// B-06 needs a query that is non-empty — `handle_tools_list_filtered`
/// delegates an empty query to the unfiltered handler and never reaches the
/// filtered assembly — and that still matches every tool the pinned literal
/// names, so the pin stays satisfiable rather than being narrowed by the
/// query itself.
#[cfg(feature = "spec-preview")]
const MATCH_ALL_QUERY: &str = "invariance";

/// A gateway whose visible tool set genuinely moves with the routing profile.
///
/// Two capability tools, both statically surfaced so they appear in
/// `tools/list`, and a `narrow` profile that denies exactly one of them. The
/// default profile denies nothing: without a profile that decides, `narrow`
/// and the default would produce the same list and every case below would
/// pass whether or not a profile leaks across connections.
async fn meta_with_narrowable_tools() -> MetaMcp {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    for (name, path) in [
        ("invariance_always", "always"),
        ("invariance_denied", "denied"),
    ] {
        crate::gateway::test_helpers::write_owner_only(
            dir.path().join(format!("{name}.yaml")),
            format!(
                r"
name: {name}
description: connection invariance fixture
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /{path}
"
            ),
        )
        .unwrap();
    }

    let cap_backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    cap_backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();

    let mut configs = std::collections::HashMap::new();
    configs.insert(
        "open".to_string(),
        RoutingProfileConfig {
            description: "denies nothing".to_string(),
            ..Default::default()
        },
    );
    configs.insert(
        NARROW_PROFILE.to_string(),
        RoutingProfileConfig {
            description: "denies one staged tool".to_string(),
            deny_tools: Some(vec!["invariance_denied".to_string()]),
            ..Default::default()
        },
    );
    let registry = ProfileRegistry::from_config(&configs, "open");

    let surfaced = ["invariance_always", "invariance_denied"]
        .into_iter()
        .map(|tool| SurfacedToolConfig {
            server: "caps".to_string(),
            tool: tool.to_string(),
        })
        .collect();

    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_profile_registry(registry)
        .with_surfaced_tools(surfaced);
    meta.set_capabilities(cap_backend);
    meta
}

/// The tool names in a `tools/list` response, sorted.
fn tools_list_set(resp: &JsonRpcResponse) -> Vec<String> {
    discovery_names(resp.result.as_ref().expect("tools/list must succeed"))
}

/// The tool-name set a modern connection is shown, pinned.
///
/// Pinned as a literal rather than compared between the two connections: two
/// observed lists move in step under a regression that changes every
/// connection identically, and `set_a == set_b` also holds when both are
/// empty and when both are identically wrong.
const B01_EXPECTED_TOOLS: &[&str] = &[
    "gateway_get_profile",
    "gateway_invoke",
    "gateway_kill_server",
    "gateway_list_disabled_capabilities",
    "gateway_list_profiles",
    "gateway_list_servers",
    "gateway_list_tools",
    "gateway_reload_capabilities",
    "gateway_revive_server",
    "gateway_search_tools",
    "gateway_set_profile",
    "gateway_set_state",
    "invariance_always",
    "invariance_denied",
];

/// B-01 — two modern-era connections to one gateway are shown one tool set.
///
/// A `initialize`s asking for `narrow`; B `initialize`s asking for nothing.
/// Both are modern, so both spell sessionlessness as the empty id and share
/// the same key: a profile bound for A would decide B's list too.
///
/// The legacy-era control run is a premise, not decoration. Without it the
/// case passes whenever `narrow` happens to deny nothing, which is the shape
/// of a fixture staging a profile that never decides.
///
/// Drives `handle_initialize` directly rather than an HTTP request: the
/// header parse one layer above is already covered by
/// `initialize_with_header_profile_takes_precedence_over_params`, and what
/// this case is about is the binding decision, not the parse.
#[tokio::test]
#[allow(clippy::similar_names)]
async fn b01_a_two_modern_connections_are_shown_the_same_tool_set() {
    let meta = meta_with_narrowable_tools().await;

    // Premise: on legacy-era connections the profile really does narrow, and
    // narrows strictly — A's set is a proper subset of B's.
    let legacy_a = Some("legacy-a");
    let legacy_b = Some("legacy-b");
    meta.handle_initialize(
        RequestId::Number(1),
        None,
        legacy_a,
        Some(NARROW_PROFILE),
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    meta.handle_initialize(
        RequestId::Number(2),
        None,
        legacy_b,
        None,
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    let legacy_a_tools = tools_list_set(&meta.handle_tools_list_for_session(
        RequestId::Number(3),
        legacy_a,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    let legacy_b_tools = tools_list_set(&meta.handle_tools_list_for_session(
        RequestId::Number(4),
        legacy_b,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        legacy_a_tools.len() < legacy_b_tools.len()
            && legacy_a_tools.iter().all(|t| legacy_b_tools.contains(t)),
        "premise: '{NARROW_PROFILE}' must strictly narrow a legacy connection, or this \
         case passes for a profile that decides nothing: {legacy_a_tools:?} vs {legacy_b_tools:?}"
    );

    meta.handle_initialize(
        RequestId::Number(5),
        None,
        MODERN_SESSIONLESS,
        Some(NARROW_PROFILE),
        crate::protocol::meta::Era::Modern,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    meta.handle_initialize(
        RequestId::Number(6),
        None,
        MODERN_SESSIONLESS,
        None,
        crate::protocol::meta::Era::Modern,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );

    let a = tools_list_set(&meta.handle_tools_list_for_session(
        RequestId::Number(7),
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    let b = tools_list_set(&meta.handle_tools_list_for_session(
        RequestId::Number(8),
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));

    assert_eq!(
        a, B01_EXPECTED_TOOLS,
        "the connection that asked for '{NARROW_PROFILE}' is shown a per-connection tool set"
    );
    assert_eq!(
        b, B01_EXPECTED_TOOLS,
        "the connection that asked for nothing is shown a per-connection tool set"
    );
}

/// B-02 — a `gateway_set_profile` on a modern connection does not change what
/// that connection is shown.
///
/// The outcome of the meta-tool is pinned, not merely its lack of effect: "the
/// profile did not change the list" is satisfied both by a correct fix and by
/// a meta-tool that silently errored for an unrelated reason. Option (a) is
/// implemented, so the accepted outcome is an explicit refusal naming the
/// missing session — `narrow` is registered here precisely so an
/// unregistered-profile error cannot masquerade as that refusal.
#[tokio::test]
async fn b02_a_set_profile_does_not_change_the_connections_tool_list() {
    let meta = meta_with_narrowable_tools().await;

    let before = tools_list_set(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));

    let set = Box::pin(meta.handle_tools_call(
        RequestId::Number(2),
        "gateway_set_profile",
        json!({"profile": NARROW_PROFILE}),
        MODERN_SESSIONLESS,
        allow_all_ctx(),
    ))
    .await;

    let refusal = set
        .error
        .expect("a sessionless modern connection has no session to hold a profile");
    assert!(
        refusal.message.contains("Routing profiles are per-session"),
        "the refusal must be the no-session one; an unregistered-profile error would satisfy \
         `is_err` while proving nothing: {}",
        refusal.message
    );

    let after = tools_list_set(&meta.handle_tools_list_for_session(
        RequestId::Number(3),
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));

    assert_eq!(
        before, B01_EXPECTED_TOOLS,
        "the list before the meta-tool call is not the pinned set"
    );
    assert_eq!(
        after, B01_EXPECTED_TOOLS,
        "gateway_set_profile changed what this connection is shown"
    );
}

/// The filtered set a modern connection is shown for `MATCH_ALL_QUERY`.
#[cfg(feature = "spec-preview")]
const B06_EXPECTED_TOOLS: &[&str] = &["invariance_always", "invariance_denied"];

/// B-06 — B-01 repeated on the `spec-preview` filtered path.
///
/// `handle_tools_list_filtered` reads the profile at its own line and then
/// filters through `collect_filtered_backend_tools`, a different assembly
/// from the surfaced-tool resolution B-01 exercises. A fix applied to
/// `surfaced.rs`/`mod.rs` alone is what this case exists to catch.
///
/// B-02 is deliberately not repeated here: folding two rules into one case
/// breaks two things at once, and an unpinned query is free to narrow the
/// list legally, which would make the pinned literal unsatisfiable rather
/// than strict.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn b06_a_two_modern_connections_get_the_same_filtered_tool_list() {
    let meta = meta_with_narrowable_tools().await;

    let legacy_a = Some("legacy-a");
    let legacy_b = Some("legacy-b");
    meta.handle_initialize(
        RequestId::Number(1),
        None,
        legacy_a,
        Some(NARROW_PROFILE),
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    meta.handle_initialize(
        RequestId::Number(2),
        None,
        legacy_b,
        None,
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    let legacy_a_tools = tools_list_set(&meta.handle_tools_list_filtered(
        RequestId::Number(3),
        MATCH_ALL_QUERY,
        legacy_a,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    let unnarrowed_tools = tools_list_set(&meta.handle_tools_list_filtered(
        RequestId::Number(4),
        MATCH_ALL_QUERY,
        legacy_b,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        legacy_a_tools.len() < unnarrowed_tools.len()
            && legacy_a_tools.iter().all(|t| unnarrowed_tools.contains(t)),
        "premise: '{NARROW_PROFILE}' must strictly narrow the filtered list too, or this \
         case passes for a query that decides everything: {legacy_a_tools:?} vs {unnarrowed_tools:?}"
    );

    meta.handle_initialize(
        RequestId::Number(5),
        None,
        MODERN_SESSIONLESS,
        Some(NARROW_PROFILE),
        crate::protocol::meta::Era::Modern,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    meta.handle_initialize(
        RequestId::Number(6),
        None,
        MODERN_SESSIONLESS,
        None,
        crate::protocol::meta::Era::Modern,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );

    let a = tools_list_set(&meta.handle_tools_list_filtered(
        RequestId::Number(7),
        MATCH_ALL_QUERY,
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    let b = tools_list_set(&meta.handle_tools_list_filtered(
        RequestId::Number(8),
        MATCH_ALL_QUERY,
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));

    assert_eq!(
        a, B06_EXPECTED_TOOLS,
        "the connection that asked for '{NARROW_PROFILE}' gets a per-connection filtered list"
    );
    assert_eq!(
        b, B06_EXPECTED_TOOLS,
        "the connection that asked for nothing gets a per-connection filtered list"
    );
}
