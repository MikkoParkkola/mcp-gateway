// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Routing profiles: listing, session binding and the sessionless path.

use super::*;

// ── Toolshed: list_profiles ───────────────────────────────────────────

#[test]
fn list_profiles_returns_all_profiles_sorted_alphabetically() {
    // GIVEN: a MetaMcp with two configured profiles
    let mm = make_meta_mcp_with_profiles();
    // WHEN: calling list_profiles
    let result = mm.list_profiles().unwrap();
    // THEN: profiles array contains both, sorted alphabetically
    let profiles = result["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    assert_eq!(profiles[0]["name"], "coding");
    assert_eq!(profiles[1]["name"], "research");
}

#[test]
fn list_profiles_includes_description_for_each_profile() {
    // GIVEN: a MetaMcp with profiles that have descriptions
    let mm = make_meta_mcp_with_profiles();
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: each profile has a non-empty description
    let profiles = result["profiles"].as_array().unwrap();
    for profile in profiles {
        assert!(
            profile["description"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "Profile '{}' missing description",
            profile["name"]
        );
    }
}

#[test]
fn list_profiles_reports_correct_default() {
    // GIVEN: registry with default = "research"
    let mm = make_meta_mcp_with_profiles();
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: default field matches
    assert_eq!(result["default"], "research");
}

#[test]
fn list_profiles_reports_correct_total() {
    // GIVEN: two configured profiles
    let mm = make_meta_mcp_with_profiles();
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: total = 2
    assert_eq!(result["total"], 2);
}

#[test]
fn list_profiles_empty_when_no_profiles_configured() {
    // GIVEN: a MetaMcp with default (empty) registry
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new()));
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: profiles array is empty, total = 0
    let profiles = result["profiles"].as_array().unwrap();
    assert!(profiles.is_empty());
    assert_eq!(result["total"], 0);
}

// ── Toolshed: handle_initialize profile binding ───────────────────────

#[test]
fn initialize_with_profile_in_params_binds_session() {
    // GIVEN: MetaMcp with profiles + a session ID + profile in params
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(1);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "coding"});
    // WHEN: initializing with session_id and profile param
    mm.handle_initialize(
        id,
        Some(&params),
        Some("session-42"),
        None,
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    // THEN: session is bound to "coding"
    let active = mm
        .session_profiles
        .get_profile_name("session-42", "research");
    assert_eq!(active, "coding");
}

#[test]
fn initialize_with_header_profile_takes_precedence_over_params() {
    // GIVEN: both header and params specify a profile
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(2);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "research"});
    // WHEN: header says "coding", params say "research"
    mm.handle_initialize(
        id,
        Some(&params),
        Some("session-99"),
        Some("coding"),
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    // THEN: header wins — session bound to "coding"
    let active = mm
        .session_profiles
        .get_profile_name("session-99", "research");
    assert_eq!(active, "coding");
}

#[test]
fn initialize_with_unknown_profile_does_not_bind_session() {
    // GIVEN: params specify a profile that doesn't exist
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(3);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "nonexistent"});
    // WHEN: initializing with unknown profile
    mm.handle_initialize(
        id,
        Some(&params),
        Some("session-77"),
        None,
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    // THEN: session is NOT bound (default remains "research")
    let active = mm
        .session_profiles
        .get_profile_name("session-77", "research");
    assert_eq!(active, "research");
}

#[test]
fn initialize_without_profile_does_not_change_session() {
    // GIVEN: no profile in params or header
    let mm = make_meta_mcp_with_profiles();
    // Pre-set session to "coding"
    mm.session_profiles.set_profile("session-5", "coding");
    let id = RequestId::Number(4);
    let params = json!({"protocolVersion": "2024-11-05"});
    // WHEN: initializing without profile hint
    mm.handle_initialize(
        id,
        Some(&params),
        Some("session-5"),
        None,
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    // THEN: existing binding is preserved
    let active = mm
        .session_profiles
        .get_profile_name("session-5", "research");
    assert_eq!(active, "coding");
}

#[test]
fn initialize_without_session_id_succeeds_without_panic() {
    // GIVEN: no session_id (stateless call)
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(5);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "coding"});
    // WHEN / THEN: no panic; profile is simply not bound
    let resp = mm.handle_initialize(
        id,
        Some(&params),
        None,
        None,
        crate::protocol::meta::Era::Legacy,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    // Response should be a success (not an error)
    let v = serde_json::to_value(resp).unwrap();
    assert!(v.get("error").is_none(), "Expected success response");
}

// ── Toolshed: gateway_list_profiles appears in tools/list ─────────────

#[test]
fn gateway_list_profiles_tool_appears_in_tools_list() {
    let mut configs = std::collections::HashMap::new();
    configs.insert(
        "probe".to_string(),
        crate::routing_profile::RoutingProfileConfig::default(),
    );
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_profile_registry(
        crate::routing_profile::ProfileRegistry::from_config(&configs, "probe"),
    );
    // WHEN: listing tools
    let id = RequestId::Number(0);
    let resp = mm.handle_tools_list(id);
    let v = serde_json::to_value(resp).unwrap();
    // THEN: gateway_list_profiles is in the tool names
    let tools = v["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        names.contains(&"gateway_list_profiles"),
        "Expected gateway_list_profiles in tools list, got: {names:?}"
    );
}

#[tokio::test]
async fn gateway_reload_config_surfaces_restart_required_fields() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");

    let old_config = Config::default();
    let mut new_config = old_config.clone();
    new_config.server.port += 1;
    crate::gateway::test_helpers::write_owner_only(
        &config_path,
        serde_yaml::to_string(&new_config).unwrap(),
    )
    .unwrap();

    let registry = Arc::new(BackendRegistry::new());
    let live_config = Arc::new(LiveConfig::new(old_config.clone()));
    let reload_ctx = Arc::new(
        ReloadContext::new(
            config_path,
            Arc::clone(&live_config),
            Arc::clone(&registry),
            old_config.failsafe.clone(),
            old_config.meta_mcp.cache_ttl,
        )
        .expect("the registry pairs with the config"),
    );

    let mm = MetaMcp::new(Arc::clone(&registry));
    mm.set_reload_context(reload_ctx);

    let resp = Box::pin(mm.handle_tools_call(
        RequestId::Number(7),
        "gateway_reload_config",
        json!({}),
        None,
        // Admin, because reloading config is admin-gated at the dispatcher.
        // The default context is non-admin, and this test is about what the
        // reload REPORTS, not about the gate — an operator running it holds
        // a credential.
        MetaMcpCallerContext {
            is_admin: true,
            input_capabilities: crate::protocol::meta::Declared::NONE,
            retry: &crate::protocol::mrtr::NO_RETRY,
            ..allow_all_ctx()
        },
    ))
    .await;

    assert!(
        resp.error.is_none(),
        "unexpected reload error: {:?}",
        resp.error
    );
    let result = resp.result.unwrap();
    let text = result["content"][0]["text"]
        .as_str()
        .expect("tool result text");
    let payload: serde_json::Value = serde_json::from_str(text).unwrap();

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["restart_required"], true);
    assert_eq!(payload["restart_reason"], "server_address_changed");
    assert!(
        payload["changes"]
            .as_str()
            .is_some_and(|changes| changes.contains("restart required")),
        "expected restart-required summary, got: {payload}"
    );
}

// ── ORDER.2: routing profiles do not exist on the modern path ─────────
//
// MCP 2026-07-28 removed protocol-level sessions, so the router hands
// `meta_mcp` an empty session id for every modern request
// (`router::handlers`, the `declares_modern_by_header` branch). An empty id
// is already read as "this caller has no session" elsewhere in the router —
// `router::helpers::attach_session_header` omits the header rather than
// emitting an empty one, and `handlers` reads it the same way when deciding
// control identity. These tests extend that one reading to the routing
// profile, which is the last piece of per-connection state a modern caller
// could still reach.
//
// Why it must be closed rather than left alone: the empty key is shared by
// *every* modern connection, so a profile written under it is not merely
// per-session, it leaks across connections. `RELEASE-4.0.0-requirements.md`
// ORDER.2 forbids the tool set varying per connection or as a side effect of
// other requests on it.

/// A profile bound to the sessionless key is not read back.
///
/// The write is staged directly rather than through `gateway_set_profile`,
/// because the read must be closed on its own: `active_profile` is the single
/// site `surfaced`, `invoke` and `spec_preview` all route through.
#[test]
fn active_profile_ignores_a_profile_bound_to_the_sessionless_key() {
    // GIVEN: a narrow profile written under the empty session id
    let mm = make_meta_mcp_with_profiles();
    mm.session_profiles().set_profile("", "coding");

    // WHEN: the modern path resolves its profile
    let profile = mm.active_profile(Some(""));

    // THEN: it is the default, not the one that was written
    assert_eq!(
        profile.name, "research",
        "an empty session id means no session, so there is no session profile \
         to read; reading one lets any modern caller narrow every other \
         modern caller's tool set"
    );
}

/// `gateway_set_profile` is refused, not silently applied under the shared key.
#[test]
fn ac_order_2_set_profile_is_refused_without_a_session() {
    // GIVEN: a sessionless (modern) caller
    let mm = make_meta_mcp_with_profiles();
    let args = json!({ "profile": "coding" });

    // WHEN: it tries to switch profile
    let result = mm.set_profile(&args, Some(""), true);

    // THEN: the call is refused and nothing is written
    assert!(
        result.is_err(),
        "a refusal is the assertion: a tool set that did not change because \
         the write went to a shared key is not the same outcome as one that \
         did not change because the tool is gone"
    );
    assert_eq!(
        mm.session_profiles().get_profile_name("", "research"),
        "research",
        "the refused call must not have written anything"
    );
}

/// `gateway_get_profile` is refused too, rather than answering with the default.
///
/// Answering would describe a selection the caller cannot make and cannot
/// rely on — the design note removes both halves of the pair, not just the
/// writer.
#[test]
fn ac_order_2_get_profile_is_refused_without_a_session() {
    // GIVEN: a sessionless (modern) caller
    let mm = make_meta_mcp_with_profiles();

    // WHEN: it asks which profile is active
    let result = mm.get_profile(Some(""), true);

    // THEN: the call is refused
    assert!(
        result.is_err(),
        "there is no per-connection profile to report on the modern path"
    );
}

/// `initialize` is the second writer, and it is closed on the same terms.
///
/// Both of its inputs are exercised: the `X-MCP-Profile` header and the
/// `params.profile` body field. Closing only the meta-tool would leave the
/// handshake able to pin a profile under the shared key.
#[test]
fn ac_order_2_initialize_binds_no_profile_without_a_session() {
    for (label, params, header) in [
        ("header", None, Some("coding")),
        ("body", Some(json!({ "profile": "coding" })), None),
    ] {
        // GIVEN: a sessionless (modern) initialize naming a profile
        let mm = make_meta_mcp_with_profiles();

        // WHEN: the handshake runs
        let _ = mm.handle_initialize(
            RequestId::Number(1),
            params.as_ref(),
            Some(""),
            header,
            crate::protocol::meta::Era::Modern,
            crate::gateway::meta_mcp::InvokeScope::allow_all(
                crate::gateway::router::CallerStanding::Admin,
            ),
        );

        // THEN: no profile was bound to the shared key
        assert_eq!(
            mm.session_profiles().get_profile_name("", "research"),
            "research",
            "initialize ({label}) must not bind a profile a modern caller has \
             no session to hold"
        );
    }
}
