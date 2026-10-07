// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Playbook steps face the invoking caller's real scope.

use super::*;
use pretty_assertions::assert_eq;

// ===========================================================================
// MIK-7252 — a playbook step faces the invoking caller's real scope.
//
// The meta-layer cases in `meta_mcp::authz_tests` prove the chokepoint is
// reached, using a test authorizer. These prove the thing that actually
// matters: the REAL policy — `RouterAuthorizer` over an `AuthenticatedClient`
// — refuses a playbook step, which no test double can demonstrate.
// ===========================================================================

/// As [`run_step_as`], but carrying a certificate or agent identity.
///
/// Separate rather than a fourth parameter on `run_step_as`, so the many cases
/// that have no such identity are not obliged to say `None, None` and mean it.
async fn run_step_with_identity(
    state: &Arc<AppState>,
    client: &AuthenticatedClient,
    cert_identity: Option<&crate::mtls::CertIdentity>,
    oauth_agent_identity: Option<&crate::gateway::oauth::AgentIdentity>,
    server: &str,
    tool: &str,
) -> JsonRpcResponse {
    let yaml = format!(
        "name: scoped\ndescription: one step\non_error: abort\nsteps:\n  - name: step\n    server: {server}\n    tool: {tool}\n"
    );
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(&yaml).expect("playbook fixture must parse");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    state.meta_mcp.set_playbook_engine(engine);

    let authorizer = super::authorization::RouterAuthorizer {
        state: state.as_ref(),
        client: Some(client),
        oauth_agent_identity,
        cert_identity,
        principal: super::authorization::refusal_principal(
            Some(client),
            oauth_agent_identity,
            cert_identity,
        ),
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &authorizer,
        api_key_name: Some(client.name.as_str()),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        is_admin: client.admin,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    Box::pin(state.meta_mcp.handle_tools_call(
        RequestId::Number(1),
        "gateway_run_playbook",
        serde_json::json!({ "name": "scoped", "arguments": {} }),
        None,
        caller,
    ))
    .await
}

/// Run a one-step playbook through the production path, with the real router
/// authorizer built exactly as `handlers.rs` builds it.
///
/// Most cases carry no certificate or agent identity, so [`run_step_as`] wraps
/// this and passes `None` for both rather than making every call site say so.
async fn run_step_as(
    state: &Arc<AppState>,
    client: &AuthenticatedClient,
    server: &str,
    tool: &str,
) -> JsonRpcResponse {
    Box::pin(run_step_with_identity(
        state, client, None, None, server, tool,
    ))
    .await
}

/// The text a dispatch came back with, whether it succeeded or failed.
///
/// A refusal surfaces as a JSON-RPC error; a network failure surfaces inside a
/// successful envelope. Both are strings to assert against — every case below
/// asserts what the response WAS, not merely that it failed.
fn response_text(response: &JsonRpcResponse) -> String {
    response.error.as_ref().map_or_else(
        || {
            response
                .result
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        },
        |e| e.message.clone(),
    )
}

#[tokio::test]
async fn authz_1_playbook_step_outside_client_backend_scope_is_refused() {
    let (state, _store) =
        test_router_app_state_with_backend(http_backend_at("beta", "http://127.0.0.1:1/")).await;
    let client = scoped_client("scoped", vec!["alpha".to_string()], None);

    let response = Box::pin(run_step_as(&state, &client, "beta", "read")).await;

    let msg = response_text(&response);
    assert!(
        response.error.is_some(),
        "a step outside the client's backend scope must be refused: {msg}"
    );
    // A3: a refused step's reason is neutral, since it would otherwise name
    // an operator-defined target the caller may not reach.
    assert!(
        msg.contains("step not permitted for this caller") && !msg.contains("beta"),
        "the refusal must be recorded without naming the target: {msg}"
    );
}

#[tokio::test]
async fn authz_1a_playbook_step_inside_client_backend_scope_is_not_refused() {
    let (state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    let client = scoped_client("scoped", vec!["alpha".to_string()], None);

    let response = Box::pin(run_step_as(&state, &client, "alpha", "read")).await;

    // The backend is unreachable, so this fails at the network — deliberately.
    // What must NOT appear is an authorization refusal: the point is that the
    // scope check passed and the call proceeded to dispatch.
    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "a permitted backend must reach dispatch rather than be refused: {}",
        response_text(&response)
    );
}

#[tokio::test]
async fn authz_2_playbook_step_outside_client_tool_scope_is_refused() {
    let (state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    let client = scoped_client(
        "scoped",
        vec!["alpha".to_string()],
        Some(vec!["safe_*".to_string()]),
    );

    let response = Box::pin(run_step_as(&state, &client, "alpha", "danger_tool")).await;

    let msg = response_text(&response);
    assert!(
        response.error.is_some(),
        "a step outside the client's tool allowlist must be refused: {msg}"
    );
    assert!(
        msg.contains("step not permitted for this caller") && !msg.contains("danger_tool"),
        "the refusal must be recorded without naming the tool (A3): {msg}"
    );
}

#[tokio::test]
async fn authz_2a_playbook_step_inside_client_tool_scope_is_not_refused() {
    let (state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    let client = scoped_client(
        "scoped",
        vec!["alpha".to_string()],
        Some(vec!["safe_*".to_string()]),
    );

    let response = Box::pin(run_step_as(&state, &client, "alpha", "safe_read")).await;

    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "a permitted tool must reach dispatch rather than be refused: {}",
        response_text(&response)
    );
}

/// A refusal only the chokepoint can see maps to 403.
///
/// The router gate answers 403 for the shapes it inspects. A playbook step is
/// not one of them — its targets never appear in the request — so before the
/// status travelled on the refusal, a denied playbook came back HTTP 200 with
/// the refusal buried in the body, telling every caller and intermediary that
/// the call had succeeded.
///
/// NOT end to end, and the name no longer claims it is. This drives the meta
/// dispatch and asserts the mapping `refusal_status` performs; it does not
/// drive the axum handler, so it would stay green if the handler stopped
/// calling that mapping. The handler's use of it is one line
/// (`let status = refusal_status(&response).unwrap_or(StatusCode::OK)`), and
/// its control is code review, which is stated here rather than implied by a
/// test name.
#[tokio::test]
async fn authz_playbook_denial_maps_to_forbidden() {
    let (state, _store) =
        test_router_app_state_with_backend(http_backend_at("beta", "http://127.0.0.1:1/")).await;
    let client = scoped_client("scoped", vec!["alpha".to_string()], None);

    let response = Box::pin(run_step_as(&state, &client, "beta", "read")).await;
    assert!(
        response.error.is_some(),
        "the step must be refused: {}",
        response_text(&response)
    );
    // Asserted through the mapping the handler applies, which reads the status
    // the dispatch layer stamped onto the error. Handing a status to
    // `build_response` instead would prove only that it uses its argument.
    assert_eq!(
        super::handlers::refusal_status(&response),
        Some(StatusCode::FORBIDDEN),
        "a refused dispatch must not answer 200"
    );

    let http = super::helpers::build_response(response, "sess-authz", StatusCode::FORBIDDEN);
    assert_eq!(http.status(), StatusCode::FORBIDDEN);
}

/// The mapping must not reclassify an error that is not a refusal.
///
/// Choosing the control took two attempts, and both failures are worth
/// recording. An unreachable backend does not work: dispatch returns a
/// SUCCESSFUL envelope carrying `isError`, so no JSON-RPC error exists and the
/// row could not fail whatever the mapping did. An invalid tool name does not
/// work either, for a more interesting reason — `authorize_tool_target`
/// validates the name first and returns a refusal, so a malformed name IS a
/// refusal in this codebase's model and the router gate has always answered it
/// 403. That is pre-existing behaviour and out of scope here; it is recorded
/// because it looks like a bug in the mapping and is not.
///
/// An unknown playbook name is the control: a genuine JSON-RPC error, raised
/// before any authorizer sees anything, so this row fails if the stamp were
/// ever applied to every error rather than to refusals alone.
#[tokio::test]
async fn authz_ordinary_error_is_not_reclassified_as_forbidden() {
    let (state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    let client = scoped_client("scoped", vec!["*".into()], None);

    let authorizer = super::authorization::RouterAuthorizer {
        state: state.as_ref(),
        client: Some(&client),
        oauth_agent_identity: None,
        cert_identity: None,
        principal: super::authorization::refusal_principal(Some(&client), None, None),
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &authorizer,
        api_key_name: Some(client.name.as_str()),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    let response = Box::pin(state.meta_mcp.handle_tools_call(
        RequestId::Number(1),
        "gateway_run_playbook",
        serde_json::json!({ "name": "no_such_playbook", "arguments": {} }),
        None,
        caller,
    ))
    .await;

    assert!(
        response.error.is_some(),
        "the control must actually produce a JSON-RPC error, or it cannot \
         fail: {}",
        response_text(&response)
    );
    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "only an authorization refusal may be mapped to 403: {}",
        response_text(&response)
    );
}

/// Four refusal branches carry the stamp: backend scope, tool scope, global
/// policy and invalid tool name.
///
/// The claim "a refusal answers 403" is only as good as the narrowest branch
/// that carries it, and each of these is minted in a different place. The
/// certificate and agent-scope branches are pinned by `authz_10` and
/// `authz_11`, which assert `refusal_status` directly; the SSRF branch has no
/// case, and the name says four rather than "every" so that gap is visible.
#[tokio::test]
async fn authz_four_refusal_branches_carry_the_status() {
    let (scoped_state, _scoped_store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;

    let tool_scoped = scoped_client(
        "scoped",
        vec!["alpha".to_string()],
        Some(vec!["safe_*".to_string()]),
    );
    let tool_refusal = Box::pin(run_step_as(
        &scoped_state,
        &tool_scoped,
        "alpha",
        "danger_tool",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&tool_refusal),
        Some(StatusCode::FORBIDDEN),
        "a tool-allowlist refusal must answer 403: {}",
        response_text(&tool_refusal)
    );

    let backend_scoped = scoped_client("scoped", vec!["alpha".to_string()], None);
    let (backend_state, _backend_store) =
        test_router_app_state_with_backend(http_backend_at("beta", "http://127.0.0.1:1/")).await;
    let backend_refusal =
        Box::pin(run_step_as(&backend_state, &backend_scoped, "beta", "read")).await;
    assert_eq!(
        super::handlers::refusal_status(&backend_refusal),
        Some(StatusCode::FORBIDDEN),
        "a backend-scope refusal must answer 403: {}",
        response_text(&backend_refusal)
    );

    // Global policy is minted in a third place, and an invalid tool name in a
    // fourth. The test's name claims EVERY branch, so it has to mean it.
    let (mut policy_state, _policy_store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    {
        let state_mut = Arc::get_mut(&mut policy_state).expect("sole owner during setup");
        state_mut.tool_policy = Arc::new(crate::security::ToolPolicy::from_config(
            &crate::security::ToolPolicyConfig {
                enabled: true,
                deny: vec!["globally_blocked".to_string()],
                ..crate::security::ToolPolicyConfig::default()
            },
        ));
    }
    let unrestricted = scoped_client("scoped", vec!["*".into()], None);
    let policy_refusal = Box::pin(run_step_as(
        &policy_state,
        &unrestricted,
        "alpha",
        "globally_blocked",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&policy_refusal),
        Some(StatusCode::FORBIDDEN),
        "a global-policy refusal must answer 403: {}",
        response_text(&policy_refusal)
    );

    let name_refusal = Box::pin(run_step_as(
        &policy_state,
        &unrestricted,
        "alpha",
        "bad/name",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&name_refusal),
        Some(StatusCode::FORBIDDEN),
        "an invalid tool name is refused by the authorizer, so it answers 403 \
         like any other refusal: {}",
        response_text(&name_refusal)
    );
}

/// AUTHZ.3 — a playbook step hitting a tool denied by GLOBAL policy is
/// refused.
///
/// Distinct from AUTHZ.1 and AUTHZ.2 on purpose: the policy lives on
/// `AppState`, not on the client, so a fix that threaded only the caller's
/// identity into the chokepoint passes those two and fails this one.
#[tokio::test]
async fn authz_3_playbook_step_denied_by_global_tool_policy_is_refused() {
    let (mut state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        state_mut.tool_policy = Arc::new(crate::security::ToolPolicy::from_config(
            &crate::security::ToolPolicyConfig {
                enabled: true,
                deny: vec!["globally_blocked".to_string()],
                ..crate::security::ToolPolicyConfig::default()
            },
        ));
    }
    let client = scoped_client("scoped", vec!["*".into()], None);

    let response = Box::pin(run_step_as(&state, &client, "alpha", "globally_blocked")).await;

    let msg = response_text(&response);
    assert!(
        response.error.is_some(),
        "a globally denied tool must be refused even for an unrestricted client: {msg}"
    );
    assert!(
        msg.contains("step not permitted for this caller") && !msg.contains("globally_blocked"),
        "the refusal must be recorded without naming the tool (A3): {msg}"
    );
}

/// AUTHZ.3a — the same policy must not refuse a permitted tool.
#[tokio::test]
async fn authz_3a_global_policy_does_not_refuse_a_permitted_tool() {
    let (mut state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        state_mut.tool_policy = Arc::new(crate::security::ToolPolicy::from_config(
            &crate::security::ToolPolicyConfig {
                enabled: true,
                deny: vec!["globally_blocked".to_string()],
                ..crate::security::ToolPolicyConfig::default()
            },
        ));
    }
    let client = scoped_client("scoped", vec!["*".into()], None);

    let response = Box::pin(run_step_as(&state, &client, "alpha", "permitted")).await;

    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "a permitted tool must reach dispatch rather than be refused: {}",
        response_text(&response)
    );
}

/// AUTHZ.10 / 10a — certificate policy reaches a playbook step.
///
/// The allow row is not decoration. `MtlsPolicy::evaluate` returns `Deny` for a
/// `None` identity once the policy is enabled, so the refusal row stays green
/// even if the certificate identity were dropped on the way to the chokepoint
/// and never consulted. Only a certificate the policy PERMITS proves the
/// identity actually arrived.
#[tokio::test]
async fn authz_10_certificate_policy_refuses_and_permits_a_playbook_step() {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    use crate::mtls::{CertIdentity, MtlsPolicy};

    let policy = Arc::new(MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![PolicyRuleConfig {
            match_criteria: CertMatchConfig {
                cn: Some("trusted-machine".to_string()),
                ..CertMatchConfig::default()
            },
            allow: ToolScopeConfig {
                backends: vec!["alpha".to_string()],
                tools: vec!["permitted".to_string()],
            },
            deny: ToolScopeConfig::default(),
        }],
        ..MtlsConfig::default()
    }));

    let (mut state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        state_mut.mtls_policy = Arc::clone(&policy);
    }
    let client = scoped_client("scoped", vec!["*".into()], None);
    let cert = CertIdentity {
        quota_principal: None,
        common_name: Some("trusted-machine".to_string()),
        display_name: "trusted-machine".to_string(),
        ..CertIdentity::default()
    };

    let refused = Box::pin(run_step_with_identity(
        &state,
        &client,
        Some(&cert),
        None,
        "alpha",
        "blocked",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&refused),
        Some(StatusCode::FORBIDDEN),
        "a tool outside the certificate's allowed scope must be refused: {}",
        response_text(&refused)
    );

    let permitted = Box::pin(run_step_with_identity(
        &state,
        &client,
        Some(&cert),
        None,
        "alpha",
        "permitted",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&permitted),
        None,
        "a tool the certificate permits must reach dispatch — without this the \
         refusal above passes with the identity dropped entirely: {}",
        response_text(&permitted)
    );
}

/// AUTHZ.11 / 11a — agent scope reaches a playbook step.
///
/// Same fail-closed trap as the certificate case, and worse: with agent auth
/// enabled, a MISSING identity is refused outright, so the deny row alone stays
/// green even if the identity never reaches the chokepoint. The allow row is
/// what proves it arrives.
#[tokio::test]
async fn authz_11_agent_scope_refuses_and_permits_a_playbook_step() {
    use crate::gateway::oauth::{AgentIdentity, Scope};

    let (mut state, _store) = test_router_app_state_with_agent_auth_enabled().await;
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        let _ = state_mut
            .backends
            .register(http_backend_at("alpha", "http://127.0.0.1:1/"));
    }
    let client = scoped_client("scoped", vec!["*".into()], None);

    // Scoped to one tool on one backend.
    let agent = AgentIdentity {
        quota_principal: None,
        client_id: "agent-1".to_string(),
        agent_name: "runner".to_string(),
        scopes: vec![Scope::parse("tools:alpha:permitted:*").expect("scope must parse")],
        raw_scopes: vec!["tools:alpha:permitted:*".to_string()],
    };

    let refused = Box::pin(run_step_with_identity(
        &state,
        &client,
        None,
        Some(&agent),
        "alpha",
        "blocked",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&refused),
        Some(StatusCode::FORBIDDEN),
        "a tool outside the agent's scope must be refused: {}",
        response_text(&refused)
    );

    let permitted = Box::pin(run_step_with_identity(
        &state,
        &client,
        None,
        Some(&agent),
        "alpha",
        "permitted",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&permitted),
        None,
        "a tool the agent's scope permits must reach dispatch — without this \
         the refusal above passes with the identity dropped entirely: {}",
        response_text(&permitted)
    );

    // And with NO agent identity at all, agent auth being enabled must refuse:
    // the check is fail-closed, and this pins that it still is.
    let anonymous = Box::pin(run_step_with_identity(
        &state,
        &client,
        None,
        None,
        "alpha",
        "permitted",
    ))
    .await;
    assert_eq!(
        super::handlers::refusal_status(&anonymous),
        Some(StatusCode::FORBIDDEN),
        "agent auth enabled with no agent identity must refuse: {}",
        response_text(&anonymous)
    );
}

/// An ordinary error must not carry the HTTP-status stamp.
///
/// The stamp is a plain JSON key on the error's `data`. Today nothing but the
/// gateway writes that field — `JsonRpcResponse::error` starts it at `None` —
/// but a future path forwarding a backend's error data would otherwise let a
/// backend choose the gateway's HTTP status. The response builder assigns both
/// arms, and this pins that: a non-refusal comes back with no `data` at all.
#[tokio::test]
async fn authz_ordinary_error_carries_no_status_stamp() {
    let (state, _store) =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/")).await;
    let client = scoped_client("scoped", vec!["*".into()], None);

    let authorizer = super::authorization::RouterAuthorizer {
        state: state.as_ref(),
        client: Some(&client),
        oauth_agent_identity: None,
        cert_identity: None,
        principal: super::authorization::refusal_principal(Some(&client), None, None),
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: None,
        authorizer: &authorizer,
        api_key_name: Some(client.name.as_str()),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    let response = Box::pin(state.meta_mcp.handle_tools_call(
        RequestId::Number(1),
        "gateway_run_playbook",
        serde_json::json!({ "name": "no_such_playbook", "arguments": {} }),
        None,
        caller,
    ))
    .await;

    let error = response.error.as_ref().expect("the control must error");
    assert!(
        error.data.is_none(),
        "an ordinary error must carry no data, so nothing can be mistaken for \
         a status stamp: {:?}",
        error.data
    );
}
