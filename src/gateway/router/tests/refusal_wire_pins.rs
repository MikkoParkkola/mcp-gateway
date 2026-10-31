// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Wire pins for every authorization refusal: the JSON-RPC code, the HTTP
//! status and the message a client sees. Recording which check refused must
//! never change any of the three, so these hold byte for byte across that
//! change. One row per refusal site, cited by `file:line` on the base it was
//! pinned against.

use super::*;
use pretty_assertions::assert_eq;

use crate::gateway::authz::{AuthorizationError, Emit, ToolAuthorizer, ToolPolicyAuthorizer};

fn wire(e: &AuthorizationError) -> (i32, u16, String) {
    (e.code, e.status.as_u16(), e.message.clone())
}

fn http_refusal(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    agent: Option<&OAuthAgentIdentity>,
    server: &str,
    tool: &str,
) -> (i32, u16, String) {
    let args = json!({});
    let refused = authorize_tool_target(
        state,
        &state.live_config.generation(),
        client,
        agent,
        None,
        ToolTarget {
            server,
            tool,
            arguments: &args,
        },
    )
    .expect_err("the case is built to be refused");
    wire(&refused)
}

fn deny_list_policy() -> crate::security::ToolPolicy {
    let config: crate::security::ToolPolicyConfig = serde_json::from_value(json!({
        "enabled": true,
        "deny": ["demo:blocked_tool"],
        "use_default_deny": false,
        "log_denied": false
    }))
    .expect("tool policy config");
    crate::security::ToolPolicy::from_config(&config)
}

#[tokio::test]
async fn http_refusals_keep_code_status_and_message() {
    let (mut state, _store) = test_router_app_state().await;
    // router/authorization.rs:340 validate_tool_name
    let syntax = http_refusal(&state, None, None, "demo", "bad tool!");
    // authz.rs:118 authorize_backend
    let elsewhere = scoped_client("c", vec!["other".into()], None);
    let backend = http_refusal(&state, Some(&elsewhere), None, "demo", "t");
    // router/authorization.rs:349 check_tool_scope
    let narrow = scoped_client("c", vec!["*".into()], Some(vec!["only_this".into()]));
    let client_tool = http_refusal(&state, Some(&narrow), None, "demo", "t");
    // router/authorization.rs:344 tool_policy.check, deny list
    Arc::get_mut(&mut state).expect("sole owner").tool_policy = Arc::new(deny_list_policy());
    let policy = http_refusal(&state, None, None, "demo", "blocked_tool");
    assert_eq!(
        [syntax, backend, client_tool, policy],
        [
            (-32600, 403, "Tool name 'bad tool!' contains disallowed character ' ' (only [A-Za-z0-9_-] is permitted)".to_owned()),
            (-32003, 403, "Client 'c' not authorized for backend 'demo'".to_owned()),
            (-32600, 403, "Tool 't' on server 'demo' is not in the allowlist for client 'c'".to_owned()),
            (-32600, 403, "Protocol error: Tool 'blocked_tool' on server 'demo' is blocked by security policy".to_owned()),
        ]
    );
}

#[tokio::test]
async fn mtls_agent_and_ssrf_refusals_keep_code_status_and_message() {
    // router/authorization.rs:360 mtls_policy.evaluate: a rule exists and the
    // caller presented no certificate.
    let (mut state, _store) = test_router_app_state().await;
    let mtls: crate::mtls::config::MtlsConfig = serde_json::from_value(json!({
        "enabled": true,
        "policies": [{ "match": { "cn": "someone" }, "allow": { "backends": ["*"], "tools": ["*"] } }]
    }))
    .expect("mtls config");
    Arc::get_mut(&mut state).expect("sole owner").mtls_policy =
        Arc::new(MtlsPolicy::from_config(&mtls));
    let mtls = http_refusal(&state, None, None, "demo", "t");

    // router/authorization.rs:386-410 agent_auth: no identity, then a scope miss
    let (agents, _agents_store) = test_router_app_state_with_agent_auth_enabled().await;
    let no_identity = http_refusal(&agents, None, None, "demo", "t");
    let identity = OAuthAgentIdentity {
        quota_principal: None,
        client_id: "agent-a".to_string(),
        agent_name: "Agent A".to_string(),
        scopes: vec![
            crate::gateway::oauth::Scope::parse("tools:demo:allowed_tool:execute").unwrap(),
        ],
        raw_scopes: vec!["tools:demo:allowed_tool:execute".to_string()],
    };
    let scope_miss = http_refusal(&agents, None, Some(&identity), "demo", "blocked_tool");

    // router/authorization.rs:425 check_configured_url
    let (mut guarded, _guarded_store) = test_router_app_state().await;
    {
        let s = Arc::get_mut(&mut guarded).expect("sole owner");
        s.trust_configured_backends = false;
    }
    // SSRF protection is a reloadable flag: it lives on the published config.
    let mut config = (*guarded.live_config.get()).clone();
    config.security.ssrf_protection = true;
    guarded.live_config.set(config);
    let _ = guarded
        .backends
        .register(http_backend_at("loopback", "http://127.0.0.1:9000/mcp"));
    let ssrf = http_refusal(&guarded, None, None, "loopback", "echo");

    assert_eq!(
        [mtls, no_identity, scope_miss, ssrf],
        [
            (-32600, 403, "Tool 't' on server 'demo' is blocked by certificate policy".to_owned()),
            (-32600, 403, "Agent authentication is enabled but no validated agent identity was found".to_owned()),
            (-32600, 403, "Agent 'agent-a' lacks scope for tool 'blocked_tool' on backend 'demo' (action: Execute)".to_owned()),
            (-32600, 403, "Protocol error: SSRF blocked: host targets private/reserved address 127.0.0.1".to_owned()),
        ]
    );
}

#[test]
fn stdio_and_admin_refusals_keep_code_status_and_message() {
    let policy = deny_list_policy();
    let stdio = ToolPolicyAuthorizer {
        tool_policy: &policy,
    };
    let refuse = |tool: &'static str| {
        let args = json!({});
        let decision = stdio.decide(ToolTarget {
            server: "demo",
            tool,
            arguments: &args,
        });
        wire(&decision.emit(Emit::Silent).expect_err("refused"))
    };
    // authz.rs:484 validate_tool_name and :488 tool_policy.check
    let syntax = refuse("bad tool!");
    let policy_refusal = refuse("blocked_tool");
    // router/authorization.rs:300 require_admin_log_level
    let log_level =
        super::authorization::require_admin_log_level("logging/setLevel", None, None, "demo")
            .expect_err("non-admin");
    assert_eq!(
        [syntax, policy_refusal, wire(&log_level)],
        [
            (-32600, 403, "Tool name 'bad tool!' contains disallowed character ' ' (only [A-Za-z0-9_-] is permitted)".to_owned()),
            (-32600, 403, "Protocol error: Tool 'blocked_tool' on server 'demo' is blocked by security policy".to_owned()),
            (-32600, 403, "logging/setLevel sets backend log levels for every user of the gateway and requires admin access; to receive fewer messages, declare a level in the request `_meta`".to_owned()),
        ]
    );
}

#[tokio::test]
async fn admin_tool_refusal_keeps_code_status_and_message() {
    // router/authorization.rs:242 require_admin_tool_access, no audit log
    let key = crate::gateway::record_principal::test_record_key();
    let refused = super::authorization::require_admin_tool_access(
        None,
        None,
        None,
        "gateway_reload_config",
        &key,
    )
    .await
    .expect_err("non-admin");
    assert_eq!(
        wire(&refused),
        (
            -32600,
            403,
            "Tool 'gateway_reload_config' requires admin access".to_owned()
        )
    );
}

#[tokio::test]
async fn admin_tool_audit_unavailable_keeps_code_status_and_message() {
    // router/authorization.rs:255 `unavailable`: a fail-closed log that cannot
    // take the admin_action record refuses an admin caller with 503.
    use crate::security::transparency_log::{TransparencyLogConfig, rotation_fault::WriteFault};
    let dir = tempfile::tempdir().expect("tempdir");
    let config = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    let log = Arc::new(
        crate::security::TransparencyLogger::open(config)
            .expect("logger opens")
            .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed),
    );
    log.arm_write_fault(Some(WriteFault::FullForever));
    let mut admin = scoped_client("root", vec!["*".into()], None);
    admin.admin = true;
    let key = crate::gateway::record_principal::test_record_key();
    let refused = super::authorization::require_admin_tool_access(
        Some(&log),
        Some(&admin),
        None,
        "gateway_reload_config",
        &key,
    )
    .await
    .expect_err("the record cannot be written");
    assert_eq!(
        wire(&refused),
        (
            -32005,
            503,
            "audit log unavailable; the call may have run but its result is withheld".to_owned()
        )
    );
}
