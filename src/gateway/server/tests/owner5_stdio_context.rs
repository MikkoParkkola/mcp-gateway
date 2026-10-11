// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.5: what the context stdio builds carries, and what it is
//! refused because of it.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I1).
//! The sole-operator deployment account stays served on stdio
//! (`stdio_sole_operator.rs`, `stdio_run_path_serves_its_operator_the_managed_account`):
//! "no personal account" means no per-user account, not that the deployment's
//! own account is withheld.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::Gateway;
use crate::gateway::authz::ToolPolicyAuthorizer;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::meta::RequestShape;
use crate::protocol::mrtr::NO_RETRY;

const BACKEND: &str = "partner";

/// T5.1. The context the production builder hands the dispatcher: the stdio
/// execution principal, the transport's mark, and no personal identity.
#[test]
fn real_stdio_context_carries_principal_and_no_personal_identity() {
    let policy = crate::security::ToolPolicy::default();
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
    };
    let context = super::super::Gateway::build_stdio_caller_context(
        false,
        None,
        &authorizer,
        &NO_RETRY,
        &RequestShape::Legacy,
        super::super::StdioClient {
            session_id: super::super::STDIO_SESSION_ID,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            modern: false,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
    );

    assert_eq!(
        context.credential_principal,
        Some(super::super::STDIO_CREDENTIAL_PRINCIPAL)
    );
    assert!(
        context.stdio_nonce.is_some(),
        "stdio must carry the transport's mark"
    );
    assert!(
        context.verified_identity.is_none(),
        "stdio carries no verified identity"
    );
    assert!(
        context.grant_subject.is_none(),
        "stdio carries no delegated grant"
    );
    assert!(context.api_key_name.is_none(), "stdio presents no API key");
}

fn call(id: u64, tool: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}})
}

/// An HTTP MCP backend with one tool; counts the `tools/call` it receives.
async fn counting_backend() -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": [{
                        "name": "read", "description": "fixture",
                        "inputSchema": {"type": "object"},
                    }]}),
                    Some("tools/call") => {
                        seen.fetch_add(1, Ordering::SeqCst);
                        json!({"content": [{"type": "text", "text": "read-ok"}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), calls)
}

/// T5.2. In one stdio session on the production boot path: a backend that
/// requires a verified end-user identity is refused before dispatch, and a
/// local mutation still works.
#[tokio::test]
async fn stdio_refuses_an_account_dependent_call_and_serves_a_local_mutation() {
    let (url, calls) = counting_backend().await;
    let mut config = Config::default();
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            enabled: true,
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "https://partner.invalid/".to_string(),
                required: true,
                session_mode: SessionMode::Stateless,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
    );
    let data_dir = tempfile::tempdir().expect("tempdir");
    let built = Gateway::new(config)
        .await
        .expect("the production constructor accepts this configuration")
        .with_data_dir(data_dir.path().to_path_buf())
        .build_meta_mcp()
        .await
        .expect("the production builder accepts this configuration");
    let session = super::super::STDIO_SESSION_ID;

    let refused = Gateway::dispatch_single(
        &built.meta_mcp,
        &built.tool_policy,
        &built.mtls_policy,
        &call(
            1,
            "gateway_invoke",
            &json!({"server": BACKEND, "tool": "read", "arguments": {}}),
        ),
        session,
    )
    .await
    .expect("an identified stdio call returns a response");
    assert!(
        refused
            .to_string()
            .contains("no verified end-user identity"),
        "the identity-requiring backend must refuse a stdio caller: {refused}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the refused call reached the backend"
    );

    let mutated = Gateway::dispatch_single(
        &built.meta_mcp,
        &built.tool_policy,
        &built.mtls_policy,
        &call(2, "gateway_set_state", &json!({"state": "triage"})),
        session,
    )
    .await
    .expect("an identified stdio call returns a response");
    assert!(
        mutated.get("error").is_none(),
        "a local mutation must still work over stdio: {mutated}"
    );
}
