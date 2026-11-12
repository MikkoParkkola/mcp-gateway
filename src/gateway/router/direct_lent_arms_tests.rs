// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every direct-route entry arm lends the CHECKED loan to a lent-only
//! per-user slot. A real loopback HTTP backend sits behind the slot, so the
//! transport's own loan check runs: an arm that hands over a credential with
//! no send check is refused there, and the row goes red. A fake transport in
//! the slot would skip exactly that check.

use std::sync::{Arc, Mutex};

use axum::body::to_bytes;
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode, SignedAssertionStrategy,
};
use crate::key_server::oidc::VerifiedIdentity;

const BACKEND: &str = "lent-arms";
const TOOL: &str = "lookup";
const MARKER: &str = "served-by-the-loopback-peer";

/// What the peer saw: each request's JSON-RPC method and headers.
type Seen = Arc<Mutex<Vec<(String, HeaderMap)>>>;

/// A streamable HTTP MCP peer on loopback: a 2026 `server/discover`, one
/// tool, and a call answered with [`MARKER`].
async fn peer() -> (String, Seen) {
    peer_with_tool(json!({
        "name": TOOL,
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
    }))
    .await
}

async fn peer_with_tool(tool: Value) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let app = axum::Router::new().fallback(
        move |headers: HeaderMap, axum::Json(message): axum::Json<Value>| {
            let log = Arc::clone(&log);
            let tool = tool.clone();
            async move {
                let method = message["method"].as_str().unwrap_or_default().to_owned();
                log.lock().unwrap().push((method.clone(), headers));
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let result = match method.as_str() {
                    "initialize" => json!({
                        "protocolVersion": message["params"]["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "lent-arms", "version": "0"}
                    }),
                    "server/discover" => json!({
                        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                        "capabilities": {"tools": {}}
                    }),
                    "tools/list" => json!({"tools": [tool]}),
                    "tools/call" => json!({"content": [{"type": "text", "text": MARKER}]}),
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, seen)
}

/// Which `tools/call` arm the direct route takes: a `passthrough` backend's
/// call goes out through the plain forward, any other through the sanitizing
/// one, whatever `sanitize_input` says.
#[derive(Clone, Copy)]
enum Guarded {
    Passthrough,
    Sanitized,
}

/// A router whose one backend, at `url`, has a required per-user binding
/// minted as a signed assertion, so each caller's slot is lent-only.
async fn gateway(
    url: String,
    guarded: Guarded,
) -> (
    axum::Router,
    (Arc<tempfile::TempDir>, super::tests::FixtureDir),
) {
    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("a key"));
    let backend = Arc::new(crate::backend::Backend::new(
        BACKEND,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "https://lent-arms.internal".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            passthrough: matches!(guarded, Guarded::Passthrough),
            ..BackendConfig::r2_off()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(backend), "the backend registers");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
    meta.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));
    let log_dir = crate::test_dir_keep::kept_tempdir();
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "lent-arms".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("the transparency log opens"),
    );
    meta.enable_transparency_log(Arc::clone(&log));
    let auth = crate::config::AuthConfig::default();
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = registry;
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    (super::create_router(state), (log_dir, store))
}

/// The given body, sent by POST to the direct route as a verified caller.
async fn post_direct(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(VerifiedIdentity::for_test(
        "alpha".to_string(),
        "alpha@example.invalid".to_string(),
        None,
        vec![],
        "https://issuer.example.invalid".to_string(),
    ));
    let response = router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Each direct-route entry arm (the plain `tools/call` of a passthrough
/// backend, the sanitizing `tools/call`, and `forward_plain` by way of
/// `tools/list`) reaches a
/// required per-user backend over its real lent-only transport and is
/// served, every request carrying the caller's minted assertion. An arm that
/// lends a credential without its send check is refused by the transport.
#[tokio::test]
async fn every_direct_route_arm_lends_the_checked_loan() {
    let call = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"}}});
    let list = json!({"jsonrpc": "2.0", "id": 8, "method": "tools/list"});
    let arms = [
        ("plain tools/call", Guarded::Passthrough, &call, MARKER),
        ("sanitizing tools/call", Guarded::Sanitized, &call, MARKER),
        ("forward_plain tools/list", Guarded::Sanitized, &list, TOOL),
    ];
    for (arm, guarded, body, expected) in arms {
        let (url, seen) = peer().await;
        let (router, _dirs) = gateway(url, guarded).await;

        let (status, answer) = post_direct(&router, body).await;

        assert_eq!(status, StatusCode::OK, "{arm}: {answer}");
        assert!(
            answer.get("error").is_none() && answer.to_string().contains(expected),
            "{arm}: not served: {answer}"
        );
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen.is_empty()
                && seen.iter().all(|(_, headers)| headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|auth| auth.starts_with("Bearer "))),
            "{arm}: a request reached the backend without the caller's assertion: {seen:?}"
        );
    }
}

/// A tools/call through the router's direct route on a backend whose slot was never
/// listed still carries its Mcp-Param mirror: the route's catalogue check fills the
/// slot before the send. Red if the route stops filling a cold slot before the
/// mirror reads it.
#[tokio::test]
async fn cold_slot_call_via_direct_route_is_mirrored() {
    let (url, seen) = peer_with_tool(json!({
        "name": "echo",
        "inputSchema": {"type": "object", "properties": {
            "tenant": {"type": "string", "x-mcp-header": "Tenant"}
        }}
    }))
    .await;
    let (router, _dirs) = gateway(url, Guarded::Sanitized).await;
    assert!(seen.lock().unwrap().is_empty(), "the slot starts cold");

    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"tenant": "acme"}}});
    let (status, answer) = post_direct(&router, &call).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(answer.get("error").is_none(), "{answer}");

    let seen = seen.lock().unwrap();
    let calls: Vec<_> = seen
        .iter()
        .filter(|(method, _)| method == "tools/call")
        .collect();
    assert_eq!(calls.len(), 1, "{seen:?}; {answer}");
    assert_eq!(
        calls[0]
            .1
            .get("Mcp-Param-Tenant")
            .and_then(|value| value.to_str().ok()),
        Some("acme"),
        "the cold direct-route call must carry its parameter mirror: {seen:?}"
    );
}
