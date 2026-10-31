// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A required per-user backend whose credential mint answers with no header:
//! the slot lender refuses the call, which carried no credential of its own,
//! before anything is sent, and the delivered 403 records `refused`.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::identity_propagation::{
    BackendDescriptor, IdentityPropagation, IdentityPropagationConfig, PropagatedCredential,
    PropagationError, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;

const BACKEND: &str = "lent";
const TOOL: &str = "lookup";

/// A mint that succeeds with `headers`, valid until `expires_at` (unix
/// seconds): none and never expiring for a call carrying no credential, one
/// long expired for a send its recheck refuses.
struct FixedMint {
    headers: Vec<(String, String)>,
    expires_at: i64,
}

#[async_trait::async_trait]
impl IdentityPropagation for FixedMint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        Ok(PropagatedCredential {
            headers: self.headers.clone(),
            expires_at: self.expires_at,
            expiry_synthetic: false,
            cache_binding: format!("{}@{}", identity.subject, backend.audience),
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// A streamable HTTP MCP peer on loopback; returns its URL and the
/// `tools/call` requests it received.
async fn peer() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let app = axum::Router::new().fallback(move |axum::Json(message): axum::Json<Value>| {
        let counted = Arc::clone(&counted);
        async move {
            let method = message["method"].as_str().unwrap_or_default().to_owned();
            let result = match method.as_str() {
                "tools/list" => json!({"tools": [{"name": TOOL,
                    "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}]}),
                "tools/call" => {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    json!({"content": [{"type": "text", "text": "ok"}]})
                }
                _ => json!({}),
            };
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, calls)
}

/// The router over one required per-user backend at `url`, minted by
/// `mint`, and its transparency log's directory.
async fn gateway(
    url: String,
    mint: FixedMint,
) -> (axum::Router, (tempfile::TempDir, super::tests::FixtureDir)) {
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
                audience: "https://lent.internal".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::r2_off()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(backend), "the backend registers");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
    meta.set_identity_propagation(Arc::new(mint));
    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "lend".to_string(),
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

/// POST a direct `tools/call` of [`TOOL`] as a verified caller, with the
/// modern protocol headers; returns the status and the parsed answer.
async fn call(router: &axum::Router) -> (axum::http::StatusCode, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"},
                   "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                             "io.modelcontextprotocol/clientCapabilities": {}}}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", TOOL)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    });
    let response = router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lent_only_call_carrying_no_credential_records_refused() {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, dirs) = gateway(url, mint).await;
    let (status, answer) = call(&router).await;
    // Premise: refused by the lender, for this reason, and never sent. A
    // refusal for any other reason means no route reaches the lender.
    assert!(
        answer.to_string().contains("this call carried none"),
        "premise: the lender's refusal: {status} {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(
        answer["error"]["code"], -32001,
        "the code is unchanged: {answer}"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let raw = std::fs::read_to_string(dirs.0.path().join("audit.jsonl")).unwrap_or_default();
    let delivered: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let [one] = delivered.as_slice() else {
        panic!("premise: one delivery record: {delivered:?}");
    };
    assert_eq!(one["response_effect"], "refused", "{one}");
    // The check is about the caller's own credential, which no decision kind
    // names yet: refused with kind `unrecorded`, never `default_allow`.
    // Flips to that kind when an identity-standing kind is added.
    let invocations: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt")
        .collect();
    let [invocation] = invocations.as_slice() else {
        panic!("premise: one invocation record: {invocations:?}");
    };
    assert_eq!(invocation["decision"]["kind"], "unrecorded", "{invocation}");
}

/// A send whose credential fails its per-send recheck (published as expired
/// long ago) is refused by the lender with `Forbidden`, and `/mcp/{name}`
/// answers it 403 with -32001, not 500, recording it refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_its_recheck_refuses_answers_403_and_records_refused() {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![("Authorization".to_string(), "Bearer lapsed".to_string())],
        expires_at: 1,
    };
    let (router, dirs) = gateway(url, mint).await;
    let (status, answer) = call(&router).await;
    // Premise: refused by the per-send recheck, for this reason, and never
    // sent. A refusal for any other reason (the mint refusing the expired
    // credential first) does not reach the lender.
    assert!(
        answer.to_string().contains("per-user send refused"),
        "premise: the recheck's refusal: {status} {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["error"]["code"], -32001, "{answer}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let raw = std::fs::read_to_string(dirs.0.path().join("audit.jsonl")).unwrap_or_default();
    let delivered: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let [one] = delivered.as_slice() else {
        panic!("premise: one delivery record: {delivered:?}");
    };
    assert_eq!(one["response_effect"], "refused", "{one}");
    // The check is about the caller's own credential, which no decision kind
    // names yet: refused with kind `unrecorded`, never `default_allow`.
    // Flips to that kind when an identity-standing kind is added.
    let invocations: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt")
        .collect();
    let [invocation] = invocations.as_slice() else {
        panic!("premise: one invocation record: {invocations:?}");
    };
    assert_eq!(invocation["decision"]["kind"], "unrecorded", "{invocation}");
}
