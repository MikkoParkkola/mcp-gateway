// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2292 end to end: `/mcp/{name}` over a real HTTP transport to a recording
//! upstream whose backend is configured with a static `Authorization`. Each
//! caller's notification arrives with that caller's credential, the same one
//! its request carries, never the static one, and never in a trace span.

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse as _;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::direct_route_state_with_identity;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::test_helpers::MetaMcp;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const NOTE: &str = "notifications/roots/list_changed";

fn static_auth() -> String {
    format!("Bearer {}", "gateway-static")
}

/// Mints `Bearer minted-for-<subject>`.
struct Mint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Mint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        let subject_key = identity.subject.clone();
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer minted-for-{subject_key}"),
            )],
            expires_at: i64::MAX,
            cache_binding: format!("{subject_key}@{}", backend.audience),
            subject_key,
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// `(method, authorization)` of every message the upstream receives.
type Wire = Arc<parking_lot::Mutex<Vec<(String, Option<String>)>>>;

/// A 2025-era MCP server on loopback: answers the handshake and `tools/list`,
/// accepts notifications, and records what it was sent.
async fn upstream() -> (String, Wire) {
    let wire = Wire::default();
    let sink = Arc::clone(&wire);
    let app = axum::Router::new().fallback(
        move |headers: HeaderMap, axum::Json(message): axum::Json<Value>| {
            let sink = Arc::clone(&sink);
            async move {
                let method = message["method"].as_str().unwrap_or_default().to_string();
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                sink.lock().push((method.clone(), auth));
                let Some(id) = message.get("id").cloned() else {
                    return StatusCode::ACCEPTED.into_response();
                };
                let body = match method.as_str() {
                    "initialize" => json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": { "name": "ledger", "version": "0" }
                    }}),
                    "tools/list" => {
                        json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": [] } })
                    }
                    _ => json!({ "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": "method not found" } }),
                };
                axum::Json(body).into_response()
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, wire)
}

struct Gateway {
    router: axum::Router,
    wire: Wire,
    _store: tempfile::TempDir,
    _audit: [tempfile::NamedTempFile; 2],
}

fn logger(file: &tempfile::NamedTempFile) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "issue-2292-wire".to_string(),
        ..TransparencyLogConfig::default()
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("transparency logger opens"))
}

async fn gateway(strategy: PropagationStrategyKind) -> Gateway {
    let (url, wire) = upstream().await;
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), static_auth());
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            headers,
            identity_propagation: Some(IdentityPropagationConfig {
                strategy,
                audience: "ledger".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(10),
    ));
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let audit = [
        tempfile::NamedTempFile::new().expect("tempfile"),
        tempfile::NamedTempFile::new().expect("tempfile"),
    ];
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.set_identity_propagation(Arc::new(Mint));
    meta.enable_transparency_log(logger(&audit[0]));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(logger(&audit[1]));
    Gateway {
        router: create_router(state),
        wire,
        _store: store,
        _audit: audit,
    }
}

/// POST `message` as `subject` or with a passthrough credential.
async fn send(
    gw: &Gateway,
    message: &Value,
    subject: Option<&str>,
    passthrough: Option<&str>,
) -> StatusCode {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json");
    if let Some(value) = passthrough {
        builder = builder.header("x-mcp-passthrough-authorization", value);
    }
    let mut request = builder
        .body(axum::body::Body::from(message.to_string()))
        .unwrap();
    if let Some(subject) = subject {
        request.extensions_mut().insert(VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@example.invalid"),
            name: None,
            groups: vec![],
            issuer: "https://idp.example.invalid".to_string(),
        });
    }
    gw.router.clone().oneshot(request).await.unwrap().status()
}

fn note() -> Value {
    json!({ "jsonrpc": "2.0", "method": NOTE, "params": {} })
}

fn list() -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })
}

/// The `Authorization` each message of `method` carried, in arrival order.
fn auths(gw: &Gateway, method: &str) -> Vec<Option<String>> {
    gw.wire
        .lock()
        .iter()
        .filter(|(m, _)| m == method)
        .map(|(_, auth)| auth.clone())
        .collect()
}

/// Two minting callers: each caller's request and notification carry that
/// caller's minted credential over HTTP, and neither carries the static one.
#[tokio::test]
async fn minted_callers_notifications_match_their_requests_on_the_wire() {
    let gw = gateway(PropagationStrategyKind::SignedAssertion).await;
    for subject in ["alpha", "beta"] {
        assert_eq!(
            send(&gw, &list(), Some(subject), None).await,
            StatusCode::OK
        );
        assert_eq!(
            send(&gw, &note(), Some(subject), None).await,
            StatusCode::ACCEPTED
        );
    }
    let minted = |s: &str| Some(format!("Bearer minted-for-{s}"));
    assert_eq!(
        auths(&gw, "tools/list"),
        vec![minted("alpha"), minted("beta")]
    );
    assert_eq!(auths(&gw, NOTE), auths(&gw, "tools/list"));
}

/// Two passthrough callers: each notification carries that caller's own value
/// over HTTP, never the backend's static credential.
#[tokio::test]
async fn passthrough_callers_notifications_carry_their_own_values_on_the_wire() {
    let gw = gateway(PropagationStrategyKind::Passthrough).await;
    let values = [
        format!("Bearer {}", "caller-one"),
        format!("Bearer {}", "caller-two"),
    ];
    for value in &values {
        assert_eq!(
            send(&gw, &note(), None, Some(value)).await,
            StatusCode::ACCEPTED
        );
    }
    assert_eq!(
        auths(&gw, NOTE),
        values.iter().cloned().map(Some).collect::<Vec<_>>()
    );
    let static_auth = static_auth();
    assert!(
        gw.wire
            .lock()
            .iter()
            .all(|(m, a)| m != NOTE || a.as_deref() != Some(static_auth.as_str())),
        "a notification carried the static credential"
    );
}

/// MIK-8072: a client's `notifications/cancelled` names the client's request
/// id, which the backend never saw (each transport numbers its own requests
/// from 1), so forwarding it could cancel another caller's call holding that
/// number. It is accepted and never sent upstream; other notifications still
/// are.
#[tokio::test]
async fn a_client_cancel_never_reaches_the_backend() {
    let gw = gateway(PropagationStrategyKind::SignedAssertion).await;
    assert_eq!(send(&gw, &list(), Some("beta"), None).await, StatusCode::OK);
    let cancel = json!({ "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": 1, "reason": "not yours" } });
    assert_eq!(
        send(&gw, &cancel, Some("alpha"), None).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        send(&gw, &note(), Some("alpha"), None).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        auths(&gw, "notifications/cancelled"),
        Vec::<Option<String>>::new()
    );
    assert_eq!(auths(&gw, NOTE).len(), 1, "the control notification");
}

/// MIK-8072 (codex P2): a dropped cancel mints no per-user credential and
/// writes no `idp_mint` record; control: the same caller's ordinary
/// notification does, so the check can see a mint.
#[tokio::test]
async fn a_dropped_cancel_mints_no_credential() {
    let gw = gateway(PropagationStrategyKind::SignedAssertion).await;
    let minted = |gw: &Gateway| {
        gw._audit
            .iter()
            .map(|f| std::fs::read_to_string(f.path()).unwrap_or_default())
            .any(|log| log.contains("idp_mint"))
    };
    let cancel = json!({ "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": 1 } });
    assert_eq!(
        send(&gw, &cancel, Some("gamma"), None).await,
        StatusCode::ACCEPTED
    );
    assert!(!minted(&gw), "a dropped cancel minted a credential");
    assert_eq!(
        send(&gw, &note(), Some("gamma"), None).await,
        StatusCode::ACCEPTED
    );
    assert!(minted(&gw), "control: a forwarded notification mints");
}

/// Neither strategy's forwarded credential reaches a trace span on the HTTP
/// notification path.
#[tokio::test]
async fn forwarded_credentials_stay_out_of_the_trace_on_the_wire() {
    use std::io::Write;
    #[derive(Clone)]
    struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = Buf(Arc::default());
    let writer = buffer.clone();
    crate::gateway::session_id::log_capture::ensure_global_interest();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let minted = gateway(PropagationStrategyKind::SignedAssertion).await;
    assert_eq!(
        send(&minted, &note(), Some("alpha"), None).await,
        StatusCode::ACCEPTED
    );
    let passthrough = gateway(PropagationStrategyKind::Passthrough).await;
    let value = format!("Bearer {}", "never-in-a-span");
    assert_eq!(
        send(&passthrough, &note(), None, Some(&value)).await,
        StatusCode::ACCEPTED
    );

    let trace = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(
        trace.contains("notify_with_headers"),
        "the span was captured"
    );
    for secret in ["minted-for-alpha", "never-in-a-span"] {
        assert!(
            !trace.contains(secret),
            "{secret} reached the trace:\n{trace}"
        );
    }
}
