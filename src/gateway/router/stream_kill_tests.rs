// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7216.IDEM.5 / IDEM.6: a response stream killed mid-flight, and the
//! re-issue the specification requires (MCP 2026-07-28, SEP-2575: "A broken
//! response stream loses the in-flight request; clients MUST re-issue it as a
//! new request with a new request ID.").
//!
//! The backend holds every `tools/call` at a gate after counting its delivery,
//! so the test can drop the HTTP request future while the backend owns the
//! call. Both HTTP routes run the dispatch inside the handler future, so the
//! drop is the stream kill.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tower::ServiceExt;

use super::create_router;
use crate::backend::Backend;
use crate::config::{
    ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig, IdempotencyConfig, IdempotencyKeyMode,
    IdempotencyReadOnlyTool,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::idempotency::IdempotencyCache;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

const KEY: &str = "key-7216";

/// Backend `alpha`: `t` is the operator-classified read-only tool, `w` a
/// side-effecting one. Counts deliveries of `tools/call`, then waits at `gate`.
struct Gated {
    calls: Arc<AtomicUsize>,
    gate: Arc<Semaphore>,
}

fn listed(name: &str) -> Value {
    json!({"name": name, "description": "A tool.", "inputSchema": {"type": "object"}})
}

#[async_trait::async_trait]
impl Transport for Gated {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(
                id,
                json!({ "tools": [listed("t"), listed("w")] }),
            ));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        // The permit goes straight back: once opened, the gate stays open.
        let _ = self.gate.acquire().await;
        Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "done"}], "isError": false}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

struct Fixture {
    state: Arc<super::AppState>,
    calls: Arc<AtomicUsize>,
    gate: Arc<Semaphore>,
    _store: tempfile::TempDir,
}

impl Fixture {
    fn deliveries(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Let every held and future backend call answer.
    fn open_gate(&self) {
        self.gate.add_permits(1);
    }
}

/// One API key, `k` (a verified principal for the keyed meta route), backend
/// `alpha` behind a closed gate, `t` operator-classified read-only, and
/// `server.idempotency_key` as given.
async fn fixture(mode: IdempotencyKeyMode) -> Fixture {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
            expires_at: None,
            name: "stream-kill-client".to_string(),
            rate_limit: 0,
            backends: vec!["alpha".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Semaphore::new(0));
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Gated {
        calls: Arc::clone(&calls),
        gate: Arc::clone(&gate),
    }));
    assert!(state_mut.backends.register(backend));
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.enable_idempotency(Arc::new(IdempotencyCache::new()), Duration::from_secs(300));
    meta.set_idempotency_config(IdempotencyConfig {
        read_only_tools: vec![IdempotencyReadOnlyTool {
            server: "alpha".to_string(),
            tool: "t".to_string(),
        }],
    });
    meta.set_idempotency_key_mode(mode);
    state_mut.meta_mcp = Arc::new(meta);
    Fixture {
        state,
        calls,
        gate,
        _store: store,
    }
}

/// A 2026-07-28 `tools/call`; `key` is the client idempotency key, if any.
fn call(id: u32, name: &str, arguments: &Value, key: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    if let Some(key) = key {
        meta[IDEMPOTENCY_KEY_META] = json!(key);
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments, "_meta": meta}})
}

/// `gateway_invoke` on `alpha` for `tool`.
fn invoke(id: u32, tool: &str, key: Option<&str>) -> Value {
    let arguments = json!({"server": "alpha", "tool": tool, "arguments": {}});
    call(id, "gateway_invoke", &arguments, key)
}

fn request(uri: &str, body: &Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("authorization", "Bearer k")
        .header("mcp-method", "tools/call")
        .header(
            "mcp-name",
            body["params"]["name"].as_str().unwrap_or_default(),
        )
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// Run the request to completion: its status and body text.
async fn send(fx: &Fixture, uri: &str, body: &Value) -> (StatusCode, String) {
    let response = create_router(Arc::clone(&fx.state))
        .oneshot(request(uri, body))
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Kill the response stream while the backend holds the call: wait until the
/// backend has counted `deliveries`, drop the request future, then open the
/// gate so nothing stays parked.
async fn kill_mid_flight(fx: &Fixture, uri: &str, body: &Value, deliveries: usize) {
    let router_call = create_router(Arc::clone(&fx.state)).oneshot(request(uri, body));
    let handle = tokio::spawn(router_call);
    let deadline = Instant::now() + Duration::from_secs(10);
    while fx.deliveries() < deliveries {
        assert!(
            Instant::now() < deadline,
            "the backend never received delivery {deliveries}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    handle.abort();
    let _ = handle.await;
    fx.open_gate();
}

/// IDEM.5, meta route. "A broken response stream loses the in-flight request;
/// clients MUST re-issue it as a new request with a new request ID." A keyed
/// side-effecting `gateway_invoke` is killed mid-flight and re-issued under a
/// new id and the same key: the effect occurred exactly once, and the re-issue
/// is answered from the admission lease (HTTP 409), not by a second delivery.
#[tokio::test]
async fn idem5_meta_killed_side_effecting_call_executes_once() {
    let fx = fixture(IdempotencyKeyMode::Optional).await;
    kill_mid_flight(&fx, "/mcp", &invoke(1, "w", Some(KEY)), 1).await;

    let (status, body) = send(&fx, "/mcp", &invoke(2, "w", Some(KEY))).await;

    assert_eq!(fx.deliveries(), 1, "the re-issue re-executed: {body}");
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body.contains("Secured execution result is unavailable") && !body.contains("done"),
        "the re-issue must not be a fresh success: {body}"
    );
}

/// IDEM.5, direct route. Same sentence as the meta cell, on `POST /mcp/alpha`:
/// the re-issue with a new id and the same key is answered from the stored
/// uncertain outcome, and the backend saw the call once.
#[tokio::test]
async fn idem5_direct_killed_side_effecting_call_executes_once() {
    let fx = fixture(IdempotencyKeyMode::Optional).await;
    kill_mid_flight(&fx, "/mcp/alpha", &call(1, "w", &json!({}), Some(KEY)), 1).await;

    let (_, body) = send(&fx, "/mcp/alpha", &call(2, "w", &json!({}), Some(KEY))).await;

    assert_eq!(fx.deliveries(), 1, "the re-issue re-executed: {body}");
    let answer: Value = serde_json::from_str(&body).expect("the re-issue answers JSON");
    assert_eq!(
        answer.pointer("/result/isError"),
        Some(&Value::Bool(true)),
        "the re-issue must carry the stored uncertain outcome: {body}"
    );
    assert!(
        body.contains("outcome is unknown"),
        "the stored outcome names itself uncertain: {body}"
    );
}

/// IDEM.6. "The mitigation is not paid for where it buys nothing": under
/// `server.idempotency_key: required` a keyless side-effecting call is
/// refused (the control), yet the operator-classified read-only `t`, sent
/// keyless as a client sends a read, is killed mid-flight and its re-issue
/// under a new id reaches the backend again and returns the normal result.
#[tokio::test]
async fn idem6_read_only_call_is_unaffected_by_the_kill() {
    let fx = fixture(IdempotencyKeyMode::Required).await;
    // Bounded: a refusal answers at once, while a call that is wrongly admitted
    // parks at the closed gate, so a missing refusal fails here, never hangs.
    let control = send(&fx, "/mcp", &invoke(9, "w", None));
    let (status, refused) = tokio::time::timeout(Duration::from_secs(5), control)
        .await
        .expect("a keyless side-effecting call must be refused at once, not dispatched");
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(refused.contains("idempotency key is required"), "{refused}");
    assert_eq!(fx.deliveries(), 0, "the refused call was delivered");

    kill_mid_flight(&fx, "/mcp", &invoke(1, "t", None), 1).await;
    let (status, body) = send(&fx, "/mcp", &invoke(2, "t", None)).await;

    assert_eq!(fx.deliveries(), 2, "the read was not re-sent: {body}");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("done"), "the normal result: {body}");
}
