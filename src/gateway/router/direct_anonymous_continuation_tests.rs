// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659 G30: the client-visible half of the unified quota rule, through
//! the real direct route `POST /mcp/{name}`. An anonymous caller that forwards
//! a passthrough credential is bound to it, so a backend's question reaches
//! the client as a gateway continuation charged to the shared key-name quota,
//! and the retry with answers reaches the backend. An anonymous caller that
//! forwards nothing has no binding and is refused the continuation.

use axum::body::to_bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::direct_notification_credential_tests::{PASSTHROUGH, backend_config, http};
use super::tests::{direct_route_state_with_identity, modern_meta};
use crate::backend::{Backend, PoolKey};
use crate::config::FailsafeConfig;
use crate::identity_propagation::PropagationStrategyKind;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

/// `(slot, params)` for every `tools/call` a slot is handed.
type Calls = Arc<parking_lot::Mutex<Vec<(&'static str, Value)>>>;

/// A backend slot that asks one question on a fresh call and answers `ok` to a
/// retry carrying its `requestState`.
struct Asker {
    slot: &'static str,
    calls: Calls,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Asker {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(
                id,
                json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
            ));
        }
        let params = params.unwrap_or(Value::Null);
        let retry = params.get("requestState").is_some();
        self.calls.lock().push((self.slot, params));
        Ok(JsonRpcResponse::success(
            id,
            if retry {
                json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
            } else {
                json!({
                    "resultType": "input_required",
                    "inputRequests": {"k1": {"method": "elicitation/create", "params": {
                        "message": "Which account?", "requestedSchema": {"type": "object"}
                    }}},
                    "requestState": "backend-state-1"
                })
            },
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

struct Gateway {
    router: axum::Router,
    calls: Calls,
    _store: tempfile::TempDir,
    _audit: tempfile::NamedTempFile,
}

/// A single-user gateway with one optional-passthrough backend, `ledger`: its
/// shared slot, and the slot an anonymous caller forwarding `CREDENTIAL` is
/// bound to, both ask once.
async fn gateway() -> Gateway {
    use sha2::Digest as _;
    let calls = Calls::default();
    let backend = Arc::new(Backend::new(
        "ledger",
        backend_config(http(), PropagationStrategyKind::Passthrough, false),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let slot = |slot| -> Arc<dyn crate::transport::Transport> {
        Arc::new(Asker {
            slot,
            calls: Arc::clone(&calls),
        })
    };
    backend.set_transport_for_test(slot("shared"));
    let digest = hex::encode(sha2::Sha256::digest(CREDENTIAL.as_bytes()));
    let principal = crate::identity_propagation::audit_subject(None);
    let binding = crate::backend::passthrough_binding(&principal, &digest);
    backend.set_pooled_transport_for_test(&PoolKey::PerUser { binding }, slot("caller"));
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let audit = tempfile::NamedTempFile::new().expect("tempfile");
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let config = TransparencyLogConfig {
        enabled: true,
        path: audit.path().to_string_lossy().to_string(),
        key_id: "mik-8659".to_string(),
        ..TransparencyLogConfig::default()
    };
    state_mut.transparency_log = Some(Arc::new(
        TransparencyLogger::open(Arc::new(config)).expect("transparency logger opens"),
    ));
    Gateway {
        router: create_router(state),
        calls,
        _store: store,
        _audit: audit,
    }
}

const CREDENTIAL: &str = "Bearer caller-own";

/// `tools/call read` on `/mcp/ledger` with no API key, a modern request
/// declaring form elicitation, forwarding `CREDENTIAL` when `bound`, with
/// `extra` merged into the params.
async fn call(gw: &Gateway, bound: bool, extra: Value) -> Value {
    let mut params = json!({"name": "read", "arguments": {}, "_meta": modern_meta()});
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "read");
    if bound {
        builder = builder.header(PASSTHROUGH, CREDENTIAL);
    }
    let request = builder
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

/// G30 bound row: the bound anonymous caller gets a gateway continuation, never
/// the backend's state, and its retry reaches its own slot with the backend's
/// state. Base refused the mint: the direct route had no key-name quota for an
/// anonymous caller.
#[tokio::test]
async fn a_bound_anonymous_direct_caller_gets_a_continuation() {
    let gw = gateway().await;
    let asked = call(&gw, true, json!({})).await;
    assert_eq!(asked["result"]["resultType"], "input_required", "{asked}");
    let state = asked["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("a continuation: {asked}"))
        .to_owned();
    assert_ne!(state, "backend-state-1", "{asked}");
    let answers = json!({"k1": {"action": "accept", "content": {"account": "work"}}});
    let done = call(
        &gw,
        true,
        json!({"requestState": state, "inputResponses": answers}),
    )
    .await;
    assert!(done.get("error").is_none(), "{done}");
    let calls = gw.calls.lock().clone();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls.iter().all(|(slot, _)| *slot == "caller"), "{calls:?}");
    assert_eq!(calls[1].1["requestState"], "backend-state-1", "{calls:?}");
}

/// G30 unbound row: an anonymous caller forwarding nothing has no binding to
/// bind a continuation to, so the question is refused (-32003) and the
/// backend's state never reaches it.
#[tokio::test]
async fn an_unbound_anonymous_direct_caller_gets_no_continuation() {
    let gw = gateway().await;
    let asked = call(&gw, false, json!({})).await;
    assert_eq!(asked["error"]["code"], -32003, "{asked}");
    assert!(
        !asked.to_string().contains("backend-state-1"),
        "the backend's state leaked: {asked}"
    );
    let calls = gw.calls.lock().clone();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].0, "shared", "{calls:?}");
}
