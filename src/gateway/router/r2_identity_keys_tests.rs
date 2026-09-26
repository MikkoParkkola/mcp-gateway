// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.SCHEMA.1 (R2), design §D: the slot a per-identity caller's
//! `tools/list` fills is the slot its `tools/call` is judged against.
//!
//! The backend propagates identity per user, so each caller lists and calls
//! over its own pool slot. If the list-side binding and the call-side
//! `identity_key` differed, the call would read a cold slot and be forwarded
//! unchecked; these rows fail in exactly that case.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::direct_route_state_with_identity;
use crate::backend::{Backend, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::test_helpers::MetaMcp;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Mints `Bearer minted-for-<subject>` bound to `<subject>@<audience>`.
pub(super) struct PerIdentityMint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for PerIdentityMint {
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

type Seen = Arc<parking_lot::Mutex<Vec<String>>>;

/// One pool slot's wire: serves the `edit` tool, records each method it saw.
struct SlotWire {
    seen: Seen,
}

#[async_trait::async_trait]
impl crate::transport::Transport for SlotWire {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Permitted,
        )
        .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen.lock().push(method.to_string());
        let schema = json!({"type": "object", "properties": {"edits": {"type": "array",
            "items": {"type": "object",
                "properties": {"oldText": {"type": "string"}, "newText": {"type": "string"}}}}}});
        let result = match method {
            "tools/list" => json!({"tools": [{
                "name": "edit", "description": "fixture", "inputSchema": schema
            }]}),
            _ => json!({"content": [{"type": "text", "text": "done"}]}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), result))
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

/// Gateway with one per-user propagating backend, `edits`; the alpha slot's
/// wire records what alpha's credential reached.
struct Gateway {
    router: axum::Router,
    alpha: Seen,
    shared: Seen,
    _store: tempfile::TempDir,
    _audit: [tempfile::NamedTempFile; 2],
}

/// A logger on `file`. A per-user mint is refused without an audit sink, so
/// the fixture needs one on each route that mints.
pub(super) fn transparency_logger(
    file: &tempfile::NamedTempFile,
) -> Arc<crate::security::TransparencyLogger> {
    let config = crate::security::TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "r2".to_string(),
        shared_secret: String::new(),
    };
    let logger = crate::security::TransparencyLogger::open(Arc::new(config));
    Arc::new(logger.expect("transparency logger opens"))
}

async fn gateway() -> Gateway {
    let backend = Arc::new(Backend::new(
        "edits",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "edits".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let (alpha, shared) = (Seen::default(), Seen::default());
    backend.set_transport_for_test(Arc::new(SlotWire {
        seen: Arc::clone(&shared),
    }));
    let key = PoolKey::PerUser {
        binding: "alpha@edits".to_string(),
    };
    backend.set_pooled_transport_for_test(
        &key,
        Arc::new(SlotWire {
            seen: Arc::clone(&alpha),
        }),
    );
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let (meta_audit, route_audit) = (
        tempfile::NamedTempFile::new().expect("tempfile"),
        tempfile::NamedTempFile::new().expect("tempfile"),
    );
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.set_identity_propagation(Arc::new(PerIdentityMint));
    meta.enable_transparency_log(transparency_logger(&meta_audit));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(transparency_logger(&route_audit));
    Gateway {
        router: create_router(state),
        alpha,
        shared,
        _store: store,
        _audit: [meta_audit, route_audit],
    }
}

async fn post_as_alpha(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    // Auth is disabled in this state, so the middleware leaves it in place.
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.invalid".to_string(),
    });
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn meta_call(tool: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 21, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}})
}

fn invented() -> Value {
    json!({"edits": [{"oldText": "a", "newText": "b", "type": "replace"}]})
}

/// The refusal as the caller reads it, through `gateway_invoke`'s envelope
/// or as the direct route's JSON-RPC result.
fn refused(body: &Value) -> bool {
    let text = body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    let inner = serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
    let result = if inner.get("isError").is_some() {
        &inner
    } else {
        &body["result"]
    };
    result["isError"] == json!(true) && result.to_string().contains("edits[0].type")
}

/// Design §D on the Meta-MCP route: alpha lists through `gateway_list_tools`,
/// then its invented nested key is refused from that same slot.
#[tokio::test]
async fn per_identity_meta_list_warms_the_slot_the_call_is_judged_against() {
    let gw = gateway().await;
    let (_, listed) = post_as_alpha(
        &gw.router,
        "/mcp",
        meta_call("gateway_list_tools", &json!({"server": "edits"})),
    )
    .await;
    assert!(
        listed.to_string().contains("\\\"edit\\\""),
        "alpha did not list: {listed}"
    );
    assert!(
        gw.alpha.lock().iter().any(|m| m == "tools/list"),
        "list missed alpha's slot"
    );

    let args = json!({"server": "edits", "tool": "edit", "arguments": invented()});
    let (_, body) = post_as_alpha(&gw.router, "/mcp", meta_call("gateway_invoke", &args)).await;
    assert!(refused(&body), "forwarded instead of refused: {body}");
    let calls = |seen: &Seen| seen.lock().iter().filter(|m| *m == "tools/call").count();
    assert_eq!(
        calls(&gw.alpha) + calls(&gw.shared),
        0,
        "the backend saw the call"
    );
}

/// Design §D on the direct route: alpha's own `tools/list` warms the slot its
/// `tools/call` is judged against.
#[tokio::test]
async fn per_identity_direct_list_warms_the_slot_the_call_is_judged_against() {
    let gw = gateway().await;
    let list = json!({"jsonrpc": "2.0", "id": 22, "method": "tools/list"});
    let (status, _) = post_as_alpha(&gw.router, "/mcp/edits", list).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        gw.alpha.lock().iter().any(|m| m == "tools/list"),
        "list missed alpha's slot"
    );

    let call = json!({"jsonrpc": "2.0", "id": 23, "method": "tools/call",
        "params": {"name": "edit", "arguments": invented()}});
    let (_, body) = post_as_alpha(&gw.router, "/mcp/edits", call).await;
    assert!(refused(&body), "forwarded instead of refused: {body}");
    let calls = |seen: &Seen| seen.lock().iter().filter(|m| *m == "tools/call").count();
    assert_eq!(
        calls(&gw.alpha) + calls(&gw.shared),
        0,
        "the backend saw the call"
    );
}
