// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7546: the direct route's `tools/list` is served from the caller's slot.
//!
//! Its own file because `router/tests.rs` is over the 800-line ceiling and the
//! gate ratchets. The upstream here answers per credential, so "alpha saw its
//! own tools" can only pass because the fetch carried alpha's credential.

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
struct PerIdentityMint;

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

/// Serves `<subject>_tool` to a minted credential and `static_tool` to none,
/// recording `(method, binding)` for every request it receives.
#[derive(Default)]
struct PerIdentityWire {
    seen: parking_lot::Mutex<Vec<(String, Option<String>)>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for PerIdentityWire {
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
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen
            .lock()
            .push((method.to_string(), identity_key.map(str::to_string)));
        let tool = extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.strip_prefix("Bearer minted-for-"))
            .map_or_else(|| "static_tool".to_string(), |s| format!("{s}_tool"));
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({ "tools": [{
                "name": tool,
                "description": "fixture tool",
                "inputSchema": { "type": "object" }
            }] }),
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

fn transparency_logger() -> Arc<crate::security::TransparencyLogger> {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file);
    Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path,
                key_id: "mik-7546".to_string(),
                shared_secret: String::new(),
            },
        ))
        .expect("transparency logger opens"),
    )
}

/// A direct-route gateway with one `per_user` propagating backend, `ledger`.
async fn gateway(required: bool) -> (axum::Router, Arc<PerIdentityWire>, tempfile::TempDir) {
    let wire = Arc::new(PerIdentityWire::default());
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "ledger".to_string(),
                required,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    for binding in ["alpha@ledger", "beta@ledger"] {
        backend.set_pooled_transport_for_test(
            &PoolKey::PerUser {
                binding: binding.to_string(),
            },
            Arc::clone(&wire) as Arc<dyn crate::transport::Transport>,
        );
    }

    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.set_identity_propagation(Arc::new(PerIdentityMint));
    meta.enable_transparency_log(transparency_logger());
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(transparency_logger());
    (create_router(state), wire, store)
}

async fn post(router: &axum::Router, method: &str, subject: Option<&str>) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": method }).to_string(),
        ))
        .unwrap();
    if let Some(subject) = subject {
        // Auth is disabled in this state, so the middleware leaves it in place.
        request.extensions_mut().insert(VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@example.invalid"),
            name: None,
            groups: vec![],
            issuer: "https://idp.example.invalid".to_string(),
        });
    }
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn tool_names(body: &Value) -> Vec<String> {
    body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list answered without tools: {body}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

fn listed(method: &str, binding: Option<&str>) -> (String, Option<String>) {
    (method.to_string(), binding.map(str::to_string))
}

#[tokio::test]
async fn two_identified_callers_list_from_their_own_slots() {
    let (router, wire, _store) = gateway(true).await;

    let (status, alpha) = post(&router, "tools/list", Some("alpha")).await;
    assert_eq!(status, StatusCode::OK, "{alpha}");
    let (status, beta) = post(&router, "tools/list", Some("beta")).await;
    assert_eq!(status, StatusCode::OK, "{beta}");

    assert_eq!(tool_names(&alpha), ["alpha_tool"], "alpha got another view");
    assert_eq!(tool_names(&beta), ["beta_tool"], "beta got another view");
    assert_eq!(
        *wire.seen.lock(),
        [
            listed("tools/list", Some("alpha@ledger")),
            listed("tools/list", Some("beta@ledger")),
        ],
        "each caller's list must run on that caller's binding"
    );
}

#[tokio::test]
async fn an_unidentified_caller_still_lists_the_shared_catalogue() {
    // IDP.5: a non-required backend with no identity keeps the static view.
    let (router, wire, _store) = gateway(false).await;

    let (status, body) = post(&router, "tools/list", None).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(tool_names(&body), ["static_tool"]);
    assert_eq!(*wire.seen.lock(), [listed("tools/list", None)]);
}

#[tokio::test]
async fn a_required_backend_refuses_tools_list_without_an_identity() {
    let (router, wire, _store) = gateway(true).await;

    let (status, body) = post(&router, "tools/list", None).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32003, "{body}");
    assert!(
        wire.seen.lock().is_empty(),
        "the refused list reached the wire"
    );
}

#[tokio::test]
async fn handshake_methods_stay_exempt_on_a_required_backend() {
    let (router, wire, _store) = gateway(true).await;

    for method in ["initialize", "ping"] {
        let (status, body) = post(&router, method, None).await;
        assert_eq!(status, StatusCode::OK, "{method} was refused: {body}");
    }
    assert_eq!(
        *wire.seen.lock(),
        [listed("initialize", None), listed("ping", None)]
    );
}
