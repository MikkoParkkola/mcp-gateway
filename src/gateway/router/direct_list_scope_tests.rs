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
use crate::security::{TransparencyLogConfig, TransparencyLogger};

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

/// One request as the upstream saw it: which pool slot's transport answered,
/// under which session binding, carrying whose minted credential.
#[derive(Debug, PartialEq)]
struct Hit {
    method: String,
    slot: &'static str,
    binding: Option<String>,
    subject: Option<String>,
}

fn hit(method: &str, slot: &'static str, subject: Option<&str>) -> Hit {
    Hit {
        method: method.to_string(),
        slot,
        binding: subject.map(|s| format!("{s}@ledger")),
        subject: subject.map(str::to_string),
    }
}

type Transcript = Arc<parking_lot::Mutex<Vec<Hit>>>;

/// The transport of ONE pool slot. It serves `<slot>_tool`, so a tool name in
/// a response proves which slot answered, and it records the credential it
/// was handed, so the transcript proves whose credential the fetch carried.
/// One wire per slot: a dispatch that landed on the shared slot cannot come
/// back as `alpha_tool` however its headers read.
struct SlotWire {
    slot: &'static str,
    seen: Transcript,
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
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        let subject = extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.strip_prefix("Bearer minted-for-"))
            .map(str::to_string);
        self.seen.lock().push(Hit {
            method: method.to_string(),
            slot: self.slot,
            binding: identity_key.map(str::to_string),
            subject,
        });
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({ "tools": [{
                "name": format!("{}_tool", self.slot),
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

/// A logger on `file`, which the caller keeps alive for the test's duration.
fn transparency_logger(file: &tempfile::NamedTempFile) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "mik-7546".to_string(),
        ..TransparencyLogConfig::default()
    };
    let logger = TransparencyLogger::open(Arc::new(config));
    Arc::new(logger.expect("transparency logger opens"))
}

/// A direct-route gateway with one `per_user` propagating backend, `ledger`.
/// The temp files are held here so they outlive every request the test makes.
struct Gateway {
    router: axum::Router,
    seen: Transcript,
    _store: tempfile::TempDir,
    _audit: [tempfile::NamedTempFile; 2],
}

async fn gateway(required: bool) -> Gateway {
    let seen = Transcript::default();
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
    let wire = |slot| -> Arc<dyn crate::transport::Transport> {
        Arc::new(SlotWire {
            slot,
            seen: Arc::clone(&seen),
        })
    };
    backend.set_transport_for_test(wire("shared"));
    for subject in ["alpha", "beta"] {
        let key = PoolKey::PerUser {
            binding: format!("{subject}@ledger"),
        };
        backend.set_pooled_transport_for_test(&key, wire(subject));
    }

    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let meta_audit = tempfile::NamedTempFile::new().expect("tempfile");
    let route_audit = tempfile::NamedTempFile::new().expect("tempfile");
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.set_identity_propagation(Arc::new(PerIdentityMint));
    meta.enable_transparency_log(transparency_logger(&meta_audit));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(transparency_logger(&route_audit));
    Gateway {
        router: create_router(state),
        seen,
        _store: store,
        _audit: [meta_audit, route_audit],
    }
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

#[tokio::test]
async fn two_identified_callers_list_from_their_own_slots() {
    let gw = gateway(true).await;

    let (status, alpha) = post(&gw.router, "tools/list", Some("alpha")).await;
    assert_eq!(status, StatusCode::OK, "{alpha}");
    let (status, beta) = post(&gw.router, "tools/list", Some("beta")).await;
    assert_eq!(status, StatusCode::OK, "{beta}");

    assert_eq!(tool_names(&alpha), ["alpha_tool"], "alpha got another view");
    assert_eq!(tool_names(&beta), ["beta_tool"], "beta got another view");
    assert_eq!(
        *gw.seen.lock(),
        [
            hit("tools/list", "alpha", Some("alpha")),
            hit("tools/list", "beta", Some("beta")),
        ],
        "each caller's list must run on its own slot with its own credential"
    );
}

#[tokio::test]
async fn an_unidentified_caller_still_lists_the_shared_catalogue() {
    // IDP.5: a non-required backend with no identity keeps the static view.
    let gw = gateway(false).await;

    let (status, body) = post(&gw.router, "tools/list", None).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(tool_names(&body), ["shared_tool"]);
    assert_eq!(*gw.seen.lock(), [hit("tools/list", "shared", None)]);
}

#[tokio::test]
async fn a_required_backend_refuses_tools_list_without_an_identity() {
    let gw = gateway(true).await;

    let (status, body) = post(&gw.router, "tools/list", None).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32003, "{body}");
    // The reason, not just the status: a 403 from another gate must not pass.
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("required") && message.contains("no verified end-user identity"),
        "refused for another reason: {body}"
    );
    assert!(
        gw.seen.lock().is_empty(),
        "the refused list reached the wire"
    );
}

#[tokio::test]
async fn handshake_methods_stay_exempt_on_a_required_backend() {
    let gw = gateway(true).await;

    for method in ["initialize", "ping"] {
        let (status, body) = post(&gw.router, method, None).await;
        assert_eq!(status, StatusCode::OK, "{method} was refused: {body}");
    }
    assert_eq!(
        *gw.seen.lock(),
        [
            hit("initialize", "shared", None),
            hit("ping", "shared", None),
        ]
    );
}
