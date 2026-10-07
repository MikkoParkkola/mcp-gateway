// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2190: the direct `POST /mcp/{name}` route resolves an account-bound
//! backend's credential for the caller the request established, through the
//! same sole-operator predicate `gateway_invoke` uses (#1961).
//!
//! The gateway is the managed-account fixture (production compile, install and
//! custody) mounted behind the real router and auth middleware.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::StatusCode;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use crate::backend::PoolKey;
use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway, OPERATOR_TOKEN,
};
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;

const NOT_CONNECTED: &str = "no connected account";
const NO_IDENTITY: &str = "no verified end-user identity";
const OPERATOR_KEY: &str = "sole-operator-key";

fn key(name: &str, secret: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// Auth on and `single_user` asserted, with `keys` and `public_paths`.
fn auth(keys: Vec<ApiKeyConfig>, public_paths: &[&str]) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: keys,
        single_user: true,
        public_paths: public_paths.iter().map(|p| (*p).to_string()).collect(),
        ..AuthConfig::default()
    }
}

/// One key: the deployment's sole operator.
fn sole_operator() -> AuthConfig {
    auth(vec![key("operator", OPERATOR_KEY)], &[])
}

struct Fx {
    router: axum::Router,
    gateway: DirectAccountGateway,
    log_path: std::path::PathBuf,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

async fn fixture(auth: AuthConfig, binding: &Binding) -> Fx {
    let audit = tempfile::tempdir().unwrap();
    let log_path = audit.path().join("audit.jsonl");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: log_path.to_string_lossy().into_owned(),
            key_id: "2190".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    let mut gateway = DirectAccountGateway::new(auth.clone(), binding);
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    // The direct route looks the backend up in the SAME registry the
    // Meta-MCP resolves against, as in the real gateway.
    state_mut.backends = gateway.backends();
    let mut meta = gateway.take_meta();
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    Fx {
        router: create_router(state),
        gateway,
        log_path,
        _dirs: (audit, store),
    }
}

async fn post(fx: &Fx, body: &Value, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json");
    if let Some(secret) = bearer {
        builder = builder.header("authorization", format!("Bearer {secret}"));
    }
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn tools_call() -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
           "params": {"name": "read", "arguments": {"folder": "inbox"}}})
}

/// The refusal a `tools/call` from `bearer` gets, asserted to be the direct
/// route's 403 / -32003, with no request reaching the backend.
async fn refused(fx: &Fx, bearer: Option<&str>) -> String {
    let (status, body) = post(fx, &tools_call(), bearer).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32003, "{body}");
    assert_eq!(fx.gateway.dispatched(), 0, "a refusal reached the backend");
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// D1, the fail-fast check. The single-user operator reaches custody, whose
/// own refusal is that nothing is connected yet, not the identity refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d1_single_user_operator_reaches_custody_on_the_direct_route() {
    let fx = fixture(sole_operator(), &Binding::Unconnected).await;
    let message = refused(&fx, Some(OPERATOR_KEY)).await;
    assert!(
        message.contains(NOT_CONNECTED) && !message.contains(NO_IDENTITY),
        "the operator must reach custody, not the identity refusal: {message}"
    );
}

/// D2. Two keys are two people, whatever `single_user` claims.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d2_multi_key_caller_is_still_refused_on_the_direct_route() {
    let keys = vec![key("key-a", "scoped-key-a"), key("key-b", "scoped-key-b")];
    let fx = fixture(auth(keys, &[]), &Binding::Connected).await;
    let message = refused(&fx, Some("scoped-key-b")).await;
    assert!(
        message.contains(NO_IDENTITY) && !message.contains(NOT_CONNECTED),
        "{message}"
    );
}

/// D3. A caller that presented nothing on a public path is never the sole
/// operator, even on a sole-operator deployment with a connected grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d3_anonymous_public_path_caller_is_refused_on_the_direct_route() {
    let keys = vec![key("operator", OPERATOR_KEY)];
    let fx = fixture(auth(keys, &["/mcp"]), &Binding::Connected).await;
    let message = refused(&fx, None).await;
    assert!(
        message.contains(NO_IDENTITY) && !message.contains(NOT_CONNECTED),
        "{message}"
    );
}

/// D6. With a connected grant the operator's call is dispatched under that
/// grant's token, on that grant's per-user slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d6_single_user_operator_is_served_the_grant_on_the_direct_route() {
    let fx = fixture(sole_operator(), &Binding::Connected).await;
    let (status, body) = post(&fx, &tools_call(), Some(OPERATOR_KEY)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    let calls = fx.gateway.tool_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let (authorization, identity_key) = &calls[0];
    assert_eq!(
        authorization.as_deref(),
        Some(format!("Bearer {OPERATOR_TOKEN}").as_str())
    );
    assert_eq!(
        identity_key.as_deref(),
        Some(DirectAccountGateway::operator_binding().as_str())
    );
}

/// D7. Only a managed account consults the sole-operator assertion: a
/// signed-assertion backend still needs a verified identity, even for the
/// operator.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d7_operator_without_identity_is_refused_on_a_non_account_backend() {
    let fx = fixture(sole_operator(), &Binding::Propagation).await;
    let message = refused(&fx, Some(OPERATOR_KEY)).await;
    assert!(message.contains(NO_IDENTITY), "{message}");
}

/// Records which slot a notification was delivered on.
struct NotifySlot {
    label: &'static str,
    seen: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for NotifySlot {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Err(crate::Error::Transport(
            "notification-only fixture".to_string(),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        self.seen.lock().push(self.label);
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// D4. A notification from the operator lands in the upstream session bucket
/// the operator's requests use, not the shared one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d4_operator_notification_lands_on_the_operator_slot() {
    let fx = fixture(sole_operator(), &Binding::Connected).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let slot = |label| {
        Arc::new(NotifySlot {
            label,
            seen: Arc::clone(&seen),
        }) as Arc<dyn crate::transport::Transport>
    };
    let backend = fx.gateway.backends().get(BACKEND).expect("registered");
    backend.set_transport_for_test(slot("shared"));
    let binding = DirectAccountGateway::operator_binding();
    backend.set_pooled_transport_for_test(&PoolKey::PerUser { binding }, slot("operator"));

    let note = json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed",
                      "params": {"requestId": 7}});
    let (status, body) = post(&fx, &note, Some(OPERATOR_KEY)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(*seen.lock(), vec!["operator"]);
}

/// D5. The direct route's own refusal record names the principal the request
/// was resolved for, the same subject the resolver records.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d5_direct_refusal_audit_names_the_sole_operator() {
    let fx = fixture(sole_operator(), &Binding::Unconnected).await;
    refused(&fx, Some(OPERATOR_KEY)).await;
    let raw = std::fs::read_to_string(&fx.log_path).unwrap_or_default();
    let subjects: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["action"] == "idp_refuse" && entry["backend"] == BACKEND)
        .map(|entry| entry["subject"].clone())
        .collect();
    // Two records, the resolver's and the direct route's own: a lost direct
    // record must fail here, not pass on the resolver's alone.
    assert_eq!(subjects.len(), 2, "{raw}");
    let operator = DirectAccountGateway::operator_subject();
    assert!(
        subjects.iter().all(|subject| *subject == operator.as_str()),
        "every refusal record must name the sole operator: {subjects:?}"
    );
}
