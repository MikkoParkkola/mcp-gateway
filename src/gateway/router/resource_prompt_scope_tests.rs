// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The resource and prompt methods on the meta route answer to the same
//! per-backend authorization `tools/call` does.
//!
//! Its own file because `router/tests.rs` is over the 800-line ceiling and the
//! gate ratchets. Every case goes through the HTTP router, so the scope under
//! test is the one the auth middleware attached to the request.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::direct_route_state_with_identity;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::ResolvedAuthConfig;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId};

/// A backend upstream that serves one resource and one prompt named after
/// itself, and records every method it was asked.
struct CatalogueWire {
    name: &'static str,
    seen: parking_lot::Mutex<Vec<String>>,
}

impl CatalogueWire {
    fn saw(&self, method: &str) -> bool {
        self.seen.lock().iter().any(|m| m == method)
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for CatalogueWire {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen.lock().push(method.to_string());
        let name = self.name;
        let body = match method {
            "resources/list" => json!({ "resources": [{ "uri": uri_of(name), "name": name }] }),
            "prompts/list" => json!({ "prompts": [{ "name": "greet" }] }),
            "resources/read" => json!({ "contents": [{ "uri": uri_of(name), "text": name }] }),
            "prompts/get" => json!({ "messages": [] }),
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
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

fn uri_of(backend: &str) -> String {
    format!("mem://{backend}/doc")
}

fn api_key(key: &str, backends: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: key.to_string(),
        name: key.to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// `required: true`: no best-effort downgrade exists for this backend.
fn required_propagation() -> BackendConfig {
    BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "ledger".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..Default::default()
    }
}

struct Fixture {
    router: axum::Router,
    beta: Arc<CatalogueWire>,
    gamma: Arc<CatalogueWire>,
    _store: tempfile::TempDir,
}

/// A single-user gateway: `alpha-key` may reach `alpha` only, `open-key`
/// every backend. Neither key carries an end-user identity.
async fn fixture() -> Fixture {
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig {
        enabled: true,
        api_keys: vec![
            api_key("alpha-key", &["alpha"]),
            api_key("open-key", &["*"]),
        ],
        ..Default::default()
    }));
    let mut wires = Vec::new();
    for (name, config) in [
        ("alpha", BackendConfig::default()),
        ("beta", BackendConfig::default()),
        ("gamma", required_propagation()),
    ] {
        let wire = Arc::new(CatalogueWire {
            name,
            seen: parking_lot::Mutex::new(Vec::new()),
        });
        let backend = Arc::new(Backend::new(
            name,
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
        assert!(state.backends.register(backend), "fixture registration");
        wires.push(wire);
    }
    let gamma = wires.pop().expect("gamma");
    let beta = wires.pop().expect("beta");
    Fixture {
        router: create_router(state),
        beta,
        gamma,
        _store: store,
    }
}

async fn call(
    router: &axum::Router,
    key: &str,
    method: &str,
    params: Value,
) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 5, "method": method, "params": params }).to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn listed(
    router: &axum::Router,
    key: &str,
    method: &str,
    field: &str,
    key_of: &str,
) -> Vec<String> {
    let (_, body) = call(router, key, method, json!({})).await;
    body["result"][field]
        .as_array()
        .unwrap_or_else(|| panic!("{method} must succeed: {body}"))
        .iter()
        .filter_map(|item| item[key_of].as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn scoped_caller_lists_only_its_own_backends_resources_and_prompts() {
    let f = fixture().await;

    let resources = listed(&f.router, "alpha-key", "resources/list", "resources", "uri").await;
    assert!(
        resources.contains(&uri_of("alpha")),
        "own backend listed: {resources:?}"
    );
    assert!(
        !resources.contains(&uri_of("beta")),
        "a caller scoped to alpha must not be shown beta's resources: {resources:?}"
    );
    let prompts = listed(&f.router, "alpha-key", "prompts/list", "prompts", "name").await;
    assert!(
        prompts.contains(&"alpha/greet".to_string()),
        "own prompt listed: {prompts:?}"
    );
    assert!(
        !prompts.contains(&"beta/greet".to_string()),
        "a caller scoped to alpha must not be shown beta's prompts: {prompts:?}"
    );
    assert!(
        !f.beta.saw("prompts/list"),
        "an out-of-scope backend must not be contacted to build the caller's list"
    );

    // CONTROL: an unscoped caller still sees every backend.
    let resources = listed(&f.router, "open-key", "resources/list", "resources", "uri").await;
    assert!(
        resources.contains(&uri_of("beta")),
        "unscoped sees beta: {resources:?}"
    );
    let prompts = listed(&f.router, "open-key", "prompts/list", "prompts", "name").await;
    assert!(
        prompts.contains(&"beta/greet".to_string()),
        "unscoped sees beta: {prompts:?}"
    );
}

#[tokio::test]
async fn scoped_caller_is_refused_another_backends_resources_and_prompts() {
    let f = fixture().await;
    let cases = [
        ("resources/read", json!({ "uri": uri_of("beta") })),
        ("resources/subscribe", json!({ "uri": uri_of("beta") })),
        ("prompts/get", json!({ "name": "beta/greet" })),
    ];
    for (method, params) in cases {
        let (status, body) = call(&f.router, "alpha-key", method, params.clone()).await;
        assert_eq!(
            (status, body["error"]["code"].as_i64()),
            (StatusCode::FORBIDDEN, Some(-32003)),
            "{method} on beta by a caller scoped to alpha must be refused like tools/call: {body}"
        );
        assert!(
            !f.beta.saw(method),
            "{method} reached beta for a caller not authorized for it"
        );

        // CONTROL: the unscoped caller is served.
        let (status, body) = call(&f.router, "open-key", method, params).await;
        assert!(
            status == StatusCode::OK && body.get("error").is_none(),
            "{method} on beta by an unscoped caller must succeed: {body}"
        );
    }
}

#[tokio::test]
async fn required_propagation_backend_is_refused_to_a_caller_without_identity() {
    let f = fixture().await;
    let cases = [
        ("resources/read", json!({ "uri": uri_of("gamma") })),
        ("resources/subscribe", json!({ "uri": uri_of("gamma") })),
        ("prompts/get", json!({ "name": "gamma/greet" })),
    ];
    for (method, params) in cases {
        let (_, body) = call(&f.router, "open-key", method, params).await;
        assert!(
            body.get("error").is_some(),
            "{method} on a required-propagation backend with no caller identity must be refused: {body}"
        );
        assert!(
            !f.gamma.saw(method),
            "{method} reached a required-propagation backend without the caller's identity"
        );
    }
}
