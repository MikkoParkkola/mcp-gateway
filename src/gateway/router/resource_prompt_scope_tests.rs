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
    /// Every method this upstream was asked, in order.
    fn transcript(&self) -> Vec<String> {
        self.seen.lock().clone()
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
            "resources/templates/list" => json!({
                "resourceTemplates": [{ "uriTemplate": format!("mem://{name}/{{id}}"), "name": name }]
            }),
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
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: key.to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// `required: true`: no best-effort downgrade exists for this backend.
///
/// HTTP so the transport can carry a minted header: on stdio the resolver
/// refuses for that reason first, and the refusal under test would never be
/// the one about the missing identity.
fn required_propagation() -> BackendConfig {
    BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "https://ledger.invalid/mcp".to_string(),
            streamable_http: true,
            protocol_version: None,
        },
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

/// A URI no backend owns, for the "indistinguishable from absent" oracle.
const NOWHERE: &str = "mem://nowhere/doc";

/// A response with the requested URI blanked, so an answer about one URI can
/// be compared with the answer about another.
async fn answer_for(
    router: &axum::Router,
    key: &str,
    method: &str,
    uri: &str,
) -> (StatusCode, String) {
    let (status, body) = call(router, key, method, json!({ "uri": uri })).await;
    (status, body["error"].to_string().replace(uri, "<uri>"))
}

#[tokio::test]
async fn scoped_caller_lists_only_its_own_backends_resources_and_prompts() {
    let f = fixture().await;
    let lists = [
        (
            "resources/list",
            "resources",
            "uri",
            uri_of("alpha"),
            uri_of("beta"),
        ),
        (
            "resources/templates/list",
            "resourceTemplates",
            "name",
            "alpha".to_string(),
            "beta".to_string(),
        ),
        (
            "prompts/list",
            "prompts",
            "name",
            "alpha/greet".to_string(),
            "beta/greet".to_string(),
        ),
    ];
    for (method, field, key_of, own, other) in &lists {
        let items = listed(&f.router, "alpha-key", method, field, key_of).await;
        assert!(
            items.contains(own),
            "{method}: own backend listed: {items:?}"
        );
        assert!(
            !items.contains(other),
            "{method}: a caller scoped to alpha must not be shown beta's items: {items:?}"
        );
    }
    assert_eq!(
        f.beta.transcript(),
        Vec::<String>::new(),
        "an out-of-scope backend must not be contacted to build the caller's lists"
    );

    // CONTROL: an unscoped caller still sees every backend.
    for (method, field, key_of, _, other) in &lists {
        let items = listed(&f.router, "open-key", method, field, key_of).await;
        assert!(
            items.contains(other),
            "{method}: unscoped sees beta: {items:?}"
        );
    }
}

#[tokio::test]
async fn scoped_caller_cannot_reach_or_detect_another_backends_resources_and_prompts() {
    let f = fixture().await;
    // `resources/subscribe` and `unsubscribe` are refused before any URI is
    // resolved (F24; `router::tests::f24_resource_subscribe`), so read is the
    // one verb left that can probe a URI.
    let uri_methods = ["resources/read"];
    for method in uri_methods {
        // An out-of-scope URI answers exactly like one nobody owns: neither
        // the backend nor the URI's existence may be probed across scopes.
        let absent = answer_for(&f.router, "alpha-key", method, NOWHERE).await;
        let out_of_scope = answer_for(&f.router, "alpha-key", method, &uri_of("beta")).await;
        assert!(
            absent.1.contains("-32602"),
            "{method} on an unowned URI: {absent:?}"
        );
        assert_eq!(
            out_of_scope, absent,
            "{method}: beta's URI must be indistinguishable from an absent one to a caller \
             scoped to alpha"
        );
    }
    let (status, body) = call(
        &f.router,
        "alpha-key",
        "prompts/get",
        json!({ "name": "beta/greet" }),
    )
    .await;
    assert_eq!(
        (status, body["error"]["code"].as_i64()),
        (StatusCode::FORBIDDEN, Some(-32003)),
        "prompts/get on beta by a caller scoped to alpha must be refused like tools/call: {body}"
    );
    assert_eq!(
        f.beta.transcript(),
        Vec::<String>::new(),
        "beta must not be contacted at all, ownership lookup included, for a caller not \
         authorized for it"
    );

    // CONTROL: the unscoped caller is served.
    let controls = uri_methods
        .map(|m| (m, json!({ "uri": uri_of("beta") })))
        .into_iter()
        .chain([("prompts/get", json!({ "name": "beta/greet" }))]);
    for (method, params) in controls {
        let (status, body) = call(&f.router, "open-key", method, params).await;
        assert!(
            status == StatusCode::OK && body.get("error").is_none(),
            "{method} on beta by an unscoped caller must succeed: {body}"
        );
    }
}

#[tokio::test]
async fn required_propagation_backend_is_not_reached_without_the_callers_identity() {
    let f = fixture().await;
    // Its catalogue is not listed either: a list fill for a caller without
    // identity would go out over the shared session.
    for (method, field, key_of) in [
        ("resources/list", "resources", "uri"),
        ("resources/templates/list", "resourceTemplates", "name"),
        ("prompts/list", "prompts", "name"),
    ] {
        let items = listed(&f.router, "open-key", method, field, key_of).await;
        assert!(
            !items.iter().any(|item| item.contains("gamma")),
            "{method}: the required-propagation backend is omitted for a caller without identity: \
             {items:?}"
        );
    }
    for method in ["resources/read"] {
        // Its catalogue is never read over the shared session, so its URI
        // resolves like an absent one rather than being forwarded.
        let absent = answer_for(&f.router, "open-key", method, NOWHERE).await;
        let gamma = answer_for(&f.router, "open-key", method, &uri_of("gamma")).await;
        assert_eq!(
            gamma, absent,
            "{method} on the required-propagation backend's URI"
        );
    }
    let (_, body) = call(
        &f.router,
        "open-key",
        "prompts/get",
        json!({ "name": "gamma/greet" }),
    )
    .await;
    // The identity resolver's refusal, not any error: a backend that failed
    // to resolve answers -32001 and names neither.
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        body["error"]["code"] == -32603
            && message.contains("identity propagation required for backend 'gamma'")
            && message.contains("no verified end-user identity"),
        "prompts/get on a required-propagation backend must be refused for the missing \
         caller identity: {body}"
    );
    assert_eq!(
        f.gamma.transcript(),
        Vec::<String>::new(),
        "a required-propagation backend must not be contacted without the caller's identity, \
         ownership lookup included"
    );
}
