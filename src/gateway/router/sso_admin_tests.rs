// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E1 (4.0.0, MIK-7570.ADMINSSO.1): an SSO identity named by an issuer-scoped
//! `role: admin` rule is a gateway admin on every surface.
//!
//! Its own file because `router/tests.rs` is over the size ceiling. Requests
//! go through `create_router`, so the real `auth_middleware` resolves each
//! credential. Two loopback ES256 identity providers (issuers A and B) serve
//! their JWKS through the verifier's test HTTP seam. Every token carries the
//! group `staff`, which the key-server policy admits; the role rule keys on a
//! different group, so admission and admin are decided apart.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::StatusCode;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::AppState;
use super::create_router;
use super::tests::test_router_app_state_with_auth_and_key_server;
use crate::config::{
    ApiKeyConfig, AuthConfig, KeyServerConfig, KeyServerPolicyConfig, KeyServerProviderConfig,
    PolicyMatchConfig, PolicyScopesConfig,
};
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::key_server::OidcVerifier;

const ISS_A: &str = "https://idp-a.example";
const ISS_B: &str = "https://idp-b.example";
const AUD: &str = "gateway";
const STANDARD_KEY: &str = "e1-standard-key";
const ADMIN_KEY: &str = "e1-admin-key";
const BEARER: &str = "e1-static-bearer";
/// The rule every admin cell starts from.
const ADMIN_GROUP_RULE: &str =
    "{ issuer: \"https://idp-a.example\", group: ops-admins, role: admin }";

/// One identity provider: a signing key and a loopback JWKS endpoint.
struct Idp {
    key: Arc<GatewayKeyPair>,
    jwks_uri: String,
    issuer: &'static str,
}

impl Idp {
    async fn start(issuer: &'static str) -> Self {
        let key = Arc::new(GatewayKeyPair::generate().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/jwks", axum::routing::get(jwks_handler))
            .with_state(Arc::clone(&key));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            key,
            jwks_uri: format!("http://{addr}/jwks"),
            issuer,
        }
    }

    fn provider(&self) -> KeyServerProviderConfig {
        KeyServerProviderConfig {
            issuer: self.issuer.to_string(),
            jwks_uri: Some(self.jwks_uri.clone()),
            discovery_url: None,
            auto_discover: false,
            audiences: vec![AUD.to_string()],
            allowed_domains: Vec::new(),
        }
    }

    /// A fresh ID token for `sub` in `groups` (plus `staff`), with `claims`
    /// merged over the defaults.
    fn token(&self, sub: &str, groups: &[&str], claims: &Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut groups: Vec<&str> = groups.to_vec();
        groups.push("staff");
        let mut body = json!({
            "iss": self.issuer, "sub": sub, "aud": AUD,
            "groups": groups, "iat": now - 5, "exp": now + 3600,
        });
        for (k, v) in claims.as_object().into_iter().flatten() {
            body[k] = v.clone();
        }
        let info = self.key.key_info();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(info.kid.clone());
        let encoding = EncodingKey::from_ec_pem(info.private_key_pem.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &body, &encoding).unwrap()
    }
}

fn staff_policy(issuer: &str) -> KeyServerPolicyConfig {
    KeyServerPolicyConfig {
        match_criteria: PolicyMatchConfig {
            domain: None,
            issuer: issuer.to_string(),
            email: None,
            group: Some("staff".to_string()),
        },
        scopes: PolicyScopesConfig {
            backends: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            rate_limit: 0,
        },
    }
}

fn api_key(key: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: key.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
    }
}

/// A gateway with auth on, a static bearer, one admin and one standard key, a
/// key server trusting issuers A and B, and `rules` as the role mapping.
struct Gateway {
    state: Arc<AppState>,
    _store: tempfile::TempDir,
    a: Idp,
    b: Idp,
}

async fn gateway(rules: &[&str]) -> Gateway {
    let (a, b) = (Idp::start(ISS_A).await, Idp::start(ISS_B).await);
    let config = KeyServerConfig {
        enabled: true,
        delegated_bearer: true,
        oidc: vec![a.provider(), b.provider()],
        policies: vec![staff_policy(ISS_A), staff_policy(ISS_B)],
        max_oidc_token_age_secs: 300,
        ..KeyServerConfig::default()
    };
    let key_server = crate::key_server::KeyServer {
        store: Arc::new(crate::key_server::InMemoryTokenStore::new()),
        oidc: Arc::new(OidcVerifier::with_http_client(
            config.oidc.clone(),
            reqwest::Client::new(),
        )),
        policy: Arc::new(crate::key_server::policy::PolicyEngine::new(
            config.policies.clone(),
        )),
        config,
    };
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![api_key(STANDARD_KEY, false), api_key(ADMIN_KEY, true)],
        ..AuthConfig::default()
    };
    let (state, store) =
        test_router_app_state_with_auth_and_key_server(&auth, Some(Arc::new(key_server))).await;
    set_rules(&state, rules);
    Gateway {
        state,
        _store: store,
        a,
        b,
    }
}

/// Publish `rules` as `control_plane.role_mapping`, as a reload would.
fn set_rules(state: &AppState, rules: &[&str]) {
    let yaml = if rules.is_empty() {
        "rules: []".to_string()
    } else {
        format!("rules: [{}]", rules.join(", "))
    };
    let mut config = (*state.live_config.get()).clone();
    config.control_plane.role_mapping = serde_yaml::from_str(&yaml).expect("rules parse");
    config
        .control_plane
        .role_mapping
        .validate()
        .expect("rules are valid");
    state.live_config.set(config);
}

async fn send(
    state: &Arc<AppState>,
    request: axum::http::Request<axum::body::Body>,
) -> (StatusCode, Value) {
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn rpc(bearer: &str, method: &str, params: &Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::post("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string(),
        ))
        .unwrap()
}

/// What an admin meta-tool call and the tool list say about `bearer`.
#[derive(Debug, PartialEq, Eq)]
enum Standing {
    /// The admin tool answered with a result, and the list names admin tools.
    Admin,
    /// The admin tool was refused in the admin-denial shape (403, -32600)
    /// and the list, answered 200, names no admin tool.
    Standard,
}

async fn standing(state: &Arc<AppState>, bearer: &str) -> Standing {
    standing_of(state, bearer, |r| r).await
}

/// [`standing`], with each request passed through `edit` first.
async fn standing_of(
    state: &Arc<AppState>,
    bearer: &str,
    edit: impl Fn(axum::http::Request<axum::body::Body>) -> axum::http::Request<axum::body::Body>,
) -> Standing {
    let call = json!({"name": "gateway_revive_server", "arguments": {"server": "alpha"}});
    let (call_status, call_body) = send(state, edit(rpc(bearer, "tools/call", &call))).await;
    let (list_status, list_body) = send(state, edit(rpc(bearer, "tools/list", &json!({})))).await;
    assert_eq!(list_status, StatusCode::OK, "tools/list: {list_body}");
    let listed = list_body["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .any(|t| t["name"] == "gateway_revive_server");
    let admin_answer = call_status == StatusCode::OK && call_body.get("result").is_some();
    let admin_refusal = call_status == StatusCode::FORBIDDEN
        && call_body["error"]["code"] == -32600
        && call_body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("requires admin access"));
    match (admin_answer, admin_refusal, listed) {
        (true, false, true) => Standing::Admin,
        (false, true, false) => Standing::Standard,
        _ => panic!("neither standing: call {call_status} {call_body}, listed={listed}"),
    }
}

#[path = "sso_admin_tests/cells.rs"]
mod cells;

// Its helpers serve the UI cells, so the module needs the UI.
#[cfg(feature = "webui")]
#[path = "sso_admin_tests/admin_action.rs"]
mod admin_action;
