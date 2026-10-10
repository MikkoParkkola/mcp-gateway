// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8286 / MIK-8287 (identity-collapse): an identity that names nobody is
//! refused as unauthenticated, never served as anonymous or as a shared
//! principal. Requests go through `create_router`, so the real
//! `auth_middleware` resolves each credential; one loopback ES256 identity
//! provider serves its JWKS to the delegated-bearer verifier.

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
    AuthConfig, KeyServerConfig, KeyServerPolicyConfig, KeyServerProviderConfig, PolicyMatchConfig,
    PolicyScopesConfig,
};
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::store::{TemporaryToken, TokenScopes};
use crate::key_server::{InMemoryTokenStore, KeyServer, OidcVerifier, TokenStore};

const ISS: &str = "https://idp-c.example";
const AUD: &str = "gateway";
const STORED_NAMELESS: &str = "mcpgw_identity_collapse_nameless";
const STORED_NAMED: &str = "mcpgw_identity_collapse_named";

struct Idp {
    key: Arc<GatewayKeyPair>,
    jwks_uri: String,
}

impl Idp {
    async fn start() -> Self {
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
        }
    }

    /// An ID token for `sub`, with `claims` merged over the defaults.
    fn token(&self, sub: &str, claims: &Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut body = json!({
            "iss": ISS, "sub": sub, "aud": AUD, "groups": ["staff"],
            "iat": now - 5, "exp": now + 3600,
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

fn identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_owned(),
        email: String::new(),
        name: None,
        groups: vec![],
        issuer: ISS.to_owned(),
    }
}

fn stored(bearer: &str, subject: &str) -> TemporaryToken {
    TemporaryToken {
        jti: format!("jti-{bearer}"),
        token: bearer.to_owned(),
        identity: identity(subject),
        scopes: TokenScopes::default(),
        iat: 0,
        exp: u64::MAX,
        client_ip: None,
    }
}

/// Auth on with `/mcp` public, a key server trusting the one issuer for
/// delegated bearers, and two stored temporary tokens: one named, one whose
/// identity names nobody.
async fn gateway(idp: &Idp) -> (Arc<AppState>, tempfile::TempDir) {
    let config = KeyServerConfig {
        enabled: true,
        delegated_bearer: true,
        oidc: vec![KeyServerProviderConfig {
            issuer: ISS.to_owned(),
            jwks_uri: Some(idp.jwks_uri.clone()),
            discovery_url: None,
            auto_discover: false,
            audiences: vec![AUD.to_owned()],
            allowed_domains: Vec::new(),
        }],
        policies: vec![KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                domain: None,
                issuer: ISS.to_owned(),
                email: None,
                group: Some("staff".to_owned()),
            },
            scopes: PolicyScopesConfig {
                backends: vec!["*".to_owned()],
                tools: vec!["*".to_owned()],
                rate_limit: 0,
            },
        }],
        max_oidc_token_age_secs: 300,
        ..KeyServerConfig::default()
    };
    let store = Arc::new(InMemoryTokenStore::new());
    store.insert(stored(STORED_NAMELESS, "")).await;
    store.insert(stored(STORED_NAMED, "alice")).await;
    let key_server = KeyServer {
        store,
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
        public_paths: vec!["/mcp".to_owned()],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, Some(Arc::new(key_server))).await
}

/// POST an `initialize` to `/mcp` with `bearer`; the status and body.
async fn initialize(state: &Arc<AppState>, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let message = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": crate::protocol::PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": { "name": "r10", "version": "0" } } });
    let request = builder
        .body(axum::body::Body::from(message.to_string()))
        .unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// R10: on a public path, a credential this gateway recognises but whose
/// identity names nobody is refused (401, -32000), never served: neither as
/// that collapsed identity nor as the anonymous public client. Mutants: the
/// nameless outcome folded into "not a token" in either lookup.
#[tokio::test]
async fn a_recognised_credential_that_names_nobody_is_refused_on_a_public_path() {
    let idp = Idp::start().await;
    let (state, _store) = gateway(&idp).await;
    let empty_sub = idp.token("", &json!({}));
    for (case, bearer) in [
        ("empty-sub bearer", empty_sub.as_str()),
        ("stored nameless token", STORED_NAMELESS),
    ] {
        let (status, body) = initialize(&state, Some(bearer)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}: {body}");
        assert_eq!(body["error"]["code"], json!(-32000), "{case}: {body}");
    }
}

/// R10 controls: a named stored token and a named bearer are served; garbage,
/// and JWT-shaped empty-sub tokens this gateway cannot vouch for (corrupted
/// signature, unknown issuer, expired), keep today's public fall-through.
/// Pins "not ours" so the refusal never widens to input it did not verify.
#[tokio::test]
async fn unverifiable_input_on_a_public_path_keeps_the_public_fall_through() {
    let idp = Idp::start().await;
    let (state, _store) = gateway(&idp).await;
    let named = idp.token("alice", &json!({}));
    let mut forged = idp.token("", &json!({}));
    forged.push('x');
    let unknown_issuer = idp.token("", &json!({ "iss": "https://idp-unknown.example" }));
    let expired = idp.token("", &json!({ "exp": chrono::Utc::now().timestamp() - 600 }));
    for (case, bearer) in [
        ("named stored token", Some(STORED_NAMED)),
        ("named bearer", Some(named.as_str())),
        ("no credential", None),
        ("garbage", Some("not-a-token")),
        ("forged empty-sub JWT", Some(forged.as_str())),
        (
            "unknown-issuer empty-sub JWT",
            Some(unknown_issuer.as_str()),
        ),
        ("expired empty-sub JWT", Some(expired.as_str())),
    ] {
        let (status, body) = initialize(&state, bearer).await;
        assert_eq!(status, StatusCode::OK, "{case}: {body}");
    }
}

/// A key server holding `tokens`: (bearer, subject, email) triples, all from
/// the one issuer, all live.
async fn key_server_with(tokens: &[(&str, &str, &str)]) -> Arc<KeyServer> {
    let ks = KeyServer::new(KeyServerConfig {
        enabled: true,
        ..KeyServerConfig::default()
    });
    for (bearer, subject, email) in tokens {
        let mut token = stored(bearer, subject);
        token.identity.email = (*email).to_owned();
        ks.store.insert(token).await;
    }
    Arc::new(ks)
}

/// `gateway_invoke` params under idempotency key `key`.
fn keyed(key: &str) -> Value {
    json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key,
    }})
}

/// R5 (the admission-lease site, `meta_mcp/admission.rs:374`): two people
/// whose stored identities both name nobody use one idempotency key. Neither
/// is admitted: both are refused (-32000) before admission, so the backend
/// never runs and B can never be served A's result. Control: a named token
/// does reach admission and the backend. Mutant: the read-back check removed.
#[tokio::test]
async fn two_nameless_callers_never_share_an_execution_lease() {
    use super::direct_continuation_tests::{code, dispatched, meta_call};
    use super::direct_guards_fixture::{Answer, fixture_with_key_server};

    let ks = key_server_with(&[
        ("mcpgw_r5_alice", "", "alice@corp.invalid"),
        ("mcpgw_r5_bob", "", "bob@corp.invalid"),
        ("mcpgw_r5_named", "carol", "carol@corp.invalid"),
    ])
    .await;
    let fx = fixture_with_key_server(Answer::Ok, ks).await;

    let control = meta_call(&fx, "mcpgw_r5_named", "alpha", keyed("op-c")).await;
    assert!(
        control.get("error").is_none(),
        "the control is admitted: {control}"
    );
    assert_eq!(dispatched(&fx), 1, "the control reached the backend");

    let alice = meta_call(&fx, "mcpgw_r5_alice", "alpha", keyed("op-1")).await;
    let bob = meta_call(&fx, "mcpgw_r5_bob", "alpha", keyed("op-1")).await;
    assert_eq!(code(&alice), Some(-32000), "{alice}");
    assert_eq!(code(&bob), Some(-32000), "{bob}");
    assert_eq!(
        dispatched(&fx),
        1,
        "neither nameless caller reached the backend"
    );
}
