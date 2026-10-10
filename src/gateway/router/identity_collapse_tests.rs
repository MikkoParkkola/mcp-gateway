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
        let now =
            i64::try_from(crate::clock::unix_secs().expect("the test host clock reads after 1970"))
                .expect("fits");
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
        scopes: TokenScopes {
            backends: vec!["*".to_owned()],
            ..TokenScopes::default()
        },
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
            // An allowlist, so a nameless token from another domain proves
            // the subject is judged before the domain (MIK-8286 review).
            allowed_domains: vec!["corp.invalid".to_owned()],
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
    let elsewhere = idp.token(
        "",
        &json!({"email": "x@elsewhere.invalid", "email_verified": true}),
    );
    for (case, bearer) in [
        ("empty-sub bearer", empty_sub.as_str()),
        (
            "empty-sub bearer from a disallowed domain",
            elsewhere.as_str(),
        ),
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
    let named = idp.token(
        "alice",
        &json!({"email": "alice@corp.invalid", "email_verified": true}),
    );
    let mut forged = idp.token("", &json!({}));
    forged.push('x');
    let unknown_issuer = idp.token("", &json!({ "iss": "https://idp-unknown.example" }));
    let expired = idp.token("", &json!({ "exp": i64::try_from(crate::clock::unix_secs().expect("clock")).expect("fits") - 600 }));
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

/// A nameless client certificate: no CN, no SAN URI, parsed by the
/// production parser.
fn nameless_cert() -> crate::mtls::CertIdentity {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key_pair = rcgen::KeyPair::generate().expect("key generation failed");
    let der = params.self_signed(&key_pair).expect("cert").der().to_vec();
    crate::mtls::CertIdentity::from_der(&der).expect("a nameless leaf still parses")
}

/// `tools/call gateway_invoke` of `alpha`/`read` on `/mcp` as API key `key`,
/// carrying client certificate `cert`, under idempotency key `op`.
async fn call_with_cert(
    fx: &super::direct_guards_fixture::Fx,
    key: &str,
    cert: &crate::mtls::CertIdentity,
    op: &str,
) -> Value {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
    });
    params
        .as_object_mut()
        .unwrap()
        .extend(keyed(op).as_object().unwrap().clone());
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    // As the TLS identity layer would, were its entry refusal missing: this
    // row pins the second layer, the grant subject's fallback removal.
    request.extensions_mut().insert(cert.clone());
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// R1 (the MIK-8286 replay, at the route): two callers behind different API
/// keys both present a nameless certificate and send one idempotency key.
/// Each is its own caller, so B's call runs rather than being served A's
/// result. Today both key on the shared display-name subject and B replays
/// A. Mutant: the display-name fallback restored. (The entry refusal, R3,
/// would stop both before this; this row pins the layer behind it.)
#[tokio::test]
async fn a_nameless_certificate_never_replays_another_callers_result() {
    use super::direct_continuation_tests::dispatched;
    use super::direct_guards_fixture::{Answer, fixture};

    let fx = fixture(Answer::Ok, |_| {}).await;
    let cert = nameless_cert();
    let a = call_with_cert(&fx, "k-std", &cert, "op-1").await;
    assert!(a.get("error").is_none(), "caller A is served: {a}");
    let b = call_with_cert(&fx, "k-budget", &cert, "op-1").await;
    assert!(b.get("error").is_none(), "caller B is served: {b}");
    assert_eq!(dispatched(&fx), 2, "B ran its own call, not A's replay");
}

/// The first `"pid"` number anywhere in `value`, looking inside JSON text.
#[cfg(unix)]
fn find_pid(value: &Value) -> Option<i64> {
    match value {
        Value::Object(map) => map
            .get("pid")
            .and_then(Value::as_i64)
            .or_else(|| map.values().find_map(find_pid)),
        Value::Array(items) => items.iter().find_map(find_pid),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .ok()
            .as_ref()
            .and_then(find_pid),
        _ => None,
    }
}

/// R2b (the per-caller child site, `capability/executor/mcp.rs`
/// `principal`): on a multi-user gateway, two callers behind different API
/// keys who both present a nameless certificate get one stdio child each.
/// Today both key the child on the shared display-name subject and share one
/// process. Mutant: the display-name fallback restored.
#[cfg(unix)]
#[tokio::test]
async fn nameless_certificates_never_share_a_per_caller_child() {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};

    use super::direct_guards_fixture::{Answer, fixture};

    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/fake_mcp.py")
        .display()
        .to_string();
    let yaml = format!(
        "name: mcp_probe\ndescription: MCP probe.\nschema:\n  input:\n    type: object\n    \
         properties:\n      operation:\n        type: string\n      text:\n        type: string\n\
         providers:\n  primary:\n    service: mcp\n    timeout: 20\n    config:\n      \
         command: 'python3'\n      args: ['{script}']\n      transport: stdio\n      \
         tool_selector:\n        param: operation\n        tools:\n          \
         say: {{ tool: echo, arguments: {{ message: \"{{text}}\" }} }}\n"
    );
    let dir = tempfile::TempDir::new().unwrap();
    // Pinned, as `mcp-gateway cap pin` would: a local process runs only
    // from a verified file.
    let hash = crate::capability::hash::compute_capability_hash(&yaml);
    let yaml = crate::capability::hash::rewrite_with_pin(&yaml, &hash);
    std::fs::write(dir.path().join("mcp_probe.yaml"), yaml).unwrap();
    // The operator allows this one command, as `capabilities.process_commands`
    // would.
    let config = crate::config::CapabilityConfig {
        process_commands: Some(vec![crate::config::ProcessCommand {
            command: "python3".to_owned(),
            args_prefix: vec![script.clone()],
        }]),
        ..crate::config::CapabilityConfig::default()
    };
    let caps = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::for_config(&config)),
    ));
    caps.load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    let fx = fixture(Answer::Ok, |meta| {
        meta.set_capabilities(Arc::clone(&caps));
        meta.set_multi_user(true);
    })
    .await;

    let cert = nameless_cert();
    let mut pids = Vec::new();
    for key in ["k-std", "k-budget"] {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke")
            .body(axum::body::Body::from(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "gateway_invoke",
                    "arguments": {"server": "caps", "tool": "mcp_probe",
                                  "arguments": {"operation": "say", "text": key}},
                    "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                              "io.modelcontextprotocol/clientCapabilities": {}},
                }})
                .to_string(),
            ))
            .unwrap();
        request.extensions_mut().insert(cert.clone());
        let response = fx.router.clone().oneshot(request).await.unwrap();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        pids.push(find_pid(&body).unwrap_or_else(|| panic!("{key}: no pid in {body}")));
    }
    assert_ne!(pids[0], pids[1], "two callers shared one child");
}

/// A personal, cacheable REST capability `name`, owned by mTLS subject
/// `owner`, served by `port`'s `/probe`.
fn personal_probe(name: &str, owner: &str, port: u16) -> String {
    format!(
        "name: {name}\ndescription: Personal cacheable probe\ncache:\n  ttl: 60\n  \
         strategy: memory\nmetadata:\n  exposure: personal\n  identity_owner:\n    \
         authority: mtls\n    subject: '{owner}'\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: http://localhost:{port}\n      path: /probe\n      method: GET\n"
    )
}

/// `tools/call gateway_invoke` of capability `tool` as API key `key` with
/// client certificate `cert`; the body.
async fn invoke_capability(
    fx: &super::direct_guards_fixture::Fx,
    key: &str,
    cert: &crate::mtls::CertIdentity,
    tool: &str,
) -> Value {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "gateway_invoke",
                "arguments": {"server": "caps", "tool": tool, "arguments": {}},
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {}},
            }})
            .to_string(),
        ))
        .unwrap();
    request.extensions_mut().insert(cert.clone());
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// R2a (the capability-cache site, `capability/executor/params.rs` `1:`
/// arm): a personal capability whose owner an operator wrote as the
/// placeholder subject. Two callers behind different API keys who both
/// present a nameless certificate must never share its cached result: today
/// both run as that owner, and B is served A's cached answer (the upstream
/// sees one request). Control: a named owner's second call is a cache hit, so
/// caching demonstrably happens. Mutant: the display-name fallback restored.
#[tokio::test]
async fn nameless_certificates_never_share_a_cached_personal_result() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::capability::{CapabilityBackend, CapabilityExecutor};

    use super::direct_guards_fixture::{Answer, fixture};

    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/probe",
            axum::routing::get(move || {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                async move { axum::Json(json!({"answer": format!("served-{n}")})) }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::TempDir::new().unwrap();
    let placeholder = nameless_cert().display_name;
    std::fs::write(
        dir.path().join("placeholder_probe.yaml"),
        personal_probe("placeholder_probe", &placeholder, port),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("named_probe.yaml"),
        personal_probe("named_probe", "agent-a", port),
    )
    .unwrap();
    let executor = CapabilityExecutor::new().with_test_http_client(reqwest::Client::new());
    let caps = Arc::new(CapabilityBackend::new("caps", Arc::new(executor)));
    caps.load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    // Each owner holds an execute grant for its own probe, as an operator
    // would write them.
    let grant = |id: &str, subject: &str, capability: &str| {
        let subject = crate::identity_grants::GrantSubject::new("mtls", subject, None);
        crate::identity_grants::IdentityGrant {
            grant_id: id.to_owned(),
            subject: subject.clone(),
            agent: crate::identity_grants::GrantAgent::Any,
            capability: capability.to_owned(),
            tool: None,
            scope: crate::identity_grants::GrantScope::Execute,
            owner: Some(subject),
            expires_at: None,
            revoked_at: None,
            provenance: "test".to_owned(),
            reason: "MIK-8286 R2a".to_owned(),
        }
    };
    let grants = crate::identity_grants::LocalIdentityGrantStore::from_grants(vec![
        grant("g-named", "agent-a", "named_probe"),
        grant("g-placeholder", &placeholder, "placeholder_probe"),
    ]);
    let fx = fixture(Answer::Ok, |meta| {
        meta.set_capabilities(Arc::clone(&caps));
        meta.set_identity_grants(grants);
    })
    .await;

    let named = named_cert("agent-a");
    let first = invoke_capability(&fx, "k-std", &named, "named_probe").await;
    assert!(
        first.to_string().contains("served-1"),
        "control runs: {first}"
    );
    let again = invoke_capability(&fx, "k-std", &named, "named_probe").await;
    assert!(
        again.to_string().contains("served-1"),
        "control is cached: {again}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the control's second call hit the cache"
    );

    let nameless = nameless_cert();
    let a = invoke_capability(&fx, "k-std", &nameless, "placeholder_probe").await;
    let b = invoke_capability(&fx, "k-budget", &nameless, "placeholder_probe").await;
    // Neither nameless caller is served: both are refused (no subject, so
    // the personal capability's owner grant cannot match), and the upstream
    // saw only the control's one request. Today A runs (served-2) and B is
    // served A's cached answer.
    for (who, body) in [("A", &a), ("B", &b)] {
        let text = body.to_string();
        assert!(!text.contains("served-"), "caller {who} was served: {text}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "no nameless call reached the upstream"
    );
}

/// A client certificate whose CN is `cn`, parsed by the production parser.
fn named_cert(cn: &str) -> crate::mtls::CertIdentity {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name = dn;
    let key_pair = rcgen::KeyPair::generate().expect("key generation failed");
    let der = params.self_signed(&key_pair).expect("cert").der().to_vec();
    crate::mtls::CertIdentity::from_der(&der).expect("parses")
}

/// POST `message` to `/mcp` with an optional `bearer` on an optional
/// `session`; the status, the body and the session the gateway names.
async fn post(
    state: &Arc<AppState>,
    bearer: Option<&str>,
    session: Option<&str>,
    message: Value,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let request = builder
        .body(axum::body::Body::from(message.to_string()))
        .unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        session,
    )
}

fn init_message() -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": crate::protocol::PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": { "name": "r10", "version": "0" } } })
}

/// What a caller with no credential gets on `session`: whether it is served,
/// and the status and body for the failure message.
async fn anonymous_resume(state: &Arc<AppState>, session: &str) -> (bool, String) {
    let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let (status, body, echoed) = post(state, None, Some(session), list).await;
    let served = status == StatusCode::OK && echoed.as_deref() == Some(session);
    (served, format!("{status}, session {echoed:?}, {body}"))
}

/// R10's positive control, made to prove what it claims (MIK-8286 review):
/// a NAMED delegated bearer on public `/mcp` is authenticated as that
/// identity, not handed the anonymous public client. Observed through
/// session ownership: the session it opens belongs to its subject, so a
/// caller with no credential cannot resume it, whereas an anonymous session
/// can be. The bearer carries a verified email in the allowlisted domain.
#[tokio::test]
async fn a_named_bearer_on_a_public_path_is_authenticated() {
    let idp = Idp::start().await;
    let (state, _store) = gateway(&idp).await;

    let (status, body, anonymous) = post(&state, None, None, init_message()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let anonymous = anonymous.expect("an anonymous session");
    let (served, seen) = anonymous_resume(&state, &anonymous).await;
    assert!(served, "the probe serves an anonymous session: {seen}");

    let named = idp.token(
        "alice",
        &json!({"email": "alice@corp.invalid", "email_verified": true}),
    );
    let (status, body, session) = post(&state, Some(&named), None, init_message()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session = session.expect("a session");
    let (served, seen) = anonymous_resume(&state, &session).await;
    assert!(
        !served,
        "the named bearer's session was resumable anonymously, so it fell through as public: {seen}"
    );
}
