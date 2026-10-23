// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7938: a delivery record names its caller as the invocation record for
//! the same call does. A certificate or OAuth-agent caller gets through only
//! with auth off or on a public path, as the client `anonymous`; its verified
//! subject must reach the `response_delivery_attempt` record too.

use super::*;

/// MIK-8672 C1/C2: auth with a static bearer and an API key named `bearer`,
/// holding different secrets, both reaching `alpha`.
fn bearer_auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER_TOKEN.to_string()),
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
            expires_at: None,
            name: "bearer".to_string(),
            rate_limit: 0,
            backends: vec!["alpha".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    }
}

/// The one delivery-attempt record in the log.
fn only_attempt(fx: &Fixture) -> Value {
    let all: Vec<Value> = std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    assert_eq!(all.len(), 1, "expected one delivery attempt: {all:?}");
    all[0].clone()
}

/// The delivery record carries `authority` and `subject`, equal to the
/// invocation record's, and keeps `caller` and `who.account` as the client.
fn assert_named(fx: &Fixture, authority: &str, subject: &str) {
    let delivery = only_attempt(fx);
    let invocation = only_invocation(fx);
    assert_eq!(delivery["who"]["authority"], authority, "{delivery}");
    assert_eq!(delivery["who"]["subject"], subject, "{delivery}");
    assert_eq!(
        delivery["who"]["subject"], invocation["who"]["subject"],
        "{invocation}"
    );
    assert_eq!(delivery["caller"], "anonymous", "{delivery}");
    assert_eq!(delivery["who"]["account"], "anonymous", "{delivery}");
}

/// AC1: a certificate caller on the direct route, auth off.
#[tokio::test]
async fn a_certificate_caller_is_named_in_the_direct_delivery_record() {
    let fx = fixture(Setup::default()).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Cert).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_named(&fx, "mtls", "spiffe://example.invalid/cert-7938");
}

/// A caller verified by an OIDC identity with auth off (`/mcp/{name}`): the
/// verified-identity channel names its subject the same way.
#[tokio::test]
async fn a_verified_identity_caller_is_named_in_the_direct_delivery_record() {
    let fx = fixture(Setup::default()).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_named(&fx, "https://a.example.invalid", "1");
}

/// AC2: an OAuth-agent caller on the direct route.
#[tokio::test]
async fn an_agent_caller_is_named_in_the_direct_delivery_record() {
    let fx = fixture(Setup::default()).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Agent).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_named(&fx, "agent_oauth", "agent-7938");
}

/// AC2: the same caller on the meta route (`POST /mcp`, `gateway_invoke`).
#[tokio::test]
async fn an_agent_caller_is_named_in_the_meta_delivery_record() {
    let fx = fixture(Setup::default()).await;
    let invoke = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "alpha", "tool": "t", "arguments": {"q": 1}},
                   "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                             "io.modelcontextprotocol/clientCapabilities": {}}}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(invoke.to_string()))
        .unwrap();
    insert_identity(&mut request, &Caller::Agent);
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_named(&fx, "agent_oauth", "agent-7938");
}

/// AC3: an API-key caller's delivery record is as before: the key's client
/// as `caller` and `who.account`, no subject.
#[tokio::test]
async fn a_key_caller_delivery_record_is_unchanged() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delivery = only_attempt(&fx);
    assert_eq!(delivery["caller"], "alpha-client", "{delivery}");
    assert_eq!(delivery["who"]["account"], "alpha-client", "{delivery}");
    assert!(delivery["who"].get("subject").is_none(), "{delivery}");
}

/// MIK-7938 safety claim, with MIK-8672's two credential fields: with no
/// verified subject, the record's `who` is exactly
/// `AuditWho::from_actor_id(caller)` with `credential_kind` and `principal`
/// set to the caller's, byte for byte, for an anonymous and an API-key caller.
#[tokio::test]
async fn a_record_without_a_subject_is_unchanged() {
    for (caller, setup, name, kind, principal) in [
        (
            Caller::Anonymous,
            Setup::default(),
            "anonymous",
            crate::security::audit::CredentialKind::None,
            String::new(),
        ),
        (
            Caller::Key,
            Setup {
                auth: Some(key_for_alpha(None)),
                ..Setup::default()
            },
            "alpha-client",
            crate::security::audit::CredentialKind::ApiKey,
            crate::gateway::auth::principal_of("k"),
        ),
    ] {
        let fx = fixture(setup).await;
        let (status, body) = post(&fx, "alpha", &tools_call("t"), &caller).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let delivery = only_attempt(&fx);
        let mut before = crate::security::audit::AuditWho::from_actor_id(name);
        before.credential_kind = Some(kind);
        before.principal = principal;
        assert_eq!(
            delivery["who"],
            serde_json::to_value(&before).expect("a who serializes"),
            "{delivery}"
        );
    }
}

/// `trusted_proxy` mode with one allowed proxy, under authority `corp-sso`.
fn proxy_setup() -> Setup {
    Setup {
        caller_identity: Some(crate::security::caller_identity::CallerIdentityConfig {
            mode: crate::security::caller_identity::CallerIdentityMode::TrustedProxy,
            trusted_proxies: vec!["10.0.0.5".parse().unwrap()],
            authority: "corp-sso".to_string(),
            ..crate::security::caller_identity::CallerIdentityConfig::default()
        }),
        ..Setup::default()
    }
}

/// `request` as the trusted proxy forwards it: from 10.0.0.5, naming `alice`.
fn through_proxy(
    mut request: axum::http::Request<axum::body::Body>,
) -> axum::http::Request<axum::body::Body> {
    request.headers_mut().insert(
        "x-gateway-identity-subject",
        axum::http::HeaderValue::from_static("alice"),
    );
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        "10.0.0.5:4000".parse::<std::net::SocketAddr>().unwrap(),
    ));
    request
}

/// Send `request` and require a 200.
async fn send_ok(fx: &Fixture, request: axum::http::Request<axum::body::Body>) {
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
}

/// ATTR.4: a subject named by a trusted proxy's header reaches the delivery
/// record on the direct route. A Cloudflare Access subject resolves through
/// `caller_grant_subject` into a `GrantSubject` of its own; its header
/// verification is pinned in `identity_header_tests`.
#[tokio::test]
async fn a_trusted_proxy_subject_is_named_in_the_direct_delivery_record() {
    let fx = fixture(proxy_setup()).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/alpha")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(tools_call("t")))
        .unwrap();
    send_ok(&fx, through_proxy(request)).await;
    assert_named(&fx, "corp-sso", "alice");
}

/// ATTR.4: that subject on the meta route (`POST /mcp`, `gateway_invoke`).
#[tokio::test]
async fn a_trusted_proxy_subject_is_named_in_the_meta_delivery_record() {
    let fx = fixture(proxy_setup()).await;
    let invoke = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "alpha", "tool": "t", "arguments": {"q": 1}},
                   "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                             "io.modelcontextprotocol/clientCapabilities": {}}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(invoke.to_string()))
        .unwrap();
    send_ok(&fx, through_proxy(request)).await;
    assert_named(&fx, "corp-sso", "alice");
}

/// ATTR.5: an API-key caller that also presents a verified certificate gets
/// the certificate subject in its delivery record; the key's client stays the
/// `caller`.
#[tokio::test]
async fn a_key_and_certificate_caller_is_named_by_the_certificate() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/alpha")
        .header("content-type", "application/json")
        .header("authorization", "Bearer k")
        .body(axum::body::Body::from(tools_call("t")))
        .unwrap();
    insert_identity(&mut request, &Caller::Cert);
    send_ok(&fx, request).await;
    let delivery = only_attempt(&fx);
    let invocation = only_invocation(&fx);
    assert_eq!(delivery["who"]["authority"], "mtls", "{delivery}");
    assert_eq!(
        delivery["who"]["subject"], "spiffe://example.invalid/cert-7938",
        "{delivery}"
    );
    assert_eq!(
        delivery["who"]["subject"], invocation["who"]["subject"],
        "{invocation}"
    );
    assert_eq!(delivery["caller"], "alpha-client", "{delivery}");
}

/// POST a `gateway_invoke` of `alpha:t` to the meta route as `caller`, with
/// the headers `/mcp` takes (MIK-8672 C2/C3). Stages credential callers only.
async fn post_meta(fx: &Fixture, caller: &Caller) -> (StatusCode, Value) {
    let invoke = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "alpha", "tool": "t", "arguments": {"q": 1}},
                   "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                             "io.modelcontextprotocol/clientCapabilities": {}}}});
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke");
    let token = match caller {
        Caller::Anonymous => None,
        Caller::Key => Some("k"),
        Caller::Bearer => Some(BEARER_TOKEN),
        _ => panic!("post_meta stages only anonymous and credential callers"),
    };
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(axum::body::Body::from(invoke.to_string()))
        .expect("a meta request builds");
    let response = fx
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("a meta response");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("an in-memory body reads");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// One C3 cell on the direct route: `caller`'s delivery record names
/// `kind`/`principal`, as its invocation record does.
async fn assert_direct_cell(setup: Setup, caller: Caller, kind: &str, principal: &str) {
    let fx = fixture(setup).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &caller).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delivery = only_attempt(&fx);
    let invocation = only_invocation(&fx);
    assert_eq!(delivery["who"]["credential_kind"], kind, "{delivery}");
    assert_eq!(delivery["who"]["principal"], principal, "{delivery}");
    assert_eq!(
        delivery["who"]["credential_kind"], invocation["who"]["credential_kind"],
        "{invocation}"
    );
    assert_eq!(
        delivery["who"]["principal"], invocation["who"]["principal"],
        "{invocation}"
    );
}

/// One C3 cell on the meta route, as [`assert_direct_cell`].
async fn assert_meta_cell(setup: Setup, caller: Caller, kind: &str, principal: &str) {
    let fx = fixture(setup).await;
    let (status, body) = post_meta(&fx, &caller).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delivery = only_attempt(&fx);
    let invocation = only_invocation(&fx);
    assert_eq!(delivery["who"]["credential_kind"], kind, "{delivery}");
    assert_eq!(delivery["who"]["principal"], principal, "{delivery}");
    assert_eq!(
        delivery["who"]["credential_kind"], invocation["who"]["credential_kind"],
        "{invocation}"
    );
    assert_eq!(
        delivery["who"]["principal"], invocation["who"]["principal"],
        "{invocation}"
    );
}

/// C1 (MIK-8672): the key `bearer` and the static bearer name their own credentials.
#[tokio::test]
async fn a_key_named_bearer_and_the_static_bearer_name_their_own_credentials() {
    let key_principal = crate::gateway::auth::principal_of("k");
    let bearer_principal = crate::gateway::auth::principal_of(BEARER_TOKEN);
    assert_ne!(
        key_principal, bearer_principal,
        "the pair needs different secrets"
    );
    for (caller, kind, principal) in [
        (Caller::Key, "api_key", key_principal),
        (Caller::Bearer, "static_bearer", bearer_principal),
    ] {
        let fx = fixture(Setup {
            auth: Some(bearer_auth()),
            ..Setup::default()
        })
        .await;
        let (status, body) = post(&fx, "alpha", &tools_call("t"), &caller).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let delivery = only_attempt(&fx);
        let invocation = only_invocation(&fx);
        assert_eq!(delivery["who"]["credential_kind"], kind, "{delivery}");
        assert_eq!(
            delivery["who"]["principal"],
            principal.as_str(),
            "{delivery}"
        );
        assert_eq!(
            delivery["who"]["credential_kind"], invocation["who"]["credential_kind"],
            "{invocation}"
        );
        assert_eq!(
            delivery["who"]["principal"], invocation["who"]["principal"],
            "{invocation}"
        );
        assert_eq!(delivery["caller"], "bearer", "{delivery}");
        assert_eq!(delivery["who"]["account"], "bearer", "{delivery}");
    }
}

/// C2 (MIK-8672): the `bearer` pair names its own credentials on the meta route.
#[tokio::test]
async fn a_key_named_bearer_and_the_static_bearer_name_their_own_credentials_on_the_meta_route() {
    let key_principal = crate::gateway::auth::principal_of("k");
    let bearer_principal = crate::gateway::auth::principal_of(BEARER_TOKEN);
    assert_ne!(
        key_principal, bearer_principal,
        "the pair needs different secrets"
    );
    for (caller, kind, principal) in [
        (Caller::Key, "api_key", key_principal),
        (Caller::Bearer, "static_bearer", bearer_principal),
    ] {
        let fx = fixture(Setup {
            auth: Some(bearer_auth()),
            ..Setup::default()
        })
        .await;
        let (status, body) = post_meta(&fx, &caller).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let delivery = only_attempt(&fx);
        let invocation = only_invocation(&fx);
        assert_eq!(delivery["who"]["credential_kind"], kind, "{delivery}");
        assert_eq!(
            delivery["who"]["principal"],
            principal.as_str(),
            "{delivery}"
        );
        assert_eq!(
            delivery["who"]["credential_kind"], invocation["who"]["credential_kind"],
            "{invocation}"
        );
        assert_eq!(
            delivery["who"]["principal"], invocation["who"]["principal"],
            "{invocation}"
        );
        assert_eq!(delivery["caller"], "bearer", "{delivery}");
        assert_eq!(delivery["who"]["account"], "bearer", "{delivery}");
    }
}

/// C3 (MIK-8672): direct delivery records name every stageable credential.
#[tokio::test]
async fn direct_delivery_records_name_every_stageable_credential() {
    // | none | Caller::Anonymous, auth off | direct, meta |
    // | api_key | Caller::Key | direct, meta |
    // | static_bearer | Caller::Bearer, bearer_auth() | direct, meta |
    // N/A (direct): oidc_bearer — no harness stages a delegated bearer on the
    // direct route; the meta row is in audit_record_tests.
    // N/A (direct): key_server_token — same; the meta row is in audit_record_tests.
    // N/A (direct): dashboard_session — same; the meta row is in audit_record_tests.
    // N/A: local_transport — stdio only (C5).
    let key_principal = crate::gateway::auth::principal_of("k");
    let bearer_principal = crate::gateway::auth::principal_of(BEARER_TOKEN);
    assert_direct_cell(Setup::default(), Caller::Anonymous, "none", "").await;
    assert_direct_cell(
        Setup {
            auth: Some(key_for_alpha(None)),
            ..Setup::default()
        },
        Caller::Key,
        "api_key",
        &key_principal,
    )
    .await;
    assert_direct_cell(
        Setup {
            auth: Some(bearer_auth()),
            ..Setup::default()
        },
        Caller::Bearer,
        "static_bearer",
        &bearer_principal,
    )
    .await;
}

/// C3 (MIK-8672): meta delivery records name every stageable credential.
#[tokio::test]
async fn meta_delivery_records_name_every_stageable_credential() {
    // | none | Caller::Anonymous, auth off | direct, meta |
    // | api_key | Caller::Key | direct, meta |
    // | static_bearer | Caller::Bearer, bearer_auth() | direct, meta |
    // N/A (meta): oidc_bearer — staged in audit_record_tests, not here.
    // N/A (meta): key_server_token — staged in audit_record_tests, not here.
    // N/A (meta): dashboard_session — staged in audit_record_tests, not here.
    // N/A: local_transport — stdio only (C5).
    let key_principal = crate::gateway::auth::principal_of("k");
    let bearer_principal = crate::gateway::auth::principal_of(BEARER_TOKEN);
    assert_meta_cell(Setup::default(), Caller::Anonymous, "none", "").await;
    assert_meta_cell(
        Setup {
            auth: Some(key_for_alpha(None)),
            ..Setup::default()
        },
        Caller::Key,
        "api_key",
        &key_principal,
    )
    .await;
    assert_meta_cell(
        Setup {
            auth: Some(bearer_auth()),
            ..Setup::default()
        },
        Caller::Bearer,
        "static_bearer",
        &bearer_principal,
    )
    .await;
}

/// C6 (MIK-8672): an API-key call refused in `resolve_caller` names its credential.
#[tokio::test]
async fn an_api_key_call_refused_in_resolve_caller_names_its_credential() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        agent_identity: Some(crate::config::AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec![],
            ..Default::default()
        }),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "never dispatched"
    );
    let delivery = only_attempt(&fx);
    assert_eq!(delivery["who"]["credential_kind"], "api_key", "{delivery}");
    assert_eq!(
        delivery["who"]["principal"],
        crate::gateway::auth::principal_of("k").as_str(),
        "{delivery}"
    );
}

/// P1 (MIK-8672): delivery records keep caller, account, authority and subject.
#[tokio::test]
async fn delivery_records_keep_caller_account_and_subject() {
    // Anonymous, auth off.
    let fx = fixture(Setup::default()).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delivery = only_attempt(&fx);
    assert_eq!(delivery["caller"], "anonymous", "{delivery}");
    assert_eq!(delivery["who"]["account"], "anonymous", "{delivery}");
    assert!(delivery["who"].get("authority").is_none(), "{delivery}");
    assert!(delivery["who"].get("subject").is_none(), "{delivery}");

    // API key alpha-client.
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delivery = only_attempt(&fx);
    assert_eq!(delivery["caller"], "alpha-client", "{delivery}");
    assert_eq!(delivery["who"]["account"], "alpha-client", "{delivery}");
    assert!(delivery["who"].get("subject").is_none(), "{delivery}");

    // An API key named like an OIDC actor id: `from_actor_id` parses it as today.
    let oidc_name = "oidc:4:iss/:3:sub";
    let fx = fixture(Setup {
        auth: Some(AuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![ApiKeyConfig {
                key: None,
                key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
                expires_at: None,
                name: oidc_name.to_string(),
                rate_limit: 0,
                backends: vec!["alpha".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                kind: crate::config::ApiKeyKind::Shared,
            }],
            public_paths: vec!["/health".to_string()],
            client_circuit_breaker: None,
            single_user: false,
            dashboard_session: crate::config::DashboardSessionConfig::default(),
        }),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delivery = only_attempt(&fx);
    assert_eq!(delivery["caller"], oidc_name, "{delivery}");
    assert_eq!(delivery["who"]["account"], oidc_name, "{delivery}");
    assert_eq!(delivery["who"]["authority"], "iss/", "{delivery}");
    assert_eq!(delivery["who"]["subject"], "sub", "{delivery}");

    // Certificate caller.
    let fx = fixture(Setup::default()).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Cert).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_named(&fx, "mtls", "spiffe://example.invalid/cert-7938");

    // Trusted-proxy subject.
    let fx = fixture(proxy_setup()).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/alpha")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(tools_call("t")))
        .expect("a proxied request builds");
    send_ok(&fx, through_proxy(request)).await;
    assert_named(&fx, "corp-sso", "alice");
}

/// P3 (MIK-8672): a public-path caller differs from an auth-off caller.
#[tokio::test]
async fn a_public_path_caller_differs_from_an_auth_off_caller() {
    let fx_anon = fixture(Setup::default()).await;
    let (status, body) = post(&fx_anon, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut auth = key_for_alpha(None);
    auth.public_paths = vec!["/mcp/alpha".to_string()];
    let fx_public = fixture(Setup {
        auth: Some(auth),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx_public, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let anon = only_attempt(&fx_anon);
    let public = only_attempt(&fx_public);
    assert_eq!(anon["caller"], "anonymous", "{anon}");
    assert_eq!(public["caller"], "public", "{public}");
    assert_ne!(anon["caller"], public["caller"]);
}
