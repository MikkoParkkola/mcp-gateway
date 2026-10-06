// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7938: a delivery record names its caller as the invocation record for
//! the same call does. A certificate or OAuth-agent caller gets through only
//! with auth off or on a public path, as the client `anonymous`; its verified
//! subject must reach the `response_delivery_attempt` record too.

use super::*;

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

/// MIK-7938 safety claim: with no verified subject, the record's `who` is
/// exactly what `AuditWho::from_actor_id(caller)` produced before this change,
/// byte for byte, for an anonymous and for an API-key caller.
#[tokio::test]
async fn a_record_without_a_subject_is_unchanged() {
    for (caller, setup, name) in [
        (Caller::Anonymous, Setup::default(), "anonymous"),
        (
            Caller::Key,
            Setup {
                auth: Some(key_for_alpha(None)),
                ..Setup::default()
            },
            "alpha-client",
        ),
    ] {
        let fx = fixture(setup).await;
        let (status, body) = post(&fx, "alpha", &tools_call("t"), &caller).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let delivery = only_attempt(&fx);
        let before = crate::security::audit::AuditWho::from_actor_id(name);
        assert_eq!(
            delivery["who"],
            serde_json::to_value(&before).unwrap(),
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
