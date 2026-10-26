// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The built binary installs a minting identity-propagation strategy end to
//! end: a caller verified by the key server reaches a `signed_assertion`
//! backend through `gateway_invoke`, and the backend receives a gateway-signed
//! assertion naming that caller, verifiable against the key the gateway itself
//! publishes. The same binary and caller against the same backend without
//! `identity_propagation` delivers no `Authorization` at all, so the header
//! comes from the installed strategy, never from forwarding.
//!
//! The caller presents an ID token from a loopback issuer as a delegated
//! bearer, which the key server verifies and binds as the same
//! `VerifiedIdentity` its `/auth/token` exchange produces (that exchange is
//! covered in process by `src/gateway/router/identity_header_tests.rs`).

#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "test code reads the host clock to stamp the ID token and check the assertion's times"
)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/journey.rs"]
#[allow(dead_code, reason = "shared harness; each journey uses a subset")]
mod journey;
#[path = "common/mcp_http_servers.rs"]
#[allow(dead_code, reason = "shared fixtures; each binary uses a subset")]
mod mcp_http_servers;

use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use axum::routing::{get, post};
use journey::{Gateway, Workspace};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mcp_gateway::gateway::oauth::GatewayKeyPair;
use serde_json::{Value, json};

const BACKEND: &str = "minted";
const AUDIENCE: &str = "urn:test:minted";
const CLIENT_ID: &str = "gateway-under-test";
const SUBJECT: &str = "user-7f3a";
const EMAIL: &str = "alice@example.test";
const PROTOCOL: &str = "2026-07-28";

/// Each JSON-RPC method the backend saw, with the `Authorization` it carried.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A Streamable HTTP MCP backend that records every request's method and
/// `Authorization` header.
async fn recording_backend(seen: &Seen) -> String {
    let seen = Arc::clone(seen);
    let app = axum::Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap, body: axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                let method = body["method"].as_str().unwrap_or_default().to_owned();
                let authorization = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                seen.lock().expect("seen").push((method, authorization));
                mcp_http_servers::answer(&body, "minted")
            }
        }),
    );
    format!("{}/mcp", mcp_http_servers::serve(app).await)
}

/// A loopback OIDC issuer: its discovery document and its JWKS.
async fn issuer(keys: &GatewayKeyPair) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind issuer");
    let base = format!("http://{}", listener.local_addr().expect("issuer address"));
    let discovery = json!({ "issuer": base, "jwks_uri": format!("{base}/jwks") });
    let jwks = serde_json::to_value(keys.jwks()).expect("jwks serializes");
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || async move { axum::Json(discovery) }),
        )
        .route("/jwks", get(move || async move { axum::Json(jwks) }));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    base
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

/// An ID token for the test caller, signed ES256 by the issuer's key.
fn id_token(keys: &GatewayKeyPair, issuer: &str) -> String {
    let info = keys.key_info();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(info.kid.clone());
    let now = now();
    let claims = json!({
        "iss": issuer, "aud": CLIENT_ID, "sub": SUBJECT, "email": EMAIL,
        "email_verified": true, "iat": now, "nbf": now, "exp": now + 300,
    });
    let key = EncodingKey::from_ec_pem(info.private_key_pem.as_bytes()).expect("issuer key");
    jsonwebtoken::encode(&header, &claims, &key).expect("ID token signs")
}

/// A workspace whose `gateway.yaml` has one HTTP backend at `backend_url`,
/// `propagation` its `identity_propagation` block (or none), and the key
/// server trusting `issuer` for delegated bearers.
fn workspace(backend_url: &str, issuer: &str, propagation: &str) -> Workspace {
    use std::os::unix::fs::PermissionsExt as _;
    let ws = Workspace::new();
    let config = ws.root.join("gateway.yaml");
    std::fs::write(
        &config,
        format!(
            "server:\n  host: 127.0.0.1\n\
             auth:\n  enabled: true\n  public_paths: [\"/health\"]\n\
             key_server:\n  enabled: true\n  delegated_bearer: true\n\
             \x20 oidc:\n    - issuer: \"{issuer}\"\n      audiences: [\"{CLIENT_ID}\"]\n\
             \x20 policies:\n    - match:\n        issuer: \"{issuer}\"\n        email: \"{EMAIL}\"\n\
             \x20     scopes:\n        backends: [\"{BACKEND}\"]\n\
             backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n{propagation}"
        ),
    )
    .expect("config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    ws
}

/// `gateway_invoke` of the backend's `ping` as the holder of `bearer`,
/// required to be a result, not a tool error, carrying the backend's answer;
/// otherwise a panic with the gateway's log.
async fn invoke(gateway: &Gateway, bearer: &str) {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": { "server": BACKEND, "tool": "ping", "arguments": {} },
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "minting-row", "version": "1" },
        },
    }});
    let response = journey::http_client()
        .post(format!("{}/mcp", gateway.url))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-protocol-version", PROTOCOL)
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("the gateway answers ({e})\n{}", gateway.logs()));
    let status = response.status();
    let text = response.text().await.expect("a body");
    let answer: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {text}\n{}", gateway.logs()));
    assert!(
        status.is_success() && answer.get("error").is_none(),
        "{status}: {answer}\n{}",
        gateway.logs()
    );
    let result = &answer["result"];
    assert_ne!(result["isError"], true, "{answer}\n{}", gateway.logs());
    assert!(
        result.to_string().contains("pong-minted"),
        "the backend's answer: {answer}\n{}",
        gateway.logs()
    );
}

/// The gateway's published signing key with id `kid`.
async fn published_key(gateway: &Gateway, kid: &str) -> DecodingKey {
    let jwks: Value = journey::http_client()
        .get(format!("{}/.well-known/jwks.json", gateway.url))
        .send()
        .await
        .expect("jwks answers")
        .json()
        .await
        .expect("jwks is JSON");
    let key = (jwks["keys"].as_array().expect("a key set").iter())
        .find(|key| key["kid"] == kid)
        .unwrap_or_else(|| panic!("no published key {kid}: {jwks}\n{}", gateway.logs()));
    DecodingKey::from_ec_components(key["x"].as_str().expect("x"), key["y"].as_str().expect("y"))
        .expect("a P-256 key")
}

/// The `Authorization` of each `tools/call` the backend received.
fn calls(seen: &Seen) -> Vec<Option<String>> {
    (seen.lock().expect("seen").iter())
        .filter(|(method, _)| method == "tools/call")
        .map(|(_, authorization)| authorization.clone())
        .collect()
}

#[tokio::test]
async fn a_minting_backend_receives_a_gateway_signed_assertion_for_the_caller() {
    let issuer_keys = GatewayKeyPair::generate().expect("issuer key");
    let issuer = issuer(&issuer_keys).await;
    let bearer = id_token(&issuer_keys, &issuer);
    let seen = Seen::default();
    let backend = recording_backend(&seen).await;
    let ws = workspace(
        &backend,
        &issuer,
        &format!(
            "    identity_propagation:\n      strategy: signed_assertion\n      \
             audience: \"{AUDIENCE}\"\n      required: false\n      session_mode: stateless\n"
        ),
    );
    let gateway = Gateway::start(&ws).await;

    invoke(&gateway, &bearer).await;
    let calls = calls(&seen);
    let [Some(authorization)] = calls.as_slice() else {
        panic!("one tools/call with an Authorization header: {calls:?}");
    };
    let token = authorization
        .strip_prefix("Bearer ")
        .unwrap_or_else(|| panic!("a bearer: {authorization}"));
    assert_ne!(token, bearer, "the caller's own bearer was forwarded");

    let kid = jsonwebtoken::decode_header(token)
        .expect("a JWT header")
        .kid
        .expect("a kid");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[AUDIENCE]);
    let key = published_key(&gateway, &kid).await;
    let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
        .unwrap_or_else(|e| {
            panic!(
                "the assertion verifies against the gateway's published key ({e})\n{}",
                gateway.logs()
            )
        })
        .claims;
    assert_eq!(claims["sub"], SUBJECT);
    assert_eq!(claims["email"], EMAIL);
    assert_eq!(claims["tenant"], issuer.as_str());
    assert_eq!(claims["aud"], AUDIENCE);
    assert!(
        claims["iss"].as_str().is_some_and(|iss| !iss.is_empty()),
        "{claims}"
    );
    let now = now();
    assert!(
        claims["nbf"].as_u64().is_some_and(|nbf| nbf <= now),
        "{claims}"
    );
    assert!(
        claims["exp"].as_u64().is_some_and(|exp| exp > now),
        "{claims}"
    );
    assert!(
        claims["jti"]
            .as_str()
            .is_some_and(|jti| uuid::Uuid::parse_str(jti).is_ok()),
        "{claims}"
    );
}

#[tokio::test]
async fn without_propagation_the_backend_receives_no_authorization() {
    let issuer_keys = GatewayKeyPair::generate().expect("issuer key");
    let issuer = issuer(&issuer_keys).await;
    let bearer = id_token(&issuer_keys, &issuer);
    let seen = Seen::default();
    let backend = recording_backend(&seen).await;
    let ws = workspace(&backend, &issuer, "");
    let gateway = Gateway::start(&ws).await;

    invoke(&gateway, &bearer).await;
    assert_eq!(calls(&seen).len(), 1, "one tools/call reached the backend");
    let seen = seen.lock().expect("seen");
    assert!(
        seen.iter()
            .all(|(_, authorization)| authorization.is_none()),
        "no backend request of any method carried Authorization: {seen:?}"
    );
}
