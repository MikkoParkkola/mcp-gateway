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

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/mcp_http_servers.rs"]
#[allow(dead_code, reason = "shared fixtures; each binary uses a subset")]
mod mcp_http_servers;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::routing::{get, post};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mcp_gateway::gateway::oauth::GatewayKeyPair;
use serde_json::{Value, json};

const BACKEND: &str = "minted";
const AUDIENCE: &str = "urn:test:minted";
const CLIENT_ID: &str = "gateway-under-test";
const SUBJECT: &str = "user-7f3a";
const EMAIL: &str = "alice@example.test";
const READY_BOUND: Duration = Duration::from_secs(60);
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

struct Gateway {
    _tmp: tempfile::TempDir,
    child: tokio::process::Child,
    log: PathBuf,
    url: String,
    http: reqwest::Client,
}

impl Gateway {
    /// The binary with one HTTP backend, `propagation` its
    /// `identity_propagation` block (or none), and the key server trusting
    /// `issuer` for delegated bearers.
    async fn start(backend_url: &str, issuer: &str, propagation: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("temp root");
        let root = tmp.path().to_path_buf();
        let config = root.join("gateway.yaml");
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
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
        let log = root.join("serve.log");
        let out = std::fs::File::create(&log).expect("serve log");
        let err = out.try_clone().expect("log handle");
        let mut command = tokio::process::Command::from(gateway_bin::command(
            &root,
            gateway_bin::Inherit::Environment,
        ));
        let child = command
            .current_dir(&root)
            .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
            .args(["-c", "gateway.yaml", "-p", "0", "serve"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .kill_on_drop(true)
            .spawn()
            .expect("serve spawns");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .build()
            .expect("an HTTP client");
        let mut gateway = Self {
            _tmp: tmp,
            child,
            log,
            url: String::new(),
            http,
        };
        gateway.wait_ready().await;
        gateway
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Read the port the child bound (`-p 0`) from its log, then wait for
    /// `/health` on it.
    async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + READY_BOUND;
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                panic!("serve exited before ready ({status})\n{}", self.logs());
            }
            if self.url.is_empty()
                && let Some(port) = gateway_bin::logged_port(&self.log)
            {
                self.url = format!("http://127.0.0.1:{port}");
            }
            if !self.url.is_empty()
                && self
                    .http
                    .get(format!("{}/health", self.url))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "serve not ready\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// `gateway_invoke` of the backend's `ping` as the holder of `bearer`.
    async fn invoke(&self, bearer: &str) -> Value {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": "ping", "arguments": {} },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": { "name": "minting-row", "version": "1" },
            },
        }});
        let text = self
            .http
            .post(format!("{}/mcp", self.url))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-protocol-version", PROTOCOL)
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke")
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await
            .expect("the gateway answers")
            .text()
            .await
            .expect("a body");
        let json = text
            .lines()
            .find_map(|line| line.strip_prefix("data:"))
            .unwrap_or(&text);
        serde_json::from_str(json.trim())
            .unwrap_or_else(|e| panic!("not JSON ({e}): {text}\n{}", self.logs()))
    }

    /// The gateway's published signing key with id `kid`.
    async fn published_key(&self, kid: &str) -> DecodingKey {
        let jwks: Value = self
            .http
            .get(format!("{}/.well-known/jwks.json", self.url))
            .send()
            .await
            .expect("jwks answers")
            .json()
            .await
            .expect("jwks is JSON");
        let key = (jwks["keys"].as_array().expect("a key set").iter())
            .find(|key| key["kid"] == kid)
            .unwrap_or_else(|| panic!("no published key {kid}: {jwks}"));
        DecodingKey::from_ec_components(
            key["x"].as_str().expect("x"),
            key["y"].as_str().expect("y"),
        )
        .expect("a P-256 key")
    }
}

/// The `Authorization` of each `tools/call` the backend received.
fn calls(seen: &Seen) -> Vec<Option<String>> {
    (seen.lock().expect("seen").iter())
        .filter(|(method, _)| method == "tools/call")
        .map(|(_, authorization)| authorization.clone())
        .collect()
}

fn answered_pong(answer: &Value) -> bool {
    answer.to_string().contains("pong-minted")
}

#[tokio::test]
async fn a_minting_backend_receives_a_gateway_signed_assertion_for_the_caller() {
    let issuer_keys = GatewayKeyPair::generate().expect("issuer key");
    let issuer = issuer(&issuer_keys).await;
    let bearer = id_token(&issuer_keys, &issuer);
    let seen = Seen::default();
    let backend = recording_backend(&seen).await;
    let gateway = Gateway::start(
        &backend,
        &issuer,
        &format!(
            "    identity_propagation:\n      strategy: signed_assertion\n      \
             audience: \"{AUDIENCE}\"\n      required: false\n      session_mode: stateless\n"
        ),
    )
    .await;

    let answer = gateway.invoke(&bearer).await;
    assert!(answered_pong(&answer), "{answer}\n{}", gateway.logs());
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
    let claims =
        jsonwebtoken::decode::<Value>(token, &gateway.published_key(&kid).await, &validation)
            .expect("the assertion verifies against the gateway's published key")
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
    let (nbf, exp) = (claims["nbf"].as_u64(), claims["exp"].as_u64());
    assert!(nbf.is_some_and(|nbf| nbf <= now + 5), "{claims}");
    assert!(exp.is_some_and(|exp| exp > now), "{claims}");
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
    let gateway = Gateway::start(&backend, &issuer, "").await;

    let answer = gateway.invoke(&bearer).await;
    assert!(answered_pong(&answer), "{answer}\n{}", gateway.logs());
    assert_eq!(calls(&seen), [None], "the call carried no Authorization");
}
