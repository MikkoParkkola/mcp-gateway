// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5 row 44: a dashboard session is an authenticated operator, and the
//! nonce quota must be told so.
//!
//! Driven through the shipped CLI over real HTTP. The cookie under test is
//! redeemed from the link `serve` prints, exactly as a browser redeems it, so
//! what is exercised is the credential the production middleware minted — not
//! an identity the test wrote for itself.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use serde_json::{Value, json};
use signing_gateway::{BackendFixture, HttpGateway, fixture_config, invoke};

const PRIMARY: &str = "dashboard-primary-key-0123456789abcdef";
/// The production per-principal admission limit (`NonceStore::new`).
const LIMIT: usize = 10_000;
/// What a browser sends back. Written on the wire rather than imported, so this
/// test stays black-box over the shipped binary.
const SESSION_COOKIE: &str = "mcp_gateway_session";
/// The tail of the link printed by `gateway::server::support::log_startup_banner`.
const BOOTSTRAP_MARKER: &str = "/dashboard?bootstrap=";

/// What a caller presents. An enum rather than two optional arguments: at a
/// call site `Session(h)` and `Bearer(t)` are the whole point of each case.
#[derive(Clone, Copy)]
enum Credential<'a> {
    /// No credential at all — the anonymous caller a public path admits.
    Anonymous,
    Bearer(&'a str),
    /// A dashboard session cookie, valid or not.
    Session(&'a str),
}

async fn start() -> (BackendFixture, HttpGateway) {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let mut config = fixture_config(&backend.url);
    config["idempotency"] = json!({"read_only_tools": [{
        "server": signing_gateway::BACKEND, "tool": signing_gateway::TOOL
    }]});
    config["auth"] = json!({
        "enabled": true,
        "bearer_token": PRIMARY,
        "public_paths": ["/health", "/mcp"]
    });
    // Repeated identical calls hit the real response cache. Nonces must still
    // be admitted for every delivery, before that cache can return a result.
    config["cache"]["enabled"] = json!(true);
    let gateway = HttpGateway::start(config).await;
    (backend, gateway)
}

/// Redeem the printed bootstrap link the way a browser does, and return the
/// opaque session handle the gateway set as a cookie.
async fn redeem_dashboard_session(gateway: &HttpGateway) -> String {
    let logs = gateway.logs();
    let start = logs
        .find(BOOTSTRAP_MARKER)
        .expect("serve prints a dashboard bootstrap link on a loopback bind")
        + BOOTSTRAP_MARKER.len();
    // base64url without padding: the value ends where that alphabet does.
    let value: String = logs[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    assert!(
        !value.is_empty(),
        "the printed link carries no bootstrap value"
    );

    // A separate client, for two reasons: following the 303 would discard the
    // `Set-Cookie` this test needs, and the gateway's own client must NOT end
    // up holding a session for every later call.
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("browser client");
    let response = browser
        .get(format!("{}/dashboard?bootstrap={value}", gateway.url))
        .send()
        .await
        .expect("dashboard bootstrap request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::SEE_OTHER,
        "a link redeemed from loopback, with nothing forwarded, must mint a session"
    );

    let cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("the redirect sets the session cookie")
        .to_str()
        .expect("cookie header text")
        .to_owned();
    let prefix = format!("{SESSION_COOKIE}=");
    let handle = cookie
        .split(';')
        .next()
        .and_then(|pair| pair.trim().strip_prefix(&prefix))
        .expect("the cookie carries the session handle")
        .to_owned();
    assert!(!handle.is_empty(), "an empty handle is not a session");
    // Compared, never printed: a failing `assert_ne!` would put the live
    // handle and the credential it must not be into the test output.
    assert!(
        handle != PRIMARY,
        "the cookie must carry an opaque handle, never the credential"
    );
    handle
}

async fn call(gateway: &HttpGateway, credential: Credential<'_>, nonce: &str) -> Value {
    let mut request = invoke(json!(nonce), json!(nonce), json!({}));
    request["params"]["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let http = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        // A caller-controlled label must never create a new quota owner.
        .header("x-agent-id", nonce)
        .json(&request);
    let http = match credential {
        Credential::Anonymous => http,
        Credential::Bearer(token) => http.bearer_auth(token),
        Credential::Session(handle) => http.header("cookie", format!("{SESSION_COOKIE}={handle}")),
    };
    let response = http.send().await.expect("quota HTTP request");
    let status = response.status();
    let body: Value = response.json().await.expect("quota JSON response");
    assert_eq!(
        status,
        if body.get("error").is_some() {
            400
        } else {
            200
        },
        "modern transport status must match the RPC outcome: {body}"
    );
    body
}

fn accepted(response: &Value, nonce: &str) {
    assert!(
        response.get("error").is_none(),
        "signed invocation failed: {response}"
    );
    assert_eq!(response["result"]["_signature"]["nonce"], nonce);
    assert_eq!(response["result"]["_signature"]["version"], 2);
}

fn refused(response: &Value, message: &str) {
    assert_eq!(response["error"]["code"], -32001, "{response}");
    assert_eq!(response["error"]["message"], message, "{response}");
    assert!(response.get("result").is_none());
}

/// Exhaust the anonymous bucket, then prove it is exhausted and that the
/// refusal never reached a backend.
async fn fill_anonymous(gateway: &HttpGateway, backend: &BackendFixture) {
    for i in 0..LIMIT {
        let nonce = format!("fill-{i}");
        accepted(&call(gateway, Credential::Anonymous, &nonce).await, &nonce);
    }
    let dispatched = backend.calls().len();
    assert!(dispatched > 0, "fixture never dispatched");
    refused(
        &call(gateway, Credential::Anonymous, "over-cap").await,
        "Signing nonce capacity exceeded",
    );
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );
}

#[tokio::test]
async fn signing_quota_anonymous_flood_cannot_starve_the_operator_dashboard() {
    let (backend, gateway) = start().await;
    let handle = redeem_dashboard_session(&gateway).await;

    fill_anonymous(&gateway, &backend).await;

    // The contract: the operator's own dashboard holds a dedicated
    // authenticated bucket, so a public flood cannot lock them out of it.
    accepted(
        &call(&gateway, Credential::Session(&handle), "dashboard-fresh").await,
        "dashboard-fresh",
    );

    let dispatched = backend.calls().len();

    // A handle this process never issued is not a session, and no cookie is no
    // session. Neither may mint a bucket by asking for one — the caller label
    // on every request here is attacker-chosen and must change nothing.
    for (credential, nonce) in [
        (
            Credential::Session("not-a-handle-this-process-issued"),
            "forged-cookie-fresh",
        ),
        (Credential::Anonymous, "no-cookie-fresh"),
    ] {
        refused(
            &call(&gateway, credential, nonce).await,
            "Signing nonce capacity exceeded",
        );
    }

    // A bucket is capacity, not a private namespace: nonce uniqueness stays
    // global, so a live anonymous nonce is still a replay under the session.
    refused(
        &call(&gateway, Credential::Session(&handle), "fill-0").await,
        "Nonce replay detected",
    );
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a refused call reached the backend"
    );

    accepted(
        &call(&gateway, Credential::Session(&handle), "dashboard-second").await,
        "dashboard-second",
    );
    // Positive control: the static credential path is untouched by all of this.
    accepted(
        &call(&gateway, Credential::Bearer(PRIMARY), "primary-fresh").await,
        "primary-fresh",
    );
}
