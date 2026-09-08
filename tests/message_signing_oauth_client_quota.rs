// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5 row 44, registered-OAuth-client leg: one VERIFIED agent client owns
//! ONE nonce quota, whichever token generation carries it — and two registered
//! clients are two quotas even when they share a display name.
//!
//! Every credential is a real HS256 agent JWT, verified by the shipped
//! middleware against the registry the production binary built from its own
//! config. No `AgentIdentity` and no `AuthenticatedClient` is constructed here:
//! an identity a test writes for itself proves nothing about the middleware that
//! is supposed to derive one.
//!
//! Static authentication is OFF throughout. That is the case, not a shortcut: a
//! separately verified agent identity must carry quota authority on its own,
//! without an API key to borrow it from. The second test turns agent auth off as
//! well, which is what discriminates "the verified identity owns a bucket" from
//! "anything token-shaped gets one".
//!
//! Not covered here, deliberately, because it is covered whole elsewhere:
//! static-key, OIDC and dashboard identities (`tests/message_signing_oidc_quota.rs`
//! and the static-identity suites). This file adds only the registered-client leg.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use signing_gateway::{BackendFixture, child_command, fixture_config, invoke};
use tempfile::TempDir;
use tokio::process::Child;

/// The production per-principal admission limit (`NonceStore::new`).
const LIMIT: usize = 10_000;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Two registrations, one display name. A quota keyed on the human-readable
/// label rather than on the registered client collapses them into one bucket,
/// and that collapse is what this file is built to see.
const AGENT_NAME: &str = "Signing Quota Agent";
const ALICE_ID: &str = "signing-quota-alice";
const BOB_ID: &str = "signing-quota-bob";
const ALICE_SECRET: &str = "alice-agent-shared-secret-0123456789abcdef";
const BOB_SECRET: &str = "bob-agent-shared-secret-0123456789abcdef";
/// Never registered against any client, so a token signed with it is a genuine
/// signature failure rather than a malformed placeholder.
const WRONG_SECRET: &str = "not-the-registered-secret-0123456789abcdef";
/// A `sub` no registration names.
const UNKNOWN_ID: &str = "signing-quota-ghost";
/// Exact wire messages. Asserted, never paraphrased.
const CAPACITY: &str = "Signing nonce capacity exceeded";
const REPLAY: &str = "Nonce replay detected";

/// Real signing, real cache, no static authentication.
///
/// The cache and the read-only idempotency mapping are what make a
/// 10,000-request fill practical; nonce admission still happens for every
/// delivery, before a cached result can be returned.
fn config(backend_url: &str, agent_auth: bool) -> Value {
    let mut config = fixture_config(backend_url);
    config["idempotency"] = json!({"read_only_tools": [{
        "server": signing_gateway::BACKEND, "tool": signing_gateway::TOOL
    }]});
    config["cache"]["enabled"] = json!(true);
    config["auth"] = json!({"enabled": false});
    config["agent_auth"] = json!({
        "enabled": agent_auth,
        "agents": [
            {"client_id": ALICE_ID, "name": AGENT_NAME,
             "hs256_secret": ALICE_SECRET, "scopes": ["tools:*"]},
            {"client_id": BOB_ID, "name": AGENT_NAME,
             "hs256_secret": BOB_SECRET, "scopes": ["tools:*"]}
        ]
    });
    config
}

/// Sign an agent JWT the shipped validator will accept for `client_id`.
///
/// `generation` is the only claim that separates two tokens for one client:
/// HS256 is deterministic, so identical claims produce one identical token and a
/// "second generation" would prove a token equals itself. `exp` outlasts a
/// 10,000-request fill, because an expired token would be refused at the door
/// and look nothing like the capacity refusal these cases are trying to observe.
fn token(client_id: &str, secret: &str, generation: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let claims = json!({
        "sub": client_id,
        "iat": now,
        "exp": now + 3600,
        "scope": "tools:*",
        "generation": generation,
    });
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("sign agent JWT")
}

/// The shipped binary, started with agent auth in whichever state the case needs.
///
/// `signing_gateway::HttpGateway` cannot start this gateway. Agent auth is
/// layered over EVERY route in `create_router_with`, `/health` included, and the
/// middleware answers a request with no bearer 401 before it reaches any
/// handler — so the shared fixture's anonymous readiness probe would time out
/// against a gateway that is working exactly as configured. The only difference
/// here is a probe that presents a credential.
struct AgentGateway {
    child: Child,
    directory: TempDir,
    url: String,
    client: reqwest::Client,
}

impl AgentGateway {
    async fn start(config: Value, readiness: Option<&str>) -> Self {
        let mut config = config;
        let directory = tempfile::tempdir().expect("gateway directory");
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve port");
        let port = reservation.local_addr().expect("reserved address").port();
        config["server"]["port"] = json!(port);
        let config_path = directory.path().join("gateway.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config YAML"),
        )
        .expect("write gateway config");
        let log = std::fs::File::create(directory.path().join("gateway.log")).expect("gateway log");
        let mut command = child_command(directory.path(), &config_path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone gateway log")))
            .stderr(Stdio::from(log));
        drop(reservation);
        let child = command.spawn().expect("spawn real HTTP gateway");
        let mut gateway = Self {
            child,
            directory,
            url: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::builder()
                .timeout(IO_TIMEOUT)
                .build()
                .expect("HTTP client"),
        };
        gateway.await_readiness(readiness).await;
        gateway
    }

    async fn await_readiness(&mut self, readiness: Option<&str>) {
        let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("gateway process status") {
                panic!("gateway startup fixture exited {status}: {}", self.logs());
            }
            let mut probe = self.client.get(format!("{}/health", self.url));
            if let Some(token) = readiness {
                probe = probe.bearer_auth(token);
            }
            if probe
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "gateway readiness fixture timed out: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("gateway.log")).unwrap_or_default()
    }
}

/// One signed invocation. Neither the presented bearer nor any part of it is
/// ever printed: a failure message carrying a live credential puts it in the log.
async fn send(
    gateway: &AgentGateway,
    token: Option<&str>,
    nonce: &str,
) -> (reqwest::StatusCode, String) {
    let mut request = invoke(json!(nonce), json!(nonce), json!({}));
    request["params"]["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut http = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        // A caller-controlled label must never create a new quota owner. It
        // varies per request, so a quota keyed on it would never fill at all.
        .header("x-agent-id", nonce)
        .json(&request);
    if let Some(token) = token {
        http = http.bearer_auth(token);
    }
    let response = http.send().await.expect("quota HTTP request");
    (
        response.status(),
        response.text().await.expect("quota response body"),
    )
}

async fn call(gateway: &AgentGateway, token: Option<&str>, nonce: &str) -> Value {
    let (status, body) = send(gateway, token, nonce).await;
    let body: Value = serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("quota JSON response ({status}): {error}"));
    // `invoke` sends the nonce as the request id, so one assertion covers the
    // correlation of both outcomes. A refusal that drops the id is a wire defect
    // nothing else in this file would notice.
    assert_eq!(
        body["id"], nonce,
        "the response must carry its request id: {body}"
    );
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

/// The agent-auth middleware refuses this credential outright, before any RPC
/// exists. The body is deliberately not read into the failure message: a bearer
/// challenge is not JSON-RPC and has nothing to add.
async fn unauthorized(gateway: &AgentGateway, token: &str, nonce: &str) {
    let (status, _) = send(gateway, Some(token), nonce).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "the gateway admitted an agent credential it must refuse"
    );
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

/// Admit exactly the production per-principal bound under one credential, then
/// prove the next distinct nonce is refused and never reached a backend.
///
/// The first admission is the positive control: real wire signing, on this
/// credential, reaching a real backend, before anything is exhausted.
async fn fill(gateway: &AgentGateway, backend: &BackendFixture, token: Option<&str>) {
    accepted(&call(gateway, token, "fill-0").await, "fill-0");
    assert!(
        !backend.calls().is_empty(),
        "the fixture never dispatched, so this fill proves nothing"
    );
    for i in 1..LIMIT {
        let nonce = format!("fill-{i}");
        accepted(&call(gateway, token, &nonce).await, &nonce);
    }
    let dispatched = backend.calls().len();
    refused(&call(gateway, token, "over-cap").await, CAPACITY);
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );
}

/// Row 44's registered-client sentence: the verified client owns the bucket.
///
/// Alice's first token generation exhausts it; a separately signed second
/// generation for the same registered client inherits the exhausted bucket; Bob,
/// a different registration carrying the identical display name, still has his
/// own.
#[tokio::test]
async fn registered_oauth_clients_own_independent_nonce_quotas() {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let alice_a = token(ALICE_ID, ALICE_SECRET, 1);
    let gateway = AgentGateway::start(config(&backend.url, true), Some(&alice_a)).await;

    // Readiness polls `/health` under Alice's bearer an unbounded number of
    // times. None of them may count as an invocation: if one did, the fill below
    // would be short by however many polls the loop happened to run, and the
    // shortfall would surface as an `over-cap` assertion that looks like a
    // defect in the code under test.
    assert!(
        backend.calls().is_empty(),
        "readiness dispatched to the backend, so the fill count is not the cap"
    );

    fill(&gateway, &backend, Some(&alice_a)).await;

    let alice_b = token(ALICE_ID, ALICE_SECRET, 2);
    // Compared, never printed: a failing `assert_ne!` would put both live
    // credentials into the test output.
    assert!(
        alice_a != alice_b,
        "two generations must be two tokens, or this case only proves a token \
         equals itself"
    );
    let dispatched = backend.calls().len();
    refused(
        &call(&gateway, Some(&alice_b), "alice-second-generation").await,
        CAPACITY,
    );
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );

    // The discriminator. Same display name, different registered client. If this
    // is refused alongside the case above, the quota is simply global and
    // nothing about identity has been shown.
    let bob = token(BOB_ID, BOB_SECRET, 1);
    accepted(&call(&gateway, Some(&bob), "bob-fresh").await, "bob-fresh");

    // A bucket is capacity, not a private namespace: Bob has room, so a live
    // Alice nonce can only be refused as a replay, and replay is decided first.
    let dispatched = backend.calls().len();
    refused(&call(&gateway, Some(&bob), "fill-0").await, REPLAY);
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a replay refusal reached the backend"
    );

    // Credentials that fail verification buy nothing — not a bucket, not a
    // dispatch. Both are well-formed JWTs naming a real shape: one is signed
    // with a secret no registration holds, the other names a client no
    // registration defines.
    for (credential, nonce) in [
        (token(ALICE_ID, WRONG_SECRET, 3), "forged-signature-fresh"),
        (token(UNKNOWN_ID, ALICE_SECRET, 1), "unknown-client-fresh"),
    ] {
        unauthorized(&gateway, &credential, nonce).await;
    }
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a refused credential reached the backend"
    );
}

/// With agent auth disabled there is no verified agent identity to own a bucket,
/// so a genuinely well-formed JWT must spend the anonymous capacity like any
/// other caller — and a caller with no credential at all must find that capacity
/// already gone.
///
/// This case passes both before and after the quota change; it is the control
/// that keeps the case above honest. Without it, "Bob succeeded" is equally
/// explained by token-shaped input quietly minting a bucket of its own.
#[tokio::test]
async fn agent_auth_disabled_jwts_never_mint_a_quota_identity() {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let gateway = AgentGateway::start(config(&backend.url, false), None).await;

    assert!(
        backend.calls().is_empty(),
        "readiness dispatched to the backend, so the fill count is not the cap"
    );

    fill(&gateway, &backend, None).await;

    // Registered client, correct secret, unexpired — and with the mechanism off
    // it is not a credential, so it is not an identity either.
    let alice = token(ALICE_ID, ALICE_SECRET, 1);
    let dispatched = backend.calls().len();
    for (credential, nonce) in [
        (alice.as_str(), "disabled-valid-jwt-fresh"),
        (
            "not-a-token-this-gateway-would-verify",
            "disabled-junk-fresh",
        ),
    ] {
        refused(&call(&gateway, Some(credential), nonce).await, CAPACITY);
    }
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "an anonymous capacity refusal reached the backend"
    );
}
