// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5 row 44, OIDC leg: one verified issuer/subject owns ONE nonce
//! quota, whichever credential generation carries it.
//!
//! Every credential here comes off a production path. The opaque bearers are
//! exchanged at the shipped `/auth/token` endpoint; the delegated bearers are
//! ES256 JWTs the gateway verifies against a real HTTPS JWKS endpoint. No
//! `AuthenticatedClient` or `VerifiedIdentity` is constructed by this test —
//! an identity a test writes for itself proves nothing about the middleware
//! that is supposed to derive one.
//!
//! LINUX INTEGRATION, honestly labelled. The JWKS fixture is trusted through a
//! child-local `SSL_CERT_FILE`, which is what rustls-platform-verifier reads on
//! Linux. That is not a verification bypass and not a machine trust-store edit,
//! but it is also not portable, so this target is gated to Linux — the same
//! qualification `tests/sub4_execution_admission.rs:412-417` puts on the same
//! fixture. The helper carries no `cfg` of its own because its parent does.

#![cfg(target_os = "linux")]

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;
#[path = "common/sub4_oidc.rs"]
pub mod sub4_oidc;

use serde_json::{Value, json};
use signing_gateway::{BackendFixture, HttpGateway, fixture_config, invoke};
use sub4_oidc::OidcFixture;

/// The production per-principal admission limit (`NonceStore::new`).
const LIMIT: usize = 10_000;
/// A second issuer that signs with the same JWKS key. Same subject strings,
/// same display labels — only the issuer differs, which is the whole point.
const SECOND_ISSUER: &str = "https://other-idp.example";
const ALICE: &str = "alice";
const BOB: &str = "bob";
/// A configured static bearer, present in every case purely as a control: the
/// public-branch ordering this increment changes is the code the static path
/// already runs through.
const PRIMARY: &str = "oidc-quota-primary-key-0123456789abcdef";
/// Exact wire messages. Asserted, never paraphrased.
const CAPACITY: &str = "Signing nonce capacity exceeded";
const REPLAY: &str = "Nonce replay detected";

/// Which gateway a case runs against. Named fields rather than positional
/// booleans: `Shape { delegated_bearer: false, ..Shape::public() }` is readable
/// at the call site without opening this file.
struct Shape {
    /// `/mcp` listed in `auth.public_paths`.
    public_mcp: bool,
    /// `key_server.delegated_bearer` — whether a raw ID token is a credential.
    delegated_bearer: bool,
    /// `auth.enabled`.
    auth_enabled: bool,
}

impl Shape {
    /// Credential required on `/mcp`.
    fn protected() -> Self {
        Self {
            public_mcp: false,
            delegated_bearer: true,
            auth_enabled: true,
        }
    }

    /// `/mcp` open to anonymous callers, as the starter config ships it.
    fn public() -> Self {
        Self {
            public_mcp: true,
            ..Self::protected()
        }
    }
}

async fn start(shape: Shape) -> (BackendFixture, HttpGateway, OidcFixture) {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let oidc = OidcFixture::start().await;
    let mut config = fixture_config(&backend.url);
    config["idempotency"] = json!({"read_only_tools": [{
        "server": signing_gateway::BACKEND, "tool": signing_gateway::TOOL
    }]});
    // Repeated identical calls hit the real response cache. Nonces must still
    // be admitted for every delivery, before that cache can return a result.
    config["cache"]["enabled"] = json!(true);
    // The fixture owns `auth` and `key_server` wholesale; patch afterwards.
    oidc.configure(&mut config);
    config["auth"]["enabled"] = json!(shape.auth_enabled);
    config["auth"]["bearer_token"] = json!(PRIMARY);
    if shape.public_mcp {
        config["auth"]["public_paths"] = json!(["/health", "/mcp"]);
    }
    config["key_server"]["delegated_bearer"] = json!(shape.delegated_bearer);
    // Two live tokens for one identity IS the contract under test, so the
    // per-identity token cap must not be what refuses the second exchange.
    config["key_server"]["max_tokens_per_identity"] = json!(8);
    // Longer than a 10,000-request fill: an expired opaque bearer would look
    // exactly like the capacity refusal this test is trying to observe.
    config["key_server"]["token_ttl_secs"] = json!(3600);
    add_second_issuer(&mut config);
    let gateway =
        HttpGateway::start_with_env(config, &[("SSL_CERT_FILE", oidc.ca_path.as_os_str())]).await;
    (backend, gateway, oidc)
}

/// Clone the fixture's provider and policy onto a second issuer. Configured for
/// every case from one builder; only the first case presents a token for it.
fn add_second_issuer(config: &mut Value) {
    let mut provider = config["key_server"]["oidc"][0].clone();
    provider["issuer"] = json!(SECOND_ISSUER);
    config["key_server"]["oidc"]
        .as_array_mut()
        .expect("the fixture configures a provider list")
        .push(provider);
    let mut policy = config["key_server"]["policies"][0].clone();
    policy["match"]["issuer"] = json!(SECOND_ISSUER);
    config["key_server"]["policies"]
        .as_array_mut()
        .expect("the fixture configures a policy list")
        .push(policy);
}

/// Exchange a real ID token at the shipped `/auth/token` endpoint and return the
/// opaque bearer the gateway minted.
///
/// Form-encoded per RFC 8693, as the handler requires. Neither the presented ID
/// token nor the issued bearer is ever printed: on refusal only the status is
/// reported, because a body that carried a credential would put it in the log.
async fn mint(gateway: &HttpGateway, subject_token: &str) -> String {
    let response = gateway
        .client
        .post(format!("{}/auth/token", gateway.url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", subject_token),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:id_token",
            ),
        ])
        .send()
        .await
        .expect("token exchange request");
    let status = response.status();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "the production token exchange refused a valid ID token"
    );
    let body: Value = response.json().await.expect("token exchange JSON");
    body["access_token"]
        .as_str()
        .expect("a successful exchange carries an opaque bearer")
        .to_owned()
}

async fn send(
    gateway: &HttpGateway,
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
        // A caller-controlled label must never create a new quota owner.
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

async fn call(gateway: &HttpGateway, token: Option<&str>, nonce: &str) -> Value {
    let (status, body) = send(gateway, token, nonce).await;
    let body: Value = serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("quota JSON response ({status}): {error}"));
    // `invoke` sends the nonce as the request id, so one assertion covers the
    // correlation of both outcomes. A refusal that drops the id is a wire
    // defect nothing else in this file would notice.
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

/// A protected path refuses this credential outright, before any RPC exists.
/// The body is deliberately not read into the failure message: an auth
/// challenge is not JSON-RPC and has nothing to add.
async fn unauthorized(gateway: &HttpGateway, token: &str, nonce: &str) {
    let (status, _) = send(gateway, Some(token), nonce).await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "a protected path admitted a credential it must refuse"
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
/// credential, before anything is exhausted.
async fn fill(gateway: &HttpGateway, backend: &BackendFixture, token: Option<&str>) {
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

/// Row 44's OIDC sentence: temporary token A fills the bucket, separately
/// minted temporary B and separately verified delegated C are refused fresh
/// nonces, and another subject still succeeds.
///
/// Every credential except A is obtained AFTER the fill — a delegated bearer
/// minted beforehand would expire during it, and a token that failed
/// verification would be indistinguishable from one refused for capacity.
#[tokio::test]
async fn oidc_generations_of_one_identity_share_a_single_nonce_quota() {
    let (backend, gateway, oidc) = start(Shape::protected()).await;
    let alice_a = mint(&gateway, &oidc.token(ALICE, 1)).await;

    fill(&gateway, &backend, Some(&alice_a)).await;

    let alice_b = mint(&gateway, &oidc.token(ALICE, 2)).await;
    // Compared, never printed: a failing `assert_ne!` would put both live
    // bearers into the test output.
    assert!(
        alice_a != alice_b,
        "two exchanges must mint two distinct opaque bearers, or this case \
         only proves a token equals itself"
    );
    let bob = mint(&gateway, &oidc.token(BOB, 1)).await;
    // Same subject string, different issuer. Both carry the fixture's identical
    // display email and name, so a quota keyed on labels would collapse them.
    let other_issuer_alice = mint(&gateway, &oidc.token_for_issuer(SECOND_ISSUER, ALICE, 1)).await;
    let delegated_alice = oidc.token(ALICE, 3);
    let delegated_bob = oidc.token(BOB, 2);

    let dispatched = backend.calls().len();
    // The contract. A separately minted generation and a delegated bearer
    // verified straight off the JWKS are the SAME verified issuer/subject, so
    // both inherit the bucket A exhausted.
    refused(
        &call(&gateway, Some(&alice_b), "alice-b-fresh").await,
        CAPACITY,
    );
    refused(
        &call(&gateway, Some(&delegated_alice), "alice-c-fresh").await,
        CAPACITY,
    );
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );

    // Discriminators. If these fail alongside the refusals above, the quota is
    // simply global and nothing about identity has been shown.
    for (token, nonce) in [
        (bob.as_str(), "bob-fresh"),
        (other_issuer_alice.as_str(), "other-issuer-fresh"),
        (delegated_bob.as_str(), "bob-delegated-fresh"),
        // The configured static bearer is untouched by all of this.
        (PRIMARY, "primary-fresh"),
    ] {
        accepted(&call(&gateway, Some(token), nonce).await, nonce);
    }

    // A bucket is capacity, not a private namespace: Bob has room, so a live
    // Alice nonce can only be refused as a replay, and replay is decided first.
    let dispatched = backend.calls().len();
    refused(&call(&gateway, Some(&bob), "fill-0").await, REPLAY);
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a replay refusal reached the backend"
    );

    // A real signature tamper, not a malformed placeholder: the JWT still
    // parses and still names a configured issuer, and is still refused.
    unauthorized(
        &gateway,
        &oidc.invalid_signature(&delegated_bob),
        "tampered-fresh",
    )
    .await;
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a refused credential reached the backend"
    );
}

/// Both paths must recognise a valid OIDC credential. The public branch
/// currently tries static auth and then falls straight to anonymous, so a
/// public caller's temporary or delegated bearer is never examined at all.
#[tokio::test]
async fn public_paths_recognise_real_oidc_credentials_and_fall_back_anonymously() {
    let (backend, gateway, oidc) = start(Shape::public()).await;

    fill(&gateway, &backend, None).await;

    let alice = mint(&gateway, &oidc.token(ALICE, 1)).await;
    let delegated_bob = oidc.token(BOB, 1);
    let tampered = oidc.invalid_signature(&delegated_bob);

    // Missing and invalid public input stays anonymous — that policy is not
    // being weakened, and it is what makes the two acceptances below mean
    // something rather than "the bucket had room".
    let dispatched = backend.calls().len();
    for (token, nonce) in [
        (Some(tampered.as_str()), "tampered-fresh"),
        (Some("not-a-token-this-gateway-issued"), "unknown-fresh"),
        (None, "no-credential-fresh"),
    ] {
        refused(&call(&gateway, token, nonce).await, CAPACITY);
    }
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "an anonymous capacity refusal reached the backend"
    );

    // Asserted AFTER the anonymous flood: a 200 before the fill would prove
    // only that the route works.
    for (token, nonce) in [
        (alice.as_str(), "alice-public-fresh"),
        (delegated_bob.as_str(), "bob-public-delegated-fresh"),
        // Public static recognition already ships; it must survive the branch
        // reordering that teaches this path about OIDC credentials.
        (PRIMARY, "primary-public-fresh"),
    ] {
        accepted(&call(&gateway, Some(token), nonce).await, nonce);
    }

    // Nonce uniqueness stays global across the public route too. This shows
    // recognition, not shared identity — the shared cap is proved in the
    // protected case, which is where the fill for it lives.
    refused(
        &call(&gateway, Some(&oidc.token(ALICE, 2)), "alice-public-fresh").await,
        REPLAY,
    );
}

/// With delegated bearers disabled, a genuinely valid signed JWT is not a
/// credential and must not acquire a quota identity — while the opaque
/// temporary token, a different mechanism entirely, still must.
#[tokio::test]
async fn delegated_disabled_jwts_never_mint_an_oidc_quota_identity() {
    let (backend, gateway, oidc) = start(Shape {
        delegated_bearer: false,
        ..Shape::public()
    })
    .await;

    fill(&gateway, &backend, None).await;

    // The exchange endpoint is not gated on `delegated_bearer`; only the raw
    // ID token as a bearer is.
    let alice = mint(&gateway, &oidc.token(ALICE, 1)).await;
    let delegated = oidc.token(BOB, 1);
    let tampered = oidc.invalid_signature(&delegated);

    let dispatched = backend.calls().len();
    for (token, nonce) in [
        (delegated.as_str(), "delegated-disabled-fresh"),
        (tampered.as_str(), "delegated-tampered-fresh"),
    ] {
        refused(&call(&gateway, Some(token), nonce).await, CAPACITY);
    }
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );

    accepted(
        &call(&gateway, Some(&alice), "temporary-still-recognised").await,
        "temporary-still-recognised",
    );
}

/// With authentication off there are no authenticated principals to have
/// buckets. A genuinely minted temporary bearer must spend the anonymous
/// capacity like any other caller, and a caller with no credential at all must
/// find that capacity already gone — which is what discriminates this from the
/// bearer quietly getting a bucket of its own.
#[tokio::test]
async fn auth_disabled_gives_real_oidc_credentials_no_quota_of_their_own() {
    let (backend, gateway, oidc) = start(Shape {
        auth_enabled: false,
        ..Shape::public()
    })
    .await;
    let alice = mint(&gateway, &oidc.token(ALICE, 1)).await;

    fill(&gateway, &backend, Some(&alice)).await;

    let delegated = oidc.token(BOB, 1);
    let dispatched = backend.calls().len();
    for (token, nonce) in [
        (None, "disabled-anonymous-fresh"),
        (Some(delegated.as_str()), "disabled-delegated-fresh"),
        (Some(alice.as_str()), "disabled-temporary-fresh"),
    ] {
        refused(&call(&gateway, token, nonce).await, CAPACITY);
    }
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );
}
