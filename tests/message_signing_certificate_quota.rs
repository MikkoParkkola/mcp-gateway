// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5 row 44, certificate leg: one VERIFIED client certificate owns ONE
//! nonce quota, across however many TLS connections present it — and two
//! certificates are two quotas even when every printable field matches.
//!
//! The gateway runs its production TLS listener with `require_client_cert`, so
//! each identity here is derived by the shipped acceptor from a leaf that passed
//! a real handshake. No `CertIdentity` is constructed by this file, no display
//! label is edited, and nothing is proved by parsing a certificate: the only
//! evidence accepted here is what the running gateway did with a caller that
//! presented one.
//!
//! Static authentication is OFF throughout. That is the case, not a shortcut: a
//! verified certificate must carry quota authority on its own, without an API
//! key to borrow it from.

#[path = "common/signing_certificate_gateway.rs"]
pub mod signing_certificate_gateway;
#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use mcp_gateway::mtls::GeneratedCert;
use serde_json::{Value, json};
use signing_certificate_gateway::{CLIENT_CN, CertFixture, TlsGateway, untrusted_client};
use signing_gateway::{BackendFixture, fixture_config, invoke};

/// The production per-principal admission limit (`NonceStore::new`).
const LIMIT: usize = 10_000;
/// Exact wire messages. Asserted, never paraphrased.
const CAPACITY: &str = "Signing nonce capacity exceeded";
const REPLAY: &str = "Nonce replay detected";

/// Real signing, real cache, real TLS, no static authentication.
///
/// The cache and the read-only idempotency mapping are what make a
/// 10,000-request fill practical; nonce admission still happens for every
/// delivery, before a cached result can be returned.
fn config(backend_url: &str, fixture: &CertFixture) -> Value {
    let mut config = fixture_config(backend_url);
    config["idempotency"] = json!({"read_only_tools": [{
        "server": signing_gateway::BACKEND, "tool": signing_gateway::TOOL
    }]});
    config["cache"]["enabled"] = json!(true);
    config["auth"] = json!({"enabled": false});
    fixture.configure(&mut config, true);
    config
}

/// One signed invocation over TLS.
///
/// Returns the transport error rather than panicking on it: a refused handshake
/// IS the expected outcome for two of the cases below, and it has no status and
/// no body to report.
async fn send(
    client: &reqwest::Client,
    url: &str,
    nonce: &str,
) -> reqwest::Result<(reqwest::StatusCode, String)> {
    let mut request = invoke(json!(nonce), json!(nonce), json!({}));
    request["params"]["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let response = client
        .post(format!("{url}/mcp"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        // A caller-controlled label must never create a new quota owner.
        .header("x-agent-id", nonce)
        .json(&request)
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.text().await?))
}

async fn call(client: &reqwest::Client, gateway: &TlsGateway, nonce: &str) -> Value {
    let (status, body) = send(client, &gateway.url, nonce)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "a trusted client was refused at the transport: {error}; logs={}",
                gateway.logs()
            )
        });
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

/// Admit exactly the production per-principal bound under one certificate, then
/// prove the next distinct nonce is refused and never reached a backend.
///
/// The first admission is the positive control for the whole TLS route: a real
/// signed response, over a real mutually-authenticated connection, reaching a
/// real backend, before anything is exhausted.
async fn fill(client: &reqwest::Client, gateway: &TlsGateway, backend: &BackendFixture) {
    accepted(&call(client, gateway, "fill-0").await, "fill-0");
    assert!(
        !backend.calls().is_empty(),
        "the fixture never dispatched over TLS, so this fill proves nothing"
    );
    for i in 1..LIMIT {
        let nonce = format!("fill-{i}");
        accepted(&call(client, gateway, &nonce).await, &nonce);
    }
    let dispatched = backend.calls().len();
    refused(&call(client, gateway, "over-cap").await, CAPACITY);
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );
}

/// Row 44's certificate sentence: the verified certificate owns the bucket.
///
/// Alice exhausts hers over one connection; a second, independent TLS client
/// presenting the SAME certificate inherits the exhausted bucket; Bob, whose
/// certificate is a different DER carrying an identical CN and therefore an
/// identical display label, still has his own.
#[tokio::test]
async fn verified_client_certificates_own_independent_nonce_quotas() {
    let backend = BackendFixture::start(json!({"content": []})).await;
    let fixture = CertFixture::generate();
    let alice = fixture.issue_client(CLIENT_CN);
    let bob = fixture.issue_client(CLIENT_CN);
    assert_ne!(
        alice.cert_pem, bob.cert_pem,
        "two issues must be two certificates, or this case only proves a \
         certificate equals itself"
    );
    let gateway = TlsGateway::start(config(&backend.url, &fixture), &fixture, &alice).await;

    // Readiness polls `/health` over Alice's connection an unbounded number of
    // times. None of them may count as an invocation: if one did, the fill below
    // would be short by however many polls the loop happened to run, and the
    // shortfall would surface as an `over-cap` assertion that looks like a
    // defect in the code under test.
    assert!(
        backend.calls().is_empty(),
        "readiness dispatched to the backend, so the fill count is not the cap"
    );

    let alice_client = gateway.client(&fixture, Some(&alice));
    fill(&alice_client, &gateway, &backend).await;

    // Same certificate, a separate client and therefore a separate TLS
    // connection. One verified identity, one bucket — connections do not
    // multiply it.
    let alice_reconnected = gateway.client(&fixture, Some(&alice));
    let dispatched = backend.calls().len();
    refused(
        &call(&alice_reconnected, &gateway, "alice-second-connection").await,
        CAPACITY,
    );
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a capacity refusal reached the backend"
    );

    // The discriminator. Identical CN, identical display label, different
    // verified DER. If this is refused alongside the case above, the quota is
    // simply global and nothing about certificate identity has been shown.
    let bob_client = gateway.client(&fixture, Some(&bob));
    accepted(&call(&bob_client, &gateway, "bob-fresh").await, "bob-fresh");

    // A bucket is capacity, not a private namespace: Bob has room, so a live
    // Alice nonce can only be refused as a replay, and replay is decided first.
    let dispatched = backend.calls().len();
    refused(&call(&bob_client, &gateway, "fill-0").await, REPLAY);
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a replay refusal reached the backend"
    );

    refused_at_the_handshake(&gateway, &fixture, &backend).await;
}

/// Callers the TLS layer must never let through, and the proof that it did not.
///
/// Both are well-formed HTTPS requests to a listener that is demonstrably
/// working — the cases above just used it. The untrusted leaf differs from
/// Alice's in exactly one respect, its issuer.
async fn refused_at_the_handshake(
    gateway: &TlsGateway,
    fixture: &CertFixture,
    backend: &BackendFixture,
) {
    let foreign: GeneratedCert = untrusted_client(CLIENT_CN);
    let untrusted = gateway.client(fixture, Some(&foreign));
    let anonymous = gateway.client(fixture, None);
    let dispatched = backend.calls().len();
    for (client, nonce) in [
        (&untrusted, "untrusted-certificate-fresh"),
        (&anonymous, "no-certificate-fresh"),
    ] {
        assert!(
            send(client, &gateway.url, nonce).await.is_err(),
            "the TLS listener admitted a caller it must refuse at the handshake"
        );
    }
    assert_eq!(
        backend.calls().len(),
        dispatched,
        "a refused handshake reached the backend"
    );
}
