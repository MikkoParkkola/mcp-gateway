// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2352 (MIK-7406 SIGNING.3): a response served from the response cache or
//! from an idempotent replay is signed for THIS delivery, over THIS request's
//! nonce and id, never handed back with a stored signature.
//!
//! Each delivered wire is checked by the independent ECMAScript oracle
//! (`tests/common/signing_verifier.mjs`), not by the gateway's own signer. The
//! backend call count proves the second request really was served from the
//! cache or the replay store; without it these tests could pass on two plain
//! dispatches.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use signing_gateway::{BackendFixture, HttpGateway, KEY, fixture_config, invoke};
use tokio::io::AsyncWriteExt as _;

const KEY_ID: &str = "signing-test-current";
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";
const BEARER: &str = "signing-replay-bearer-2352-0123456789abcdef";

fn backend_result() -> Value {
    json!({"content": [{"type": "text", "text": "signing cache sentinel"}]})
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

/// Verify `response` with the independent oracle, for `request_id` and `nonce`.
async fn verify(response: &Value, request_id: &str, nonce: &str) {
    let verifier =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs");
    let mut child = tokio::process::Command::new("node")
        .arg(verifier)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node is required for the independent signing oracle");
    let mut stdin = child.stdin.take().expect("verifier stdin");
    let input = json!({
        "wire": serde_json::to_string(response).expect("serialize delivered wire"),
        "options": {
            "key": KEY,
            "keyId": KEY_ID,
            "expectedId": {"kind": "string", "value": request_id},
            "expectedNonce": nonce,
            "now": now_unix()
        }
    });
    stdin
        .write_all(input.to_string().as_bytes())
        .await
        .expect("write verifier stdin");
    drop(stdin);
    let output = tokio::time::timeout(IO_TIMEOUT, child.wait_with_output())
        .await
        .expect("bounded node oracle")
        .expect("node oracle process");
    assert!(
        output.status.success(),
        "oracle refused the {request_id} delivery: stdout={} stderr={} wire={response}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A fresh nonce per request, made at run time rather than written into the
/// test, so each run signs over values no earlier run used.
fn fresh_nonce(tag: &str) -> String {
    format!("{tag}-{}-{}", std::process::id(), now_unix())
}

/// A client that presents [`BEARER`] on every request.
fn bearer_client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {BEARER}").parse().expect("header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(IO_TIMEOUT)
        .build()
        .expect("client")
}

fn signature_of(response: &Value) -> String {
    response["result"]["_signature"]["sig"]
        .as_str()
        .unwrap_or_else(|| panic!("a signed result is required: {response}"))
        .to_owned()
}

/// Cache on: the second request is a cache hit, yet it carries a signature
/// over its own nonce and id, and the two signatures differ.
#[tokio::test]
async fn a_cache_hit_is_signed_for_its_own_nonce() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut config = fixture_config(&backend.url);
    config["cache"] = json!({"enabled": true, "default_ttl": "5m", "max_entries": 100});
    let gateway = HttpGateway::start(config).await;
    let session = gateway.initialize().await;
    let cache_nonce_1 = fresh_nonce("cache-1");
    let cache_nonce_2 = fresh_nonce("cache-2");

    let first = gateway
        .call(
            &session,
            &invoke(json!("cache-1"), json!(cache_nonce_1), json!({})),
        )
        .await;
    let second = gateway
        .call(
            &session,
            &invoke(json!("cache-2"), json!(cache_nonce_2), json!({})),
        )
        .await;

    assert_eq!(
        backend.calls().len(),
        1,
        "the second request must be a cache hit, or this proves nothing: {second}"
    );
    verify(&first, "cache-1", &cache_nonce_1).await;
    verify(&second, "cache-2", &cache_nonce_2).await;
    assert_ne!(signature_of(&first), signature_of(&second));
}

/// A synchronous idempotent replay: the same key served from the replay store
/// is signed over the replaying request's own nonce and id.
#[tokio::test]
async fn an_idempotent_replay_is_signed_for_its_own_nonce() {
    let backend = BackendFixture::start(backend_result()).await;
    // An idempotency key needs a verified caller to scope it to, so auth is on.
    let mut config = fixture_config(&backend.url);
    config["auth"] = json!({"enabled": true, "bearer_token": BEARER});
    let mut gateway = HttpGateway::start(config).await;
    gateway.client = bearer_client();
    let session = gateway.initialize().await;
    let replay_nonce_1 = fresh_nonce("replay-1");
    let replay_nonce_2 = fresh_nonce("replay-2");
    let keyed = |id: &str, nonce: &str| {
        let mut request = invoke(json!(id), json!(nonce), json!({}));
        request["params"]["_meta"] = json!({(IDEMPOTENCY_KEY_META): "signing-replay-key-2352"});
        request
    };

    let first = gateway
        .call(&session, &keyed("replay-1", &replay_nonce_1))
        .await;
    let second = gateway
        .call(&session, &keyed("replay-2", &replay_nonce_2))
        .await;

    assert_eq!(
        backend.calls().len(),
        1,
        "the second request must be an idempotent replay, or this proves nothing: {second}"
    );
    verify(&first, "replay-1", &replay_nonce_1).await;
    verify(&second, "replay-2", &replay_nonce_2).await;
    assert_ne!(signature_of(&first), signature_of(&second));
}
