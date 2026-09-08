// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7377.SIGNING.6 sender-only rotation: delivered wire verifies under the
//! current key and fails under the previous key. Same raw HTTP body for both
//! Node oracle checks; key_id stays the current identifier.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use signing_gateway::{BackendFixture, HttpGateway, KEY, fixture_config, invoke};
use tokio::io::AsyncWriteExt;

const PREVIOUS: &str = "signing-test-previous-key-0123456789abcdef";
const KEY_ID: &str = "signing-test-current";
const REQUEST_ID: &str = "sender-rotation-1";
const NONCE: &str = "sender-rotation-nonce";
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(30);

fn backend_result() -> Value {
    json!({"content": [{"type": "text", "text": "sender-rotation sentinel"}]})
}

fn verifier_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

fn oracle_input(wire: &str, key: &str, now: u64) -> Value {
    json!({
        "wire": wire,
        "options": {
            "key": key,
            "keyId": KEY_ID,
            "expectedId": {"kind": "string", "value": REQUEST_ID},
            "expectedNonce": NONCE,
            "now": now
        }
    })
}

async fn verify_wire(wire: &str, key: &str, now: u64) -> std::process::Output {
    let mut child = tokio::process::Command::new("node")
        .arg(verifier_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node is required for the independent signing oracle");
    let mut stdin = child.stdin.take().expect("verifier stdin");
    stdin
        .write_all(oracle_input(wire, key, now).to_string().as_bytes())
        .await
        .expect("write verifier stdin");
    drop(stdin);
    tokio::time::timeout(VERIFIER_TIMEOUT, child.wait_with_output())
        .await
        .expect("bounded node oracle")
        .expect("node oracle process")
}

#[tokio::test]
async fn signing_6_delivered_wire_verifies_under_current_key_not_previous() {
    assert_ne!(
        KEY.as_bytes(),
        PREVIOUS.as_bytes(),
        "SIGNING.6 current and previous keys must be distinct"
    );

    let backend = BackendFixture::start(backend_result()).await;
    let mut config = fixture_config(&backend.url);
    config["security"]["message_signing"]["previous_secret"] = json!(PREVIOUS);
    let gateway = HttpGateway::start(config).await;
    let session = gateway.initialize().await;
    let request = invoke(json!(REQUEST_ID), json!(NONCE), json!({}));
    let http = gateway
        .client
        .post(format!("{}/mcp", gateway.url))
        .header("mcp-session-id", &session)
        .json(&request)
        .send()
        .await
        .expect("gateway HTTP response");
    let status = http.status();
    let wire = http.text().await.expect("raw gateway response body");
    assert!(
        status.is_success(),
        "SIGNING.6 HTTP dispatch must succeed: {status} {wire}"
    );

    let parsed: Value = serde_json::from_str(&wire).unwrap_or_else(|error| {
        panic!("SIGNING.6 delivered body must be JSON: {error}; body={wire}")
    });
    assert!(
        parsed.get("error").is_none() && parsed["result"]["_signature"].is_object(),
        "SIGNING.6 enabled two-key fixture must deliver a signed success: {parsed}"
    );
    assert_eq!(
        parsed["result"]["_signature"]["key_id"], KEY_ID,
        "SIGNING.6 must emit the current key id on the wire: {parsed}"
    );
    assert_eq!(
        backend.calls().len(),
        1,
        "SIGNING.6 backend must dispatch once: {parsed}"
    );

    let now = now_unix();
    let current = verify_wire(&wire, KEY, now).await;
    assert_eq!(
        current.status.code(),
        Some(0),
        "SIGNING.6 current-key oracle must accept the exact wire: stderr={}",
        String::from_utf8_lossy(&current.stderr)
    );
    let verified: Value = serde_json::from_slice(&current.stdout).unwrap_or_else(|error| {
        panic!(
            "SIGNING.6 current-key oracle must return JSON: {error}; stdout={}",
            String::from_utf8_lossy(&current.stdout)
        )
    });
    assert!(
        verified["result"]["_signature"].is_object(),
        "SIGNING.6 current-key oracle must return the verified result: {verified}"
    );
    assert_eq!(
        verified["request_id"],
        json!({"kind": "string", "value": REQUEST_ID}),
        "SIGNING.6 current-key oracle must echo the typed string request ID: {verified}"
    );

    let previous = verify_wire(&wire, PREVIOUS, now).await;
    assert_eq!(
        previous.status.code(),
        Some(1),
        "SIGNING.6 previous-key oracle must reject the same wire: stdout={}",
        String::from_utf8_lossy(&previous.stdout)
    );
    assert_eq!(
        String::from_utf8_lossy(&previous.stderr),
        "MAC mismatch\n",
        "SIGNING.6 previous-key rejection must be cryptographic, not a key-id mismatch"
    );
}
