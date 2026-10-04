// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ASI07 increment 3 (design 2026-09-30-asi07-chain-inc3): verify and append
//! across gateway hops, end to end on the shipped binary. Red-first.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

#[path = "signature_chain_hops/fake.rs"]
mod fake;
#[path = "signature_chain_hops/oracle.rs"]
mod oracle;
#[path = "signature_chain_hops/rows_hops.rs"]
mod rows_hops;
#[path = "signature_chain_hops/rows_policy.rs"]
mod rows_policy;

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use signing_gateway::HttpGateway;

use fake::{NONCE_KEY, TOOL, U_ID, U_SEED, V_ID, V_SEED};
use oracle::{CHAIN_KEY, Trust};

/// This (downstream) gateway's chain identity.
pub const D_SEED: [u8; 32] = [31; 32];
pub const D_ID: &str = "gw-d";
/// The backend name the upstream is registered under on D.
pub const UP: &str = "up";

/// Which of D's two routes a row drives.
#[derive(Clone, Copy, Debug)]
pub enum Route {
    Invoke,
    Direct,
}

pub const ROUTES: [Route; 2] = [Route::Invoke, Route::Direct];

/// D's config: one backend at `upstream_url` under chain `mode`, trusting
/// `gw-u` as origin and signer (and `gw-v` as a known key), with its own chain
/// identity and HMAC message signing off unless a row turns it on.
pub fn d_config(upstream_url: &str, mode: &str, emit: &str) -> Value {
    json!({
        "server": {"host": "127.0.0.1", "modern_protocol": true},
        "cache": {"enabled": false},
        "tasks": {"store_dir": "tasks"},
        "backends": {(UP): {"http_url": upstream_url, "streamable_http": true,
            "signature_chain": mode, "chain_origins": [U_ID], "chain_signer": U_ID}},
        "security": {
            "trust_configured_backends": true,
            "message_signing": {"enabled": false},
            "signature_chain": {"signing_key": STANDARD.encode(D_SEED), "key_id": D_ID, "emit": emit},
            "remote_server_signing": {"trusted_keys": {
                (U_ID): {"algorithm": "ed25519", "public_key": oracle::public_key(U_SEED)},
                (V_ID): {"algorithm": "ed25519", "public_key": oracle::public_key(V_SEED)}
            }}
        }
    })
}

/// A client call through `route`, carrying `nonce` as the chain nonce when set.
pub fn request(route: Route, id: &str, nonce: Option<&str>) -> (String, Value) {
    let (path, mut body) = match route {
        Route::Invoke => (
            "/mcp".to_owned(),
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "gateway_invoke", "arguments": {"server": UP, "tool": TOOL, "arguments": {}}}}),
        ),
        Route::Direct => (
            format!("/mcp/{UP}"),
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": TOOL, "arguments": {}}}),
        ),
    };
    if let Some(nonce) = nonce {
        body["params"]["_meta"] = json!({(NONCE_KEY): nonce});
    }
    (path, body)
}

/// POST `body` to `path` on `gateway` inside an initialized session.
pub async fn post(gateway: &HttpGateway, path: &str, body: &Value) -> Value {
    let session = gateway.initialize().await;
    let response = gateway
        .client
        .post(format!("{}{path}", gateway.url))
        .header("mcp-session-id", &session)
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("gateway response: {e}; {}", gateway.logs()));
    let text = response.text().await.expect("gateway body");
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("gateway JSON: {e}; {text}; {}", gateway.logs()))
}

/// Call D once through `route` with `nonce`.
pub async fn call(gateway: &HttpGateway, route: Route, nonce: Option<&str>) -> Value {
    let (path, body) = request(route, "c-1", nonce);
    post(gateway, &path, &body).await
}

/// The result a client reads: for `gateway_invoke` the delivered result
/// itself (the chain rides on it), for the direct route the backend result.
pub fn result_of(response: &Value) -> &Value {
    response
        .get("result")
        .unwrap_or_else(|| panic!("a result is required: {response}"))
}

pub fn chain_len(response: &Value) -> usize {
    result_of(response)
        .get("_meta")
        .and_then(|meta| meta.get(CHAIN_KEY))
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

/// The keys a client trusts: the upstream's, the extra key and D's.
pub fn client_keys() -> BTreeMap<String, String> {
    BTreeMap::from([
        (U_ID.to_owned(), oracle::public_key(U_SEED)),
        (V_ID.to_owned(), oracle::public_key(V_SEED)),
        (D_ID.to_owned(), oracle::public_key(D_SEED)),
    ])
}

/// The client's verdict on a two-hop chain: origin `gw-u`, last signer D.
pub fn client_verify(response: &Value, nonce: &str) -> Result<Vec<Value>, &'static str> {
    let keys = client_keys();
    let trust = Trust {
        keys: &keys,
        origins: &[U_ID],
        signer: D_ID,
    };
    oracle::verify(result_of(response), &trust, nonce)
}

/// A `-32001` refusal naming `rule` (a `ChainRefusal` name).
pub fn assert_refused(response: &Value, rule: &str) {
    assert_eq!(response["error"]["code"], -32001, "{response}");
    let message = response["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(rule),
        "refusal must name {rule}: {response}"
    );
    assert!(!response.to_string().contains(CHAIN_KEY), "{response}");
}
