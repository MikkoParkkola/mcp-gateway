// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ASI07 increment 2 (design amendment A3): the delivery construction sites
//! carry the dispatch outcome into origin-link emission, on the real binary.
//!
//! Rows CS, R15b, E6h, E8m and E8d. The positive rows are red until the
//! carrier exists; the negative rows are controls against "chain everything".

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use signing_gateway::{BACKEND, BackendFixture, HttpGateway, fixture_config, invoke};

const CHAIN_KEY: &str = "io.mcp-gateway/signature-chain";
const NONCE_KEY: &str = "io.mcp-gateway/chain-nonce";
const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";
const CHAIN_KEY_ID: &str = "gw-sites";
/// Base64 of 32 bytes of 0x07: a fixed Ed25519 seed for the fixture only.
const CHAIN_SEED: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
const BEARER: &str = "chain-sites-bearer-0123456789abcdef0123";
const IO_TIMEOUT: Duration = Duration::from_secs(30);

fn backend_result() -> Value {
    json!({"content": [{"type": "text", "text": "chain sites sentinel"}]})
}

/// The signing fixture with the chain identity added and emission on request.
fn chain_config(backend_url: &str) -> Value {
    let mut config = fixture_config(backend_url);
    config["security"]["signature_chain"] =
        json!({"signing_key": CHAIN_SEED, "key_id": CHAIN_KEY_ID, "emit": "on_request"});
    config
}

/// Auth on (an idempotency key needs a verified caller) plus the audit log
/// auth requires. Returns the temp dir that must outlive the gateway.
fn with_auth(config: &mut Value) -> tempfile::TempDir {
    config["auth"] = json!({"enabled": true, "bearer_token": BEARER});
    let audit = tempfile::tempdir().expect("audit dir");
    config["security"]["transparency_log"] =
        json!({"enabled": true, "path": audit.path().join("audit").join("log.jsonl")});
    audit
}

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

/// Put `nonce` where a client asks for a chain: `params._meta`.
fn chained(mut request: Value, nonce: &str) -> Value {
    request["params"]["_meta"][NONCE_KEY] = json!(nonce);
    request
}

fn keyed(mut request: Value, key: &str) -> Value {
    request["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!(key);
    request
}

fn signed_invoke(id: &str, hmac_nonce: &str) -> Value {
    invoke(json!(id), json!(hmac_nonce), json!({}))
}

/// The single origin link on a response, or a failure naming the response.
fn origin(response: &Value) -> &Value {
    let chain = response["result"]["_meta"][CHAIN_KEY]
        .as_array()
        .unwrap_or_else(|| panic!("an origin link is required: {response}"));
    assert_eq!(chain.len(), 1, "exactly one origin link: {response}");
    let link = &chain[0];
    assert_eq!(link["gw"], CHAIN_KEY_ID, "{link}");
    assert_eq!(link["up"], "none", "{link}");
    assert!(link["prev"].is_null() && link["in"].is_null(), "{link}");
    link
}

fn unchained(response: &Value) -> bool {
    !response.to_string().contains(CHAIN_KEY)
}

/// `H(result)` computed independently: SHA-256 hex of RFC 8785 of the
/// delivered result minus top-level `_meta` and `_signature`.
fn digest_of_delivered(result: &Value) -> String {
    let mut content = result.as_object().expect("object result").clone();
    content.remove("_meta");
    content.remove("_signature");
    let canonical = serde_json_canonicalizer::to_vec(&Value::Object(content)).expect("jcs");
    hex::encode(Sha256::digest(&canonical))
}

/// CS (HTTP): a backend `gateway_invoke` result is Backend at the router's
/// construction site, so it carries a live origin link over the delivered result.
#[tokio::test]
async fn cs_http_backend_invoke_carries_a_live_origin_link() {
    let backend = BackendFixture::start(backend_result()).await;
    let gateway = HttpGateway::start(chain_config(&backend.url)).await;
    let session = gateway.initialize().await;
    let response = gateway
        .call(
            &session,
            &chained(signed_invoke("cs-1", "hmac-cs-1"), "chain-cs-1"),
        )
        .await;
    let link = origin(&response);
    assert_eq!(link["src"], "live", "{link}");
    assert_eq!(link["nonce"], "chain-cs-1", "{link}");
    // E6h: `out` is the digest of what the client received, `_signature`
    // excluded, whatever protocol shaping added to the result.
    assert_eq!(
        link["out"].as_str(),
        Some(digest_of_delivered(&response["result"]).as_str()),
        "{response}"
    );
}

/// CS (HTTP): a meta-only tool is gateway-authored and never chained.
#[tokio::test]
async fn cs_http_meta_only_tool_is_not_chained() {
    let backend = BackendFixture::start(backend_result()).await;
    let gateway = HttpGateway::start(chain_config(&backend.url)).await;
    let session = gateway.initialize().await;
    let request = json!({"jsonrpc": "2.0", "id": "cs-2", "method": "tools/call", "params": {
        "name": "gateway_search_tools", "arguments": {"query": "echo"}
    }});
    let response = gateway
        .call(&session, &chained(request, "chain-cs-2"))
        .await;
    assert!(
        response.get("result").is_some(),
        "control: the search answered: {response}"
    );
    assert!(unchained(&response), "{response}");
}

/// A3 R6'': the chain nonce is taken off the request before sanitization, so
/// control characters survive byte-exact into the link.
#[tokio::test]
async fn cs_http_control_character_nonce_is_carried_byte_exact() {
    let backend = BackendFixture::start(backend_result()).await;
    let gateway = HttpGateway::start(chain_config(&backend.url)).await;
    let session = gateway.initialize().await;
    let nonce = "a\u{0}b\u{1}c";
    let response = gateway
        .call(
            &session,
            &chained(signed_invoke("cs-3", "hmac-cs-3"), nonce),
        )
        .await;
    assert_eq!(origin(&response)["nonce"], nonce, "{response}");
}

/// R15b (HTTP): a dispatch failure, retried under the same key, is the
/// gateway's own wrapper both times and is never chained.
#[tokio::test]
async fn r15b_http_retried_dispatch_failure_is_not_chained() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut config = chain_config(&backend.url);
    let _audit = with_auth(&mut config);
    let mut gateway = HttpGateway::start(config).await;
    gateway.client = bearer_client();
    let session = gateway.initialize().await;
    // Stop the backend after startup: every dispatch now fails.
    drop(backend);
    for (id, hmac) in [("r15b-1", "hmac-r15b-1"), ("r15b-2", "hmac-r15b-2")] {
        let request = keyed(chained(signed_invoke(id, hmac), "chain-r15b"), "r15b-key");
        let response = gateway.call(&session, &request).await;
        assert!(unchained(&response), "{id}: {response}");
    }
}

/// E8m (HTTP, real replay store): the replay re-links with the replaying
/// request's nonce and `src: replay`; the backend ran once.
#[tokio::test]
async fn e8m_http_replay_relinks_with_the_new_nonce() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut config = chain_config(&backend.url);
    let _audit = with_auth(&mut config);
    let mut gateway = HttpGateway::start(config).await;
    gateway.client = bearer_client();
    let session = gateway.initialize().await;
    let call = |id: &str, hmac: &str, chain: &str| {
        keyed(chained(signed_invoke(id, hmac), chain), "e8m-key")
    };
    let first = gateway
        .call(&session, &call("e8m-1", "hmac-e8m-1", "chain-e8m-1"))
        .await;
    let second = gateway
        .call(&session, &call("e8m-2", "hmac-e8m-2", "chain-e8m-2"))
        .await;
    assert_eq!(
        backend.calls().len(),
        1,
        "the second call must replay: {second}"
    );
    assert_eq!(origin(&first)["src"], "live", "{first}");
    let replayed = origin(&second);
    assert_eq!(replayed["src"], "replay", "{replayed}");
    assert_eq!(replayed["nonce"], "chain-e8m-2", "{replayed}");
}

/// E8d (direct route): the live call carries a live origin link. Its replay
/// is served from the direct idempotency store, which can also hold a
/// gateway-authored side-effect notice and records no origin, so in inc2 the
/// replay is never linked (A3 R3, fail-safe).
#[tokio::test]
async fn e8d_direct_live_linked_and_replay_not() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut config = chain_config(&backend.url);
    config["security"]["message_signing"]["enabled"] = json!(false);
    let _audit = with_auth(&mut config);
    let mut gateway = HttpGateway::start(config).await;
    gateway.client = bearer_client();
    let session = gateway.initialize().await;
    let mut responses = Vec::new();
    for (id, chain) in [("e8d-1", "chain-e8d-1"), ("e8d-2", "chain-e8d-2")] {
        let request = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
            "name": signing_gateway::TOOL, "arguments": {},
            "_meta": {(NONCE_KEY): chain, (IDEMPOTENCY_KEY_META): "e8d-key"}
        }});
        let response: Value = gateway
            .client
            .post(format!("{}/mcp/{BACKEND}", gateway.url))
            .header("mcp-session-id", &session)
            .json(&request)
            .send()
            .await
            .expect("direct route response")
            .json()
            .await
            .expect("direct route JSON");
        responses.push(response);
    }
    assert_eq!(
        backend.calls().len(),
        1,
        "the second call must replay: {responses:?}"
    );
    let live = origin(&responses[0]);
    assert_eq!(live["src"], "live", "{live}");
    assert_eq!(live["nonce"], "chain-e8d-1", "{live}");
    assert!(unchained(&responses[1]), "{}", responses[1]);
}

/// A bare `serve --stdio` child: one JSON-RPC frame per line each way.
struct StdioChild {
    _child: tokio::process::Child,
    _directory: tempfile::TempDir,
    input: tokio::process::ChildStdin,
    output: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
}

impl StdioChild {
    async fn start(config: &Value) -> Self {
        use tokio::io::AsyncBufReadExt as _;
        let directory = tempfile::tempdir().expect("stdio directory");
        let config_path = directory.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(
            &config_path,
            serde_yaml::to_string(config).expect("config YAML"),
        )
        .expect("write config");
        let mut command = signing_gateway::child_command(directory.path(), &config_path);
        command
            .arg("--stdio")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().expect("stdio gateway");
        let input = child.stdin.take().expect("stdin");
        let output = tokio::io::BufReader::new(child.stdout.take().expect("stdout")).lines();
        let mut gateway = Self {
            _child: child,
            _directory: directory,
            input,
            output,
        };
        let initialized = gateway
            .call(
                json!({"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "chain-sites", "version": "test"}
                }}),
            )
            .await;
        assert!(initialized.get("result").is_some(), "{initialized}");
        gateway
    }

    async fn call(&mut self, request: Value) -> Value {
        use tokio::io::AsyncWriteExt as _;
        let mut frame = serde_json::to_vec(&request).expect("frame");
        frame.push(b'\n');
        self.input.write_all(&frame).await.expect("write frame");
        self.input.flush().await.expect("flush frame");
        let wanted = request["id"].clone();
        tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let line = self
                    .output
                    .next_line()
                    .await
                    .expect("read stdout")
                    .expect("stdout open");
                let frame: Value = serde_json::from_str(&line).expect("JSON-RPC frame");
                if frame.get("id") == Some(&wanted) {
                    return frame;
                }
            }
        })
        .await
        .expect("bounded stdio response")
    }
}

/// CS (stdio): the stdio construction site carries the same outcome: a
/// backend `gateway_invoke` result is linked, a meta-only tool is not.
#[tokio::test]
async fn cs_stdio_backend_invoke_linked_and_meta_tool_not() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut gateway = StdioChild::start(&chain_config(&backend.url)).await;
    let response = gateway
        .call(chained(signed_invoke("cs-s1", "hmac-cs-s1"), "chain-cs-s1"))
        .await;
    let link = origin(&response);
    assert_eq!(link["src"], "live", "{link}");
    assert_eq!(link["nonce"], "chain-cs-s1", "{link}");
    let search = json!({"jsonrpc": "2.0", "id": "cs-s2", "method": "tools/call", "params": {
        "name": "gateway_search_tools", "arguments": {"query": "echo"}
    }});
    let response = gateway.call(chained(search, "chain-cs-s2")).await;
    assert!(response.get("result").is_some(), "control: {response}");
    assert!(unchained(&response), "{response}");
}
