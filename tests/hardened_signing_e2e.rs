// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH1942.HARDEN.1 rows 6 and 7 through the shipped binary: under
//! `security.posture: hardened` signing is forced, and every successful
//! `tools/call` result on the meta route and the direct route carries a v2
//! `_signature` over a nonce from `params._meta["io.mcp-gateway/nonce"]`,
//! admitted once, before dispatch.
//!
//! Hardened refuses an HTTP backend on loopback, so the outer gateway's backend
//! is this same binary over stdio (which the destination policy does not
//! cover), running `standard` and forwarding to the counting HTTP fixture.

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use signing_gateway::{BACKEND, BackendFixture, HttpGateway, KEY, TOOL, fixture_config};
use tokio::io::AsyncWriteExt as _;

/// The outer gateway's stdio backend.
const INNER: &str = "inner";
const NONCE_META: &str = "io.mcp-gateway/nonce";
const MODERN: &str = "2026-07-28";
/// A personal API key: the per-caller identity hardened requires (row 8).
const CALLER: &str = "hardened-signing-caller-0123456789abcdef";

fn backend_result() -> Value {
    json!({"content": [{"type": "text", "text": "hardened signing sentinel"}]})
}

/// The inner gateway: `standard`, no signing, one HTTP backend.
fn inner_config(directory: &std::path::Path, backend_url: &str) -> std::path::PathBuf {
    let config = json!({
        "cache": {"enabled": false},
        "tasks": {"store_dir": directory.join("tasks")},
        "backends": {(BACKEND): {"http_url": backend_url, "streamable_http": true}},
        "security": {"trust_configured_backends": true}
    });
    let path = directory.join("inner.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&config).expect("inner config YAML"),
    )
    .expect("write inner config");
    path
}

/// The hardened outer gateway. `enabled` is not set: the posture forces it.
/// Auth on requires the audit log (UPGRADING item 43).
fn outer_config(inner: &std::path::Path, inner_home: &std::path::Path) -> Value {
    let command = format!(
        "\"{}\" --config \"{}\" serve --stdio",
        env!("CARGO_BIN_EXE_mcp-gateway"),
        inner.display()
    );
    json!({
        "server": {"host": "127.0.0.1", "modern_protocol": true},
        "cache": {"enabled": false},
        "auth": {
            "enabled": true,
            "api_keys": [{
                "name": "caller",
                "key_sha256": mcp_gateway::config::api_key_digest_spec(CALLER.as_bytes()),
                "kind": "personal",
                "backends": ["*"]
            }]
        },
        "backends": {(INNER): {
            "command": command,
            "env": {"HOME": inner_home}
        }},
        "security": {
            "posture": "hardened",
            "message_signing": {"shared_secret": KEY, "key_id": "signing-test-current"},
            "transparency_log": {"enabled": true, "path": inner_home.join("audit").join("log.jsonl")}
        }
    })
}

struct Stack {
    backend: BackendFixture,
    gateway: HttpGateway,
    _inner: tempfile::TempDir,
}

async fn stack() -> Stack {
    let backend = BackendFixture::start(backend_result()).await;
    let inner = tempfile::tempdir().expect("inner directory");
    let inner_path = inner_config(inner.path(), &backend.url);
    let gateway = HttpGateway::start(outer_config(&inner_path, inner.path())).await;
    Stack {
        backend,
        gateway,
        _inner: inner,
    }
}

/// A well-formed 2026-07-28 `tools/call` carrying `nonce` in `_meta`.
fn modern_call(id: u64, name: &str, arguments: &Value, nonce: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    if let Some(nonce) = nonce {
        meta[NONCE_META] = json!(nonce);
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": meta}})
}

/// The direct-route call: the inner gateway's `gateway_invoke`, which reaches
/// the counting fixture.
fn direct_call(id: u64, nonce: Option<&str>) -> Value {
    modern_call(
        id,
        "gateway_invoke",
        &json!({"server": BACKEND, "tool": TOOL, "arguments": {}}),
        nonce,
    )
}

/// A meta-route call to a meta tool other than `gateway_invoke`.
fn meta_call(id: u64, nonce: Option<&str>) -> Value {
    modern_call(id, "gateway_list_servers", &json!({}), nonce)
}

/// POST `request` to `path` and return the delivered JSON-RPC text.
async fn post(stack: &Stack, path: &str, request: &Value) -> String {
    let gateway = &stack.gateway;
    let response = gateway
        .client
        .post(format!("{}{path}", gateway.url))
        .header("authorization", format!("Bearer {CALLER}"))
        .header("mcp-protocol-version", MODERN)
        .header("mcp-method", "tools/call")
        .header(
            "mcp-name",
            request["params"]["name"].as_str().unwrap_or_default(),
        )
        .json(request)
        .send()
        .await
        .unwrap_or_else(|error| panic!("POST {path}: {error}; logs={}", gateway.logs()));
    let text = response.text().await.expect("response body");
    // A streamed answer carries the message on its `data:` line.
    text.lines()
        .find_map(|line| line.strip_prefix("data:"))
        .map_or(text.clone(), |data| data.trim().to_string())
}

fn parse(wire: &str) -> Value {
    serde_json::from_str(wire).unwrap_or_else(|error| panic!("not JSON ({error}): {wire}"))
}

/// The `_signature` the gateway attached, asserting it is a v2 MAC over `nonce`.
fn assert_signed(wire: &str, nonce: &str, what: &str) {
    let response = parse(wire);
    assert!(
        response.get("error").is_none(),
        "{what}: refused: {response}"
    );
    let signature = response["result"]
        .get("_signature")
        .unwrap_or_else(|| panic!("{what}: delivered unsigned: {response}"));
    assert_eq!(signature["version"], 2, "{what}: {signature}");
    assert_eq!(signature["nonce"], nonce, "{what}: {signature}");
    assert_eq!(signature["key_id"], "signing-test-current", "{what}");
}

fn assert_refused(wire: &str, what: &str) {
    let response = parse(wire);
    assert!(
        response.get("result").is_none() && response.get("error").is_some(),
        "{what}: served: {response}"
    );
}

/// Whether the independent ECMAScript oracle (`tests/common/signing_verifier.mjs`,
/// no gateway code) accepts `wire` as signed with [`KEY`] for `id` and `nonce`.
async fn oracle_accepts(wire: &str, id: &Value, nonce: &str) -> bool {
    let verifier =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs");
    let mut child = tokio::process::Command::new("node")
        .arg(verifier)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("node is required for the independent signing oracle");
    let input = json!({"wire": wire, "options": {"key": KEY, "keyId": "signing-test-current",
        "expectedId": id, "expectedNonce": nonce, "now": chrono::Utc::now().timestamp()}});
    let mut stdin = child.stdin.take().expect("oracle stdin");
    stdin
        .write_all(input.to_string().as_bytes())
        .await
        .expect("write oracle stdin");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("bounded oracle")
        .expect("oracle process")
        .success()
}

/// Row 7: a non-invoke meta `tools/call` and a direct-route `tools/call` are
/// both delivered with a v2 MAC the independent oracle accepts.
#[tokio::test]
async fn hardened_signs_tools_call_on_both_routes() {
    let stack = stack().await;
    let wire = post(&stack, "/mcp", &meta_call(11, Some("meta-nonce"))).await;
    assert_signed(&wire, "meta-nonce", "a meta gateway_list_servers call");
    let id = json!({"kind": "number", "value": "11"});
    assert!(
        oracle_accepts(&wire, &id, "meta-nonce").await,
        "meta MAC must verify: {wire}"
    );

    let path = format!("/mcp/{INNER}");
    let wire = post(&stack, &path, &direct_call(12, Some("direct-nonce"))).await;
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "direct call dispatched: {wire}"
    );
    assert_signed(&wire, "direct-nonce", "a direct tools/call");
    let id = json!({"kind": "number", "value": "12"});
    assert!(
        oracle_accepts(&wire, &id, "direct-nonce").await,
        "direct MAC must verify: {wire}"
    );
}

/// Row 7: a nonce is admitted once, before dispatch, in one store for both
/// routes.
#[tokio::test]
async fn hardened_tool_call_nonce_replay_refused() {
    let stack = stack().await;
    let first = post(&stack, "/mcp", &meta_call(21, Some("replayed-meta"))).await;
    assert_signed(&first, "replayed-meta", "the first meta call");
    let again = post(&stack, "/mcp", &meta_call(22, Some("replayed-meta"))).await;
    assert_refused(&again, "a replayed meta nonce");

    let path = format!("/mcp/{INNER}");
    let first = post(&stack, &path, &direct_call(23, Some("replayed-direct"))).await;
    assert_signed(&first, "replayed-direct", "the first direct call");
    let again = post(&stack, &path, &direct_call(24, Some("replayed-direct"))).await;
    assert_refused(&again, "a replayed direct nonce");
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "a replayed nonce reached the backend: {again}"
    );

    // Used on the meta route, then presented on the direct route.
    let across = post(&stack, &path, &direct_call(25, Some("replayed-meta"))).await;
    assert_refused(&across, "a meta nonce replayed on the direct route");
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "cross-route replay dispatched"
    );
}

/// Row 7: an empty or oversized nonce is refused `-32602` on each route, with
/// nothing dispatched.
#[tokio::test]
async fn malformed_signing_nonce_refused() {
    let stack = stack().await;
    let oversized = "n".repeat(257);
    let path = format!("/mcp/{INNER}");
    for nonce in ["", oversized.as_str()] {
        let wire = post(&stack, "/mcp", &meta_call(31, Some(nonce))).await;
        assert_refused(&wire, "a malformed meta nonce");
        assert_eq!(parse(&wire)["error"]["code"], -32602, "{wire}");
        let wire = post(&stack, &path, &direct_call(32, Some(nonce))).await;
        assert_refused(&wire, "a malformed direct nonce");
        assert_eq!(parse(&wire)["error"]["code"], -32602, "{wire}");
    }
    assert_eq!(
        stack.backend.calls().len(),
        0,
        "a malformed nonce dispatched"
    );
}

/// Row 16: `standard` with signing explicitly on keeps today's scope: a
/// non-invoke meta call and a direct call are delivered unsigned, and
/// `gateway_invoke` is signed as before.
#[tokio::test]
async fn standard_signing_keeps_invoke_only_scope() {
    let backend = BackendFixture::start(backend_result()).await;
    let mut config = fixture_config(&backend.url);
    // Each call below carries a nonce; requiring one would only add refusals.
    config["security"]["message_signing"]["require_nonce"] = json!(false);
    let stack = Stack {
        gateway: HttpGateway::start(config).await,
        backend,
        _inner: tempfile::tempdir().expect("unused directory"),
    };

    let wire = post(&stack, "/mcp", &meta_call(41, Some("standard-meta"))).await;
    let response = parse(&wire);
    assert!(response.get("error").is_none(), "{response}");
    assert!(
        response["result"].get("_signature").is_none(),
        "standard signed a non-invoke meta call: {response}"
    );

    // Standard keeps G7: with signing on, the direct route serves no
    // tools/call, since only `gateway_invoke` is signed.
    let path = format!("/mcp/{BACKEND}");
    let request = modern_call(42, TOOL, &json!({}), Some("standard-direct"));
    let wire = post(&stack, &path, &request).await;
    assert!(
        wire.contains("message signing is enabled; use gateway_invoke"),
        "standard served a direct tools/call with signing on: {wire}"
    );
    assert_eq!(
        stack.backend.calls().len(),
        0,
        "a refused direct call dispatched"
    );

    let invoke = modern_call(
        43,
        "gateway_invoke",
        &json!({"server": BACKEND, "tool": TOOL, "arguments": {}, "nonce": "standard-invoke"}),
        None,
    );
    let wire = post(&stack, "/mcp", &invoke).await;
    assert_signed(&wire, "standard-invoke", "standard gateway_invoke");
}

const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

/// Row 7: a direct-route idempotent replay is served from the cache (the
/// backend still saw one call) and signed over the replaying request's nonce.
#[tokio::test]
async fn hardened_direct_cached_result_is_signed() {
    let stack = stack().await;
    let path = format!("/mcp/{INNER}");
    let keyed = |id: u64, nonce: &str| {
        let mut request = direct_call(id, Some(nonce));
        request["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!("hardened-direct-replay");
        request
    };
    let first = post(&stack, &path, &keyed(51, "cached-first")).await;
    assert_signed(&first, "cached-first", "the first keyed call");
    let second = post(&stack, &path, &keyed(52, "cached-second")).await;
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "the second call must be a replay, or this proves nothing: {second}"
    );
    assert_signed(&second, "cached-second", "the replayed call");
    let id = json!({"kind": "number", "value": "52"});
    assert!(
        oracle_accepts(&second, &id, "cached-second").await,
        "the replay's MAC must verify for its own nonce: {second}"
    );
}
