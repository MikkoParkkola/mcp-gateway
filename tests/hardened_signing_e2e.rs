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

use signing_gateway::gateway_bin;

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
        gateway_bin::path(),
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
    stack_with(|_| {}).await
}

/// [`stack`], with `edit` applied to the outer config before it starts.
async fn stack_with(edit: impl FnOnce(&mut Value)) -> Stack {
    let backend = BackendFixture::start(backend_result()).await;
    let inner = tempfile::tempdir().expect("inner directory");
    let inner_path = inner_config(inner.path(), &backend.url);
    let mut config = outer_config(&inner_path, inner.path());
    edit(&mut config);
    let gateway = HttpGateway::start(config).await;
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

/// A meta-route `gateway_invoke` carrying its nonce in `_meta`. It reaches the
/// counting fixture through the inner gateway, so a dispatch is observable.
fn meta_invoke(id: u64, nonce: Option<&str>) -> Value {
    modern_call(
        id,
        "gateway_invoke",
        &json!({"server": INNER, "tool": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}}}),
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

/// A surfaced tool the inner gateway never lists: the task gate cannot read
/// it, so it confirms it as unclassified.
const UNLISTED: &str = "unlisted_task_tool";

/// Row 7: the task-augmented destructive gate answers before admission, so a
/// malformed nonce is refused ahead of it with `-32602`, never answered with a
/// challenge (whose delivery would fail `-32603`) or the gate's own refusal.
#[tokio::test]
async fn malformed_signing_nonce_refused_before_the_task_gate() {
    let stack = stack_with(|config| {
        config["meta_mcp"] = json!({"surfaced_tools": [{"server": INNER, "tool": UNLISTED}]});
    })
    .await;
    let mut request = modern_call(51, UNLISTED, &json!({}), Some(""));
    request["params"]["task"] = json!({});
    request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
        json!({"extensions": {"io.modelcontextprotocol/tasks": {}}});
    request["params"]["_meta"]["io.mcp-gateway/idempotency-key"] = json!("task-gate-key");
    let wire = post(&stack, "/mcp", &request).await;
    assert_refused(&wire, "a malformed nonce on a task-augmented call");
    assert_eq!(parse(&wire)["error"]["code"], -32602, "{wire}");
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
    let id = json!({"kind": "number", "value": "43"});
    assert!(
        oracle_accepts(&wire, &id, "standard-invoke").await,
        "the standard invoke MAC must verify: {wire}"
    );
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

/// Row 7: a passthrough backend takes the direct route's other dispatch exit,
/// and is signed and replay-checked there too.
#[tokio::test]
async fn hardened_passthrough_direct_call_is_signed() {
    let stack = stack_with(|config| config["backends"][INNER]["passthrough"] = json!(true)).await;
    let path = format!("/mcp/{INNER}");
    let wire = post(&stack, &path, &direct_call(61, Some("passthrough-nonce"))).await;
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "passthrough dispatched: {wire}"
    );
    assert_signed(&wire, "passthrough-nonce", "a passthrough direct call");
    let id = json!({"kind": "number", "value": "61"});
    assert!(
        oracle_accepts(&wire, &id, "passthrough-nonce").await,
        "the passthrough MAC must verify: {wire}"
    );
    let again = post(&stack, &path, &direct_call(62, Some("passthrough-nonce"))).await;
    assert_refused(&again, "a replayed passthrough nonce");
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "a replay reached the backend"
    );
}

/// Row 7: on the meta route the nonce is admitted before dispatch, so a replay
/// or a malformed nonce never reaches the backend.
#[tokio::test]
async fn hardened_meta_replay_never_dispatches() {
    let stack = stack().await;
    let first = post(&stack, "/mcp", &meta_invoke(71, Some("meta-counted"))).await;
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "the first call dispatched: {first}"
    );
    assert_signed(&first, "meta-counted", "the first meta gateway_invoke");
    let id = json!({"kind": "number", "value": "71"});
    assert!(
        oracle_accepts(&first, &id, "meta-counted").await,
        "the MAC must verify: {first}"
    );

    let again = post(&stack, "/mcp", &meta_invoke(72, Some("meta-counted"))).await;
    assert_refused(&again, "a replayed meta nonce");
    let oversized = "n".repeat(257);
    for nonce in ["", oversized.as_str()] {
        let wire = post(&stack, "/mcp", &meta_invoke(73, Some(nonce))).await;
        assert_refused(&wire, "a malformed meta nonce");
    }
    assert_eq!(
        stack.backend.calls().len(),
        1,
        "a replayed or malformed nonce reached the backend"
    );
}

/// The in-band confirmation question's key (`meta_mcp/confirmation.rs`).
const CONFIRMATION_KEY: &str = "io.mcp-gateway.destructive-confirmation.v1";

/// Increment 5, row 7: the ordinary destructive gate runs after admission, so
/// its in-band challenge is signed over the asking nonce. The follow-up is a new
/// request: resending the first nonce is a replay, refused before the gate (the
/// envelope stays unspent and nothing runs), and a fresh nonce completes signed.
#[tokio::test]
async fn confirmation_follow_up_needs_a_fresh_nonce() {
    // `gateway_kill_server` is the destructive meta tool, and admin-only.
    let stack = stack_with(|config| config["auth"]["api_keys"][0]["admin"] = json!(true)).await;
    // A name no backend has, so the action touches nothing the stack uses.
    let arguments = json!({"server": "confirm-sentinel"});
    let ask = post(
        &stack,
        "/mcp",
        &modern_call(81, "gateway_kill_server", &arguments, Some("confirm-ask")),
    )
    .await;
    let asked = parse(&ask);
    assert_eq!(asked["result"]["resultType"], "input_required", "{ask}");
    assert_signed(&ask, "confirm-ask", "the confirmation challenge");
    let id = json!({"kind": "number", "value": "81"});
    assert!(
        oracle_accepts(&ask, &id, "confirm-ask").await,
        "the challenge MAC must verify: {ask}"
    );
    let envelope = asked["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("no envelope: {ask}"))
        .to_string();

    let follow_up = |id: u64, nonce: &str| {
        let mut request = modern_call(id, "gateway_kill_server", &arguments, Some(nonce));
        request["params"]["inputResponses"] = json!({ CONFIRMATION_KEY: true });
        request["params"]["requestState"] = json!(envelope);
        request
    };
    let replay = post(&stack, "/mcp", &follow_up(82, "confirm-ask")).await;
    assert_refused(&replay, "a follow-up resending the asking nonce");

    let done = post(&stack, "/mcp", &follow_up(83, "confirm-fresh")).await;
    assert_signed(&done, "confirm-fresh", "the confirmed follow-up");
    let id = json!({"kind": "number", "value": "83"});
    assert!(
        oracle_accepts(&done, &id, "confirm-fresh").await,
        "the follow-up MAC must verify: {done}"
    );
    // The refused replay ran nothing: the confirmed call is the first kill.
    let flat: String = parse(&done)["result"]
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\\')
        .collect();
    assert!(
        flat.contains("\"was_already_killed\":false"),
        "the replay must not have run the action: {done}"
    );
}

/// 4c plan row 13: under hardened, a tool call to an HTTP backend on loopback
/// is served when the backend is listed in `security.hardened.private_backends`
/// (the backend sees it, and the result is signed), and refused before it is
/// reached when it is not listed.
#[tokio::test]
async fn listed_private_backend_tool_call_is_served() {
    for listed in [true, false] {
        let backend = BackendFixture::start(backend_result()).await;
        let home = tempfile::tempdir().expect("gateway home");
        let mut config = outer_config(home.path(), home.path());
        config["backends"] = json!({(BACKEND): {"http_url": backend.url, "streamable_http": true}});
        if listed {
            config["security"]["hardened"] = json!({"private_backends": [BACKEND]});
        }
        let stack = Stack {
            gateway: HttpGateway::start(config).await,
            backend,
            _inner: home,
        };
        let nonce = if listed {
            "listed-call"
        } else {
            "unlisted-call"
        };
        let call = modern_call(
            91,
            "gateway_invoke",
            &json!({"server": BACKEND, "tool": TOOL, "arguments": {}}),
            Some(nonce),
        );
        let wire = post(&stack, "/mcp", &call).await;
        if listed {
            assert_signed(&wire, nonce, "a call to a listed loopback backend");
            assert_eq!(stack.backend.calls().len(), 1, "not served: {wire}");
        } else {
            let response = parse(&wire);
            assert!(
                response.get("error").is_some() || response["result"]["isError"] == json!(true),
                "an unlisted loopback backend was served: {wire}"
            );
            assert_eq!(
                stack.backend.calls().len(),
                0,
                "an unlisted loopback backend was reached: {wire}"
            );
        }
    }
}

/// MIK-7698: a meta call refused before the tool acts leaves its nonce
/// unspent, so the same nonce then carries a later call, signed. Two such
/// refusals: a tool the operator hides, and answers sent to no question.
#[tokio::test]
async fn a_refused_meta_call_leaves_its_nonce_unspent() {
    let stack = stack_with(|config| {
        config["meta_mcp"] =
            json!({"exposed_meta_tools": ["gateway_list_servers", "gateway_invoke"]});
    })
    .await;
    let hidden = modern_call(91, "gateway_list_tools", &json!({}), Some("unspent-hidden"));
    let refused = post(&stack, "/mcp", &hidden).await;
    assert_eq!(parse(&refused)["error"]["code"], -32601, "{refused}");
    let later = post(&stack, "/mcp", &meta_call(92, Some("unspent-hidden"))).await;
    assert_signed(
        &later,
        "unspent-hidden",
        "a call after a hidden-tool refusal",
    );

    let mut unsolicited = meta_call(93, Some("unspent-unsolicited"));
    unsolicited["params"]["inputResponses"] = json!({"unasked": true});
    let refused = post(&stack, "/mcp", &unsolicited).await;
    assert_eq!(parse(&refused)["error"]["code"], -32602, "{refused}");
    let later = post(&stack, "/mcp", &meta_call(94, Some("unspent-unsolicited"))).await;
    assert_signed(
        &later,
        "unspent-unsolicited",
        "a call after an unsolicited answer",
    );
}

/// MIK-7698 (direct route): a call the idempotency guard refuses leaves its
/// nonce unspent; a cache hit is still admitted and signed over its own nonce
/// (`hardened_direct_cached_result_is_signed`).
#[tokio::test]
async fn a_direct_call_refused_by_its_key_leaves_its_nonce_unspent() {
    let stack = stack().await;
    let path = format!("/mcp/{INNER}");
    let keyed = |id: u64, nonce: &str, arguments: Value| {
        let mut request = modern_call(
            id,
            "gateway_invoke",
            &json!({"server": BACKEND, "tool": TOOL, "arguments": arguments}),
            Some(nonce),
        );
        request["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!("unspent-direct-key");
        request
    };
    let first = post(&stack, &path, &keyed(95, "unspent-first", json!({}))).await;
    assert_signed(&first, "unspent-first", "the first keyed direct call");
    let mismatch = keyed(96, "unspent-reused", json!({"other": 1}));
    let refused = post(&stack, &path, &mismatch).await;
    assert_refused(&refused, "a key reused for a different request");
    let later = post(&stack, &path, &direct_call(97, Some("unspent-reused"))).await;
    assert_signed(&later, "unspent-reused", "a call after a key refusal");
}
