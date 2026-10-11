// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only stdio task driver for the route x check matrix (MIK-8137 family,
//! b3), on the stdio task fixture (`owner2_stdio_tasks`): one task-augmented
//! `tools/call` of a surfaced tool through the real stdio dispatch. The
//! matrix (`gateway::route_check_matrix_tests`) owns every assertion.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{
    BACKEND, TOOL, backend, backend_listing, dispatch, fixture_on_with,
};
use crate::config::SurfacedToolConfig;
pub(crate) use crate::gateway::router::route_matrix_driver_tests::Surfacing;

/// R5: a modern task-augmented `tools/call echo` by its surfaced name over
/// stdio, declaring the tasks extension and form elicitation, keyed. `echo`
/// is listed `destructiveHint: true`, so X14 has a destructive call to decide
/// (an unannotated tool reads as harmless once the catalogue is warm).
/// Returns the answer and the backend's `tools/call` count.
pub(crate) async fn stdio_task_surfaced() -> (Value, usize) {
    stdio_task_read(None, Surfacing::On).await
}

/// [`stdio_task_surfaced`] with the tool `policy` stdio enforces, on a fixture
/// that surfaces `echo` per `surfacing` (MIK-8326: a denied surfaced tool must
/// answer as the name does where nothing is surfaced).
pub(crate) async fn stdio_task_read(
    policy: Option<crate::security::ToolPolicy>,
    surfacing: Surfacing,
) -> (Value, usize) {
    let served = backend_listing(json!([{
        "name": TOOL,
        "inputSchema": {"type": "object"},
        "annotations": {"destructiveHint": true, "readOnlyHint": false}
    }]))
    .await;
    let calls = std::sync::Arc::clone(&served.1);
    let fixture = Box::pin(fixture_on_with(served, policy, |config| {
        if matches!(surfacing, Surfacing::On) {
            config.meta_mcp.surfaced_tools = vec![SurfacedToolConfig {
                server: BACKEND.to_string(),
                tool: TOOL.to_string(),
            }];
        }
    }))
    .await;
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": TOOL,
            "arguments": {},
            "task": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {
                    "elicitation": {"form": {}},
                    "extensions": {"io.modelcontextprotocol/tasks": {}}
                },
                "io.modelcontextprotocol/clientInfo": {"name": "matrix", "version": "1"},
                "io.mcp-gateway/idempotency-key": "x14-stdio",
            },
        },
    });
    let body = dispatch(&fixture, request).await;
    (body, calls.load(Ordering::SeqCst))
}

/// R5: `tools/call gateway_invoke` of the fixture's `echo` over stdio with a
/// NUL in its arguments, on a gateway built from config with
/// `security.sanitize_input` = `on`. Returns the answer and the backend's
/// `tools/call` count.
pub(crate) async fn stdio_sanitizing(on: bool) -> (Value, usize) {
    let served = backend().await;
    let calls = std::sync::Arc::clone(&served.1);
    let fixture = Box::pin(fixture_on_with(served, None, |config| {
        config.security.sanitize_input = on;
    }))
    .await;
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"cmd": "a\u{0}b"}},
        },
    });
    let body = dispatch(&fixture, request).await;
    (body, calls.load(Ordering::SeqCst))
}

/// R5 through the real serve loop (MIK-8149.REQFW.2, design A6): a gateway
/// built from config with `security.sanitize_input` on, served by
/// `run_stdio_on` over in-memory pipes, answers one `gateway_invoke echo`
/// carrying a NUL. Returns the answer and the backend's `tools/call` count:
/// the setting reaches stdio from the config, not from a test-built client.
pub(crate) async fn served_sanitizing() -> (Value, usize) {
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (url, calls) = backend().await;
    let store = tempfile::tempdir().expect("store root");
    let mut config = crate::config::Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.security.sanitize_input = true;
    config.backends.insert(
        BACKEND.to_string(),
        crate::config::BackendConfig {
            enabled: true,
            transport: crate::config::TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..crate::config::BackendConfig::default()
        },
    );
    let data = tempfile::tempdir().expect("data dir");
    let gateway = super::super::Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(data.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    let handshake = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "matrix", "version": "1"}}});
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"cmd": "a\u{0}b"}}}});
    let mut answer = Value::Null;
    for frame in [handshake, call] {
        stdin
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("write");
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("answered in time")
            .expect("read")
            .expect("a line");
        answer = serde_json::from_str(&line).expect("one JSON answer per line");
    }
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(40), served)
        .await
        .expect("EOF returns within the bound")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");
    (answer, calls.load(Ordering::SeqCst))
}

/// P3 (seats' delta improvement): one signing nonce across X14's round trip on
/// hardened stdio. The challenged call gives its nonce back (the route stage
/// answered), the redemption carrying the same nonce is admitted and spends
/// it, and a third call with it is a replay. A fourth, under a fresh nonce
/// with the same key and no grant, is the admitted task's retry: X14 lets it
/// through to admission (`already_admitted` under the stdio owner) and it gets
/// the task's handle, not a second challenge. Returns the four answers.
pub(crate) async fn stdio_x14_signed_round() -> (Value, Value, Value, Value) {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    const NONCE: &str = "stdio-x14-round-0001";
    let served = backend_listing(json!([{
        "name": TOOL,
        "inputSchema": {"type": "object"},
        "annotations": {"destructiveHint": true, "readOnlyHint": false}
    }]))
    .await;
    let fixture = Box::pin(fixture_on_with(served, None, |config| {
        config.server.modern_protocol = true;
        config.security.posture = crate::security::SecurityPosture::Hardened;
        config.security.hardened.private_backends = vec![BACKEND.to_string()];
        config.security.message_signing.enabled = true;
        config.security.message_signing.shared_secret =
            "p3-x14-round-secret-0123456789abcdef".to_string();
        config.security.message_signing.require_nonce = true;
        config.security.message_signing.replay_window = 300;
        config.security.message_signing.key_id = "p3-x14-round".to_string();
        config.meta_mcp.surfaced_tools = vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }];
    }))
    .await;
    let call = |id: u64, nonce: &str, extra: Value| {
        let mut params = json!({
            "name": TOOL,
            "arguments": {},
            "task": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {
                    "elicitation": {"form": {}},
                    "extensions": {"io.modelcontextprotocol/tasks": {}}
                },
                "io.mcp-gateway/idempotency-key": "x14-round",
                NONCE_META: nonce,
            },
        });
        if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
            params.extend(extra.clone());
        }
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
    };
    let challenge = dispatch(&fixture, call(1, NONCE, json!({}))).await;
    let state = challenge["result"]["requestState"].clone();
    let key = challenge["result"]["inputRequests"]
        .as_object()
        .and_then(|requests| requests.keys().next().cloned())
        .unwrap_or_default();
    let answer = json!({
        "requestState": state,
        "inputResponses": { key: { "action": "accept" } },
    });
    let redeemed = dispatch(&fixture, call(2, NONCE, answer)).await;
    let replay = dispatch(&fixture, call(3, NONCE, json!({}))).await;
    let retried = dispatch(&fixture, call(4, "stdio-x14-round-0002", json!({}))).await;
    (challenge, redeemed, replay, retried)
}

/// An argument the request firewall blocks as shell injection, built so no
/// such literal sits in the source.
const SHELL_PATTERN: &str = concat!(";", " rm", " -rf", " / ");

/// R5 (P3, grok's row): a modern task-augmented `gateway_invoke echo` over
/// stdio whose argument the request firewall blocks, on the production-built
/// gateway (its firewall scans requests by default). Returns the answer and
/// the backend's `tools/call` count.
pub(crate) async fn stdio_blocked_task() -> (Value, usize) {
    let served = backend().await;
    let calls = std::sync::Arc::clone(&served.1);
    let fixture = Box::pin(fixture_on_with(served, None, |_| {})).await;
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"cmd": SHELL_PATTERN}},
            "task": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": {"io.modelcontextprotocol/tasks": {}}
                },
                "io.mcp-gateway/idempotency-key": "blocked-task",
            },
        },
    });
    let body = dispatch(&fixture, request).await;
    (body, calls.load(Ordering::SeqCst))
}
