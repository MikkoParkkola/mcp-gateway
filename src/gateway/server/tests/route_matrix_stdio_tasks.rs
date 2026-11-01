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
    policy: Option<crate::security::ToolPolicyConfig>,
    surfacing: Surfacing,
) -> (Value, usize) {
    let trace = Box::pin(stdio_task_run(policy, surfacing, None)).await;
    (trace.body, trace.backend_calls)
}

/// What a stdio task submit left behind (MIK-8326): the answer, the backend's
/// call count, the firewall audit log's event names, the tasks committed, the
/// legacy idempotency responses stored and the execution admission entries.
pub(crate) struct StdioTrace {
    pub(crate) body: Value,
    pub(crate) backend_calls: usize,
    pub(crate) events: Vec<String>,
    pub(crate) committed: usize,
    pub(crate) stored_keys: usize,
    pub(crate) admitted: usize,
}

/// [`stdio_task_read`] with the production firewall on, writing to `audit`.
#[cfg(feature = "firewall")]
pub(crate) async fn stdio_task_traced(
    policy: Option<crate::security::ToolPolicyConfig>,
    surfacing: Surfacing,
    audit: &std::path::Path,
) -> StdioTrace {
    Box::pin(stdio_task_run(policy, surfacing, Some(audit))).await
}

async fn stdio_task_run(
    policy: Option<crate::security::ToolPolicyConfig>,
    surfacing: Surfacing,
    audit: Option<&std::path::Path>,
) -> StdioTrace {
    let served = backend_listing(json!([{
        "name": TOOL,
        "inputSchema": {"type": "object"},
        "annotations": {"destructiveHint": true, "readOnlyHint": false}
    }]))
    .await;
    let calls = std::sync::Arc::clone(&served.1);
    let fixture = Box::pin(fixture_on_with(served, policy, |config| {
        if let Some(audit) = audit {
            let firewall = &mut config.security.firewall;
            firewall.enabled = true;
            firewall.scan_requests = true;
            firewall.audit_log = Some(audit.to_path_buf());
        }
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
    StdioTrace {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
        events: audit.map_or_else(
            Vec::new,
            crate::gateway::router::route_matrix_driver_tests::audit_events,
        ),
        committed: fixture.tasks.service.store.committed_count_for_test(),
        stored_keys: fixture.meta.idempotency_completed_for_test().len(),
        admitted: fixture.meta.execution_admission().snapshot().entries,
    }
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
    served_sanitizing_with(false).await
}

/// [`served_sanitizing`] with the backend's `passthrough` set to
/// `passthrough` (MIK-8154 P2: exempt from sanitization on stdio too).
pub(crate) async fn served_sanitizing_with(passthrough: bool) -> (Value, usize) {
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"cmd": "a\u{0}b"}}}});
    Box::pin(served_sanitizing_call(passthrough, call)).await
}

/// One `call` frame served on stdio with sanitizing on, after the handshake:
/// its answer and the backend's call count.
pub(crate) async fn served_sanitizing_call(passthrough: bool, call: Value) -> (Value, usize) {
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
            passthrough,
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
    const NONCE: &str = "stdio-x14-round-0001";
    let fixture = signed_x14_fixture().await;
    let call = |id: u64, nonce: &str, extra: Value| x14_call(id, nonce, "x14-round", extra);
    let challenge = dispatch(&fixture, call(1, NONCE, json!({}))).await;
    let redeemed = dispatch(&fixture, call(2, NONCE, accept(&challenge))).await;
    let replay = dispatch(&fixture, call(3, NONCE, json!({}))).await;
    let retried = dispatch(&fixture, call(4, "stdio-x14-round-0002", json!({}))).await;
    (challenge, redeemed, replay, retried)
}

/// The hardened, signed stdio fixture surfacing the destructive `echo`, so X14
/// challenges a task-augmented call to it.
async fn signed_x14_fixture() -> super::owner2_stdio_tasks::Fixture {
    signed_fixture_listing(json!({"destructiveHint": true, "readOnlyHint": false})).await
}

/// The hardened, signed stdio fixture surfacing `echo` listed with
/// `annotations`.
async fn signed_fixture_listing(annotations: Value) -> super::owner2_stdio_tasks::Fixture {
    let served = backend_listing(json!([{
        "name": TOOL,
        "inputSchema": {"type": "object"},
        "annotations": annotations
    }]))
    .await;
    Box::pin(fixture_on_with(served, None, |config| {
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
    .await
}

/// A task-augmented, keyed, signed `tools/call` of the surfaced `echo` under
/// `nonce`, with `extra` merged into its params (an X14 answer).
fn x14_call(id: u64, nonce: &str, key: &str, extra: Value) -> Value {
    use crate::gateway::meta_mcp::signing::NONCE_META;
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
            "io.mcp-gateway/idempotency-key": key,
            NONCE_META: nonce,
        },
    });
    if let (Some(params), Value::Object(extra)) = (params.as_object_mut(), extra) {
        params.extend(extra);
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
}

/// The answer accepting `challenge`'s X14 question.
fn accept(challenge: &Value) -> Value {
    let state = challenge["result"]["requestState"].clone();
    let key = challenge["result"]["inputRequests"]
        .as_object()
        .and_then(|requests| requests.keys().next().cloned())
        .unwrap_or_default();
    json!({
        "requestState": state,
        "inputResponses": { key: { "action": "accept" } },
    })
}

/// Waits until task `id` is terminal and returns its status, as the local
/// operator reads it.
async fn terminal_status(fixture: &super::owner2_stdio_tasks::Fixture, id: &str) -> String {
    let id = super::owner2_stdio_tasks::wait_terminal(fixture, id.to_owned()).await;
    let task = (fixture.tasks.service)
        .get(crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL, &id)
        .expect("the local operator owns its task");
    format!("{:?}", task.task.status())
}

/// MIK-8353 STDIO-TWIN (pairs with E2E.1): a signed task call of a surfaced
/// tool listed harmless, on a warm catalogue so X14 has nothing to ask. With
/// the backend killed, execution admission refuses it with nothing consumed;
/// the backend is revived, and the same nonce re-sent, then sent a third time.
/// Returns (the refusal, the re-send, the re-send's terminal task status, the
/// third send, the backend `tools/call` count once that task is terminal).
pub(crate) async fn stdio_task_refused_without_a_grant() -> (Value, Value, String, Value, usize) {
    const NONCE: &str = "stdio-twin-nonce-0001";
    let fixture =
        signed_fixture_listing(json!({"destructiveHint": false, "readOnlyHint": true})).await;
    let backend =
        (fixture.meta.registry_for_test().get(BACKEND)).expect("the backend is registered");
    backend
        .get_tools()
        .await
        .expect("the backend lists its tools");
    fixture.meta.kill_switch().kill(BACKEND);
    let refused = dispatch(&fixture, x14_call(1, NONCE, "twin-a", json!({}))).await;
    fixture.meta.kill_switch().revive(BACKEND);
    let resent = dispatch(&fixture, x14_call(2, NONCE, "twin-b", json!({}))).await;
    let status = match resent.pointer("/result/taskId").and_then(Value::as_str) {
        Some(id) => terminal_status(&fixture, id).await,
        None => String::new(),
    };
    let calls = fixture.rounds.load(Ordering::SeqCst);
    let third = dispatch(&fixture, x14_call(3, NONCE, "twin-c", json!({}))).await;
    (refused, resent, status, third, calls)
}

/// What MIK-8353.E2E.1's round observed (see [`stdio_x14_consumed_then_refused`]).
pub(crate) struct ConsumedThenRefused {
    pub(crate) challenge: Value,
    /// The redemption, refused by admission after X14 consumed its grant.
    pub(crate) refused: Value,
    /// The confirmation ledger's consumed count before the challenge, before
    /// and after the redemption, and after the re-send.
    pub(crate) ledger: [usize; 4],
    /// The same nonce re-sent once the backend is revived.
    pub(crate) resent: Value,
    /// Backend `tools/call` count after the re-send.
    pub(crate) calls_before_honest: usize,
    /// A fresh nonce's full round (challenge, redemption) and its terminal task.
    pub(crate) honest: Value,
    pub(crate) calls_after_honest: usize,
}

/// MIK-8353.E2E.1 on hardened stdio. The backend is killed, so the route stage
/// still asks X14 and the redemption consumes the grant, but execution
/// admission's task branch (`check_target_policy` -> `admit_target`) refuses
/// it. The backend is then revived; the same nonce is re-sent; and a fresh
/// nonce runs the honest round end to end.
pub(crate) async fn stdio_x14_consumed_then_refused() -> ConsumedThenRefused {
    const NONCE: &str = "stdio-e2e1-nonce-0001";
    const FRESH: &str = "stdio-e2e1-nonce-0002";
    let fixture = signed_x14_fixture().await;
    let ledger = fixture.meta.continuation();
    fixture.meta.kill_switch().kill(BACKEND);
    let unasked = ledger.ledger().len().await;
    let challenge = dispatch(&fixture, x14_call(1, NONCE, "e2e1-a", json!({}))).await;
    let before = ledger.ledger().len().await;
    let refused = dispatch(&fixture, x14_call(2, NONCE, "e2e1-a", accept(&challenge))).await;
    let after = ledger.ledger().len().await;
    fixture.meta.kill_switch().revive(BACKEND);
    let resent = dispatch(&fixture, x14_call(3, NONCE, "e2e1-b", json!({}))).await;
    let after_resend = ledger.ledger().len().await;
    let calls_before_honest = fixture.rounds.load(Ordering::SeqCst);
    let asked = dispatch(&fixture, x14_call(4, FRESH, "e2e1-c", json!({}))).await;
    let created = dispatch(&fixture, x14_call(5, FRESH, "e2e1-c", accept(&asked))).await;
    let honest = match created.pointer("/result/taskId").and_then(Value::as_str) {
        Some(id) => json!({"taskId": id, "status": terminal_status(&fixture, id).await}),
        None => created,
    };
    ConsumedThenRefused {
        challenge,
        refused,
        ledger: [unasked, before, after, after_resend],
        resent,
        calls_before_honest,
        honest,
        calls_after_honest: fixture.rounds.load(Ordering::SeqCst),
    }
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
