// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! R5 / MIK-7570.STDIO.1: a modern-era stdio caller is handed a continuation.
//!
//! A modern client declares its capabilities per request, in `_meta`, and a
//! modern server asks by returning `inputRequests` with a `requestState` the
//! client retries with. It does not push `elicitation/create` down the pipe:
//! that is the legacy bridge, and it stays legacy-only (design §3 D). So these
//! rows assert an envelope and its redemption, never an outbound question.
//!
//! "Declared" means the request's own `_meta`, in both directions, which is
//! what an HTTP modern caller gets (coordinator ruling on design rev 3 item 1):
//! the handshake neither grants a modern call the capability nor takes it away.
//!
//! The stdio rows spawn the shipped binary; the HTTP row drives the router in
//! process, because it is the other transport's half of one isolation claim.

mod common;
#[path = "common/stdio_session.rs"]
mod stdio_session;

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use common::{AppState, Arc, Fixture, Value, json};
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use stdio_session::StdioSession;

/// The legacy revision `initialize` negotiates; the modern era is per request.
const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";
const BACKEND: &str = "fixture";
const ASKING_TOOL: &str = "needs_input";
/// The backend's own opaque state. It must reach the backend on the retry and
/// never the client.
const BACKEND_STATE: &str = "r5-backend-state";

/// Every JSON-RPC request the fixture backend was handed, in arrival order.
type Received = Arc<Mutex<Vec<Value>>>;

fn saw_method(received: &Received, method: &str) -> bool {
    received
        .lock()
        .expect("fixture sink poisoned")
        .iter()
        .any(|request| request.get("method").and_then(Value::as_str) == Some(method))
}

/// An HTTP MCP backend whose one tool asks an `elicitation/create` question on
/// the first call and answers once the retry carries `inputResponses`.
async fn spawn_fixture_backend() -> (String, Received) {
    let sink: Received = Arc::new(Mutex::new(Vec::new()));
    let app_sink = Arc::clone(&sink);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let sink = Arc::clone(&app_sink);
            async move { axum::Json(fixture_answer(&request, &sink)) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture backend address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/"), sink)
}

fn fixture_answer(request: &Value, sink: &Received) -> Value {
    sink.lock()
        .expect("fixture sink poisoned")
        .push(request.clone());
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": BACKEND, "version": "0"},
        }),
        Some("tools/list") => json!({
            "tools": [{
                "name": ASKING_TOOL,
                "description": "asks its caller a question before answering",
                "inputSchema": {"type": "object"},
            }],
        }),
        Some("tools/call") if request.pointer("/params/inputResponses").is_some() => {
            json!({"content": [{"type": "text", "text": "answered"}]})
        }
        Some("tools/call") => json!({
            "resultType": "input_required",
            "inputRequests": {
                "branch": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "form",
                        "message": "Which branch?",
                        "requestedSchema": {"type": "object", "properties": {}},
                    },
                },
            },
            "requestState": BACKEND_STATE,
        }),
        _ => json!({}),
    };
    json!({"jsonrpc": "2.0", "id": request.get("id").cloned(), "result": result})
}

/// The config the child reads from its working directory.
fn write_config(home: &Path, backend_url: &str) {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
        ),
    )
    .expect("write gateway.yaml");
}

fn frames_lenient(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Where a row's client declares `elicitation`.
#[derive(Clone, Copy)]
enum Declares {
    /// On the `initialize` handshake and in the call's `_meta`.
    Both,
    /// In the call's `_meta` only.
    RequestOnly,
    /// On the `initialize` handshake only.
    HandshakeOnly,
    /// Nowhere.
    Neither,
}

impl Declares {
    fn at_handshake(self) -> bool {
        matches!(self, Self::Both | Self::HandshakeOnly)
    }

    fn per_request(self) -> bool {
        matches!(self, Self::Both | Self::RequestOnly)
    }
}

fn modern_initialize(id: i64, declares: Declares) -> Value {
    let capabilities = if declares.at_handshake() {
        json!({"elicitation": {}})
    } else {
        json!({})
    };
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            "capabilities": capabilities,
            "clientInfo": {"name": "r5-stdio-acs", "version": "0"},
        },
    })
}

/// The `_meta` that classifies a call Modern (`src/protocol/meta.rs:44-50`).
fn modern_meta(declares: Declares) -> Value {
    let capabilities = if declares.per_request() {
        json!({"elicitation": {}})
    } else {
        json!({})
    };
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": capabilities,
    })
}

fn modern_asking_call(id: i64, declares: Declares) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "_meta": modern_meta(declares),
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": ASKING_TOOL, "arguments": {}},
        },
    })
}

/// The retry: the same call, carrying the envelope and the answer
/// (`RetryFields::from_params` reads both from top-level `params`).
fn modern_retry(id: i64, request_state: &str) -> Value {
    let mut retry = modern_asking_call(id, Declares::Both);
    retry["params"]["requestState"] = json!(request_state);
    retry["params"]["inputResponses"] = json!({
        "branch": {"action": "accept", "content": {"branch": "main"}},
    });
    retry
}

/// One modern asking call, made after `initialize`.
struct ModernRun {
    session: StdioSession,
    received: Received,
    /// Every frame read on the way to the reply, the reply included.
    frames: Vec<Value>,
    reply: Value,
    /// Held so the child's config directory outlives the child.
    _home: tempfile::TempDir,
}

async fn modern_exchange(declares: Declares) -> ModernRun {
    let home = tempfile::tempdir().expect("temporary home");
    let (backend_url, received) = spawn_fixture_backend().await;
    write_config(home.path(), &backend_url);
    let mut session = StdioSession::spawn(home.path());

    session.send(&modern_initialize(1, declares)).await;
    let (_, initialized) = session.read_until_id(1).await;
    assert!(initialized.is_some(), "the child never answered initialize");

    session.send(&modern_asking_call(2, declares)).await;
    let (lines, reply) = session.read_until_id(2).await;
    let reply = reply.unwrap_or_else(|| panic!("no reply to the modern call: {lines:?}"));
    assert!(
        saw_method(&received, "tools/call"),
        "the fixture backend was never called, so nothing could have asked: {lines:?}"
    );
    ModernRun {
        session,
        received,
        frames: frames_lenient(&lines),
        reply,
        _home: home,
    }
}

/// The envelope the gateway minted, read from wherever `gateway_invoke` put it.
fn request_state_of(reply: &Value) -> Option<String> {
    reply
        .pointer("/result/requestState")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The reply is an `InputRequiredResult` the client can retry: the backend's
/// question as `inputRequests`, a gateway-minted `requestState`, and no frame
/// on the wire refused `-32003`.
fn assert_continuation(frames: &[Value], reply: &Value, case: &str) {
    assert!(
        frames
            .iter()
            .all(|f| f.pointer("/error/code").and_then(Value::as_i64) != Some(-32003)),
        "{case}: a modern stdio caller must not be refused -32003: {reply}"
    );
    let state = request_state_of(reply)
        .unwrap_or_else(|| panic!("{case}: the reply must carry a requestState: {reply}"));
    assert_ne!(
        state, BACKEND_STATE,
        "{case}: the backend's own state must not reach the client: {reply}"
    );
    assert!(
        reply.pointer("/result/inputRequests/branch").is_some(),
        "{case}: the reply must carry the backend's question as inputRequests: {reply}"
    );
}

/// R5-T1: declared on both sides, the call is answered with a continuation.
#[tokio::test]
async fn ac_stdio_modern_caller_receives_a_continuation_not_a_refusal() {
    let ModernRun {
        session,
        frames,
        reply,
        ..
    } = modern_exchange(Declares::Both).await;
    assert_continuation(&frames, &reply, "R5-T1");
    session.shutdown().await;
}

/// R5-T3 (guard): the modern caller is asked through the envelope, never
/// through a server-initiated `elicitation/create` on its pipe.
#[tokio::test]
async fn ac_stdio_modern_caller_is_not_sent_elicitation_create() {
    let ModernRun {
        mut session,
        mut frames,
        reply,
        ..
    } = modern_exchange(Declares::Both).await;
    frames.extend(frames_lenient(
        &session.collect_lines(Duration::from_secs(1)).await,
    ));
    assert!(
        !frames
            .iter()
            .any(|f| f.get("method").and_then(Value::as_str) == Some("elicitation/create")),
        "R5: the bridge is legacy-only; a modern caller must not be pushed a request. \
         Reply {reply}, frames {frames:?}"
    );
    session.shutdown().await;
}

/// R5-T2: the retry carrying the envelope and the answer completes, and the
/// backend receives its own state and the answer, never the gateway's envelope.
#[tokio::test]
async fn ac_stdio_modern_retry_with_the_envelope_completes() {
    let ModernRun {
        mut session,
        received,
        reply,
        ..
    } = modern_exchange(Declares::Both).await;
    let envelope = request_state_of(&reply)
        .unwrap_or_else(|| panic!("R5: no envelope to retry with: {reply}"));

    session.send(&modern_retry(3, &envelope)).await;
    let (lines, answer) = session.read_until_id(3).await;
    let answer = answer.unwrap_or_else(|| panic!("R5: no reply to the retry: {lines:?}"));
    let inner = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or_else(|| panic!("R5: no invoke envelope in the retry's result: {answer}"));
    assert_eq!(
        inner.pointer("/content/0/text").and_then(Value::as_str),
        Some("answered"),
        "R5: the retry must complete with the backend's answered branch: {answer}"
    );

    let calls = received.lock().expect("fixture sink poisoned").clone();
    let retried = calls
        .iter()
        .filter(|call| call.get("method").and_then(Value::as_str) == Some("tools/call"))
        .find(|call| call.pointer("/params/inputResponses").is_some())
        .unwrap_or_else(|| panic!("R5: the backend never received the answer: {calls:?}"));
    assert_eq!(
        retried
            .pointer("/params/requestState")
            .and_then(Value::as_str),
        Some(BACKEND_STATE),
        "R5: the backend must receive its own state, not the gateway's envelope: {retried}"
    );
    assert!(
        !retried.to_string().contains(&envelope),
        "R5: the gateway's envelope must not reach the backend: {retried}"
    );
    session.shutdown().await;
}

/// R5-T9 (ruling (b)): declared in the call's `_meta` alone is declared.
#[tokio::test]
async fn ac_stdio_modern_caller_declaring_only_per_request_is_minted() {
    let ModernRun {
        session,
        frames,
        reply,
        ..
    } = modern_exchange(Declares::RequestOnly).await;
    assert_continuation(&frames, &reply, "R5-T9");
    session.shutdown().await;
}

/// Assert the MRTR.9 refusal, and that no envelope was handed out.
fn assert_undeclared(reply: &Value, case: &str) {
    assert_eq!(
        reply.pointer("/error/code").and_then(Value::as_i64),
        Some(-32021),
        "{case}: an undeclared capability is refused -32021 as on HTTP: {reply}"
    );
    assert!(
        !reply.to_string().contains("requestState"),
        "{case}: no InputRequiredResult may reach a client that cannot answer it: {reply}"
    );
}

/// R5-T8 (guard, rev 3 item 1): declared nowhere, no `InputRequiredResult`.
#[tokio::test]
async fn ac_stdio_modern_caller_without_elicitation_gets_no_input_required_result() {
    let ModernRun { session, reply, .. } = modern_exchange(Declares::Neither).await;
    assert_undeclared(&reply, "R5-T8");
    session.shutdown().await;
}

/// R5-T10 (guard, ruling (b) converse): the handshake does not declare for a
/// modern call.
#[tokio::test]
async fn ac_stdio_modern_caller_declaring_only_at_initialize_is_undeclared() {
    let ModernRun { session, reply, .. } = modern_exchange(Declares::HandshakeOnly).await;
    assert_undeclared(&reply, "R5-T10");
    session.shutdown().await;
}

/// Put the fixture behind [`BACKEND`] on an in-process gateway.
fn register_fixture_backend(state: &Arc<AppState>, url: &str) {
    let config = BackendConfig {
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let backend = Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert!(state.backends.register(Arc::new(backend)));
}

/// R5-T7, the cross-transport isolation cell.
///
/// GIVEN a modern HTTP caller with no verified identity that declared
/// elicitation, WHEN its backend asks for input, THEN it is still refused
/// `-32003`: the stdio binding is set only by the two stdio context builders,
/// so nothing on HTTP can acquire it. Asserted on the mint's own sentence, so
/// an earlier refusal cannot pass the row.
#[tokio::test]
async fn ac_r5_an_http_caller_without_identity_is_still_refused() {
    let (state, _store_dir) = common::state(Fixture::default()).await;
    let (url, received) = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let mut body = modern_asking_call(1, Declares::Both);
    body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"] =
        json!({"name": "r5-http", "version": "0"});
    let (_status, response) = common::post(&state, body, &[]).await;

    assert!(
        saw_method(&received, "tools/call"),
        "R5-T7: the backend was never asked, so the mint was never reached: {response}"
    );
    assert_eq!(
        response.pointer("/error/code").and_then(Value::as_i64),
        Some(-32003),
        "R5-T7: an unnamed HTTP caller is refused -32003: {response}"
    );
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("R5-T7: an unnamed HTTP caller must be refused: {response}"));
    assert!(
        message.contains("cannot be continued for this caller"),
        "R5-T7: the refusal must be the mint's, got {message:?}"
    );
}
