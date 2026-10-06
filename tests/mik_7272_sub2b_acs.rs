// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-7272.SUB.2b` acceptance rows: a request-scoped notification rides its
//! own request's response.
//!
//! Scope is the PR bar, not ADR-014's full thirteen rows: test-plan `S-02`
//! (`docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md:58`)
//! and the `notifications/progress` half of `S-03` (`:59`). See ADR-014
//! Amendment 1 for why the `notifications/message` half of `S-03` has no stdio
//! instance here, and the note above [`s03_message_http_isolates_by_stream`]
//! for the same reason stated where a reader of this file will meet it.
//!
//! **Every row spawns the shipped binary.** The client-facing legs are the
//! thing under test — `Server::run_stdio`'s loop and the HTTP handler's
//! response — so a harness that calls dispatch directly would satisfy the
//! ordering rows by construction and could never fail them. Reads are bounded
//! and the child is killed on every exit path, so a missing line fails an
//! assertion instead of hanging the suite.
//!
//! The stdio harness is deliberately a second copy of the one in
//! `tests/mik_7212_mrtr7_stdio_acs.rs`, which is the model for it. Neither can
//! import the other: an integration test is its own crate. Collapsing both
//! onto one helper in `tests/common/mod.rs` is a follow-up, not this change —
//! `common` is linked into every test binary in the suite, and adding a
//! process-spawning helper to it to save one duplication is a wider blast
//! radius than the duplication costs.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::{IntoResponse, Response};
use mcp_gateway::protocol::headers::{encode_header_value, mcp_name_body_field};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// The revision the handshake settles on, and the one the fixture backend
/// answers `initialize` with.
const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";

/// The revision each `tools/call` declares in `params._meta`.
///
/// Not the handshake's: 2026-07-28 deleted the handshake, so a per-request
/// declaration is the only way to reach that revision, and the gateway decides
/// the era per request precisely so one connection can carry both. Nothing
/// else is accepted — `protocol::meta::MODERN_VERSIONS` holds this one string,
/// and a request declaring any other earns -32022.
const REQUEST_PROTOCOL_VERSION: &str = "2026-07-28";
const BACKEND: &str = "fixture";

/// Emits one notification, then blocks until [`RELEASE_TOOL`] is called.
const SLOW_TOOL: &str = "slow_notifier";
/// Releases every blocked [`SLOW_TOOL`] call, as a second call in flight --
/// which is what makes the liveness assertion in ADR-014 row 4 mean something
/// on a transport that can carry two calls at once. It is not the only way in:
/// `spawn_fixture_backend` also hands back the gate, for rows whose transport
/// cannot have a second call in flight.
const RELEASE_TOOL: &str = "release";

const READ_TIMEOUT: Duration = Duration::from_secs(15);
const COLLECT_WINDOW: Duration = Duration::from_secs(3);

/// What the fixture received, for rows that assert on the minted token.
type Received = Arc<Mutex<Vec<Value>>>;

/// Fixture state: what arrived, and the gate that holds a result back.
#[derive(Clone)]
struct FixtureState {
    received: Received,
    /// Zero permits until a release call adds one. A semaphore rather than a
    /// `Notify`: a release that arrives before the slow call parks must still
    /// release it, and `notify_waiters` would drop that wakeup.
    gate: Arc<Semaphore>,
    /// One permit **per** release call, for the two-gate body.
    ///
    /// Separate from `gate` because that one opens wide (64 permits) so a
    /// batch of parked calls all resume on one release. Counting releases is
    /// the whole point here: two gates need two of them.
    releases: Arc<Semaphore>,
}

/// The token the gateway minted for this call, read back off the wire.
///
/// ADR-014 §2 requires the gateway to send its **own** token to the backend
/// and translate the client's back on the way out, so the fixture must echo
/// whatever it was given rather than assume the client's.
fn minted_token(request: &Value) -> Value {
    request
        .pointer("/params/_meta/progressToken")
        .cloned()
        .unwrap_or(Value::Null)
}

fn tool_name(request: &Value) -> Option<String> {
    request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// A `notifications/progress` for the call the gateway is making right now.
fn progress_frame(token: &Value) -> Value {
    numbered_progress_frame(token, 1)
}

/// The same, at a caller-chosen step. Two gated notifications must be
/// distinguishable, or reading the first one twice would pass the row.
fn numbered_progress_frame(token: &Value, progress: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progressToken": token, "progress": progress, "total": 2},
    })
}

/// A `notifications/message` carrying no request linkage — because the
/// protocol defines none. This is the frame whose stdio isolation row does
/// not exist; see [`s03_message_http_isolates_by_stream`].
fn message_frame(marker: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"level": "info", "logger": BACKEND, "data": marker},
    })
}

fn ok_result(id: &Value, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"content": [{"type": "text", "text": text}]},
    })
}

/// Unary answers: everything that is not the slow tool.
fn unary_answer(request: &Value, state: &FixtureState) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": BACKEND, "version": "0"},
            },
        }),
        Some("tools/list") => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": [
                {
                    "name": SLOW_TOOL,
                    "description": "notifies, then waits to be released",
                    "inputSchema": {"type": "object"},
                },
                {
                    "name": RELEASE_TOOL,
                    "description": "releases every waiting call",
                    "inputSchema": {"type": "object"},
                },
            ]},
        }),
        _ => {
            if tool_name(request).as_deref() == Some(RELEASE_TOOL) {
                state.gate.add_permits(64);
                state.releases.add_permits(1);
                ok_result(&id, "released")
            } else {
                ok_result(&id, "ok")
            }
        }
    }
}

/// The slow tool's response body: a notification event, then a gap, then the
/// result event.
///
/// The body **streams**. A fixture that buffered both events and sent them
/// together would let an implementation that flushes at the end pass a row
/// written to catch exactly that — ADR-014 row 4's *"a design that buffers and
/// flushes at the end deadlocks here instead of passing"*.
fn slow_stream(request: &Value, state: &FixtureState, message: Option<String>) -> Response {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let token = minted_token(request);
    let gate = Arc::clone(&state.gate);
    let releases = Arc::clone(&state.releases);
    let gates = request
        .pointer("/params/arguments/gates")
        .and_then(Value::as_u64);
    let body = async_stream::stream! {
        let first = match &message {
            Some(marker) => message_frame(marker),
            None => progress_frame(&token),
        };
        yield Ok::<_, std::io::Error>(format!("event: message\ndata: {first}\n\n"));
        if gates == Some(3) {
            // A timed second notification: no client call in between.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let second = numbered_progress_frame(&token, 2);
            yield Ok(format!("event: message\ndata: {second}\n\n"));
            let _release = releases.acquire().await;
        } else if gates == Some(2) {
            // The second notification does not exist until a release arrives,
            // and the client only releases once it has read the first. A
            // consumer that flushes one buffer at the end never gets here.
            let _first_release = releases.acquire().await;
            let second = numbered_progress_frame(&token, 2);
            yield Ok(format!("event: message\ndata: {second}\n\n"));
            let _second_release = releases.acquire().await;
        } else {
            // Held until a *second* call releases it. Nothing else can.
            let _permit = gate.acquire().await;
        }
        let result = ok_result(&id, "slow done");
        yield Ok(format!("event: message\ndata: {result}\n\n"));
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

/// Spawn the fixture backend. Returns its URL, what it received, and the gate
/// that holds [`SLOW_TOOL`] parked.
///
/// The gate is handed back so a row can release its own parked call directly.
/// Over stdio that is the only way: the gateway serves one request at a time,
/// so a release sent as a second JSON-RPC call is never read while the first
/// is still parked. Rows with two calls genuinely in flight keep using
/// [`RELEASE_TOOL`].
async fn spawn_fixture_backend() -> (String, Received, Arc<Semaphore>) {
    let state = FixtureState {
        received: Arc::new(Mutex::new(Vec::new())),
        gate: Arc::new(Semaphore::new(0)),
        releases: Arc::new(Semaphore::new(0)),
    };
    let received = Arc::clone(&state.received);
    let gate = Arc::clone(&state.gate);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let state = state.clone();
            async move {
                state
                    .received
                    .lock()
                    .expect("fixture sink poisoned")
                    .push(request.clone());
                if tool_name(&request).as_deref() == Some(SLOW_TOOL) {
                    let marker = request
                        .pointer("/params/arguments/message_marker")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    return slow_stream(&request, &state, marker);
                }
                axum::Json(unary_answer(&request, &state)).into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture backend address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/"), received, gate)
}

fn write_config(home: &Path, backend_url: &str) {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        format!(
            "tasks:\n  store_dir: tasks\nbackends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
        ),
    )
    .expect("write gateway.yaml");
}

// ── Client harness: stdio ───────────────────────────────────────────────────

struct StdioSession {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl StdioSession {
    fn spawn(home: &Path) -> Self {
        let mut command = Command::from(gateway_bin::command(
            home,
            gateway_bin::Inherit::Environment,
        ));
        command.arg("serve").arg("--stdio").current_dir(home);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited rather than piped: an undrained stderr pipe deadlocks
            // the child once its logs fill the buffer.
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gateway over stdio");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();
        Self {
            child,
            stdin,
            stdout,
        }
    }

    async fn send(&mut self, message: &Value) {
        let message = with_idempotency_key(message.clone());
        self.stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("write to child stdin");
        self.stdin.flush().await.expect("flush child stdin");
    }

    /// Read lines until one satisfies `wanted`, or the bound expires.
    ///
    /// Returns every line consumed on the way, in order. The order is the
    /// assertion in every `S-02` row: a notification that arrives after the
    /// result is a different line in this vector, not a different value.
    async fn read_until(&mut self, wanted: impl Fn(&Value) -> bool) -> (Vec<Value>, Option<Value>) {
        let mut seen = Vec::new();
        loop {
            let Ok(Ok(Some(line))) = timeout(READ_TIMEOUT, self.stdout.next_line()).await else {
                return (seen, None);
            };
            let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if wanted(&frame) {
                return (seen, Some(frame));
            }
            seen.push(frame);
        }
    }

    /// Drain for a fixed window. Used by rows asserting a notification is
    /// *absent*, where there is no line to wait for.
    async fn collect(&mut self, window: Duration) -> Vec<Value> {
        let mut frames = Vec::new();
        let _ = timeout(window, async {
            while let Ok(Some(line)) = self.stdout.next_line().await {
                if let Ok(frame) = serde_json::from_str::<Value>(&line) {
                    frames.push(frame);
                }
            }
        })
        .await;
        frames
    }

    async fn shutdown(mut self) {
        drop(self.stdin);
        let _ = self.child.kill().await;
    }
}

fn has_id(frame: &Value, id: i64) -> bool {
    frame.get("id").and_then(Value::as_i64) == Some(id)
}

fn is_method(frame: &Value, method: &str) -> bool {
    frame.get("method").and_then(Value::as_str) == Some(method)
}

fn progress_token_of(frame: &Value) -> Option<&Value> {
    frame.pointer("/params/progressToken")
}

/// The gateway's own audit line rides the caller's stream alongside the
/// backend's whenever the request declared a level (ADR-014 §4,
/// `MIK-7272.SUB.2b`). The `S-02` and `S-03` rows below are about the
/// *backend's* notifications reaching the right caller, so they step over it;
/// the audit line itself is asserted in
/// `gateway::meta_mcp::outbound_log_tests`.
fn is_gateway_own(frame: &Value) -> bool {
    frame
        .pointer("/params/logger")
        .and_then(Value::as_str)
        .is_some_and(|logger| logger.starts_with("gateway."))
}

fn initialize_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "sub2b-acs", "version": "0"},
        },
    })
}

/// A `tools/call` reaching a fixture tool through the invoke meta tool.
///
/// Backend tools are not on `tools/call` by their own name unless an operator
/// pins them, so this is the route a real client takes.
///
/// `request_meta` is merged into `params._meta`: it carries the
/// request-scoped declaration — a `progressToken`, a `logLevel`, or both —
/// which ADR-014 makes the condition for a request-scoped response.
fn invoke(id: i64, tool: &str, arguments: &Value, request_meta: &Value) -> Value {
    // Both keys, always. A `_meta` carrying the version key alone is not a
    // quiet legacy request: `protocol::meta::classify_request` reads a version
    // without a capability declaration as a declaration begun and not
    // finished, and the gateway refuses it with -32602 before dispatch. A
    // harness that sent half a declaration would be testing a client the
    // specification does not describe.
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": REQUEST_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    if let (Some(target), Some(extra)) = (meta.as_object_mut(), request_meta.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": tool, "arguments": arguments},
            "_meta": meta,
        },
    })
}

/// Bring a stdio child up to the point where it will route a tool call.
async fn stdio_session(home: &Path) -> StdioSession {
    let mut session = StdioSession::spawn(home);
    session.send(&initialize_request(1)).await;
    let (_, initialized) = session.read_until(|frame| has_id(frame, 1)).await;
    assert!(
        initialized.is_some(),
        "the gateway must answer initialize before any row can mean anything"
    );
    session
}

include!("sub2b/stdio_rows.rs");

include!("sub2b/http_harness.rs");

include!("sub2b/http_s03_rows.rs");

include!("sub2b/http_s02_rows.rs");

include!("sub2b/http_gate_rows.rs");

include!("sub2b/command_backend.rs");
