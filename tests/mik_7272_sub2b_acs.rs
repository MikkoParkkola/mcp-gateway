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

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";
const BACKEND: &str = "fixture";

/// Emits one notification, then blocks until [`RELEASE_TOOL`] is called.
const SLOW_TOOL: &str = "slow_notifier";
/// Releases every blocked [`SLOW_TOOL`] call. A second call in flight is the
/// only way to release the first, which is what makes the liveness assertion
/// in ADR-014 row 4 mean something.
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
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progressToken": token, "progress": 1, "total": 2},
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
    let body = async_stream::stream! {
        let first = match &message {
            Some(marker) => message_frame(marker),
            None => progress_frame(&token),
        };
        yield Ok::<_, std::io::Error>(format!("event: message\ndata: {first}\n\n"));
        // Held until a *second* call releases it. Nothing else can.
        let _permit = gate.acquire().await;
        let result = ok_result(&id, "slow done");
        yield Ok(format!("event: message\ndata: {result}\n\n"));
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

/// Spawn the fixture backend. Returns its URL and what it received.
async fn spawn_fixture_backend() -> (String, Received) {
    let state = FixtureState {
        received: Arc::new(Mutex::new(Vec::new())),
        gate: Arc::new(Semaphore::new(0)),
    };
    let received = Arc::clone(&state.received);
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
    (format!("http://{address}/"), received)
}

fn write_config(home: &Path, backend_url: &str) {
    std::fs::write(
        home.join("gateway.yaml"),
        format!(
            "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        command
            .arg("serve")
            .arg("--stdio")
            .current_dir(home)
            .env("HOME", home);
        // The developer's own environment must not decide what this child
        // connects to.
        for (name, _) in std::env::vars() {
            if name.starts_with("MCP_GATEWAY_") {
                command.env_remove(name);
            }
        }
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
    async fn read_until(
        &mut self,
        wanted: impl Fn(&Value) -> bool,
    ) -> (Vec<Value>, Option<Value>) {
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
fn invoke(id: i64, tool: &str, arguments: Value, request_meta: Value) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": CLIENT_PROTOCOL_VERSION,
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

// ── S-02 over stdio ─────────────────────────────────────────────────────────

/// `S-02`, progress half, stdio: a backend's `notifications/progress` during a
/// `tools/call` reaches that call before its result, carrying the client's own
/// token.
///
/// GIVEN a fixture that emits a progress notification and then blocks,
/// WHEN the client releases it with a second call made only after the
/// notification has been read off stdout,
/// THEN the notification line precedes the response line and carries the
/// client's token byte-identically.
///
/// The release is what makes this liveness rather than ordering: a gateway
/// that buffered notifications and flushed them with the response would never
/// reach the release, and this row would time out — ADR-014 row 4's
/// *"deadlocks here instead of passing"*.
#[tokio::test]
async fn s02_stdio_progress_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN
    let client_token = "client-token-A";
    session
        .send(&invoke(
            2,
            SLOW_TOOL,
            json!({}),
            json!({"progressToken": client_token}),
        ))
        .await;
    let (before_notification, notification) = session
        .read_until(|frame| is_method(frame, "notifications/progress"))
        .await;
    assert!(
        notification.is_some(),
        "no notifications/progress reached the client before the read bound; \
         the call is still blocked in the fixture, which is what an \
         implementation that flushes at the end looks like from here"
    );
    // Only now — the fixture cannot return until this lands, so reaching the
    // result at all proves the notification preceded it.
    session
        .send(&invoke(3, RELEASE_TOOL, json!({}), json!({})))
        .await;
    let (_, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(
        !before_notification.iter().any(|frame| has_id(frame, 2)),
        "the response for the call arrived before its own notification: {before_notification:?}"
    );
    assert!(result.is_some(), "the released call never returned a result");
    let notification = notification.expect("checked above");
    assert_eq!(
        progress_token_of(&notification),
        Some(&json!(client_token)),
        "the client must get its own token back byte-identically, not the \
         gateway's minted one"
    );
    let minted = received
        .lock()
        .expect("fixture sink poisoned")
        .iter()
        .filter(|request| tool_name(request).as_deref() == Some(SLOW_TOOL))
        .map(minted_token)
        .next()
        .expect("the fixture must have seen the slow call");
    assert_ne!(
        minted,
        json!(client_token),
        "the token sent to the backend must be gateway-minted, not the \
         client's own (ADR-014 §2)"
    );
    session.shutdown().await;
}

/// `S-02`, message half, stdio: a backend's `notifications/message` during a
/// `tools/call` reaches that call before its result.
///
/// One call is in flight, so attribution is unambiguous even without a
/// linkage field. That is exactly why this row exists over stdio and its
/// `S-03` counterpart does not.
#[tokio::test]
async fn s02_stdio_message_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, _received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN
    let marker = "sub2b-stdio-message";
    session
        .send(&invoke(
            2,
            SLOW_TOOL,
            json!({"message_marker": marker}),
            json!({"logLevel": "info"}),
        ))
        .await;
    let (before_notification, notification) = session
        .read_until(|frame| is_method(frame, "notifications/message"))
        .await;
    assert!(
        notification.is_some(),
        "no notifications/message reached the client before the read bound"
    );
    session
        .send(&invoke(3, RELEASE_TOOL, json!({}), json!({})))
        .await;
    let (_, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(
        !before_notification.iter().any(|frame| has_id(frame, 2)),
        "the response arrived before its own notification: {before_notification:?}"
    );
    assert!(result.is_some(), "the released call never returned a result");
    assert_eq!(
        notification
            .as_ref()
            .and_then(|frame| frame.pointer("/params/data")),
        Some(&json!(marker)),
        "the delivered notification must be the backend's own, not one the \
         gateway invented"
    );
    session.shutdown().await;
}

/// `S-02` precondition, stdio: with nothing request-scoped declared, the
/// response is what it is today and no notification is delivered.
///
/// This is ADR-014 row 2's control. It passes vacuously against the current
/// tree and is only meaningful once the rows above are green; it is here so
/// that "deliver everything to everyone" cannot satisfy them.
#[tokio::test]
async fn stdio_without_request_scoped_meta_delivers_no_notification() {
    // GIVEN
    let (backend_url, _received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN — no progressToken and no logLevel.
    session
        .send(&invoke(2, RELEASE_TOOL, json!({}), json!({})))
        .await;
    let (seen, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(result.is_some(), "the plain call must still answer");
    assert!(
        !seen.iter().any(|frame| is_method(frame, "notifications/message")
            || is_method(frame, "notifications/progress")),
        "a request that declared nothing request-scoped received a \
         notification: {seen:?}"
    );
    session.shutdown().await;
}

// ── S-03 over stdio: the progress half only ─────────────────────────────────

/// `S-03`, progress half, stdio: two calls in flight, each notification
/// carrying its own call's token and no other's.
///
/// Both calls are provably in flight: neither can return until the third call
/// releases them, and the third call cannot be dispatched at all unless the
/// loop reads a new line while two are outstanding.
#[tokio::test]
async fn s03_progress_stdio_each_call_sees_only_its_own_token() {
    // GIVEN
    let (backend_url, _received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    write_config(home.path(), &backend_url);
    let mut session = stdio_session(home.path()).await;

    // WHEN
    session
        .send(&invoke(2, SLOW_TOOL, json!({}), json!({"progressToken": "token-A"})))
        .await;
    session
        .send(&invoke(3, SLOW_TOOL, json!({}), json!({"progressToken": "token-B"})))
        .await;
    let (mut seen, first) = session
        .read_until(|frame| is_method(frame, "notifications/progress"))
        .await;
    assert!(first.is_some(), "no notification reached the client");
    seen.extend(first);
    session
        .send(&invoke(4, RELEASE_TOOL, json!({}), json!({})))
        .await;
    let (tail, _) = session.read_until(|frame| has_id(frame, 3)).await;
    seen.extend(tail);
    seen.extend(session.collect(COLLECT_WINDOW).await);

    // THEN
    let tokens: Vec<&Value> = seen
        .iter()
        .filter(|frame| is_method(frame, "notifications/progress"))
        .filter_map(progress_token_of)
        .collect();
    assert_eq!(
        tokens.iter().filter(|token| **token == &json!("token-A")).count(),
        1,
        "call A's token must appear exactly once: {tokens:?}"
    );
    assert_eq!(
        tokens.iter().filter(|token| **token == &json!("token-B")).count(),
        1,
        "call B's token must appear exactly once: {tokens:?}"
    );
    assert!(
        tokens
            .iter()
            .all(|token| **token == json!("token-A") || **token == json!("token-B")),
        "a notification carried a token no caller supplied — the gateway's \
         minted token leaked to the client: {tokens:?}"
    );
    session.shutdown().await;
}

// ── S-03, message half: why there is no stdio row here ──────────────────────
//
// `S-03` asks that a notification "reaches the provoking call's stream and no
// other". Over HTTP the response body *is* the per-request stream, so the
// question has an answer. Over client-facing stdio there is one client and one
// stdout: there is no other caller to leak to, and the failure that can
// actually occur — misattribution between two in-flight calls of the *same*
// client — is undetectable for `notifications/message`, because MCP defines no
// per-request relation on a logging notification and this repository has none
// (no `relatedRequestId`, no `progressToken` in `src/protocol/`).
//
// So a stdio row for the message half could assert only that *a* message
// notification arrived — which `s02_stdio_message_reaches_its_own_call_before_
// the_result` already asserts, and which no misrouting could fail. It is
// omitted deliberately. A test that cannot fail is worse than a missing one,
// because the criteria ledger counts it.
//
// This is recorded as UNMET, not as covered: see ADR-014 Amendment 1 and the
// `MIK-7272.SUB.2b` row of `docs/requirements/RELEASE-4.0.0-criteria-status.md`.
// The `notifications/progress` half has a real stdio row above, because the
// client's own token gives it a discriminator.

// ── S-02 and S-03 over HTTP ─────────────────────────────────────────────────
//
// NOT YET WRITTEN — the next piece of this file, not a decision to omit them.
// The HTTP client rows need a harness this file does not yet have: the child
// spawned in HTTP mode, a POST carrying `Accept: text/event-stream`, and the
// response body read incrementally so that "the notification arrived before
// the body was read to its end" is an observation rather than an assumption.
// Four rows land here: the progress and message halves of `S-02`, and both
// halves of `S-03` — the message half being the *discriminating* instance of
// `S-03`, which is why HTTP carries it and stdio does not.
