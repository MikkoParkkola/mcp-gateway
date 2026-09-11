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

/// Spawn the fixture backend. Returns its URL and what it received.
async fn spawn_fixture_backend() -> (String, Received) {
    let state = FixtureState {
        received: Arc::new(Mutex::new(Vec::new())),
        gate: Arc::new(Semaphore::new(0)),
        releases: Arc::new(Semaphore::new(0)),
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
            &json!({}),
            &json!({"progressToken": client_token}),
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
        .send(&invoke(3, RELEASE_TOOL, &json!({}), &json!({})))
        .await;
    let (_, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(
        !before_notification.iter().any(|frame| has_id(frame, 2)),
        "the response for the call arrived before its own notification: {before_notification:?}"
    );
    assert!(
        result.is_some(),
        "the released call never returned a result"
    );
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
            &json!({"message_marker": marker}),
            &json!({"logLevel": "info"}),
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
        .send(&invoke(3, RELEASE_TOOL, &json!({}), &json!({})))
        .await;
    let (_, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(
        !before_notification.iter().any(|frame| has_id(frame, 2)),
        "the response arrived before its own notification: {before_notification:?}"
    );
    assert!(
        result.is_some(),
        "the released call never returned a result"
    );
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
        .send(&invoke(2, RELEASE_TOOL, &json!({}), &json!({})))
        .await;
    let (seen, result) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    assert!(result.is_some(), "the plain call must still answer");
    assert!(
        !seen
            .iter()
            .any(|frame| is_method(frame, "notifications/message")
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
        .send(&invoke(
            2,
            SLOW_TOOL,
            &json!({}),
            &json!({"progressToken": "token-A"}),
        ))
        .await;
    session
        .send(&invoke(
            3,
            SLOW_TOOL,
            &json!({}),
            &json!({"progressToken": "token-B"}),
        ))
        .await;
    let (mut seen, first) = session
        .read_until(|frame| is_method(frame, "notifications/progress"))
        .await;
    assert!(first.is_some(), "no notification reached the client");
    seen.extend(first);
    session
        .send(&invoke(4, RELEASE_TOOL, &json!({}), &json!({})))
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
        tokens
            .iter()
            .filter(|token| **token == &json!("token-A"))
            .count(),
        1,
        "call A's token must appear exactly once: {tokens:?}"
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| **token == &json!("token-B"))
            .count(),
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
// Four rows belong here: the progress and message halves of `S-02`, and both
// halves of `S-03`. Both halves of `S-03` are written below, on the harness
// that follows.
//
// The two `S-02` rows assert liveness: the fixture releases a result only once
// the client has read the notification (ADR-014 Acceptance row 4). They
// therefore cannot use `post_sse`, which reads a body to its end — a client
// that waits for the whole body waits for a result the fixture is withholding
// from it, and the four-step deadlock that follows is a property of the
// consumer and not of any harness. `SseReader` below is the incremental
// consumer they need instead.
//
// `S-03` is unaffected either way: which stream carried which notification is
// fully observable in a buffered body. Batching breaks liveness, not
// isolation, which is why the two `S-03` rows keep reading to the end.

// ── Client harness: HTTP ────────────────────────────────────────────────────

fn write_http_config(home: &Path, backend_url: &str, port: u16) {
    std::fs::write(
        home.join("gateway.yaml"),
        format!(
            "server:\n  host: \"127.0.0.1\"\n  port: {port}\n\
             backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n"
        ),
    )
    .expect("write gateway.yaml");
}

struct HttpSession {
    child: Child,
    client: reqwest::Client,
    url: String,
    /// The session the gateway assigned at `initialize`. A Streamable HTTP
    /// client echoes it on every later POST; a harness that dropped it would
    /// run each call on a virgin session and would be testing a client the
    /// spec does not describe.
    session: String,
}

impl HttpSession {
    /// Spawn the gateway in HTTP mode and wait until it answers `initialize`.
    async fn spawn(home: &Path, backend_url: &str) -> Self {
        // Ask the OS for a free port and hand it straight to the child. The
        // listener is dropped before the child binds, so the port is briefly
        // unclaimed; the readiness loop below is what makes that safe, and a
        // timeout there names this race.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve a port")
            .local_addr()
            .expect("reserved port")
            .port();
        write_http_config(home, backend_url, port);

        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        command.arg("serve").current_dir(home).env("HOME", home);
        // The developer's own environment must not decide what this child
        // connects to.
        for (name, _) in std::env::vars() {
            if name.starts_with("MCP_GATEWAY_") {
                command.env_remove(name);
            }
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn gateway over http");

        let url = format!("http://127.0.0.1:{port}/mcp");
        let client = reqwest::Client::new();
        let ready = timeout(READ_TIMEOUT, async {
            loop {
                let posted = client
                    .post(&url)
                    .header("Accept", "application/json, text/event-stream")
                    .json(&initialize_request(1))
                    .send()
                    .await;
                if let Ok(response) = posted
                    && response.status() == reqwest::StatusCode::OK
                {
                    return response
                        .headers()
                        .get("mcp-session-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let session = ready.unwrap_or_else(|_| {
            panic!(
                "the gateway never answered initialize on 127.0.0.1:{port} — either \
                 it failed to start, or another process took the reserved port \
                 between the probe bind and the child's own bind"
            )
        });
        assert!(
            !session.is_empty(),
            "the gateway assigned no session at initialize; every later POST \
             would open a new one"
        );

        // The handshake is not complete until the client says so, and a call
        // made before it is a call made against a server that is still
        // initializing.
        let (status, _, body) = post_sse(
            &client,
            &url,
            &session,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
        assert!(
            (200..300).contains(&status),
            "the gateway refused notifications/initialized: {status} {body}"
        );

        Self {
            child,
            client,
            url,
            session,
        }
    }

    async fn shutdown(mut self) {
        let _ = self.child.kill().await;
    }
}

/// POST one JSON-RPC message, offering a stream. Returns status, content type
/// and body; every failure message in the HTTP rows quotes the body, because a
/// refusal is a body and not a status.
async fn post_sse(
    client: &reqwest::Client,
    url: &str,
    session: &str,
    message: Value,
) -> (u16, String, String) {
    // Mirror whatever the body declared, and nothing when it declared nothing.
    // The gateway reads the header as well as the body and refuses the two
    // disagreeing with -32020 — including the case where only one of them
    // speaks, which is why this is derived from the message rather than set on
    // every POST: `notifications/initialized` carries no `_meta`, and a header
    // on it would be a declaration the body does not make.
    let declared = message
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .and_then(Value::as_str);
    let mut request = client
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", session);
    if let Some(version) = declared {
        request = request.header("MCP-Protocol-Version", version);
        // A modern POST mirrors its method too, and its name for the three
        // methods that carry one. The gateway requires both and refuses an
        // absent one with -32020, so both are derived from the same message
        // the body is built from rather than written out beside it, which is
        // how a header and a body drift apart.
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        request = request.header("Mcp-Method", method);
        if let Some(field) = mcp_name_body_field(method) {
            if let Some(name) = message
                .pointer(&format!("/params/{field}"))
                .and_then(Value::as_str)
            {
                request = request.header("Mcp-Name", encode_header_value(name));
            }
        }
    }
    let response = request
        .json(&message)
        .send()
        .await
        .expect("POST to the gateway");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = response.text().await.expect("read the response body");
    (status, content_type, body)
}

/// The JSON frames of an SSE body, in order.
fn sse_frames(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .collect()
}

/// Reads one SSE body frame by frame, as the bytes arrive.
///
/// The `S-02` liveness rows need a consumer that acts on a notification before
/// the response it belongs to has ended — that is the whole assertion — so
/// they cannot buffer. Everything else here reads to the end with
/// [`post_sse`].
struct SseReader {
    stream: std::pin::Pin<Box<dyn futures::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>,
    pending: String,
}

impl SseReader {
    /// POST `message` offering a stream, and return a reader over the body
    /// alongside the status and content type of its head.
    ///
    /// The head is available before the body because the gateway commits to
    /// SSE headers before dispatch finishes; a row that never sees a head has
    /// found the buffered arm, which is the failure it exists to catch.
    async fn post(
        client: &reqwest::Client,
        url: &str,
        session: &str,
        message: Value,
    ) -> (u16, String, Self) {
        let version = message
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str)
            .expect("an S-02 row declares its revision");
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut request = client
            .post(url)
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Session-Id", session)
            .header("MCP-Protocol-Version", version)
            .header("Mcp-Method", method);
        if let Some(field) = mcp_name_body_field(method) {
            if let Some(name) = message
                .pointer(&format!("/params/{field}"))
                .and_then(Value::as_str)
            {
                request = request.header("Mcp-Name", encode_header_value(name));
            }
        }
        let response = request
            .json(&message)
            .send()
            .await
            .expect("POST to the gateway");
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        (
            status,
            content_type,
            Self {
                stream: Box::pin(response.bytes_stream()),
                pending: String::new(),
            },
        )
    }

    /// The next complete frame, or `None` when the body ends without one.
    ///
    /// Bounded by [`READ_TIMEOUT`] rather than left to the test harness: a row
    /// whose notification never arrives is exactly the regression being
    /// guarded against, and it must fail as an assertion rather than hang.
    async fn next_frame(&mut self) -> Option<Value> {
        use futures::StreamExt as _;

        loop {
            if let Some(split) = self.pending.find("\n\n") {
                let frame: String = self.pending.drain(..split + 2).collect();
                if let Some(data) = frame.lines().find_map(|l| l.strip_prefix("data: ")) {
                    if let Ok(value) = serde_json::from_str::<Value>(data) {
                        return Some(value);
                    }
                }
                continue;
            }
            let chunk = timeout(READ_TIMEOUT, self.stream.next())
                .await
                .expect("the response body stalled with no frame in it")?;
            let chunk = chunk.expect("read the response body");
            self.pending.push_str(&String::from_utf8_lossy(&chunk));
        }
    }
}

/// Wait until `count` slow calls have reached the fixture and parked there.
///
/// This is the concurrency precondition of the isolation rows: two streams
/// cannot be shown to be separate unless both are open at once.
async fn parked_slow_calls(received: &Received, count: usize) -> bool {
    timeout(READ_TIMEOUT, async {
        loop {
            let parked = received
                .lock()
                .expect("fixture sink poisoned")
                .iter()
                .filter(|request| tool_name(request).as_deref() == Some(SLOW_TOOL))
                .count();
            if parked >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok()
}

// ── S-03 over HTTP: both halves ─────────────────────────────────────────────

/// Two slow calls held open at once on one session, released by a third, and
/// the body each was answered with.
///
/// Both isolation rows need the same three POSTs — two calls that park in the
/// fixture so their streams are provably open at the same time, and a third
/// that releases them — and differ only in the discriminator they then look
/// for. So only the discriminator lives in the rows.
///
/// `call_a` and `call_b` are each that call's `arguments` and its
/// request-scoped `_meta` declaration. Call A is id 2, call B is id 3, and the
/// release is id 4.
async fn concurrent_slow_bodies(
    session: &HttpSession,
    received: &Received,
    call_a: (Value, Value),
    call_b: (Value, Value),
) -> (String, String) {
    let post = |id: i64, (arguments, request_meta): (Value, Value)| {
        let (client, url, mcp_session) = (
            session.client.clone(),
            session.url.clone(),
            session.session.clone(),
        );
        tokio::spawn(async move {
            post_sse(
                &client,
                &url,
                &mcp_session,
                invoke(id, SLOW_TOOL, &arguments, &request_meta),
            )
            .await
        })
    };
    let answering_a = post(2, call_a);
    let answering_b = post(3, call_b);

    let both_parked = parked_slow_calls(received, 2).await;
    if !both_parked {
        // Release whatever did park, so the two bodies below are answers and
        // not a second timeout, and report them: a row that fails here fails
        // because of what the gateway said, and the message must carry it.
        let reached_fixture: Vec<String> = received
            .lock()
            .expect("fixture sink poisoned")
            .iter()
            .map(|request| {
                tool_name(request).unwrap_or_else(|| {
                    request
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                        .to_owned()
                })
            })
            .collect();
        let _ = post_sse(
            &session.client,
            &session.url,
            &session.session,
            invoke(4, RELEASE_TOOL, &json!({}), &json!({})),
        )
        .await;
        let answered_a = timeout(READ_TIMEOUT, answering_a).await;
        let answered_b = timeout(READ_TIMEOUT, answering_b).await;
        panic!(
            "both calls must be in flight at once for this row to observe \
             isolation. The fixture saw {reached_fixture:?}; call A answered \
             {answered_a:?}; call B answered {answered_b:?}"
        );
    }
    assert!(
        !answering_a.is_finished() && !answering_b.is_finished(),
        "a slow call answered before it was released"
    );

    let (release_status, _, release_body) = post_sse(
        &session.client,
        &session.url,
        &session.session,
        invoke(4, RELEASE_TOOL, &json!({}), &json!({})),
    )
    .await;
    assert_eq!(
        release_status, 200,
        "the release call failed, so nothing below can run: {release_body}"
    );

    let answered_a = timeout(READ_TIMEOUT, answering_a).await;
    let answered_b = timeout(READ_TIMEOUT, answering_b).await;
    let (status_a, content_type_a, body_a) =
        answered_a.expect("call A never returned").expect("call A");
    let (status_b, content_type_b, body_b) =
        answered_b.expect("call B never returned").expect("call B");
    for (label, status, content_type, body) in [
        ("A", status_a, &content_type_a, &body_a),
        ("B", status_b, &content_type_b, &body_b),
    ] {
        assert_eq!(status, 200, "call {label} was refused: {body}");
        assert!(
            content_type.contains("text/event-stream"),
            "call {label} answered {content_type}, not a stream: {body}"
        );
    }
    assert!(
        sse_frames(&body_a).iter().any(|frame| has_id(frame, 2)),
        "call A's body carries no result of its own: {body_a}"
    );
    assert!(
        sse_frames(&body_b).iter().any(|frame| has_id(frame, 3)),
        "call B's body carries no result of its own: {body_b}"
    );
    (body_a, body_b)
}

/// Every notification of one method carried by one response body, in order.
fn notified(body: &str, method: &str, field: &str) -> Vec<Value> {
    sse_frames(body)
        .into_iter()
        .filter(|frame| is_method(frame, method))
        .filter_map(|frame| frame.pointer(field).cloned())
        .collect()
}

/// `S-03`, message half, HTTP: two `tools/call` POSTs in flight at once each
/// receive their own backend `notifications/message` and no other's.
///
/// GIVEN two concurrent calls to the slow tool, each declaring `logLevel` and
/// each carrying a marker only its own backend leg echoes,
/// WHEN both have reached the fixture and parked there — so both response
/// streams are open at the same time — and a third call releases them,
/// THEN each response body carries its own result id and exactly its own
/// marker.
///
/// This is the row stdio cannot have (see "why there is no stdio row here"
/// above): a logging notification carries no request linkage, so the only
/// discriminator is *which stream it was written to*, and over HTTP the
/// response body is that stream. ADR-014 row 14.
///
/// The release differs from the stdio rows: it is a third POST rather than a
/// second message on one connection, because two parked calls hold two
/// connections and neither can be used to send anything.
#[tokio::test]
async fn s03_message_http_isolates_by_stream() {
    // GIVEN
    let (backend_url, received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let marker_a = "sub2b-http-message-A";
    let marker_b = "sub2b-http-message-B";
    let (body_a, body_b) = concurrent_slow_bodies(
        &session,
        &received,
        (
            json!({"message_marker": marker_a}),
            json!({"logLevel": "info"}),
        ),
        (
            json!({"message_marker": marker_b}),
            json!({"logLevel": "info"}),
        ),
    )
    .await;

    // THEN
    assert_eq!(
        notified(&body_a, "notifications/message", "/params/data"),
        vec![json!(marker_a)],
        "call A's stream must carry its own message and only its own: {body_a}"
    );
    assert_eq!(
        notified(&body_b, "notifications/message", "/params/data"),
        vec![json!(marker_b)],
        "call B's stream must carry its own message and only its own: {body_b}"
    );
    session.shutdown().await;
}

/// `S-03`, progress half, HTTP: two `tools/call` POSTs in flight at once each
/// receive their own `notifications/progress`, carrying their own caller's
/// token.
///
/// GIVEN two concurrent calls to the slow tool, each declaring its own
/// `progressToken`,
/// WHEN both have parked in the fixture and a third call releases them,
/// THEN each response body carries exactly its own caller's token — not the
/// other call's, and not the gateway's minted one, which ADR-014 §2 requires
/// be translated back on the way out.
///
/// The stdio instance of this row
/// (`s03_progress_stdio_each_call_sees_only_its_own_token`) can only count
/// tokens on one shared stdout. Here the two streams are separate objects, so
/// *the token is on the wrong stream* is a distinguishable failure rather than
/// an inference. ADR-014 row 14.
#[tokio::test]
async fn s03_progress_http_isolates_by_stream() {
    // GIVEN
    let (backend_url, received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let (body_a, body_b) = concurrent_slow_bodies(
        &session,
        &received,
        // The `call` argument is inert — the fixture reads only
        // `message_marker` — and exists so the two calls are not byte-identical
        // below `_meta`. Two requests that differ only inside `_meta` are the
        // shape an in-flight dedupe would collapse into one, and a collapsed
        // pair fails this row for a reason that has nothing to do with
        // isolation.
        (json!({"call": "A"}), json!({"progressToken": "token-A"})),
        (json!({"call": "B"}), json!({"progressToken": "token-B"})),
    )
    .await;

    // THEN
    assert_eq!(
        notified(&body_a, "notifications/progress", "/params/progressToken"),
        vec![json!("token-A")],
        "call A's stream must carry its own token and only its own: {body_a}"
    );
    assert_eq!(
        notified(&body_b, "notifications/progress", "/params/progressToken"),
        vec![json!("token-B")],
        "call B's stream must carry its own token and only its own: {body_b}"
    );
    session.shutdown().await;
}

// ── S-02 over HTTP ──────────────────────────────────────────────────────────

/// Read one notification off a still-open call, then release it and read the
/// result — the liveness assertion of ADR-014 row 4, over HTTP.
///
/// Returns the notification frame and the result frame, in the order the
/// client actually saw them. The release is a second POST because the first
/// connection is parked and cannot carry anything.
async fn notification_then_result(
    session: &HttpSession,
    received: &Received,
    arguments: Value,
    request_meta: Value,
) -> (Value, Value) {
    let (status, content_type, mut reader) = SseReader::post(
        &session.client,
        &session.url,
        &session.session,
        invoke(2, SLOW_TOOL, &arguments, &request_meta),
    )
    .await;
    assert_eq!(status, 200, "the slow call was refused before it streamed");
    assert!(
        content_type.contains("text/event-stream"),
        "the gateway answered {content_type}, so it never committed to a \
         stream and the notification below cannot arrive before the result"
    );

    // The first frame must arrive while the call is still parked at the
    // fixture. Nothing has released it, so a buffered consumer would deadlock
    // here and this read is what proves the gateway does not.
    let notification = reader
        .next_frame()
        .await
        .expect("the body ended before any frame");
    assert!(
        parked_slow_calls(received, 1).await,
        "the frame arrived but the call is not parked, so it proves no \
         liveness: {notification}"
    );

    let (release_status, _, release_body) = post_sse(
        &session.client,
        &session.url,
        &session.session,
        invoke(3, RELEASE_TOOL, &json!({}), &json!({})),
    )
    .await;
    assert_eq!(
        release_status, 200,
        "the release call failed, so the result below cannot arrive: \
         {release_body}"
    );

    let mut result = reader.next_frame().await;
    while result.as_ref().is_some_and(|frame| !has_id(frame, 2)) {
        result = reader.next_frame().await;
    }
    let result = result.expect("the body ended before the result frame");
    (notification, result)
}

/// `S-02`, progress half, HTTP: a backend's `notifications/progress` reaches
/// the client that provoked it *before* that call's result.
///
/// GIVEN a call to the slow tool, which emits one progress notification and
/// then withholds its result until a second call releases it,
/// WHEN the client reads the response body incrementally,
/// THEN it reads the notification while the call is still parked, and the
/// result only after it releases it.
///
/// The order is the assertion and the parking is what gives it force: a
/// gateway that buffers cannot pass this row, because the result it would be
/// buffering does not exist until the client has acted on the notification.
/// ADR-014 Acceptance row 4.
#[tokio::test]
async fn s02_progress_http_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let (notification, result) = timeout(
        READ_TIMEOUT,
        notification_then_result(
            &session,
            &received,
            json!({}),
            json!({"progressToken": "client-token"}),
        ),
    )
    .await
    .expect("the row deadlocked, which is the buffered arm answering");

    // THEN
    assert!(
        is_method(&notification, "notifications/progress"),
        "the first frame was not a progress notification: {notification}"
    );
    assert_eq!(
        progress_token_of(&notification),
        Some(&json!("client-token")),
        "the client must see its own token back, not the minted one: \
         {notification}"
    );
    assert!(
        has_id(&result, 2),
        "the last frame is not this call's result: {result}"
    );
    session.shutdown().await;
}

/// `S-02`, message half, HTTP: a backend's `notifications/message` reaches the
/// client that provoked it before that call's result.
///
/// GIVEN a call to the slow tool declaring `logLevel`, so the fixture emits a
/// logging notification and then withholds its result,
/// WHEN the client reads the response body incrementally,
/// THEN it reads the notification while the call is still parked, and the
/// result only after it releases it.
///
/// The separate row matters because a logging notification carries no request
/// linkage: the only thing tying it to this call is the stream it arrived on,
/// so the progress row above cannot stand in for it. ADR-014 Acceptance row 4.
#[tokio::test]
async fn s02_message_http_reaches_its_own_call_before_the_result() {
    // GIVEN
    let (backend_url, received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let marker = "sub2b-http-message-solo";
    let (notification, result) = timeout(
        READ_TIMEOUT,
        notification_then_result(
            &session,
            &received,
            json!({"message_marker": marker}),
            json!({"logLevel": "info"}),
        ),
    )
    .await
    .expect("the row deadlocked, which is the buffered arm answering");

    // THEN
    assert!(
        is_method(&notification, "notifications/message"),
        "the first frame was not a logging notification: {notification}"
    );
    assert_eq!(
        notification.pointer("/params/data"),
        Some(&json!(marker)),
        "the logging notification is not the one this call provoked: \
         {notification}"
    );
    assert!(
        has_id(&result, 2),
        "the last frame is not this call's result: {result}"
    );
    session.shutdown().await;
}

/// Release every parked call; the two-gate body counts one release per call.
async fn release(session: &HttpSession, id: i64) {
    let (status, _, body) = post_sse(
        &session.client,
        &session.url,
        &session.session,
        invoke(id, RELEASE_TOOL, &json!({}), &json!({})),
    )
    .await;
    assert_eq!(status, 200, "the release call failed: {body}");
}

/// `S-02`, HTTP: each notification reaches the caller as it decodes, not
/// batched into one write at the end.
///
/// GIVEN a backend that emits its second notification only after a release,
/// WHEN the client reads the first notification and releases,
/// THEN the second notification arrives before the result.
///
/// One gate proves a flush happened; two prove the flushing is per-event. The
/// frame that prompts the second release does not exist until the first has
/// been read and acted on, so a consumer that drains one buffer at the end
/// never reaches it. The PROBE labels localise a failure: which one fires says
/// whether the release was serviced, whether the frame followed it, and
/// whether the result ever came.
#[tokio::test]
#[ignore = "reproduction for the open client-leg defect; un-ignore with the fix"]
async fn s02_http_flushes_each_notification_rather_than_one_buffer() {
    // GIVEN
    let (backend_url, received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    // WHEN
    let (first, second, result) = timeout(READ_TIMEOUT * 10, async {
        let (status, content_type, mut reader) = SseReader::post(
            &session.client,
            &session.url,
            &session.session,
            invoke(
                2,
                SLOW_TOOL,
                &json!({"gates": 2}),
                &json!({"progressToken": "client-token"}),
            ),
        )
        .await;
        assert_eq!(
            status, 200,
            "the two-gate call was refused before it streamed"
        );
        assert!(
            content_type.contains("text/event-stream"),
            "the gateway answered {content_type}, so it never committed to a \
             stream and nothing below can arrive early"
        );

        let first = reader
            .next_frame()
            .await
            .expect("the body ended before the first notification");
        assert!(
            parked_slow_calls(&received, 1).await,
            "the frame arrived but the call is not parked, so it proves no \
             liveness: {first}"
        );

        timeout(READ_TIMEOUT, release(&session, 3))
            .await
            .expect("PROBE-A: the release call never returned while the first call streamed");
        let second = timeout(READ_TIMEOUT, reader.next_frame())
            .await
            .expect("PROBE-B: the release landed but no second frame followed")
            .expect("the body ended before the second notification");

        timeout(READ_TIMEOUT, release(&session, 4))
            .await
            .expect("PROBE-C: the second release call never returned");
        let mut result = timeout(READ_TIMEOUT, reader.next_frame())
            .await
            .expect("PROBE-D: no frame followed the second release");
        while result.as_ref().is_some_and(|frame| !has_id(frame, 2)) {
            result = timeout(READ_TIMEOUT, reader.next_frame())
                .await
                .expect("PROBE-E: the stream stalled before the result frame");
        }
        (
            first,
            second,
            result.expect("the body ended before the result frame"),
        )
    })
    .await
    .expect("the row deadlocked, which is one buffered flush answering");

    // THEN
    assert_eq!(
        first.pointer("/params/progress"),
        Some(&json!(1)),
        "the first frame is not the first notification: {first}"
    );
    assert!(
        is_method(&second, "notifications/progress"),
        "the second gated frame is not a notification: {second}"
    );
    assert_eq!(
        second.pointer("/params/progress"),
        Some(&json!(2)),
        "the second frame repeats the first, so no second flush is proven: {second}"
    );
    assert_eq!(
        progress_token_of(&second),
        Some(&json!("client-token")),
        "the client must see its own token back on every frame: {second}"
    );
    assert!(
        has_id(&result, 2),
        "the last frame is not this call's result: {result}"
    );
    session.shutdown().await;
}

/// The discriminator: identical to the two-gate row except the second
/// notification is emitted on a timer, with no client call in between. It
/// separates "the client leg forwards only one notification" from "the second
/// notification is never produced while a stream is open".
#[tokio::test]
#[ignore = "discriminator for the row above; runs with it"]
async fn s02_http_forwards_a_second_notification_with_no_call_between() {
    let (backend_url, _received) = spawn_fixture_backend().await;
    let home = tempfile::tempdir().expect("temp home");
    let session = HttpSession::spawn(home.path(), &backend_url).await;

    let (_status, _ct, mut reader) = SseReader::post(
        &session.client,
        &session.url,
        &session.session,
        invoke(
            2,
            SLOW_TOOL,
            &json!({"gates": 3}),
            &json!({"progressToken": "client-token"}),
        ),
    )
    .await;
    let first = reader.next_frame().await.expect("first frame");
    assert_eq!(first.pointer("/params/progress"), Some(&json!(1)));
    let second = timeout(READ_TIMEOUT, reader.next_frame())
        .await
        .expect("no second frame followed the timer")
        .expect("the body ended before the second notification");
    assert_eq!(
        second.pointer("/params/progress"),
        Some(&json!(2)),
        "the timed second notification did not reach the client: {second}"
    );
    session.shutdown().await;
}
