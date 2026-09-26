// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the stdio transport, split out of `stdio.rs` to keep it under the file-size
//! ceiling. A `#[path]` child, not a sibling module: `use super::*` still resolves to the
//! transport's own items, so nothing had to be widened to move it here.

use super::*;
use std::collections::HashMap;

#[cfg(windows)]
#[path = "stdio_windows_env_tests.rs"]
mod windows_env;

#[cfg(unix)]
const CHILD_SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_CHILD_ENV_SCENARIO";
#[cfg(unix)]
const PARENT_SECRET_ENV: &str = "MCP_GATEWAY_TEST_PARENT_SECRET";
#[cfg(unix)]
const EXPLICIT_BACKEND_ENV: &str = "MCP_GATEWAY_TEST_EXPLICIT_BACKEND";

#[test]
fn pending_request_guard_removes_entry_on_drop() {
    let pending: dashmap::DashMap<String, oneshot::Sender<crate::protocol::JsonRpcResponse>> =
        dashmap::DashMap::new();
    let (tx, _rx) = oneshot::channel::<crate::protocol::JsonRpcResponse>();
    pending.insert("7".to_string(), tx);
    assert_eq!(pending.len(), 1);

    {
        let _guard = PendingRequestGuard::new(&pending, "7");
        assert_eq!(pending.len(), 1, "entry present while guard alive");
    }

    assert!(pending.is_empty(), "guard drop removes the entry");
}

fn make_transport(cmd: &str) -> Arc<StdioTransport> {
    StdioTransport::new(
        cmd,
        HashMap::new(),
        None,
        std::time::Duration::from_secs(30),
        None,
    )
}

// =========================================================================
// Construction
// =========================================================================

#[test]
fn new_stores_command_and_defaults() {
    let t = make_transport("node server.js");
    assert_eq!(t.command, "node server.js");
    assert!(!t.is_connected());
    assert!(t.env.is_empty());
    assert!(t.cwd.is_none());
    assert!(t.protocol_version.read().is_none());
}

#[test]
fn new_with_env_and_cwd() {
    let mut env = HashMap::new();
    env.insert("NODE_ENV".to_string(), "test".to_string());
    let t = StdioTransport::new(
        "node index.js",
        env,
        Some("/tmp".to_string()),
        std::time::Duration::from_secs(45),
        None,
    );
    assert_eq!(t.env.get("NODE_ENV").unwrap(), "test");
    assert_eq!(t.cwd.as_deref(), Some("/tmp"));
    assert_eq!(t.request_timeout, std::time::Duration::from_secs(45));
}

#[test]
fn new_with_explicit_protocol_version() {
    let t = StdioTransport::new(
        "echo",
        HashMap::new(),
        None,
        std::time::Duration::from_secs(30),
        Some("2025-06-18".to_string()),
    );
    assert_eq!(*t.protocol_version.read(), Some("2025-06-18".to_string()));
}

// =========================================================================
// next_id
// =========================================================================

#[test]
fn next_id_increments_sequentially() {
    let t = make_transport("echo");
    assert_eq!(t.next_id(), RequestId::Number(1));
    assert_eq!(t.next_id(), RequestId::Number(2));
    assert_eq!(t.next_id(), RequestId::Number(3));
}

// =========================================================================
// handle_response - valid JSON-RPC responses
// =========================================================================

#[test]
fn handle_response_routes_to_pending_request() {
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("1".to_string(), tx);

    let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
    t.handle_response(json).unwrap();

    let response = rx.try_recv().unwrap();
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[test]
fn handle_response_string_id() {
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("req-42".to_string(), tx);

    let json = r#"{"jsonrpc":"2.0","id":"req-42","result":{}}"#;
    t.handle_response(json).unwrap();

    let response = rx.try_recv().unwrap();
    assert!(response.result.is_some());
}

/// An inbound request that happens to carry an `id` must never be routed to
/// a pending caller as if it were that caller's answer. The frame is a
/// server-to-client request (`sampling/createMessage`), not a response.
#[test]
fn handle_response_rejects_inbound_request_and_leaves_caller_pending() {
    // GIVEN: a caller waiting on id 5
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("5".to_string(), tx);

    // WHEN: the peer sends a *request* that reuses that id
    let json = r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{}}"#;
    let outcome = t.handle_response(json);

    // THEN: the frame is refused, and the caller is still waiting
    assert!(
        outcome.is_err(),
        "a frame carrying `method` must not parse as a response"
    );
    assert!(rx.try_recv().is_err(), "caller must not be completed");
    assert!(
        t.pending.contains_key("5"),
        "caller must remain pending, not be silently consumed"
    );
}

#[test]
fn handle_response_no_matching_pending() {
    let t = make_transport("echo");
    // No pending request registered - should not panic
    let json = r#"{"jsonrpc":"2.0","id":99,"result":{}}"#;
    t.handle_response(json).unwrap();
}

#[test]
fn handle_response_no_id_notification() {
    let t = make_transport("echo");
    // Notifications have no id - should be handled gracefully
    let json = r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#;
    t.handle_response(json).unwrap();
}

#[test]
fn handle_response_error_response() {
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("5".to_string(), tx);

    let json = r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32601,"message":"Method not found"}}"#;
    t.handle_response(json).unwrap();

    let response = rx.try_recv().unwrap();
    assert!(response.error.is_some());
    assert_eq!(response.error.unwrap().code, -32601);
}

#[test]
fn handle_response_invalid_json_returns_error() {
    let t = make_transport("echo");
    let result = t.handle_response("not valid json");
    assert!(result.is_err());
}

// =========================================================================
// build_init_params
// =========================================================================

#[test]
fn build_init_params_contains_version() {
    let params = StdioTransport::build_init_params("2025-06-18");
    assert_eq!(params["protocolVersion"], "2025-06-18");
    assert_eq!(params["clientInfo"]["name"], "mcp-gateway");
}

// =========================================================================
// is_connected
// =========================================================================

#[test]
fn initially_not_connected() {
    let t = make_transport("echo");
    assert!(!t.is_connected());
}

#[test]
fn connected_flag_toggles() {
    let t = make_transport("echo");
    t.connected.store(true, Ordering::Relaxed);
    assert!(t.is_connected());
    t.connected.store(false, Ordering::Relaxed);
    assert!(!t.is_connected());
}

#[tokio::test]
async fn request_cleans_pending_entry_when_write_fails() {
    let t = make_transport("echo");

    let result = t.request("tools/list", None).await;

    assert!(matches!(result, Err(Error::Transport(message)) if message == "Not connected"));
    assert!(t.pending.is_empty());
}

/// Dropping an in-flight `request()` future must not strand its `pending`
/// entry. This is the exact cancellation path the aggregation timeout in
/// `meta_mcp` exercises: an outer `tokio::time::timeout` (or a task abort)
/// drops the request future BEFORE the transport's own request timeout
/// fires, so neither the reader task nor the internal timeout removes the
/// entry — the RAII `PendingRequestGuard` must. A real child that answers
/// `initialize` but never answers `prompts/list` holds the request open so
/// the drop happens mid-await.
#[cfg(unix)]
#[tokio::test]
async fn cancelled_request_does_not_strand_pending_entry() {
    let workspace = tempfile::tempdir().expect("workspace");
    let server = workspace.path().join("server.sh");
    std::fs::write(
        &server,
        r#"while IFS= read -r request; do
case "$request" in
    *'"method":"initialize"'*)
        printf '%s
' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'
        ;;
    # deliberately answer NOTHING for prompts/list — holds the request open
esac
done
"#,
    )
    .expect("write server");

    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(workspace.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(30), // far beyond the test's abort
        None,
    );
    transport.start().await.expect("start");

    // Run the request on its own task so aborting it is a real cancellation
    // (an outer `tokio::time::timeout` / task abort dropping the future
    // mid-await) rather than a test-only `drop` of a pinned future.
    let request_transport = transport.clone();
    let request_task =
        tokio::spawn(async move { request_transport.request("prompts/list", None).await });

    // Wait for the request to register in `pending` — the write has happened
    // and the child is holding the request open unanswered.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if !transport.pending.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "precondition: request registered in pending while the child holds it open"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Abort the task mid-await. The child never answers, so the internal 30s
    // timeout has not fired — the guard's Drop is what must remove the entry.
    request_task.abort();
    let _ = request_task.await; // reaps the handle once the task is dropped

    assert!(
        transport.pending.is_empty(),
        "a cancelled in-flight request must not strand its pending entry"
    );

    transport.close().await.expect("close");
}

#[test]
#[cfg(unix)]
fn backend_subprocess_receives_only_safe_and_explicit_environment() {
    let current_test_binary = std::env::current_exe().expect("resolve current test binary");
    let scenario_name = "transport::stdio::tests::stdio_child_environment_isolation_scenario";
    let output = std::process::Command::new(current_test_binary)
        .args(["--exact", scenario_name, "--nocapture"])
        .env(CHILD_SCENARIO_ENV, "1")
        .env(
            PARENT_SECRET_ENV,
            "dummy-parent-secret-must-not-reach-backend",
        )
        .output()
        .expect("run isolated child-environment scenario");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(scenario_name),
        "nested test filter did not execute the environment scenario; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        output.status.success(),
        "stdio child environment scenario failed; stdout={stdout:?} stderr={stderr:?}"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn stdio_child_environment_isolation_scenario() {
    if std::env::var_os(CHILD_SCENARIO_ENV).is_none() {
        return;
    }
    assert!(
        std::env::var_os(PARENT_SECRET_ENV).is_some(),
        "nested scenario must start with the parent-only sentinel present"
    );

    let workspace = tempfile::tempdir().expect("create stdio child workspace");
    let server = workspace.path().join("server.sh");
    std::fs::write(
        &server,
        r#"while IFS= read -r request; do
case "$request" in
    *'"method":"initialize"'*)
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'
        ;;
    *'"method":"env/check"'*)
        parent_secret_present=false
        explicit_backend_present=false
        path_present=false
        home_present=false
        tmpdir_present=false
        cwd_preserved=false
        [ "${MCP_GATEWAY_TEST_PARENT_SECRET+x}" = x ] && parent_secret_present=true
        [ "${MCP_GATEWAY_TEST_EXPLICIT_BACKEND:-}" = configured-value ] && explicit_backend_present=true
        [ -n "${PATH:-}" ] && path_present=true
        [ -n "${HOME:-}" ] && home_present=true
        [ -n "${TMPDIR:-}" ] && tmpdir_present=true
        [ -f server.sh ] && cwd_preserved=true
        printf '{"jsonrpc":"2.0","id":2,"result":{"parent_secret_present":%s,"explicit_backend_present":%s,"path_present":%s,"home_present":%s,"tmpdir_present":%s,"cwd_preserved":%s}}\n' \
            "$parent_secret_present" "$explicit_backend_present" "$path_present" \
            "$home_present" "$tmpdir_present" "$cwd_preserved"
        ;;
esac
done
"#,
    )
    .expect("write stdio child server");

    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::from([(
            EXPLICIT_BACKEND_ENV.to_string(),
            "configured-value".to_string(),
        )]),
        Some(workspace.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );

    transport.start().await.expect("start stdio child server");
    let response = transport
        .request("env/check", None)
        .await
        .expect("request child environment report");
    transport.close().await.expect("close stdio child server");

    let report = response.result.expect("environment report result");
    assert_eq!(report["parent_secret_present"], false);
    assert_eq!(report["explicit_backend_present"], true);
    assert_eq!(report["path_present"], true);
    assert_eq!(report["home_present"], true);
    assert_eq!(report["tmpdir_present"], true);
    assert_eq!(report["cwd_preserved"], true);
}

/// Is dropping every handle enough to reap the child, or does the reader
/// task's strong `Arc` keep the whole thing alive?
// Unix-only: drives a real child and reads the process table via `kill`.
#[cfg(unix)]
#[tokio::test]
async fn dropping_the_last_handle_reaps_the_child() {
    let workspace = tempfile::tempdir().expect("workspace");
    let server = workspace.path().join("server.sh");
    let pidfile = workspace.path().join("child.pid");
    std::fs::write(
        &server,
        format!(
            r#"echo $$ > "{}"
while IFS= read -r request; do
case "$request" in
    *'"method":"initialize"'*)
        printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2025-11-25"}}}}'
        ;;
esac
done
"#,
            pidfile.display()
        ),
    )
    .expect("write server");

    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(workspace.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );
    transport.start().await.expect("start");

    let pid = std::fs::read_to_string(&pidfile)
        .expect("child wrote its pid")
        .trim()
        .to_string();
    let alive = || {
        std::process::Command::new("kill")
            .args(["-0", &pid])
            .status()
            .is_ok_and(|s| s.success())
    };
    assert!(alive(), "precondition: child is running");

    drop(transport);

    for _ in 0..40 {
        if !alive() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid])
        .status();
    panic!("child survived dropping every handle to its transport: pid {pid} still alive after 2s");
}

// =========================================================================
// MIK-7272.SUB.2b — request-scoped notification capture over stdio.
//
// stdout is ONE multiplexed stream, so "arrived on that request's own
// stream" buys nothing here: the token match IS the correlation. Plan
// rows: docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md
// :58 (S-02, "over stdio and over HTTP") and :59 (S-03, per-request
// isolation on one connection).
// =========================================================================

fn progress_line(token: &str, progress: u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"progressToken":"{token}","progress":{progress}}}}}"#
    )
}

/// S-02 over stdio: a backend's progress notification reaches the caller
/// *while its call is still running*, not when the call ends.
///
/// The reader runs on a spawned task with none of the caller's
/// task-locals, which is what the production read loop is and what makes
/// the registered handle the only route to the sink. The caller is held
/// open on a oneshot so the receive below cannot be satisfied by a flush
/// on the way out -- the collect-then-emit shape would deadlock here
/// rather than pass, which is the point.
#[tokio::test]
async fn stdio_streams_a_progress_notification_while_its_call_is_still_running() {
    let transport = std::sync::Arc::new(make_transport("cat"));
    let reader = std::sync::Arc::clone(&transport);
    let (release, held) = tokio::sync::oneshot::channel::<()>();

    let (call, mut rx) = crate::transport::notification_sink::scope(async move {
        let _ = transport.register_progress_token("tok-a");
        tokio::spawn(async move {
            reader
                .handle_response(&progress_line("tok-a", 1))
                .expect("a notification must not fail the read loop");
        })
        .await
        .expect("the reader task must not panic");
        held.await.expect("the caller is released by the assertion");
    });
    let call = tokio::spawn(call);

    let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the notification must arrive before the call is released")
        .expect("the sink must not be closed while the call is in flight");
    assert_eq!(got.method, "notifications/progress");

    release.send(()).expect("the call is still in flight");
    call.await.expect("the call must not panic");
}

/// S-03 over stdio: two calls in flight on the one stdout. The notification
/// reaches the call that provoked it and no other.
///
/// Routing is now a property of which destination the token resolves to,
/// so the unregistered side is asserted by a sink that stays empty rather
/// than by an empty accumulation.
#[tokio::test]
async fn stdio_routes_a_progress_notification_to_only_the_call_that_supplied_the_token() {
    let transport = std::sync::Arc::new(make_transport("cat"));
    let reader = std::sync::Arc::clone(&transport);

    let (call, mut tok_b_rx) = crate::transport::notification_sink::scope(async {
        // tok-a's caller gets its own scope, so a misroute is visible. Both
        // registrations in one scope share a sender, and a frame delivered
        // to the wrong destination then arrives on the right receiver --
        // the isolation this row exists to prove would be unfalsifiable.
        // The sender is cloned into the map at registration, so it outlives
        // the scope that supplied it.
        let (tok_a_call, tok_a_rx) = crate::transport::notification_sink::scope(async {
            let _ = transport.register_progress_token("tok-a");
        });
        tok_a_call.await;

        let _ = transport.register_progress_token("tok-b");
        tokio::spawn(async move {
            reader
                .handle_response(&progress_line("tok-b", 7))
                .expect("handling a progress frame must succeed");
        })
        .await
        .expect("the reader task must not panic");
        tok_a_rx
    });
    let mut tok_a_rx = call.await;

    let first = tok_b_rx
        .recv()
        .await
        .expect("tok-b's caller must be reached");
    assert_eq!(
        first.params.as_ref().and_then(|p| p.get("progress")),
        Some(&serde_json::json!(7)),
        "the frame delivered must be the one tok-b provoked"
    );
    assert!(
        tok_b_rx.try_recv().is_err(),
        "tok-b's caller must see exactly the one frame it provoked"
    );
    assert!(
        tok_a_rx.try_recv().is_err(),
        "the other call in flight must see nothing at all"
    );
}

/// A second registration of a live token is refused, not honoured.
///
/// Overwriting would point the incumbent's token at the newcomer's
/// channel, so one call's progress would surface inside another call's
/// response stream -- a cross-caller leak, and worse than losing the
/// frame. ADR-014 §2 names it as one of the three defects that sank
/// registering the caller's own token.
#[tokio::test]
async fn stdio_refuses_to_reroute_a_progress_token_that_is_already_live() {
    let transport = std::sync::Arc::new(make_transport("cat"));
    let reader = std::sync::Arc::clone(&transport);

    // Two notification scopes, so the incumbent's sink and the newcomer's
    // are distinguishable. Registering twice inside one scope cannot tell
    // a refused insert from an overwriting one -- both would deliver to
    // the same receiver.
    let (incumbent_call, mut incumbent_rx) = crate::transport::notification_sink::scope(async {
        let _owner = ProgressRegistrationGuard::register(&transport, "tok-a");

        let (newcomer_call, mut newcomer_rx) = crate::transport::notification_sink::scope(async {
            let refused = ProgressRegistrationGuard::register(&transport, "tok-a");
            assert!(
                !refused.owns_registration,
                "a token already registered to a live call must be refused"
            );
        });
        newcomer_call.await;

        // The refused guard has dropped by here. Its cleanup must not
        // have retired the incumbent's route -- that would silence a
        // call that is still open, the exact damage the refusal exists
        // to prevent.
        assert!(
            newcomer_rx.try_recv().is_err(),
            "the refused call must have been routed nothing"
        );
        assert_eq!(
            transport.progress_destinations.len(),
            1,
            "the refused guard must leave the incumbent's entry in place"
        );

        // Delivery runs off-scope on purpose: the sender has to travel
        // in the map, not be read from the ambient task-local.
        tokio::spawn(async move {
            reader
                .handle_response(&progress_line("tok-a", 3))
                .expect("handling a progress frame must succeed");
        })
        .await
        .expect("the reader task must not panic");
    });
    incumbent_call.await;

    let got = incumbent_rx
        .recv()
        .await
        .expect("the incumbent must still be reached after the refusal");
    assert_eq!(
        got.params.as_ref().and_then(|p| p.get("progress")),
        Some(&serde_json::json!(3)),
        "the frame must carry the incumbent's progress value"
    );
}

/// The production request path reads the token from `params._meta`, which
/// is where a caller puts it. Pinned separately from the capture side
/// because the two shapes differ and a mismatch fails quietly.
#[test]
fn stdio_reads_the_callers_progress_token_from_request_meta() {
    let params = serde_json::json!({
        "name": "t",
        "_meta": { "progressToken": "tok-live" }
    });
    assert_eq!(
        request_progress_token(Some(&params)).as_deref(),
        Some("tok-live")
    );
    // A numeric token is the same token.
    let numeric = serde_json::json!({ "_meta": { "progressToken": 7 } });
    assert_eq!(request_progress_token(Some(&numeric)).as_deref(), Some("7"));
    // No token offered, none invented.
    assert!(request_progress_token(Some(&serde_json::json!({ "name": "t" }))).is_none());
    assert!(request_progress_token(None).is_none());
}

/// S-02 over stdio, end to end through the sink: register as the request
/// path does, deliver as the reader task does -- and the caller's sink
/// holds the notification with no flush of any kind in between.
#[tokio::test]
async fn stdio_delivers_a_notification_into_the_callers_sink() {
    let t = make_transport("cat");
    let params = serde_json::json!({ "_meta": { "progressToken": "tok-live" } });

    let ((), drained) = crate::transport::notification_sink::collect(async {
        let token = request_progress_token(Some(&params)).expect("token");
        let _ = t.register_progress_token(&token);
        t.handle_response(&progress_line("tok-live", 3)).unwrap();
    })
    .await;

    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].method, "notifications/progress");
}

/// Negative control for stdio: a notification whose token nobody registered
/// reaches no sink, even with a call in flight that has one.
#[tokio::test]
async fn stdio_never_attributes_a_stray_token_to_an_open_call() {
    let t = make_transport("cat");

    let ((), drained) = crate::transport::notification_sink::collect(async {
        let _ = t.register_progress_token("tok-mine");
        t.handle_response(&progress_line("tok-stray", 1)).unwrap();
    })
    .await;

    assert!(
        drained.is_empty(),
        "a stray token must not be attributed to whichever call is open"
    );
}

/// `register_progress_token` inserts and only the drain removes, so an
/// error return that skipped the drain would strand the entry for the
/// transport's lifetime. The request path drains on every exit.
#[tokio::test]
async fn stdio_request_retires_its_registration_even_when_the_write_fails() {
    let t = make_transport("cat"); // never connected: the write fails
    let params = serde_json::json!({ "_meta": { "progressToken": "tok-leak" } });

    let (result, drained) = crate::transport::notification_sink::collect(async {
        t.request("tools/call", Some(params)).await
    })
    .await;

    assert!(result.is_err(), "precondition: the write must fail");
    assert!(drained.is_empty());
    assert!(
        !t.progress_destinations.contains_key("tok-leak"),
        "the registration must not outlive the failed request"
    );
}

/// The fourth exit path, and the one a drain written after the await
/// cannot reach: the request future is DROPPED while still parked on its
/// response (an outer timeout, a task abort). Nothing after the await runs,
/// so retiring the registration has to happen in `Drop`.
///
/// The guard is tested directly rather than through a cancelled
/// `request()`: reaching a parked await needs a live child that completes
/// `start()`'s handshake, and `cat` cannot. What ties the guard to the
/// request path is that it is now the ONLY drain there —
/// `stdio_request_retires_its_registration_even_when_the_write_fails` goes
/// red the moment `request` stops holding one.
#[tokio::test]
async fn a_dropped_progress_registration_retires_its_destination() {
    // GIVEN a registration holding one captured notification.
    let t = make_transport("cat");
    let ((), drained) = crate::transport::notification_sink::collect(async {
        let guard = ProgressRegistrationGuard::register(&t, "tok-cancel");
        t.handle_response(&progress_line("tok-cancel", 1)).unwrap();

        // WHEN the guard drops without anyone draining explicitly, which is
        // what a dropped request future leaves behind.
        drop(guard);
    })
    .await;

    // THEN what was captured still reaches the sink, and the entry is gone.
    assert_eq!(
        drained.len(),
        1,
        "a retired registration must route nothing"
    );
    assert!(
        !t.progress_destinations.contains_key("tok-cancel"),
        "a cancelled request must not strand its registration for the transport's lifetime"
    );
}

/// Condition 2 of the correlation rule: an unregistered token is never
/// forwarded. A backend's token is passed through only on a match.
#[tokio::test]
async fn stdio_drops_a_progress_notification_no_caller_asked_for() {
    let t = make_transport("cat");

    let ((), drained) = crate::transport::notification_sink::collect(async {
        let _ = t.register_progress_token("tok-a");
        t.handle_response(&progress_line("tok-stray", 3)).unwrap();
    })
    .await;

    assert!(
        drained.is_empty(),
        "an unregistered token reaches no caller, registered neighbour or not"
    );
    assert!(
        !t.progress_destinations.contains_key("tok-stray"),
        "and it must not register itself on the way through"
    );
}

/// MIK-7570.ATTEST.1 (owner ruling, option A): the gateway relays no backend
/// `notifications/resources/updated` to any caller, even with a call open, so
/// a `resources/subscribe` attested under enforce grants no data flow for the
/// token's expiry to end. If this ever starts delivering, subscription expiry
/// needs a design (an attested subscription must stop at the token's `exp`).
#[tokio::test]
async fn stdio_relays_no_resource_update_so_attestation_expiry_has_nothing_to_end() {
    let t = make_transport("cat");
    let update = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": { "uri": "file:///a" }
    })
    .to_string();

    let ((), drained) = crate::transport::notification_sink::collect(async {
        let _ = t.register_progress_token("tok-open-call");
        t.handle_response(&update).unwrap();
    })
    .await;

    assert!(
        drained.is_empty(),
        "a resource update must reach no caller: {drained:?}"
    );
}
