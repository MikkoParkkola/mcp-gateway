// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Route-check-parity P3 (MIK-8149, MIK-8160, MIK-8326): stdio gets the route
//! checks `/mcp` runs, and a surfaced tool withheld from the caller answers as
//! a name that matches no tool. Each row asserts the fixed behaviour and was
//! run red on the release line before the fix.

use super::Route;
use super::rows::{BLOCKED, NUL_REFUSED, X14_PROMPT, audit_rows, blocked_call, message};
use crate::gateway::router::route_matrix_driver_tests::{self as router, Surfacing};
use crate::gateway::server::route_matrix_driver_tests as stdio;

/// MIK-8149.REQFW.1: on stdio a blocked argument is refused by the route-stage
/// request firewall: a blocking `event=request` audit row, the code and
/// message `/mcp` answers for the same argument, and no backend call.
#[tokio::test]
async fn stdio_route_firewall_refuses_as_mcp_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stdio_audit = dir.path().join("stdio.jsonl");
    let mcp_audit = dir.path().join("mcp.jsonl");
    let (stdio_body, stdio_calls) = blocked_call(Route::Stdio, &stdio_audit).await;
    let (mcp_body, _) = blocked_call(Route::Invoke, &mcp_audit).await;
    let requests = audit_rows(&stdio_audit, "request");
    assert!(
        requests.iter().any(|row| row["action"] == "block"),
        "stdio: no blocking request row for {BLOCKED:?}: {requests:?}; {stdio_body}"
    );
    assert_eq!(
        stdio_body["error"]["code"], mcp_body["error"]["code"],
        "stdio answered {stdio_body}, /mcp answered {mcp_body}"
    );
    assert_eq!(
        message(&stdio_body),
        message(&mcp_body),
        "stdio answered {stdio_body}, /mcp answered {mcp_body}"
    );
    assert_eq!(stdio_calls, 0, "stdio reached its backend: {stdio_body}");
}

/// MIK-8149.REQFW.2: with `security.sanitize_input` on, stdio refuses a NUL
/// byte with the sanitizer's own -32600 refusal, before any backend call.
#[tokio::test]
async fn stdio_sanitize_refuses_a_nul_when_on() {
    let (body, calls) = stdio::stdio_sanitizing(true).await;
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert!(
        message(&body).contains(NUL_REFUSED),
        "not the sanitizer's refusal: {body}"
    );
    assert_eq!(calls, 0, "the NUL reached the backend: {body}");
}

/// MIK-8160.X14.1: a modern task call of a destructive surfaced tool over
/// stdio gets X14's challenge, bound to the stdio principal: no task is made
/// and the backend is not called.
#[tokio::test]
async fn stdio_destructive_task_gets_the_x14_challenge() {
    let (body, calls) = Box::pin(stdio::stdio_task_surfaced()).await;
    assert!(
        body.to_string().contains(X14_PROMPT),
        "no X14 challenge on stdio: {body}"
    );
    assert!(
        body.pointer("/result/taskId").is_none(),
        "a task was made before X14 decided: {body}"
    );
    assert_eq!(calls, 0, "dispatched before X14: {body}");
}

/// [`router::task_submit_read_as`] on a current-thread runtime, with the
/// warnings it logged on this thread.
fn submit_logged(
    key: &str,
    surfacing: Surfacing,
) -> ((axum::http::StatusCode, router::Sent), String) {
    crate::test_log_capture::capture_warnings(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(router::task_submit_read_as(key, surfacing))
    })
}

/// MIK-8326.X14.1 (WH.1): on `/mcp`, a modern task call of a destructive
/// surfaced tool withheld from the caller (`k-deny` is denied `read`) answers
/// exactly as the same name does where it matches no tool: the same error and
/// HTTP status. The cause is the operator-only authorization-refusal warning
/// naming `read`, which the caller never sees. No X14 challenge, no task, no
/// backend call.
#[test]
fn mcp_withheld_surfaced_task_answers_as_a_missing_name() {
    let ((withheld_status, withheld), warnings) = submit_logged("k-deny", Surfacing::On);
    let ((missing_status, missing), _) = submit_logged("k-std", Surfacing::Off);
    assert_eq!(
        missing.body["error"]["code"], -32601,
        "premise: an unsurfaced `read` matches no tool: {}",
        missing.body
    );
    assert_eq!(
        withheld.body["error"], missing.body["error"],
        "withheld {} vs missing {}",
        withheld.body, missing.body
    );
    assert_eq!(withheld_status, missing_status, "HTTP status differs");
    let refusal = warnings
        .lines()
        .find(|line| line.contains("Tool invocation refused by authorization"))
        .unwrap_or_else(|| panic!("no operator refusal warning:\n{warnings}"));
    assert!(refusal.contains("read"), "{refusal}");
    assert!(
        !withheld.body.to_string().contains(X14_PROMPT),
        "X14 challenged a withheld tool: {}",
        withheld.body
    );
    assert_eq!(withheld.backend_calls, 0, "{}", withheld.body);
}
