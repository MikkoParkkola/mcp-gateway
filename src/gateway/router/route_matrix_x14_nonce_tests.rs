// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 1 drivers on `/mcp` (H1-mcp and its control): a signed task
//! call refused by execution admission, with and without an X14 grant consumed
//! first. The rows (`gateway::route_check_matrix_p3_tests`) own the assertions.

use std::sync::atomic::Ordering;

use serde_json::Value;

use super::direct_guards_fixture::Answer;
use super::route_matrix_driver_tests::{Destructive, TASK_SUBMIT_HEADERS, surfacing};

/// MIK-8353 H1-mcp's answers (see [`mcp_x14_consumed_then_refused`]).
pub(crate) struct McpConsumedThenRefused {
    pub(crate) challenge: Value,
    /// The redemption, refused by admission after X14 consumed its grant.
    pub(crate) refused: Value,
    /// The confirmation ledger's consumed count before the challenge, before
    /// and after the redemption, and after the re-send.
    pub(crate) ledger: [usize; 4],
    /// The same nonce re-sent once the backend is revived.
    pub(crate) resent: Value,
    pub(crate) calls_before_honest: usize,
    /// A fresh nonce's redemption, and the backend calls once its task ran.
    pub(crate) honest: Value,
    /// The honest task's terminal status, from `tasks/get`.
    pub(crate) honest_status: String,
    pub(crate) calls_after_honest: usize,
}

/// A signed, task-augmented `tools/call read` on `/mcp` under `nonce` and
/// idempotency key `key`, with `extra` merged into its params.
fn signed_task_read(nonce: &str, key: &str, extra: &Value) -> Value {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let mut params = serde_json::json!({
        "name": "read",
        "arguments": {},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "elicitation": {"form": {}},
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key,
            NONCE_META: nonce,
        }
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    params
}

/// The params accepting `challenge`'s X14 question.
fn accepting(challenge: &Value) -> Value {
    let state = challenge.pointer("/result/requestState").cloned();
    let issued = challenge
        .pointer("/result/inputRequests")
        .and_then(Value::as_object)
        .and_then(|requests| requests.keys().next().cloned())
        .unwrap_or_default();
    serde_json::json!({
        "requestState": state,
        "inputResponses": { issued: {"action": "accept"} },
    })
}

/// `params` as `k-std` on `/mcp`, with the modern header mirrors.
async fn send_task(fx: &super::direct_guards_fixture::Fx, params: Value) -> Value {
    super::direct_guards_fixture::send_with_headers(
        fx,
        "/mcp",
        "k-std",
        "tools/call",
        params,
        None,
        &TASK_SUBMIT_HEADERS,
    )
    .await
    .1
}

/// Loads `alpha`'s tool list into its cache, so X14 classifies `read` from
/// its listed annotation instead of confirming an unknown tool.
async fn warm(fx: &super::direct_guards_fixture::Fx) {
    let backend = fx.state.backends.get("alpha").expect("alpha is registered");
    backend.get_tools().await.expect("alpha lists its tools");
}

/// Polls `tasks/get` for `id` as `k-std` (up to 10 s) until the task is
/// terminal, and returns its status (empty if it never was).
async fn terminal_status(fx: &super::direct_guards_fixture::Fx, id: &str) -> String {
    const TERMINAL: [&str; 3] = ["completed", "failed", "cancelled"];
    // The modern era mirrors the task id in `Mcp-Name` (-32020 otherwise).
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tasks/get"),
        ("mcp-name", id),
    ];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let params = serde_json::json!({ "taskId": id, "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
        }});
        let (_, got) = super::direct_guards_fixture::send_with_headers(
            fx,
            "/mcp",
            "k-std",
            "tasks/get",
            params,
            None,
            &headers,
        )
        .await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if let Some(status) = status.filter(|status| TERMINAL.contains(status)) {
            return status.to_owned();
        }
        if tokio::time::Instant::now() >= deadline {
            return format!("never terminal; last tasks/get answer: {got}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Waits (up to 10 s) until the backend has seen more than `seen` calls.
async fn backend_calls_past(calls: &std::sync::atomic::AtomicUsize, seen: usize) -> usize {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while calls.load(Ordering::SeqCst) <= seen && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    calls.load(Ordering::SeqCst)
}

/// MIK-8353 H1-mcp on the hardened, signed `/mcp` fixture over a backend
/// listing `read` destructive. With `alpha` killed, X14 still asks and the
/// redemption consumes the grant (X14 runs before nonce admission on `/mcp`),
/// then admission's task branch refuses it. The backend is revived, the same
/// nonce re-sent, and a fresh nonce runs the honest round.
pub(crate) async fn mcp_x14_consumed_then_refused() -> McpConsumedThenRefused {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = std::sync::Arc::new(Destructive {
        calls: std::sync::Arc::clone(&calls),
    });
    let fx = super::direct_guards_fixture::with_transport(
        transport,
        Box::pin(super::direct_guards_fixture::fixture_hardened_signed_built(
            Answer::Ok,
            true,
            surfacing,
        )),
    )
    .await;
    warm(&fx).await;
    let meta = &fx.state.meta_mcp;
    let none = serde_json::json!({});
    meta.kill_switch().kill("alpha");
    let unasked = meta.continuation().ledger().len().await;
    let challenge = send_task(&fx, signed_task_read("h1-n1", "h1-a", &none)).await;
    let before = meta.continuation().ledger().len().await;
    let answer = accepting(&challenge);
    let refused = send_task(&fx, signed_task_read("h1-n1", "h1-a", &answer)).await;
    let after = meta.continuation().ledger().len().await;
    meta.kill_switch().revive("alpha");
    // X14 runs before nonce admission here, so the same nonce reaches the
    // nonce check only with a new grant: X14 asks again and consumes it.
    let again = send_task(&fx, signed_task_read("h1-n1", "h1-b", &none)).await;
    let resent = send_task(&fx, signed_task_read("h1-n1", "h1-b", &accepting(&again))).await;
    let after_resend = meta.continuation().ledger().len().await;
    let calls_before_honest = calls.load(Ordering::SeqCst);
    let asked = send_task(&fx, signed_task_read("h1-n2", "h1-c", &none)).await;
    let honest = send_task(&fx, signed_task_read("h1-n2", "h1-c", &accepting(&asked))).await;
    let calls_after_honest = backend_calls_past(&calls, calls_before_honest).await;
    let honest_status = match honest.pointer("/result/taskId").and_then(Value::as_str) {
        Some(id) => terminal_status(&fx, id).await,
        None => String::new(),
    };
    McpConsumedThenRefused {
        challenge,
        refused,
        ledger: [unasked, before, after, after_resend],
        resent,
        calls_before_honest,
        honest,
        honest_status,
        calls_after_honest,
    }
}

/// MIK-8353 H1-mcp-control: the same admission refusal with no grant consumed.
/// `read` is listed unannotated on this fixture and the catalogue is warmed,
/// so X14 classifies it harmless and has nothing to ask. With
/// `alpha` killed, the signed task call is refused by admission; the backend is
/// revived and the same nonce re-sent, then sent a third time. Returns (the
/// refusal, the re-send, the re-send's terminal task status, the third send,
/// the backend calls once the re-send's task had a chance to run).
pub(crate) async fn mcp_task_refused_without_grant() -> (Value, Value, String, Value, usize) {
    let fx =
        super::direct_guards_fixture::fixture_hardened_signed_built(Answer::Ok, true, surfacing)
            .await;
    warm(&fx).await;
    let meta = &fx.state.meta_mcp;
    let none = serde_json::json!({});
    meta.kill_switch().kill("alpha");
    let refused = send_task(&fx, signed_task_read("h1c-n1", "h1c-a", &none)).await;
    meta.kill_switch().revive("alpha");
    let resent = send_task(&fx, signed_task_read("h1c-n1", "h1c-b", &none)).await;
    let calls = backend_calls_past(&fx.calls, 0).await;
    let status = match resent.pointer("/result/taskId").and_then(Value::as_str) {
        Some(id) => terminal_status(&fx, id).await,
        None => String::new(),
    };
    let third = send_task(&fx, signed_task_read("h1c-n1", "h1c-c", &none)).await;
    (refused, resent, status, third, calls)
}
