// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 rows D2 and D6: a keyed no-principal task submit and a modern
//! `gateway_set_profile` on `/mcp` are refused at intake.

use super::*;

/// An anonymous keyed modern task submit of `server`/`t` (a `task` member,
/// the tasks extension declared), key `key`.
fn task_submit(server: &str, key: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
    "name": "gateway_invoke",
    "arguments": {"server": server, "tool": "t", "arguments": {"customer_id": "c"}},
    "task": {},
    "_meta": {
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
        "io.modelcontextprotocol/protocolVersion": crate::protocol::meta::MODERN_VERSIONS[0],
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    }}})
    .to_string()
}

/// D2 CONTROL (row re-pinned after the 2026-10-17 ruling B, which supersedes
/// D8(a)): on this auth-off gateway an anonymous keyed task submit keeps
/// pooled anonymous task ownership (MIK-7272.TASK.1.20, design 2026-09-08):
/// the intake leaves it to the task path, which answers with a task handle,
/// not -32003.
#[tokio::test]
async fn d2_auth_off_anonymous_keyed_task_keeps_the_pooled_owner() {
    let fx = fixture(idempotent()).await;
    let (status, answer) = post_to(&fx, "/mcp", &task_submit("alpha", KEY), &Caller::Modern).await;
    assert_eq!(status, StatusCode::OK, "d2: {answer}");
    assert!(
        answer.pointer("/result/taskId").is_some(),
        "d2: no task handle: {answer}"
    );
    assert_ne!(
        refusal(&answer),
        (Some(-32003), NO_PRINCIPAL),
        "d2: refused at intake: {answer}"
    );
}

/// D2b (ruling B's proof row): an auth-off anonymous keyed task submit
/// naming a counting backend (`alpha`), an unreachable one (`dead`, a socket
/// bound and never listening) and an absent one (`nope`) is answered with a
/// task handle each time, and `alpha` is sent no `tools/list` and no
/// `tools/call` by the time its handle is returned: the submit does no
/// backend work before task admission. Counters are read straight after the
/// answer, so the worker running after the handle can only add to them, and
/// zero holds only if nothing ran before it. `dead` and `nope` are not
/// counted transports: their cells show only that no backend failure decided
/// the answer.
#[tokio::test]
async fn d2b_auth_off_task_submit_does_no_backend_work_before_its_handle() {
    let fx = fixture(idempotent()).await;
    let _closed = register_dead(&fx);
    let mut cells = Vec::new();
    // The counting cell last: the earlier cells' workers name other backends,
    // so alpha's counters stay its own.
    for (case, server) in [
        ("unreachable", "dead"),
        ("absent", "nope"),
        ("counting", "alpha"),
    ] {
        let key = format!("d2b-{server}");
        let (status, answer) =
            post_to(&fx, "/mcp", &task_submit(server, &key), &Caller::Modern).await;
        let (lists, calls) = (
            fx.lists.load(Ordering::SeqCst),
            fx.calls.load(Ordering::SeqCst),
        );
        if status != StatusCode::OK || answer.pointer("/result/taskId").is_none() {
            cells.push(format!("d2b {case}: no task handle: {status} {answer}"));
        }
        if (lists, calls) != (0, 0) {
            cells.push(format!(
                "d2b {case}: alpha was sent tools/list {lists}, tools/call {calls} \
                 by the time the handle came back"
            ));
        }
    }
    assert!(cells.is_empty(), "d2b:\n{}", cells.join("\n"));
}

/// D6 (D8(c)): a keyed no-principal modern `gateway_set_profile` is refused
/// at intake (-32003). RED: today its own Protocol refusal answers first
/// (admission's `set_profile` check precedes the principal check).
#[tokio::test]
async fn d6_set_profile_answers_intake_first() {
    let fx = fixture(idempotent()).await;
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
    "name": "gateway_set_profile",
    "arguments": {"profile": "default"},
    "_meta": {
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY,
        "io.modelcontextprotocol/protocolVersion": crate::protocol::meta::MODERN_VERSIONS[0],
        "io.modelcontextprotocol/clientCapabilities": {},
    }}})
    .to_string();
    let (status, answer) = post_to(&fx, "/mcp", &body, &Caller::Modern).await;
    assert_eq!(
        refusal(&answer),
        (Some(-32003), NO_PRINCIPAL),
        "d6: {answer}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "d6: {answer}");
}
