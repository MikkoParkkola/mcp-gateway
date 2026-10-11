// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 B (lead ruling (i)): a task resume is an admission point. Its
//! stored call is re-judged against the current config; a call no longer
//! exempt is sanitized before it is sent again.

use super::*;

const MODERN: [(&str, &str); 1] = [("mcp-protocol-version", "2026-07-28")];

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "elicitation": {"form": {}},
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

async fn send(fx: &Fx, method: &str, name: &str, params: Value) -> Value {
    let headers = [MODERN[0], ("mcp-method", method), ("mcp-name", name)];
    let send = super::super::direct_guards_fixture::send_with_headers;
    send(fx, "/mcp", "k-std", method, params, None, &headers)
        .await
        .1
}

/// Poll `tasks/get` until the task's status is none of `passing`.
async fn settled(fx: &Fx, id: &str, passing: &[&str]) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let get = json!({"taskId": id, "_meta": modern_meta()});
            let body = Box::pin(send(fx, "tasks/get", id, get)).await;
            let status = body.pointer("/result/status").and_then(Value::as_str);
            if !status.is_some_and(|status| passing.contains(&status)) {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task never settled")
}

/// R3: a task over the passthrough backend parks on the backend's question,
/// carrying a NUL its submit was exempt to send. The backend is reloaded as
/// non-passthrough, then the client answers: the resume re-judges, the call
/// is no longer exempt, its NUL is refused, and the new instance receives
/// nothing (the one send is the asking round's, to the judged instance).
#[tokio::test]
async fn r3_a_resume_re_judges_and_sends_nothing_unsanitized() {
    let fx = Box::pin(sanitizing(
        true,
        fixture_built(Answer::AskOnce, |meta| meta),
    ))
    .await;
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("r3-k");
    let submit = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha-pt", "tool": "read", "arguments": {"cmd": NUL}},
        "task": {},
        "_meta": meta,
    });
    let created = Box::pin(send(&fx, "tools/call", "gateway_invoke", submit)).await;
    let id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("r3: the submit was refused: {created}"))
        .to_owned();
    let parked = Box::pin(settled(&fx, &id, &["working"])).await;
    assert_eq!(
        parked.pointer("/result/status"),
        Some(&json!("input_required")),
        "r3 premise: the task did not park: {parked}"
    );
    assert_eq!(calls(&fx), 1, "r3 premise: the asking round");
    super::super::direct_guards_fixture::reload_for_test(&fx, "alpha-pt", false)();
    let update = json!({
        "taskId": id,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "work"}}},
        "_meta": modern_meta(),
    });
    let _ = Box::pin(send(&fx, "tasks/update", &id, update)).await;
    let done = Box::pin(settled(&fx, &id, &["working", "input_required"])).await;
    assert_ne!(
        done.pointer("/result/status"),
        Some(&json!("completed")),
        "r3: the resumed call ran: {done}"
    );
    assert_eq!(
        calls(&fx),
        1,
        "r3: the reloaded instance received a send: {done}"
    );
}
