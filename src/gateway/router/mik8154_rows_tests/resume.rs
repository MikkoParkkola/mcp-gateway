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
    // Failed, by the re-admission's refusal: not completed, and not parked
    // again or cancelled by some other path.
    assert_eq!(
        done.pointer("/result/status"),
        Some(&json!("failed")),
        "r3: the resume was not refused: {done}"
    );
    assert!(
        done.to_string().contains("null bytes"),
        "r3: refused, but not by the sanitizer: {done}"
    );
    assert_eq!(
        calls(&fx),
        1,
        "r3: the reloaded instance received a send: {done}"
    );
}

/// R4 CONTROL (critical coverage of `LiveHost::readmit`'s exempt branch): the
/// same parked passthrough task, with no reload: the resume re-judges, the
/// call is still exempt, and the backend receives the NUL as submitted.
#[tokio::test]
async fn r4_a_resume_still_exempt_forwards_as_submitted() {
    let fx = Box::pin(sanitizing(
        true,
        fixture_built(Answer::AskOnce, |meta| meta),
    ))
    .await;
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("r4-k");
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
        .unwrap_or_else(|| panic!("r4: the submit was refused: {created}"))
        .to_owned();
    let parked = Box::pin(settled(&fx, &id, &["working"])).await;
    assert_eq!(
        parked.pointer("/result/status"),
        Some(&json!("input_required")),
        "r4 premise: the task did not park: {parked}"
    );
    let update = json!({
        "taskId": id,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "work"}}},
        "_meta": modern_meta(),
    });
    let _ = Box::pin(send(&fx, "tasks/update", &id, update)).await;
    let done = Box::pin(settled(&fx, &id, &["working", "input_required"])).await;
    assert_eq!(
        done.pointer("/result/status"),
        Some(&json!("completed")),
        "r4: the exempt resume did not complete: {done}"
    );
    assert_eq!(calls(&fx), 2, "r4: the resumed round was not sent: {done}");
    assert!(forwarded_nul(&fx), "r4: the resumed round lost the NUL");
}

/// R5 (MIK-8378, lead ruling (a)): a resume applies intake's full rule. A
/// stored `gateway_invoke` call whose own argument key is dirty is refused by
/// key validation on re-admission, never stripped into `server`. The row
/// models a task stored by a process with `sanitize_input` off and resumed by
/// one restarted with it on: in one process the call is unreachable, because
/// intake validates whenever `sanitize_input` is on, exempt calls included
/// (`dispatch_intake.rs:282`), and `sanitize_input` is fixed for the process.
#[tokio::test]
async fn r5_a_resume_refuses_a_dirty_meta_key_it_stored() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let host = crate::gateway::task_service::host::LiveHost::Http(std::sync::Arc::clone(&fx.state));
    let call = crate::gateway::task_service::TaskCall {
        tool: "gateway_invoke".to_owned(),
        arguments: json!({"ser\u{7}ver": "alpha", "tool": "read", "arguments": {}}),
    };
    let caller = crate::gateway::meta_mcp::anonymous_caller();
    let refused = match host.readmit(&call, &caller, None).await {
        Ok((arguments, _)) => panic!("r5: re-admitted, stripped to {arguments}"),
        Err(refused) => serde_json::to_value(&*refused).expect("a response serializes"),
    };
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32600)),
        "r5: {refused}"
    );
    assert!(
        refused.to_string().contains("control characters"),
        "r5: not the key validation's refusal: {refused}"
    );
    assert_eq!(calls(&fx), 0, "r5: dispatched");
}

/// R6 (code seat, MIK-8378): re-admission validates before it judges the
/// exemption, as intake does (`dispatch_intake.rs:282` runs before the
/// exemption at :381). A stored call that is still exempt (passthrough
/// `alpha-pt`) with a dirty own key is refused, not sent as stored. Modelled
/// as R5 is: stored by a process with `sanitize_input` off.
#[tokio::test]
async fn r6_a_resume_still_exempt_refuses_a_dirty_meta_key() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let host = crate::gateway::task_service::host::LiveHost::Http(std::sync::Arc::clone(&fx.state));
    let call = crate::gateway::task_service::TaskCall {
        tool: "gateway_invoke".to_owned(),
        arguments: json!({"server": "alpha-pt", "tool": "read", "arguments": {},
            "_me\u{7}ta": {}}),
    };
    let caller = crate::gateway::meta_mcp::anonymous_caller();
    let refused = match host.readmit(&call, &caller, None).await {
        Ok((arguments, _)) => panic!("r6: re-admitted as {arguments}"),
        Err(refused) => serde_json::to_value(&*refused).expect("a response serializes"),
    };
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32600)),
        "r6: {refused}"
    );
    assert!(
        refused.to_string().contains("control characters"),
        "r6: not the key validation's refusal: {refused}"
    );
    assert_eq!(calls(&fx), 0, "r6: dispatched");
}
