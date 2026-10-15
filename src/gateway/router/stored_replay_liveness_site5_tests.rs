// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 liveness rows, part 2: site 5 (repeated task calls),
//! E8's hidden-name twins, the direct-route guard and the fixture checks.

use super::*;

/// P8406 (gap pin, MIK-8406 PLANREPLAY.4): a plan-task repeat skips site 5,
/// so a completed keyed `gateway_execute` task repeated on a live account is
/// served its stored task with no account proof: it resolves only for the
/// route stage's per-step checks (2, measured), never at site 5. E9 still
/// runs before the plan carve-out, so a Lacked and Unavailable plan repeat
/// answers retryable; only the proof is missing. This row turns red when
/// MIK-8406 adds the proof, and the read matrix's gap row moves with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8406_a_plan_task_repeat_is_served_without_an_account_proof() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let made = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("p8406", true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    assert_eq!(
        done.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: {done}"
    );
    let resolved = fx.gateway.resolves();
    let again = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("p8406", true),
    )
    .await;
    eprintln!(
        "P8406 repeat ({} resolutions): {again}",
        fx.gateway.resolves() - resolved
    );
    assert_eq!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "P8406: the plan repeat is not the stored task: {again}"
    );
    // The route stage's per-step checks resolve twice; a site-5 proof would
    // add one per account.
    assert_eq!(
        fx.gateway.resolves() - resolved,
        2,
        "P8406: the plan repeat's resolutions moved (MIK-8406 closed?): {again}"
    );
}

/// T7 (twin guard): a revoked vault plan-task repeat answers as a missing
/// name does. A task-augmented keyed `gateway_execute` completes; the grant
/// is revoked; the same task call repeated answers -32601 for the step tool,
/// equal, after normalising only each caller's own input (`id`, the step
/// tool it named), to the same keyed task-augmented call naming a step tool
/// that exists on no backend. Sends +0, and no stored output. M36 (a hint
/// beyond the echoed name) must fail this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t7_revoked_vault_plan_repeat_answers_as_a_missing_name() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let made = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("t7", true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    assert_eq!(
        done.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: {done}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("t7", true),
    )
    .await;
    eprintln!("T7 repeat: {again}");
    assert_eq!(
        again.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601),
        "T7: the revoked plan repeat is not -32601: {again}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "T7: stored output served: {again}"
    );
    assert!(
        again.pointer("/result/taskId").is_none(),
        "T7: a task was answered back: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "T7: a step was re-run: {again}"
    );
    // The missing twin: the same keyed task-augmented call naming a step
    // tool that exists on no backend. Fresh key, same shape.
    let missing_tool = format!("{BACKEND}:no_such_tool_8392");
    let mut missing_params = json!({
        "name": "gateway_execute",
        "arguments": {"chain": [{"tool": missing_tool, "arguments": {"folder": "inbox"}}]},
        "_meta": meta(Some("t7-missing"), true),
    });
    missing_params["task"] = json!({});
    let fx_missing = fixture(false).await;
    let missing = send(&fx_missing, "tools/call", "gateway_execute", missing_params).await;
    eprintln!("T7 missing: {missing}");
    // Equal once only each caller's own input (the `id` and the step tool it
    // named) is normalised; any other detail still differs (M36).
    assert_eq!(
        caller_input_normalised(&again, TOOL),
        caller_input_normalised(&missing, "no_such_tool_8392"),
        "T7: the revoked answer differs from the missing-name answer: {again} vs {missing}"
    );
    assert!(
        fx_missing.gateway.tool_calls().is_empty(),
        "T7: the missing-name call reached the backend: {missing}"
    );
    // No never-granted twin here: an operator who never held the account has
    // no stored task under this key, so the same call is a FRESH task call
    // (answered "working", refused later inside the task), not a repeat. The
    // two are different operations, not a leak; R4 carries the strict twin.
}

/// A keyed task-augmented `gateway_invoke` that completed, for T8/T9.
async fn completed_task(fx: &Fx, key: &str) -> String {
    answer_marker(fx);
    let made = send(
        fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some(key), true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(fx, &id).await;
    assert_eq!(
        done.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: {done}"
    );
    id
}

/// T8 (E9): with custody failing (the account `Unavailable`), a repeated task
/// call answers exactly as the live call does (retryable), not as a missing
/// name: byte-identical after normalising only `id` to the same call made
/// live with a fresh key. M37 (the catalogue refusal kept first) must fail
/// this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t8_unavailable_repeat_answers_as_the_live_call() {
    let fx = fixture_with(false, true).await;
    completed_task(&fx, "t8").await;
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.fail_custody_for_test(true);
    let refusals = idp_refusals(&fx);
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("t8"), true),
    )
    .await;
    let repeat_refusals = idp_refusals(&fx) - refusals;
    let refusals = idp_refusals(&fx);
    let live = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("t8-live"), false),
    )
    .await;
    let live_refusals = idp_refusals(&fx) - refusals;
    assert_eq!(
        live_refusals, 1,
        "premise: the live call writes one idp_refuse"
    );
    assert_eq!(
        repeat_refusals, 1,
        "T8: the repeat writes exactly one idp_refuse"
    );
    eprintln!("T8 repeat: {again}");
    eprintln!("T8 live: {live}");
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused: {live}"
    );
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(
        again_id, live_id,
        "T8: the repeat differs from the live call: {again} vs {live}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "T8: stored output served: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "T8: the call reached the backend: {again}"
    );
}

/// T9 (E9 guard): the same outage, but the tool is ALSO withheld for a reason
/// that is not its account (its description is blocked). E9 must not fire:
/// the repeat answers exactly as the live call to that blocked tool does
/// (byte-identical after normalising only `id`), never the outage's retryable
/// answer. M37's leak variant (E9 applied to any withholding) must fail this
/// row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t9_unavailable_never_unhides_a_tool_hidden_for_another_reason() {
    let fx = fixture(false).await;
    completed_task(&fx, "t9").await;
    let sent = fx.gateway.tool_calls().len();
    fx.gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .block_tool_for_test(TOOL);
    fx.gateway.fail_custody_for_test(true);
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("t9"), true),
    )
    .await;
    let live = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("t9-live"), false),
    )
    .await;
    eprintln!("T9 repeat: {again}");
    eprintln!("T9 live: {live}");
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(
        again_id, live_id,
        "T9: the blocked tool's repeat differs from its live call: {again} vs {live}"
    );
    assert_ne!(
        again.pointer("/error/code").and_then(Value::as_i64),
        Some(-32603),
        "T9: the outage answer leaked for a tool withheld for another reason: {again}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "T9: stored output served: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "T9: the call reached the backend: {again}"
    );
}

/// S1 (guard): a LIVE vault account's keyed replay is deferred at admission
/// and lifted after the dispatch's resolution proves the account live (E10:
/// every per-caller replay defers, the former admission shortcut once guarded
/// by M14 is deleted): the retained result is served with nothing sent and no
/// more custody resolutions than the base path (2), as the lift reuses the
/// route stage's resolution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_live_account_replay_is_served_without_a_second_resolution() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let first = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("s1"), false),
    )
    .await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let (sent, resolved) = (fx.gateway.tool_calls().len(), fx.gateway.resolves());
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("s1"), false),
    )
    .await;
    assert!(
        again.to_string().contains(MARKER),
        "S1: the live replay was not served: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "S1: the replay was re-sent: {again}"
    );
    // Measured on the release base without STORED.2 (573338311): the live
    // replay resolves custody twice (the route-stage verdict and the
    // dispatch's own read). STORED.2 may not add a third.
    assert!(
        fx.gateway.resolves() <= resolved + 2,
        "S1: the live replay resolved custody {} times (base: 2)",
        fx.gateway.resolves() - resolved
    );
}

/// S4 (mutant M16): a keyed single-call replay during a custody outage
/// (the account `Unavailable`) defers, its live resolution fails, and the
/// answer equals the same call made live (normalising only `id`); the
/// retained result is never served. Serving `Unavailable` at admission as if
/// it were live (M16) must fail this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_outage_replay_answers_as_the_live_call() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let first = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("s4"), false),
    )
    .await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.fail_custody_for_test(true);
    let refusals = idp_refusals(&fx);
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("s4"), false),
    )
    .await;
    assert_eq!(
        idp_refusals(&fx) - refusals,
        1,
        "S4: the deferred replay writes exactly one idp_refuse"
    );
    let live = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("s4-live"), false),
    )
    .await;
    eprintln!("S4 repeat: {again}");
    eprintln!("S4 live: {live}");
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused: {live}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "S4: the retained result was served: {again}"
    );
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(
        again_id, live_id,
        "S4: the replay differs from the live call: {again} vs {live}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "S4: the call reached the backend: {again}"
    );
}

/// L3 (mutant M3): two deferred replays in one memo scope, under different
/// keys. Each take consumes only its own entry, once; a key never recorded
/// takes nothing.
#[tokio::test]
async fn l3_a_deferred_replay_is_taken_only_by_its_own_key_once() {
    use crate::gateway::meta_mcp::visible::{
        DeferredReplay, deferred_replay_key, record_deferred_replay, take_deferred_replay,
        with_visibility_memo,
    };
    let retry = |key: &str| crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some(key.to_string()),
        malformed: Vec::new(),
        attestation: None,
    };
    let entry = |text: &str| DeferredReplay {
        response: crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"content": [{"type": "text", "text": text}]}),
        ),
        audit: None,
        tool_name: "gateway_invoke".to_string(),
        arguments: json!({}),
    };
    with_visibility_memo(async {
        let a = deferred_replay_key(BACKEND, TOOL, &retry("l3-a")).expect("keyed");
        let b = deferred_replay_key(BACKEND, TOOL, &retry("l3-b")).expect("keyed");
        let never = deferred_replay_key(BACKEND, TOOL, &retry("l3-never")).expect("keyed");
        record_deferred_replay(a.clone(), entry("A"));
        record_deferred_replay(b.clone(), entry("B"));
        assert!(
            take_deferred_replay(&never).is_none(),
            "L3: an unrecorded key took an entry"
        );
        let took_a = take_deferred_replay(&a).expect("L3: key a takes its entry");
        assert!(
            took_a
                .response
                .to_value_lossy()
                .to_string()
                .contains("\"A\""),
            "L3: key a took another entry"
        );
        assert!(
            take_deferred_replay(&a).is_none(),
            "L3: key a took its entry twice"
        );
        let took_b = take_deferred_replay(&b).expect("L3: key b keeps its entry");
        assert!(
            took_b
                .response
                .to_value_lossy()
                .to_string()
                .contains("\"B\""),
            "L3: key b took another entry"
        );
    })
    .await;
}

/// T4 (guard; mutant M20': an extra live resolution at site 5): a LIVE vault account's repeated task call is
/// answered with the stored task, nothing sent, and no more custody
/// resolutions than the base path (`T4_BASE_RESOLVES`, measured on the
/// release base without STORED.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t4_live_task_repeat_is_served_at_the_base_custody_cost() {
    let fx = fixture(false).await;
    let id = completed_task(&fx, "t4").await;
    let (sent, resolved) = (fx.gateway.tool_calls().len(), fx.gateway.resolves());
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("t4"), true),
    )
    .await;
    let cost = fx.gateway.resolves() - resolved;
    eprintln!("T4 custody resolutions for the live task repeat: {cost}");
    assert_eq!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "T4: the live task repeat was not answered with the stored task: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "T4: the repeat was re-sent: {again}"
    );
    assert!(
        cost <= T4_BASE_RESOLVES,
        "T4: the live task repeat resolved custody {cost} times (base: {T4_BASE_RESOLVES})"
    );
}

/// Custody resolutions a live task repeat costs on the release base.
/// Measured on 573338311 (release base), and the same with STORED.2 (E10b).
const T4_BASE_RESOLVES: usize = 2;

/// E8a (no-leak twin; mutant M40): a revoked caller's keyed repeat by the
/// surfaced name with the key that HAS a stored result answers byte-for-byte
/// (normalising only `id`), and with the same HTTP status, as the same call
/// with a fresh key that has none: no key state is consulted before the live
/// answer. Consulting stored-key state first (M40) reveals the key (a 409).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e8a_a_stored_key_and_a_fresh_key_answer_alike_for_a_hidden_name() {
    let fx = fixture(true).await;
    answer_marker(&fx);
    let call = |key: &str| json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": meta(Some(key), false)});
    let first = send(&fx, "tools/call", TOOL, call("e8a")).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    fx.gateway.revoke_operator_grant().await;
    let (stored_status, stored) = send_full(&fx, TOOL, call("e8a")).await;
    let (fresh_status, fresh) = send_full(&fx, TOOL, call("e8a-fresh")).await;
    eprintln!("E8a stored key: {stored}");
    eprintln!("E8a fresh key: {fresh}");
    let (mut stored_id, mut fresh_id) = (stored.clone(), fresh.clone());
    stored_id["id"] = Value::Null;
    fresh_id["id"] = Value::Null;
    assert_eq!(
        stored_id, fresh_id,
        "E8a: the stored key answers differently: {stored} vs {fresh}"
    );
    assert_eq!(
        stored_status, fresh_status,
        "E8a: the stored key's HTTP status differs"
    );
}

/// N1 (no execution; mutant M39): a live surfaced tool runs once under a key,
/// then its description is blocked, so the name has no target for the
/// caller. The keyed repeat is admitted unprotected (E8) and the live path
/// refuses it: nothing reaches the backend and no stored output is served.
/// Removing the live withheld-tool refusal (M39) lets it through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n1_a_hidden_name_with_a_stored_key_never_executes() {
    let fx = fixture(true).await;
    answer_marker(&fx);
    let call = || json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": meta(Some("n1"), false)});
    let first = send(&fx, "tools/call", TOOL, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .block_tool_for_test(TOOL);
    let again = send(&fx, "tools/call", TOOL, call()).await;
    eprintln!("N1 answer: {again}");
    assert_refused_unsent(&fx, "N1", &again, sent);
}

/// G1 (guard; mutant M31): on the direct route a revoked grant's keyed replay
/// is refused at stage 5 (the identity mint), before 7a/7b can serve a stored
/// answer; nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g1_direct_route_refuses_a_revoked_keyed_replay_at_stage_five() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let uri = format!("/mcp/{BACKEND}");
    let call = || json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": meta(Some("g1"), false)});
    let first = send_to(&fx, &uri, "tools/call", TOOL, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send_to(&fx, &uri, "tools/call", TOOL, call()).await;
    eprintln!("G1 answer: {again}");
    assert_refused_unsent(&fx, "G1", &again, sent);
}

/// U1/U2: `alpha` binds no per-user account (not isolation-guarded), so no
/// liveness proof applies and stored answers are served as today.
mod unguarded {
    use std::sync::atomic::Ordering;

    use serde_json::{Value, json};

    use super::{MARKER, meta};
    use crate::gateway::router::direct_guards_fixture::{Answer, Fx, fixture, send_with_headers};

    async fn call(fx: &Fx, params: Value) -> Value {
        let name = params["name"].as_str().unwrap_or_default().to_owned();
        let headers = [
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", name.as_str()),
        ];
        send_with_headers(fx, "/mcp", "k-std", "tools/call", params, None, &headers)
            .await
            .1
    }

    /// Poll task `id` until it is terminal, within the tree's 10 s bound.
    async fn settled(fx: &Fx, id: &str) {
        let headers = [
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tasks/get"),
            ("mcp-name", id),
        ];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let params = json!({"taskId": id, "_meta": meta(None, true)});
            let got = send_with_headers(fx, "/mcp", "k-std", "tasks/get", params, None, &headers)
                .await
                .1;
            let status = got.pointer("/result/status").and_then(Value::as_str);
            if matches!(status, Some("completed" | "failed" | "cancelled")) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "premise: the task settled: {got}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    fn invoke(key: &str, tasks: bool) -> Value {
        let mut params = json!({"name": "gateway_invoke",
            "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
            "_meta": meta(Some(key), tasks)});
        if tasks {
            params["task"] = json!({});
        }
        params
    }

    /// U1 (guard; mutant M32): a keyed replay on an unguarded backend is
    /// served the retained result; nothing is sent again.
    #[tokio::test]
    async fn u1_unguarded_keyed_replay_is_served() {
        let fx = fixture(Answer::Text(MARKER), |_| {}).await;
        let first = call(&fx, invoke("u1", false)).await;
        assert!(
            first.to_string().contains(MARKER),
            "premise: dispatched: {first}"
        );
        let sent = fx.calls.load(Ordering::SeqCst);
        let again = call(&fx, invoke("u1", false)).await;
        assert!(
            again.to_string().contains(MARKER),
            "U1: not served: {again}"
        );
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            sent,
            "U1: re-sent: {again}"
        );
    }

    /// U2 (guard; mutant M33): a repeated task call on an unguarded backend
    /// is answered with the stored task; nothing is sent again.
    #[tokio::test]
    async fn u2_unguarded_repeated_task_call_is_answered_with_the_stored_task() {
        let fx = fixture(Answer::Text(MARKER), |_| {}).await;
        let made = call(&fx, invoke("u2", true)).await;
        let id = made
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
            .to_owned();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while fx.calls.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        settled(&fx, &id).await;
        let sent = fx.calls.load(Ordering::SeqCst);
        assert_eq!(sent, 1, "premise: the task dispatched once");
        let again = call(&fx, invoke("u2", true)).await;
        assert_eq!(
            again.pointer("/result/taskId").and_then(Value::as_str),
            Some(id.as_str()),
            "U2: not answered with the stored task: {again}"
        );
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            sent,
            "U2: re-sent: {again}"
        );
    }
}

/// The fixture's scripted backend failure (MIK-8406 P8i): with the account
/// live, the next call reaches the backend and fails; the one after succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_fail_next_fails_one_call_with_the_account_live() {
    let fx = fixture(false).await;
    fx.gateway.fail_next(503);
    let failed = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(None, false),
    )
    .await;
    assert!(
        failed.get("error").is_some() || failed.pointer("/result/isError") == Some(&json!(true)),
        "the scripted failure did not surface: {failed}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        1,
        "the failing call reached the backend: {failed}"
    );
    answer_marker(&fx);
    let ok = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(None, false),
    )
    .await;
    assert!(
        ok.to_string().contains(MARKER),
        "the next call succeeds: {ok}"
    );
}

/// R6u (E7 unit): a per-caller propagation backend without `account:`
/// classifies as needing proof at site 1, so its Replay defers. M34 (that
/// backend exempted like an unguarded one) makes the deferral false.
#[test]
fn r6u_per_caller_propagation_without_account_defers() {
    let mut gateway = DirectAccountGateway::new(sole_operator(), &Binding::Propagation);
    let meta = gateway.take_meta();
    // No `account:`, so no per-user account to judge ...
    assert!(
        meta.target_account(BACKEND, TOOL).is_none(),
        "R6u: a propagation backend without `account:` names an account"
    );
    // ... but it mints per caller, so site 1 defers to a live mint (E7).
    assert!(
        meta.mints_per_caller(BACKEND, TOOL),
        "R6u: a per-caller propagation backend mints nothing per caller"
    );
    assert!(
        meta.stored_replay_defers(BACKEND, TOOL),
        "R6u: a per-caller propagation backend's Replay does not defer"
    );
    // Contrast: a backend that mints nothing per caller is exempt.
    let empty =
        crate::gateway::meta_mcp::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    assert!(
        !empty.stored_replay_defers("no-backend", "no-tool"),
        "R6u: a backend that mints nothing per caller defers"
    );
}
