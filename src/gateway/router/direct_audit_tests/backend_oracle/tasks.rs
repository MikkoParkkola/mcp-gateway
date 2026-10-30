// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 W1 and R2b: task calls (`task` param) on `/mcp` as the scoped key.

use super::*;

/// Modern `_meta` declaring the tasks extension.
fn tasks_meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
           "io.modelcontextprotocol/clientCapabilities": {
               "extensions": {"io.modelcontextprotocol/tasks": {}}}})
}

/// POST `method` with `params` as key `k` on the 2026-07-28 revision; `name`
/// is the `mcp-name` header. The HTTP status and the JSON-RPC message.
async fn send(fx: &Fixture, method: &str, name: &str, params: Value) -> (StatusCode, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("authorization", "Bearer k")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, sse_or_json(&bytes))
}

/// A task call of `gateway_execute` `[alpha:t, X:t]`.
async fn submit_mixed_chain(fx: &Fixture, server: &str) -> (StatusCode, Value) {
    let chain = json!([{"tool": "alpha:t", "arguments": {}},
                       {"tool": format!("{server}:t"), "arguments": {}}]);
    send(
        fx,
        "tools/call",
        "gateway_execute",
        json!({"name": "gateway_execute", "arguments": {"chain": chain},
               "task": {}, "_meta": keyed_tasks_meta(server)}),
    )
    .await
}

/// [`tasks_meta`] with an idempotency key, which task creation requires.
fn keyed_tasks_meta(server: &str) -> Value {
    let mut meta = tasks_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(format!("k-8387-w1-{server}"));
    meta
}

/// Wait until the worker has written `server`'s step record and the task
/// has left `working`, then return the read as its caller sees it
/// (`tasks/get`). A read of a task whose stored target is unregistered is
/// answered by the stored-read layer, so the read itself, error or not, is
/// the cell's outcome.
async fn settled(fx: &Fixture, id: &str, server: &str) -> (StatusCode, Value) {
    let bound = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let read = send(
            fx,
            "tasks/get",
            id,
            json!({"taskId": id, "_meta": tasks_meta()}),
        )
        .await;
        let working = read
            .1
            .pointer("/result/status")
            .is_some_and(|status| status == "working" || status == "submitted");
        if !working && !step_record(fx, server).is_empty() {
            return read;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the worker settles `{server}`'s step: {read:?} {:?}",
            invocations(fx)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The worker's record for `server`'s step, once the task has settled.
fn step_record(fx: &Fixture, server: &str) -> Vec<Value> {
    invocations(fx)
        .into_iter()
        .filter(|entry| entry["server"] == server)
        .collect()
}

/// Each cell's outcome as (HTTP status, body), name and task id masked: the
/// settled task's read, or the submit's own answer when intake refused to
/// make one; with the fixture and whether a task was made.
async fn worker_cells() -> Vec<(&'static str, (String, Fixture, bool))> {
    let mut cells = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = scoped_fixture(MetaMode::CodeMode).await;
        let (submitted, made) = submit_mixed_chain(&fx, name).await;
        let id = made
            .pointer("/result/task/taskId")
            .or_else(|| made.pointer("/result/taskId"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let (outcome, worked) = match id {
            Some(id) => {
                let (status, read) = settled(&fx, &id, name).await;
                let read = json!([status.as_u16(), read]).to_string();
                (read.replace(&id, "<task>"), true)
            }
            None => (
                json!([submitted.as_u16(), {"intake": made}]).to_string(),
                false,
            ),
        };
        let outcome = masked(&outcome, name);
        cells.push((name, (outcome, fx, worked)));
    }
    cells
}

/// `ghost`'s and `beta`'s tasks must be made at the tip: only `nosuch`'s
/// intake refusal is the documented baseline (the O1 split), so no row can
/// lose its worker or stored-read coverage to an intake refusal unseen.
fn assert_tasks_made(row: &str, cells: &[(&str, (String, Fixture, bool))]) {
    for (name, (outcome, _, worked)) in cells {
        assert!(
            *worked || *name == NOSUCH,
            "{row}: premise: `{name}`'s task was not made: {outcome}"
        );
    }
}

/// W1 (d5, GPT F2; §2a cell 13), record half: the worker has no route-stage
/// memo, so the step's own record must keep its reason: `beta` and `nosuch`
/// `denied -32003`, and `ghost` not `denied`. Green at the tip through
/// `may_invoke`'s note (`gate.rs:472`). At the tip intake refuses `nosuch`'s
/// task (the O1 split), so that cell is checked here once S1 lets it through.
#[tokio::test]
async fn w1_a_worker_step_record_keeps_the_scope_refusal() {
    let cells = worker_cells().await;
    assert_tasks_made("W1", &cells);
    for (name, (outcome, fx, worked)) in cells {
        if !worked {
            continue;
        }
        let records = step_record(&fx, name);
        assert_eq!(records.len(), 1, "W1 {name}: {records:?} (task: {outcome})");
        if name == GHOST {
            assert_ne!(records[0]["outcome"], "denied", "W1 {name}: {records:?}");
        } else {
            assert_eq!(records[0]["outcome"], "denied", "W1 {name}: {records:?}");
            assert_eq!(records[0]["error_code"], -32003, "W1 {name}: {records:?}");
        }
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            1,
            "W1 {name}: only alpha ran"
        );
    }
}

/// R2 at T0 (found by the W1 rows): a mixed-chain task whose second step is
/// absent is accepted at intake, so its caller can read it back. The read
/// is answered by the stored-read layer (S7): at the tip `beta`'s task
/// answers -32003 naming `beta` (`authorize_stored`), `ghost`'s answers
/// -32001, and intake refuses `nosuch`'s task. The worker's own answer is
/// not observable through `tasks/get` once S7 refuses the read; W1's record
/// half pins the worker. Status and body are compared together.
#[tokio::test]
async fn r2_t0_a_stored_read_of_an_unreachable_step_answers_as_an_absent_one() {
    let cells = worker_cells().await;
    assert_tasks_made("R2 (T0)", &cells);
    let answers: Vec<(&str, String)> = cells
        .into_iter()
        .map(|(name, (outcome, _, _))| (name, outcome))
        .collect();
    assert_cells_equal("R2 (T0)", &answers);
}

/// R2b (Kimi): a task call to an absent target stores no task in any cell,
/// and neither does a repeat of the same call. (The submit's own answer is
/// O1's split; this row pins only that nothing is stored.)
#[tokio::test]
async fn r2b_a_refused_task_call_stores_no_task_in_any_cell() {
    // Control: the same keyed task call to the key's own backend stores one.
    let fx = scoped_fixture(MetaMode::Plain).await;
    let (_, control) = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
               "arguments": {"server": "alpha", "tool": "t", "arguments": {}},
               "task": {}, "_meta": keyed_tasks_meta("alpha")}),
    )
    .await;
    assert!(
        control
            .pointer("/result/task/taskId")
            .or_else(|| control.pointer("/result/taskId"))
            .is_some(),
        "R2b control: no task stored for alpha: {control}"
    );
    let mut stored = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = scoped_fixture(MetaMode::Plain).await;
        let params = json!({"name": "gateway_invoke",
                            "arguments": {"server": name, "tool": "t", "arguments": {}},
                            "task": {}, "_meta": keyed_tasks_meta(name)});
        for attempt in ["submit", "repeat"] {
            let (_, made) = send(&fx, "tools/call", "gateway_invoke", params.clone()).await;
            let id = made
                .pointer("/result/task/taskId")
                .or_else(|| made.pointer("/result/taskId"));
            if id.is_some() {
                stored.push((name, attempt, made));
            }
        }
    }
    assert!(stored.is_empty(), "R2b: tasks were stored: {stored:?}");
}

/// MIK-8387 PR-B R3, a guard (test plan v2 §5): R2 (T0)'s stored read of
/// `beta`'s task, refused by S7's `check_visible_policy`, emits the
/// `audit_refusal` warning with its real fields (`authz.rs:281`: server and
/// the scope refusal's reason, no numeric code; W1 pins the record's -32003);
/// `ghost`'s read emits none. The capture covers one read after the task has
/// settled, so the worker's own warnings stay out of it. Mutant M16: S7's
/// `check_visible_policy` call removed.
#[test]
fn r3_a_stored_read_refused_for_scope_logs_the_refusal_and_an_absent_one_does_not() {
    const REFUSED: &str = "Tool invocation refused by authorization";
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let mut cells = Vec::new();
    for name in [WITHHELD, GHOST] {
        let (fx, id) = rt.block_on(async {
            let fx = scoped_fixture(MetaMode::CodeMode).await;
            let (_, made) = submit_mixed_chain(&fx, name).await;
            let id = made
                .pointer("/result/task/taskId")
                .or_else(|| made.pointer("/result/taskId"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("R3 {name}: premise: a task was made: {made}"))
                .to_owned();
            let _ = settled(&fx, &id, name).await;
            (fx, id)
        });
        let (read, warnings) = crate::test_log_capture::capture_warnings(|| {
            rt.block_on(send(
                &fx,
                "tasks/get",
                &id,
                json!({"taskId": id, "_meta": tasks_meta()}),
            ))
        });
        cells.push((name, read, warnings));
    }
    let (_, beta_read, beta) = &cells[0];
    let line = beta
        .lines()
        .find(|l| l.contains(REFUSED))
        .unwrap_or_else(|| {
            panic!("R3: no audit_refusal warning for beta; read {beta_read:?}; log:\n{beta}")
        });
    // The warning's own fields (`authz.rs` `audit_refusal`): the scoped
    // key's caller name, the stored target, and the scope refusal's reason.
    for field in [
        "caller=\"alpha-client\"",
        "server=\"beta\"",
        "tool=\"t\"",
        "reason=\"Client 'alpha-client' not authorized for backend 'beta'\"",
    ] {
        assert!(
            line.contains(field),
            "R3: refusal line lacks {field}: {line}"
        );
    }
    let (_, ghost_read, ghost) = &cells[1];
    assert!(
        !ghost.contains(REFUSED),
        "R3: ghost's read logged a refusal; read {ghost_read:?}; log:\n{ghost}"
    );
}

/// A stored read records `refused` only for the gateway's policy refusal:
/// `beta`'s read, refused for the key's scope, records it; `ghost`'s, an
/// unregistered backend answered as absent, records no effect (a miss is
/// not a refusal).
#[tokio::test]
async fn only_a_stored_read_refused_for_policy_records_refused() {
    for (name, refused) in [(WITHHELD, true), (GHOST, false)] {
        let fx = scoped_fixture(MetaMode::CodeMode).await;
        let (_, made) = submit_mixed_chain(&fx, name).await;
        let id = made
            .pointer("/result/task/taskId")
            .or_else(|| made.pointer("/result/taskId"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{name}: premise: a task was made: {made}"))
            .to_owned();
        let (_, read) = settled(&fx, &id, name).await;
        assert!(
            read.get("error").is_some(),
            "{name}: premise: refused: {read}"
        );
        let last = std::fs::read_to_string(&fx.path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
            .rfind(|entry| entry["event"] == "response_delivery_attempt")
            .expect("the read's delivery record");
        assert_eq!(
            last["response_effect"] == "refused",
            refused,
            "{name}: {last}"
        );
    }
}
