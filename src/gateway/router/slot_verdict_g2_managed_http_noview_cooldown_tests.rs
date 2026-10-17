// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8439 (MIK-8361.NOVIEW.1, NOVIEW.3) on `/mcp`: the sole operator of a
//! managed per-user backend with no current grant has no view of it. A tool
//! other callers pushed into error-rate cooldown must answer as a missing
//! name does (the account's connect offer), on every entry; an operator
//! with a grant keeps the cooldown refusal. Uses the parent's fixture.

use axum::http::StatusCode;

use super::*;

const MISSING: &str = "no_such_tool";

/// Push [`TOOL`] into error-rate cooldown, as other callers' failures would.
fn cool(fx: &Fx) {
    let kill_switch = fx.meta.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(BACKEND, TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(BACKEND, TOOL),
        "premise: {TOOL} is in cooldown"
    );
}

/// The cooldown refusal as the dispatch renders it: `Error::JsonRpc`'s
/// Display (error.rs) through `error_response_preserving_status`.
fn dispatch_cooldown_text() -> String {
    format!(
        "JSON-RPC error -32000: {}",
        crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::cooldown_refusal(
            BACKEND, TOOL
        )
    )
}

/// `text` with both twin names factored out, on either side alike ("read"
/// also sits inside words such as "already").
fn normalised(text: &str) -> String {
    text.replace(TOOL, "<tool>").replace(MISSING, "<tool>")
}

/// The transparency log's actions for [`BACKEND`], in order.
fn audit_actions(fx: &Fx) -> Vec<String> {
    let path = fx.dirs.0.path().join("audit.jsonl");
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    raw.lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["backend"] == BACKEND || entry["server"] == BACKEND)
        .map(|entry| entry["action"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// One `/mcp` request as the sole operator: the status and the body bytes.
/// `modern` adds the headers a 2026-07-28 client sends.
async fn post(fx: &Fx, body: &Value, modern: Option<&str>) -> (StatusCode, String) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR_KEY}"));
    if let Some(name) = modern {
        builder = builder
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", body["method"].as_str().unwrap_or_default())
            .header("mcp-name", name);
    }
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// `gateway_invoke` of `tool` on [`BACKEND`], its nonce in the arguments
/// when given.
fn invoke_body(id: u64, tool: &str, nonce: Option<&str>) -> Value {
    let mut arguments = json!({"server": BACKEND, "tool": tool, "arguments": {"folder": "inbox"}});
    if let Some(nonce) = nonce {
        arguments["nonce"] = json!(nonce);
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": arguments}})
}

/// What one twin left behind: status, body with the names factored out, the
/// audit actions it added and the `tools/call` sends it added.
#[derive(Debug, PartialEq)]
struct Twin {
    status: StatusCode,
    body: String,
    audit: Vec<String>,
    sent: usize,
}

async fn twin(fx: &Fx, body: &Value, modern: Option<&str>) -> Twin {
    let (actions, sends) = (audit_actions(fx).len(), fx.gateway.tool_calls().len());
    let (status, body) = post(fx, body, modern).await;
    Twin {
        status,
        body: normalised(&body),
        audit: audit_actions(fx)[actions..].to_vec(),
        sent: fx.gateway.tool_calls().len() - sends,
    }
}

/// The premise every no-view twin row rests on: the missing name's answer
/// is the account's connect offer, so equality is not two wrong answers.
fn assert_offer(missing: &Twin, row: &str) {
    assert!(
        missing.body.contains("no connected account"),
        "premise ({row}): the missing name gets the account answer: {missing:?}"
    );
}

/// R1 (NOVIEW.1, red first): unsigned `/mcp`, no grant, [`TOOL`] in
/// cooldown. Its `gateway_invoke` answers byte-equal to a missing name's
/// once the name is factored out (status, body, audit actions) and sends
/// nothing. RED at base: admission answers 400 with the cooldown text,
/// naming the tool. Kills M1 and M6 (status and audit compared).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_noview_cooldown_twin_answers_as_missing_mcp() {
    let fx = fixture_with(&Binding::Unconnected).await;
    cool(&fx);
    let missing = twin(&fx, &invoke_body(1, MISSING, None), None).await;
    assert_offer(&missing, "R1");
    // The dispatch renders an unstamped refusal at 200: R4's pin rests on it.
    assert_eq!(
        missing.status,
        StatusCode::OK,
        "premise: the dispatch's offer: {missing:?}"
    );
    let hidden = twin(&fx, &invoke_body(1, TOOL, None), None).await;
    assert!(
        !hidden.body.contains("temporarily disabled"),
        "R1: the cooldown named the tool: {hidden:?}"
    );
    assert_eq!(hidden, missing, "R1: in cooldown vs missing");
    assert_eq!(hidden.sent, 0, "R1: sent");
}

/// R2 (NOVIEW.1 signed, red first): as R1 with message signing on, a fresh
/// nonce per twin, then each nonce re-sent. Both first answers are equal and
/// both re-sends are refused as a replay. RED at base: signing answers the
/// cooldown before the nonce is admitted, so its re-send is not a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_noview_cooldown_twin_answers_as_missing_mcp_signed() {
    let fx = fixture_armed(&Binding::Unconnected, |meta| {
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"noview-cooldown-mcp-signing-secret-32-bytes".to_vec(),
                None,
                "r2".to_owned(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
    })
    .await;
    cool(&fx);
    let mut sides = Vec::new();
    for (name, nonce) in [(MISSING, "r2-missing-n1"), (TOOL, "r2-hidden-n1")] {
        let first = twin(&fx, &invoke_body(1, name, Some(nonce)), None).await;
        let resent = twin(&fx, &invoke_body(2, name, Some(nonce)), None).await;
        assert!(
            resent.body.contains("Nonce replay detected"),
            "R2 {name}: the re-sent nonce was not refused as a replay: {resent:?} after {first:?}"
        );
        // The premise runs before the hidden twin, so it runs at base too.
        if name == MISSING {
            assert_offer(&first, "R2");
        }
        sides.push((first, resent));
    }
    let (missing, hidden) = (&sides[0], &sides[1]);
    assert_eq!(hidden.0, missing.0, "R2: in cooldown vs missing");
    assert_eq!(hidden.1, missing.1, "R2: re-sends");
    assert_eq!(hidden.0.sent + hidden.1.sent, 0, "R2: sent");
}

/// R4 (NOVIEW.3 control on `/mcp`): an operator with a grant is still
/// refused for the cooldown, -32000 with the full dispatch text, and nothing
/// is sent. RED at base on the status only: admission renders the same body
/// with HTTP 400; the dispatch answers 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_view_caller_still_gets_cooldown_mcp() {
    let fx = fixture_with(&Binding::Connected).await;
    cool(&fx);
    let sends = fx.gateway.tool_calls().len();
    let (status, body) = post(&fx, &invoke_body(1, TOOL, None), None).await;
    let answer: Value = serde_json::from_str(&body).expect("a JSON-RPC body");
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32000)),
        "R4: {body}"
    );
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some(dispatch_cooldown_text().as_str()),
        "R4: {body}"
    );
    assert_eq!(status, StatusCode::OK, "R4: the dispatch's status: {body}");
    assert_eq!(fx.gateway.tool_calls().len(), sends, "R4: sent");
}

/// How a modern `tools/call` asks to run.
#[derive(Clone, Copy)]
enum Run {
    Sync,
    Task,
}

/// A modern `tools/call` of `name` with `arguments`, under the idempotency
/// key `key` when given, run as `run` asks.
fn modern_body(id: u64, name: &str, arguments: &Value, key: Option<&str>, run: Run) -> Value {
    let mut meta = super::super::tests::modern_meta();
    if let Some(key) = key {
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    }
    let mut params = json!({"name": name, "arguments": arguments, "_meta": meta});
    if matches!(run, Run::Task) {
        params["task"] = json!({});
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
}

fn invoke_arguments(tool: &str) -> Value {
    json!({"server": BACKEND, "tool": tool, "arguments": {"folder": "inbox"}})
}

const MARKER: &str = "noview-cooldown-r6-output";

/// R6 (keyed control, green at base): an operator with a grant makes a keyed
/// call of [`TOOL`] in cooldown, then the same key again: the cooldown both
/// times, never 409 in flight and never a stored replay, nothing sent. Once
/// the cooldown is cleared the same key is sent fresh and served: the key
/// stayed usable, and the second refusal was a fresh one, not a stored
/// cooldown error. Pins the lease abandon for the dispatch site (design §5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r6_keyed_view_caller_cooldown_frees_its_key_mcp() {
    let fx = fixture_with(&Binding::Connected).await;
    cool(&fx);
    let sends = fx.gateway.tool_calls().len();
    let keyed = |id| {
        modern_body(
            id,
            "gateway_invoke",
            &invoke_arguments(TOOL),
            Some("r6-key"),
            Run::Sync,
        )
    };
    for id in [1, 2] {
        let (status, body) = post(&fx, &keyed(id), Some("gateway_invoke")).await;
        assert!(
            body.contains(
                &crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::cooldown_refusal(
                    BACKEND, TOOL,
                ),
            ),
            "R6 call {id}: not the cooldown ({status}): {body}"
        );
        assert_ne!(
            status,
            StatusCode::CONFLICT,
            "R6 call {id}: in flight: {body}"
        );
    }
    assert_eq!(fx.gateway.tool_calls().len(), sends, "R6: sent in cooldown");
    fx.meta.kill_switch().revive_capability(BACKEND, TOOL);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let (status, body) = post(&fx, &keyed(3), Some("gateway_invoke")).await;
    assert!(
        body.contains(MARKER) && !body.contains("temporarily disabled"),
        "R6: the same key after the cooldown was not served fresh ({status}): {body}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sends + 1,
        "R6: one fresh send"
    );
}

/// A task's settled record, read from the store (a no-view caller's
/// `tasks/get` answers -32601 whatever the task did, as W2 found), with what
/// differs per task (id, times) removed and the names factored out.
async fn settled(fx: &Fx, made: &str) -> String {
    let made: Value = serde_json::from_str(made).expect("a JSON-RPC body");
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task was made: {made}"))
        .to_owned();
    let store = &fx.state.task_executor.service.store;
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = store.status_for_test(&id);
        if matches!(
            status,
            Some(
                crate::protocol::tasks::TaskStatus::Completed
                    | crate::protocol::tasks::TaskStatus::Failed
                    | crate::protocol::tasks::TaskStatus::Cancelled
            )
        ) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "the task settled: {status:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let digest = store
        .owner_digest_for_test(&id)
        .expect("the task has an owner");
    let committed = store.get(&digest, &id).expect("the settled task reads");
    let mut wire = serde_json::to_value(committed.task.wire()).expect("JSON");
    if let Some(record) = wire.as_object_mut() {
        for volatile in [
            "taskId",
            "createdAt",
            "lastUpdatedAt",
            "ttl",
            "pollInterval",
        ] {
            record.remove(volatile);
        }
    }
    normalised(&wire.to_string().replace(&id, "<task>"))
}

/// R7 (task, red first): with no grant, a task `gateway_invoke` of [`TOOL`]
/// in cooldown is accepted, as the missing name's is, and both settle to
/// the same record (the offer, read from the store); nothing is sent. RED at base: refused at
/// submit with the cooldown text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r7_noview_cooldown_task_answers_as_missing_mcp() {
    let fx = fixture_with(&Binding::Unconnected).await;
    cool(&fx);
    let mut sides = Vec::new();
    for (name, key) in [(MISSING, "r7-missing"), (TOOL, "r7-hidden")] {
        let body = modern_body(
            1,
            "gateway_invoke",
            &invoke_arguments(name),
            Some(key),
            Run::Task,
        );
        let (status, made) = post(&fx, &body, Some("gateway_invoke")).await;
        assert!(
            !made.contains("temporarily disabled"),
            "R7 {name}: the cooldown named the tool at submit ({status}): {made}"
        );
        let record = settled(&fx, &made).await;
        // The premise runs before the hidden twin, so it runs at base too.
        assert!(
            name != MISSING || record.contains("no connected account"),
            "premise: the missing name's task settles to the offer: {record}"
        );
        sides.push((status, record));
    }
    assert_eq!(sides[1], sides[0], "R7: in cooldown vs missing");
    assert_eq!(fx.gateway.tool_calls().len(), 0, "R7: sent");
}

/// R8 (chain, red first): with no grant, a keyed `gateway_execute` chain of
/// `[BACKEND:TOOL]` answers as `[BACKEND:no_such_tool]` once the names are
/// factored out; nothing is sent. RED at base: admission refuses the chain
/// with the cooldown text (`admission_plan.rs`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r8_noview_cooldown_chain_answers_as_missing_mcp() {
    let fx = fixture_with(&Binding::Unconnected).await;
    cool(&fx);
    let chain = |tool: &str, key: &str| {
        let arguments = json!({"chain": [{"tool": format!("{BACKEND}:{tool}"), "arguments": {"folder": "inbox"}}]});
        modern_body(1, "gateway_execute", &arguments, Some(key), Run::Sync)
    };
    let missing = twin(&fx, &chain(MISSING, "r8-key-a"), Some("gateway_execute")).await;
    assert_offer(&missing, "R8");
    let hidden = twin(&fx, &chain(TOOL, "r8-key-b"), Some("gateway_execute")).await;
    assert!(
        !hidden.body.contains("temporarily disabled"),
        "R8: the cooldown named the tool: {hidden:?}"
    );
    assert_eq!(hidden, missing, "R8: in cooldown vs missing");
    assert_eq!(hidden.sent + missing.sent, 0, "R8: sent");
}

/// R9 (direct route control, green at base): `/mcp/{BACKEND}` resolves the
/// credential before its guards, so with no grant a tool in cooldown already
/// answers as a missing one (the offer); nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r9_noview_cooldown_direct_route_answers_as_missing() {
    let fx = fixture_with(&Binding::Unconnected).await;
    cool(&fx);
    let hidden = direct_named(&fx, TOOL).await;
    let missing = direct_named(&fx, MISSING).await;
    assert!(missing.idp_refusals > 0, "premise: {missing:?}");
    assert!(
        !hidden.body.contains("temporarily disabled"),
        "R9: the cooldown named the tool: {hidden:?}"
    );
    assert_eq!(
        (hidden.status, &hidden.body, hidden.idp_refusals),
        (missing.status, &missing.body, missing.idp_refusals),
        "R9: in cooldown vs missing"
    );
    assert_eq!(fx.gateway.tool_calls().len(), 0, "R9: sent");
}
