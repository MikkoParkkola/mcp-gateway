// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An answer this request did not produce (a replay, a composite's) states no
//! effect and no findings: its delivery record omits both fields rather than
//! claim `delivered` for bytes no scan of this request judged.

use super::backend_oracle::sse_or_json;
use super::meta_replay::{keyed_invoke, post_modern};
use super::*;

/// Every delivery record in the log, in order.
fn deliveries(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect()
}

/// The first delivery states its effect; the replay states none.
fn assert_first_vouched_replay_not(fx: &Fixture) {
    let rows = deliveries(fx);
    let [first, replay] = rows.as_slice() else {
        panic!("two delivery records: {rows:?}");
    };
    assert_eq!(first["response_effect"], "delivered", "{first}");
    for field in ["response_effect", "response_findings"] {
        assert!(replay.get(field).is_none(), "{field}: {replay}");
    }
}

/// A direct idempotent replay (7a) serves the first run's answer.
#[tokio::test]
async fn a_direct_idempotent_replay_states_no_effect() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::Idempotent,
        ..Setup::default()
    })
    .await;
    for _ in 0..2 {
        let call = direct_call("cust-1", Some("k-unvouched"));
        let (status, answer) = post_modern_as(&fx, "/mcp/alpha", &call, &Caller::ModernOidc).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: a replay");
    assert_first_vouched_replay_not(&fx);
}

/// A keyed direct call whose backend failed replays the stored failure: the
/// replay states no effect either.
#[tokio::test]
async fn a_direct_cached_failure_replay_states_no_effect() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::Idempotent,
        backend_error: Some(-32010),
        ..Setup::default()
    })
    .await;
    for _ in 0..2 {
        let call = direct_call("cust-1", Some("k-unvouched-failure"));
        let (_, answer) = post_modern_as(&fx, "/mcp/alpha", &call, &Caller::ModernOidc).await;
        assert!(answer.get("error").is_some(), "premise: failed: {answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: a replay");
    let rows = deliveries(&fx);
    let [first, replay] = rows.as_slice() else {
        panic!("two delivery records: {rows:?}");
    };
    assert!(first.get("response_effect").is_some(), "{first}");
    for field in ["response_effect", "response_findings"] {
        assert!(replay.get(field).is_none(), "{field}: {replay}");
    }
}

/// A meta admission replay serves the first run's answer.
#[tokio::test]
async fn a_meta_admission_replay_states_no_effect() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    for id in [1, 2] {
        let (status, answer) = post_modern(&fx, &keyed_invoke(id).0).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: a replay");
    assert_first_vouched_replay_not(&fx);
}

/// A1: a keyed call whose grant slot write failed was answered -32005 before
/// its record, so its execution stores that refusal. The replay serves the
/// refusal, never the answer the slot refused.
#[tokio::test]
async fn a_replay_after_a_slot_refusal_serves_the_refusal() {
    use crate::gateway::meta_mcp::grant_audit::seams;
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    seams::inject_note_for_test("alpha", "t", seams::Inject::NextSlotOpen);
    seams::fail_append_at_for_test(1);
    let (_, first) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert!(
        first.contains("-32005"),
        "premise: the slot refused: {first}"
    );
    let (_, again) = post_modern(&fx, &keyed_invoke(2).0).await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "premise: a replay: {again}"
    );
    assert!(
        again.contains("-32005"),
        "the replay serves the refusal: {again}"
    );
}

/// The playbook `yaml` registered on `fx`, run on `/mcp`: its answer.
pub(super) async fn run_playbook(fx: &Fixture, yaml: &str, name: &str) -> (StatusCode, Value) {
    run_playbook_as(fx, yaml, name, &Caller::Anonymous).await
}

/// [`run_playbook`] as `caller`.
pub(super) async fn run_playbook_as(
    fx: &Fixture,
    yaml: &str,
    name: &str,
    caller: &Caller,
) -> (StatusCode, Value) {
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(crate::yaml::from_str(yaml).expect("the playbook parses"));
    fx.state.meta_mcp.set_playbook_engine(engine);
    let call = json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
        "name": "gateway_run_playbook", "arguments": {"name": name, "arguments": {}}}});
    post_to(fx, "/mcp", &call.to_string(), caller).await
}

/// The last delivery record states neither an effect nor findings.
fn assert_last_states_nothing(fx: &Fixture) {
    let rows = deliveries(fx);
    let row = rows.last().expect("the composite's delivery record");
    for field in ["response_effect", "response_findings"] {
        assert!(row.get(field).is_none(), "{field}: {row}");
    }
}

/// A playbook carrying on past a step the gateway refused still delivers
/// its report: the step's refusal stays in the step's own cell and never
/// marks the composite `refused`.
#[tokio::test]
async fn a_playbook_past_a_refused_step_states_no_effect() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::ContractRefuses,
        ..Setup::default()
    })
    .await;
    let yaml = "name: onward\ndescription: one refused step\non_error: continue\n\
         steps:\n  - name: read\n    server: alpha\n    tool: t\n    arguments: {}\n";
    let (status, answer) = run_playbook(&fx, yaml, "onward").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(
        answer.to_string().contains("steps_failed"),
        "premise: the playbook delivered its report: {answer}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: the step ran");
    assert_last_states_nothing(&fx);
}

/// A playbook whose only step its condition skips runs no step, and still
/// states nothing: a composite is unvouched at its arm.
#[tokio::test]
async fn a_playbook_that_runs_no_step_states_no_effect() {
    let fx = fixture(Setup::default()).await;
    let yaml = "name: idle\ndescription: a skipped step\n\
         steps:\n  - name: read\n    server: alpha\n    tool: t\n    condition: $inputs.go\n    arguments: {}\n";
    let (status, answer) = run_playbook(&fx, yaml, "idle").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        0,
        "premise: no step ran: {answer}"
    );
    assert_last_states_nothing(&fx);
}

/// A chain delivers a composite: no one step's facts describe it.
#[tokio::test]
async fn a_composite_states_no_effect() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::CodeMode,
        ..Setup::default()
    })
    .await;
    let chain = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"chain": [{"tool": "alpha:t", "arguments": {}}]}}});
    let (status, answer) = post_to(&fx, "/mcp", &chain.to_string(), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: the step ran");
    let rows = deliveries(&fx);
    let [row] = rows.as_slice() else {
        panic!("one delivery record: {rows:?}");
    };
    for field in ["response_effect", "response_findings"] {
        assert!(row.get(field).is_none(), "{field}: {row}");
    }
}

/// POST `method` with `params` as key `k` on the 2026-07-28 revision with the
/// tasks extension; `name` is the `mcp-name` header.
async fn send_modern(fx: &Fixture, method: &str, name: &str, params: Value) -> Value {
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
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    sse_or_json(&bytes)
}

fn tasks_meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
           "io.modelcontextprotocol/clientCapabilities": {
               "extensions": {"io.modelcontextprotocol/tasks": {}}}})
}

/// A task read on `/mcp` serves the stored answer, not one this request
/// produced.
#[tokio::test]
async fn a_meta_task_read_states_no_effect() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let mut meta = tasks_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("k-unvouched-task");
    let call = json!({"name": "gateway_invoke", "task": {}, "_meta": meta,
        "arguments": {"server": "alpha", "tool": "t", "arguments": {}}});
    let made = send_modern(&fx, "tools/call", "gateway_invoke", call).await;
    let id = made
        .pointer("/result/task/taskId")
        .or_else(|| made.pointer("/result/taskId"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let params = json!({"taskId": id, "_meta": tasks_meta()});
        let read = send_modern(&fx, "tasks/get", &id, params).await;
        if read.pointer("/result/status") == Some(&json!("completed")) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: settles: {read}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let rows = deliveries(&fx);
    let read = rows.last().expect("the read's delivery record");
    for field in ["response_effect", "response_findings"] {
        assert!(read.get(field).is_none(), "{field}: {read}");
    }
}
