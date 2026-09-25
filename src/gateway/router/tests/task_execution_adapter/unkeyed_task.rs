// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F10 T10: under `server.idempotency_key: required`, a task call is not a
//! sync admission. It is neither refused by the `required` gate nor counted in
//! `mcp_unkeyed_calls_total`.
//!
//! Deviation from the design's T10 wording, recorded in the PR: a task call
//! with NO key never reaches admission at all, because the task builder
//! (`handlers/tasks.rs`, `task_intent_for_call`) already refuses it with
//! "task creation requires an idempotency key". So the keyed half is the
//! task-protected admission, and the keyless half pins that builder refusal
//! rather than the `required` one.

use metrics_exporter_prometheus::PrometheusBuilder;

use super::super::*;
use super::support::*;

fn unkeyed_total(handle: &metrics_exporter_prometheus::PrometheusHandle) -> u64 {
    handle
        .render()
        .lines()
        .filter(|line| line.starts_with("mcp_unkeyed_calls_total{"))
        .filter_map(|line| line.rsplit_once(' ')?.1.trim().parse::<u64>().ok())
        .sum()
}

#[tokio::test]
async fn t10_required_admits_a_keyed_task_through_the_task_path_uncounted() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    state
        .meta_mcp
        .set_idempotency_key_mode(crate::config::IdempotencyKeyMode::Required);
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    let created = post(&state, "key-a", task_invoke(1001, "t10-key", json!({}))).await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;

    assert_carries_the_backend_result(&settled);
    std::assert_eq!(mock.calls(), 1, "{settled}");
    std::assert_eq!(unkeyed_total(&handle), 0, "{}", handle.render());
}

#[tokio::test]
async fn t10_required_leaves_a_keyless_task_to_the_task_builder_refusal() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    state
        .meta_mcp
        .set_idempotency_key_mode(crate::config::IdempotencyKeyMode::Required);
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    let mut request = task_invoke(1002, "placeholder", json!({}));
    request["params"]["_meta"]
        .as_object_mut()
        .expect("task_invoke builds _meta")
        .remove(IDEMPOTENCY_KEY_META);
    let refused = post(&state, "key-a", request).await;

    std::assert_eq!(refused["error"]["code"], -32602, "{refused}");
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("task creation requires an idempotency key"),
        "the task builder refuses first, not the `required` gate: {refused}"
    );
    std::assert_eq!(mock.calls(), 0, "{refused}");
    std::assert_eq!(unkeyed_total(&handle), 0, "{}", handle.render());
}

/// POST `body` to `POST /mcp/{BACKEND}` as `principal`.
async fn post_to_backend_route(state: &Arc<AppState>, principal: &str, body: &Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", TOOL)
        .header("authorization", format!("Bearer {principal}"))
        .body(axum::body::Body::from(body.to_string()))
        .expect("a well-formed request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// T11, with T2 on the HTTP meta route as its control: under `required` the
/// meta route refuses an un-keyed modern mutation, while `POST /mcp/{name}`,
/// which performs no sync admission, admits the same call.
#[tokio::test]
async fn t11_required_refuses_on_meta_and_admits_on_the_backend_route() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    state
        .meta_mcp
        .set_idempotency_key_mode(crate::config::IdempotencyKeyMode::Required);

    let refused = post(&state, "key-a", sync_invoke(1101, json!({}))).await;
    std::assert_eq!(refused["error"]["code"], -32602, "{refused}");
    std::assert_eq!(mock.calls(), 0, "{refused}");

    let call = modern(
        1102,
        "tools/call",
        json!({"name": TOOL, "arguments": {}}),
        false,
    );
    // F12c: the backend route performs no sync admission, so the un-keyed
    // call it admits is not counted (UPGRADING §28).
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
    let admitted = post_to_backend_route(&state, "key-a", &call).await;
    assert!(admitted.get("error").is_none(), "{admitted}");
    std::assert_eq!(mock.calls(), 1, "{admitted}");
    std::assert_eq!(unkeyed_total(&handle), 0, "{}", handle.render());
}

/// T1 on the HTTP meta route: the default admits the same un-keyed call.
#[tokio::test]
async fn t1_default_admits_an_unkeyed_modern_mutation_on_the_meta_route() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);

    let admitted = post(&state, "key-a", sync_invoke(1103, json!({}))).await;

    assert!(admitted.get("error").is_none(), "{admitted}");
    std::assert_eq!(mock.calls(), 1, "{admitted}");
    // The positive control for T11's zero: this harness does see the counter.
    std::assert_eq!(unkeyed_total(&handle), 1, "{}", handle.render());
}
