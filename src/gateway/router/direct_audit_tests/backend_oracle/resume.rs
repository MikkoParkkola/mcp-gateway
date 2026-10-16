// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 R1 and R1g: a stored chain resumed after its pending step's
//! backend became absent. Only `ghost` can flip while the gateway runs (a
//! static key's scope is restart-only and the resume keyring is per process),
//! so these rows are `ghost` cells (lead ruling on assumption 1).

use super::*;
use crate::gateway::meta_mcp::withheld_gate::seams;

/// `ghost`, answering every call with a question, counting its calls.
fn asking_ghost(calls: &Arc<AtomicUsize>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        GHOST,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Scripted {
        calls: Arc::clone(calls),
        error: None,
        fail: None,
        reply: Some(json!({
            "resultType": "input_required",
            "inputRequests": {"q1": {"method": "elicitation/create",
                                     "params": {"message": "which?"}}},
            "requestState": "backend-state-1"
        })),
        notify_refused: false,
    }));
    backend
}

/// The first `requestState` anywhere in `value`, a text block's JSON included.
fn request_state_in(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => match map.get("requestState") {
            Some(Value::String(state)) => Some(state.clone()),
            _ => map.values().find_map(request_state_in),
        },
        Value::Array(items) => items.iter().find_map(request_state_in),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .ok()
            .as_ref()
            .and_then(request_state_in),
        _ => None,
    }
}

/// `gateway_execute` of `[ghost:t]` as key `k`, declaring elicitation, and
/// resuming `handle` when given.
async fn execute(fx: &Fixture, handle: Option<&str>) -> (StatusCode, Value) {
    let mut params = json!({"name": "gateway_execute",
        "arguments": {"chain": [{"tool": format!("{GHOST}:t"), "arguments": {}}]},
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                  "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}}});
    if let Some(handle) = handle {
        params["requestState"] = json!(handle);
        params["inputResponses"] = json!({"q1": {"action": "accept", "content": {"pick": "b"}}});
    }
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("authorization", "Bearer k")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_execute")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, sse_or_json(&bytes))
}

/// A chain stopped on `ghost`'s question: the fixture, `ghost`'s call
/// counter and the resume handle.
async fn stopped(fail_closed: bool) -> (Fixture, Arc<AtomicUsize>, String) {
    let fx = fixture(Setup {
        auth: Some(scoped_key()),
        meta_mode: MetaMode::CodeMode,
        fail_closed,
        ..Setup::default()
    })
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(
        fx.state.backends.register(asking_ghost(&calls)),
        "premise: ghost registers"
    );
    let (_, stop) = execute(&fx, None).await;
    let handle = request_state_in(&stop)
        .unwrap_or_else(|| panic!("premise: the chain stops with a resume handle: {stop}"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: ghost asked once: {stop}"
    );
    (fx, calls, handle)
}

/// The resume's answer is the pinned miss, with one not-found record of its
/// own, and `ghost` saw nothing more.
fn assert_resume_missed(
    row: &str,
    fx: &Fixture,
    before: usize,
    calls: &AtomicUsize,
    resumed: &Value,
) {
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "{row}: ghost was dispatched again: {resumed}"
    );
    assert_eq!(resumed["error"]["code"], -32001, "{row}: {resumed}");
    assert_eq!(
        resumed["error"]["message"],
        format!("Backend not found: {GHOST}"),
        "{row}: {resumed}"
    );
    let records = invocations(fx);
    let new: Vec<&Value> = records[before..].iter().collect();
    assert_eq!(new.len(), 1, "{row}: the resume writes one record: {new:?}");
    assert_eq!(new[0]["server"], GHOST, "{row}: {new:?}");
    assert_eq!(new[0]["error_code"], -32001, "{row}: {new:?}");
}

/// R1 (d4, GPT F1; §2a cell 10), `ghost` cell: unregistered between the stop
/// and the resume. The resume answers -32001 `Backend not found` (escaping at
/// chain_exec.rs:38) and writes exactly one not-found record. No `beta`
/// cell exists at T1, so the pin is the design's (design-8387 d5 §3 S6,
/// §5 row R1; lead ruling on stage 1).
#[tokio::test]
async fn r1_a_resume_whose_step_was_removed_answers_the_backend_miss_with_one_record() {
    let (fx, calls, handle) = stopped(false).await;
    assert!(fx.state.backends.remove(GHOST), "premise: ghost is removed");
    let before = invocations(&fx).len();
    let (_, resumed) = execute(&fx, Some(&handle)).await;
    assert_resume_missed("R1", &fx, before, &calls, &resumed);
}

/// R1(c): under `FailClosed` with a failing log, the resume answers the
/// write error, as every other refusal on this writer does (design-8387 d5
/// §3 S6 `record_absent_step`, `written.and(result)` at audit.rs:513; §5
/// row R1(c); lead ruling on stage 1).
#[tokio::test]
async fn r1c_a_resume_refusal_under_a_failing_log_answers_the_write_error() {
    let (fx, _calls, handle) = stopped(true).await;
    assert!(fx.state.backends.remove(GHOST), "premise: ghost is removed");
    fx.log.fail_next_append_for_test();
    let (status, resumed) = execute(&fx, Some(&handle)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "R1(c): {resumed}");
    assert_eq!(resumed["error"]["code"], -32005, "R1(c): {resumed}");
}

/// R1g (d5, GPT F3; §2a cell 11): `ghost` is unregistered when the resume
/// request starts, so S1 records it absent, and is registered again at the
/// seam just before `resume_fingerprint`. The record decides: the resume
/// answers as R1 does, and `ghost` sees no second request (design-8387 d5
/// §3 S6 memo-first, §5 row R1g; lead ruling on stage 1).
#[tokio::test]
async fn r1g_a_name_registered_before_the_resume_step_keeps_its_recorded_absence() {
    let (fx, calls, handle) = stopped(false).await;
    let ghost = fx.state.backends.get(GHOST).expect("ghost");
    assert!(fx.state.backends.remove(GHOST), "premise: ghost is removed");
    let state = Arc::clone(&fx.state);
    seams::before_resume(move || {
        assert!(
            state.backends.register(ghost),
            "premise: ghost registers at the seam"
        );
    });
    let before = invocations(&fx).len();
    let (_, resumed) = execute(&fx, Some(&handle)).await;
    assert_resume_missed("R1g", &fx, before, &calls, &resumed);
}
