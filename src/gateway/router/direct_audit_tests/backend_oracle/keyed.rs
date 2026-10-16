// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 d5 rows for keyed retries and mixed chains on `/mcp`: I1, I2,
//! K1(b) and O2m. A static key's scope cannot change while the gateway runs
//! (auth is restart-only), so the T1 cells flip only `ghost` (lead ruling).

use super::cells::scripted;
use super::*;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// A modern `tools/call` of the meta tool `name` with `arguments`, as key
/// `k`, carrying `key` as its idempotency key when given: the status and the
/// body with `server` replaced by [`NAME`] and trace ids masked.
async fn call(
    fx: &Fixture,
    (name, arguments): (&str, Value),
    key: Option<&str>,
    server: &str,
) -> (StatusCode, String) {
    let mut meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {}});
    if let Some(key) = key {
        meta[IDEMPOTENCY_KEY_META] = json!(key);
    }
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": name, "arguments": arguments, "_meta": meta}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("authorization", "Bearer k")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, masked(&String::from_utf8_lossy(&bytes), server))
}

/// An answer's JSON-RPC message without the result's `_meta` (server info a
/// modern answer carries), for comparing with a pinned answer.
fn core(answer: &(StatusCode, String)) -> Value {
    let mut value = sse_or_json(answer.1.as_bytes());
    if let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("_meta");
    }
    value
}

/// The pinned miss of a single-target call: `beta`'s answer at the tip.
fn single_miss() -> Value {
    let (_, pin) = pinned(Route::Invoke).expect("invoke is pinned");
    serde_json::from_str(&pin).expect("pin is JSON")
}

/// The pinned miss of a mixed chain's second step: `beta`'s answer at the tip.
fn chain_miss() -> Value {
    let absent = ABSENT_T;
    json!({"error": {"code": -32603, "message": format!(
               "JSON-RPC error -32603: Chain step 1 ({NAME}:t) failed: {absent}")},
           "id": 7, "jsonrpc": "2.0"})
}

fn invoke(server: &str) -> (&'static str, Value) {
    let arguments = json!({"server": server, "tool": "t", "arguments": {}});
    ("gateway_invoke", arguments)
}

fn execute_single(server: &str) -> (&'static str, Value) {
    (
        "gateway_execute",
        json!({"tool": format!("{server}:t"), "arguments": {}}),
    )
}

/// `gateway_execute` of the chain `[alpha:t, X:t]`.
fn mixed_chain(server: &str) -> (&'static str, Value) {
    let chain = json!([{"tool": "alpha:t", "arguments": {}},
                       {"tool": format!("{server}:t"), "arguments": {}}]);
    ("gateway_execute", json!({"chain": chain}))
}

fn code_mode() -> MetaMode {
    MetaMode::CodeMode
}

/// I1 (d5, §2a cells 4 and 23), T0: a keyed all-absent call sent twice. Both
/// sends answer alike in every cell, and the three cells answer alike.
#[tokio::test]
async fn i1_a_keyed_retry_of_an_absent_target_answers_as_an_absent_one() {
    for (label, request) in [
        ("invoke", invoke as fn(&str) -> (&'static str, Value)),
        ("execute", execute_single),
    ] {
        let mut answers = Vec::new();
        for name in [GHOST, WITHHELD, NOSUCH] {
            let fx = scoped_fixture(code_mode()).await;
            let first = call(&fx, request(name), Some("k-8387-i1"), name).await;
            let second = call(&fx, request(name), Some("k-8387-i1"), name).await;
            assert_eq!(
                first, second,
                "I1 {label} {name}: the retry answered otherwise"
            );
            answers.push((name, second));
        }
        assert_cells_equal(&format!("I1 {label}"), &answers);
        assert_eq!(
            (answers[0].1.0, core(&answers[0].1)),
            (StatusCode::OK, single_miss()),
            "I1 {label}: unpinned answer"
        );
    }
}

/// I1, T1 variant (`ghost` only, lead ruling): the first keyed send is served
/// while `ghost` is registered; `ghost` is then removed and the key resent.
/// The retry must not return the first send's stored output: it answers as
/// `beta`, never reachable, answers the same keyed call.
#[tokio::test]
async fn i1_t1_a_keyed_retry_after_removal_answers_as_an_absent_one() {
    for (label, request) in [
        ("invoke", invoke as fn(&str) -> (&'static str, Value)),
        ("execute", execute_single),
    ] {
        let beta_fx = scoped_fixture(code_mode()).await;
        let beta = call(&beta_fx, request(WITHHELD), Some("k-8387-i1t1"), WITHHELD).await;

        let fx = scoped_fixture(code_mode()).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let ghost = scripted(GHOST, BackendConfig::default(), &calls);
        assert!(
            fx.state.backends.register(ghost),
            "premise: ghost registers"
        );
        let served = call(&fx, request(GHOST), Some("k-8387-i1t1"), GHOST).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "premise {label}: served: {served:?}"
        );
        assert!(fx.state.backends.remove(GHOST), "premise: ghost is removed");
        let retried = call(&fx, request(GHOST), Some("k-8387-i1t1"), GHOST).await;
        assert_ne!(
            retried, served,
            "I1 {label}: the retry returned the stored output"
        );
        assert_eq!(
            retried, beta,
            "I1 {label}: the absent retry answers unlike `beta`"
        );
    }
}

/// I2(a) (d5, GPT F1; §2a cell 8), `ghost` only: a keyed mixed chain whose
/// first run dispatched `ghost`; `ghost` is then removed and the key resent.
/// The replay is refused 400 -32001 `Backend not found`, never served the
/// stored output. No `beta` cell exists at T1, so the pin is the design's
/// (design-8387 d5 §3 S2b′, §5 row I2(a); lead ruling on stage 1).
#[tokio::test]
async fn i2a_a_keyed_mixed_chain_replay_after_removal_answers_the_backend_miss() {
    let fx = scoped_fixture(code_mode()).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let ghost = scripted(GHOST, BackendConfig::default(), &calls);
    assert!(
        fx.state.backends.register(ghost),
        "premise: ghost registers"
    );
    let served = call(&fx, mixed_chain(GHOST), Some("k-8387-i2a"), GHOST).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: ghost ran: {served:?}"
    );
    assert!(fx.state.backends.remove(GHOST), "premise: ghost is removed");
    let (status, body) = call(&fx, mixed_chain(GHOST), Some("k-8387-i2a"), GHOST).await;
    assert_ne!(
        (status, &body),
        (served.0, &served.1),
        "I2(a): stored output replayed"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "I2(a): {body}");
    let answer: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(answer["error"]["code"], -32001, "I2(a): {body}");
    assert_eq!(
        answer["error"]["message"],
        format!("Backend not found: {NAME}"),
        "I2(a): {body}"
    );
}

/// I2(b) (§2a cell 9): X is absent at the first run, so the replay serves
/// that run's stored answer. Both sends agree in each cell, and the three
/// cells agree.
#[tokio::test]
async fn i2b_a_keyed_mixed_chain_replay_of_an_absent_step_answers_alike() {
    let (mut answers, mut runs) = (Vec::new(), Vec::new());
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = scoped_fixture(code_mode()).await;
        let first = call(&fx, mixed_chain(name), Some("k-8387-i2b"), name).await;
        let ran = fx.calls.load(Ordering::SeqCst);
        let second = call(&fx, mixed_chain(name), Some("k-8387-i2b"), name).await;
        runs.push((name, ran, fx.calls.load(Ordering::SeqCst)));
        assert_eq!(first, second, "I2(b) {name}: the replay answered otherwise");
        answers.push((name, second));
    }
    assert_cells_equal("I2(b)", &answers);
    // A replay serves the first run's answer: `alpha` ran once, and the
    // retry did not run the chain again (two fresh runs also answer alike).
    for (name, ran, after) in runs {
        assert_eq!(
            (ran, after),
            (1, 1),
            "I2(b) {name}: alpha runs (first, after retry)"
        );
    }
    assert_eq!(
        (answers[0].1.0, core(&answers[0].1)),
        (StatusCode::OK, chain_miss()),
        "I2(b): unpinned answer"
    );
}

/// K1(b) (design r2, GPT-2): `beta` kill-switched, a keyed mixed chain. At
/// the tip the plan-time kill switch (`admission_plan.rs:169`) refuses `beta`
/// alone with 400.
#[tokio::test]
async fn k1b_a_kill_switched_step_in_a_keyed_chain_answers_as_an_absent_one() {
    let mut answers = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = scoped_fixture(code_mode()).await;
        fx.state.meta_mcp.kill_switch().kill(WITHHELD);
        answers.push((
            name,
            call(&fx, mixed_chain(name), Some("k-8387-k1b"), name).await,
        ));
    }
    assert_cells_equal("K1(b)", &answers);
    assert_eq!(
        (answers[0].1.0, core(&answers[0].1)),
        (StatusCode::OK, chain_miss()),
        "K1(b): unpinned answer"
    );
}

/// O2m (§2a cell 7): an unkeyed mixed chain. The cells answer alike, and the
/// absent step's record keeps its reason: `beta` and `nosuch` `denied -32003`.
#[tokio::test]
async fn o2m_a_mixed_chain_answers_an_unreachable_step_as_an_absent_one() {
    let mut answers = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = scoped_fixture(code_mode()).await;
        answers.push((name, call(&fx, mixed_chain(name), None, name).await));
        if name != GHOST {
            let records: Vec<Value> = invocations(&fx)
                .into_iter()
                .filter(|entry| entry["server"] == name)
                .collect();
            assert_eq!(records.len(), 1, "O2m {name}: {records:?}");
            assert_eq!(records[0]["outcome"], "denied", "O2m {name}: {records:?}");
            assert_eq!(records[0]["error_code"], -32003, "O2m {name}: {records:?}");
        }
    }
    assert_cells_equal("O2m", &answers);
    assert_eq!(
        (answers[0].1.0, core(&answers[0].1)),
        (StatusCode::OK, chain_miss()),
        "O2m: unpinned answer"
    );
}
