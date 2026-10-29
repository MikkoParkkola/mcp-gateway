// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9091: a backend's error counts as the backend's in
//! `mcp_gateway_errors_total`, on the direct route and on the meta route,
//! whether it reaches the client as an error frame or folded into an
//! `isError` tool result.

use std::future::Future;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, fixture, post_direct, send};
use crate::protocol::RequestId;

/// Run `fut` on a current-thread runtime under a local recorder built like
/// the production one; return its output and what a scrape would show.
fn counted<T>(fut: impl Future<Output = T>) -> (T, String) {
    let recorder = crate::metrics::builder().build_recorder();
    let handle = recorder.handle();
    let out = telemetry_metrics::with_local_recorder(&recorder, || {
        crate::gateway::health_metrics::register();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    });
    (out, handle.render())
}

/// Every kind's count, in label order: auth, request, internal, backend.
fn all(rendered: &str) -> [u64; 4] {
    ["auth", "request", "internal", "backend"].map(|kind| {
        let key = format!("mcp_gateway_errors_total{{kind=\"{kind}\"}} ");
        rendered
            .lines()
            .find_map(|l| l.strip_prefix(&key)?.parse().ok())
            .unwrap_or_else(|| panic!("no {kind} series in:\n{rendered}"))
    })
}

const KEY: &str = "k-std";
const BACKEND: [u64; 4] = [0, 0, 0, 1];

/// The error a peer's 400 JSON-RPC body becomes in the HTTP transport,
/// through the production `peer_refusal` (not a hand-built look-alike).
fn peer_400() -> crate::Error {
    let body = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32001, "message": "backend says no"}
    })
    .to_string();
    crate::transport::peer_refusal_for_test(
        &body,
        &RequestId::Number(1),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .expect("premise: a 400 body answering this request is surfaced")
}

/// A peer's 400 body shaped as the gateway's account refusal (code -32603,
/// an `accounts.v1` data object), through the production `peer_refusal`.
fn peer_account_shaped() -> crate::Error {
    let body = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": {
            "code": -32603,
            "message": "connect your account",
            "data": {
                "schema_version": "accounts.v1",
                "account_id": "acct-1",
                "error": {"code": "reconnect_required"}
            }
        }
    })
    .to_string();
    crate::transport::peer_refusal_for_test(
        &body,
        &RequestId::Number(1),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .expect("premise: a 400 body answering this request is surfaced")
}

fn backend_timeout() -> crate::Error {
    crate::Error::BackendTimeout("alpha".to_string())
}

/// `gateway_invoke read` on `alpha` over the meta route.
async fn invoke(fx: &super::direct_guards_fixture::Fx) -> (StatusCode, Value) {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}}
    });
    send(fx, "/mcp", KEY, "tools/call", params, None).await
}

/// The folded `isError` text of a meta answer, asserting the premise that
/// the failure was folded into a tool result and not sent as an error frame.
fn folded_text(answer: &Value) -> String {
    assert!(
        answer.get("error").is_none(),
        "premise: folded, not an error frame: {answer}"
    );
    assert_eq!(
        answer["result"]["isError"], true,
        "premise: an isError result: {answer}"
    );
    answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// N1: a backend's 400 refusal on the direct route counts once as `backend`.
#[test]
fn a_backends_400_refusal_on_the_direct_route_counts_as_backend() {
    let ((_, answer), text) = counted(async {
        let fx = fixture(Answer::FailsWith(peer_400), |_| {}).await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(
        answer["error"]["code"], -32001,
        "premise: the peer's code: {answer}"
    );
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("backend says no")),
        "premise: the peer's message: {answer}"
    );
    assert_eq!(all(&text), BACKEND, "{text}");
}

/// N3: a backend's in-band JSON-RPC error on the meta route, folded into an
/// `isError` result, counts once as `backend` (today it counts as nothing).
#[test]
fn a_backends_in_band_error_on_the_meta_route_counts_as_backend() {
    let ((_, answer), text) = counted(async {
        let fx = fixture(Answer::RpcError(-32001), |_| {}).await;
        invoke(&fx).await
    });
    folded_text(&answer);
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// N4: a backend timeout on the meta route, folded, counts once as `backend`.
#[test]
fn a_backend_timeout_on_the_meta_route_counts_as_backend() {
    let ((_, answer), text) = counted(async {
        let fx = fixture(Answer::FailsWith(backend_timeout), |_| {}).await;
        invoke(&fx).await
    });
    folded_text(&answer);
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// N17 control: a backend tool's own `isError` result on a single meta call
/// is the tool's answer, not an error: it counts nothing.
#[test]
fn a_tools_own_is_error_result_on_the_meta_route_counts_nothing() {
    let ((_, answer), text) = counted(async {
        let fx = fixture(Answer::IsError, |_| {}).await;
        invoke(&fx).await
    });
    assert_eq!(answer["result"]["isError"], true, "premise: {answer}");
    assert_eq!(all(&text), [0, 0, 0, 0], "{answer}\n{text}");
}

/// M1 (MIK-9091.BEO.9): a backend's error shaped like the gateway's account
/// refusal is not honoured as one on the direct route: it answers 500 with
/// its own text, as every other backend failure there does.
#[test]
fn a_backends_account_shaped_error_on_the_direct_route_is_not_the_account_refusal() {
    let ((status, answer), text) = counted(async {
        let fx = fixture(Answer::FailsWith(peer_account_shaped), |_| {}).await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{answer}");
    assert_ne!(answer["error"]["code"], -32003, "{answer}");
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("connect your account")),
        "its own text: {answer}"
    );
    assert_eq!(all(&text), BACKEND, "{text}");
}

/// A playbook `p` of one `alpha/read` step, failing per `on_error`.
fn one_step(on_error: &str) -> crate::playbook::PlaybookDefinition {
    serde_json::from_value(json!({
        "playbook": "1.0", "name": "p", "description": "one step",
        "on_error": on_error,
        "steps": [{"name": "s0", "tool": "read", "server": "alpha", "arguments": {}}]
    }))
    .expect("the playbook deserialises")
}

/// A fixture answering `answer` that serves `definition`.
async fn serving(
    answer: Answer,
    definition: crate::playbook::PlaybookDefinition,
) -> super::direct_guards_fixture::Fx {
    fixture(answer, move |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
    })
    .await
}

/// Run playbook `p` over the meta route.
async fn run_p(fx: &super::direct_guards_fixture::Fx) -> (StatusCode, Value) {
    let params = json!({"name": "gateway_run_playbook",
        "arguments": {"name": "p", "arguments": {}}});
    send(fx, "/mcp", KEY, "tools/call", params, None).await
}

/// `gateway_execute` of `alpha:read`, single or as a one-step chain.
async fn execute(fx: &super::direct_guards_fixture::Fx, chain: bool) -> (StatusCode, Value) {
    let arguments = if chain {
        json!({"chain": [{"tool": "alpha:read", "arguments": {}}]})
    } else {
        json!({"tool": "alpha:read", "arguments": {}})
    };
    let params = json!({"name": "gateway_execute", "arguments": arguments});
    send(fx, "/mcp", KEY, "tools/call", params, None).await
}

/// N7: a plan that aborts on a backend's in-band error (folded in its step)
/// counts once as `backend`, not as the gateway's `internal`.
#[test]
fn a_plan_ending_on_a_backends_error_counts_as_backend() {
    let ((_, answer), text) = counted(async {
        let fx = serving(Answer::RpcError(-32001), one_step("abort")).await;
        run_p(&fx).await
    });
    assert!(
        answer.get("error").is_some(),
        "premise: the plan ended in error: {answer}"
    );
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// N8: a plan that aborts on a backend tool's own `isError` result is the
/// tool's failure: it counts once as `backend`.
#[test]
fn a_plan_ending_on_a_tools_own_is_error_counts_as_backend() {
    let ((_, answer), text) = counted(async {
        let fx = serving(Answer::IsError, one_step("abort")).await;
        run_p(&fx).await
    });
    assert!(
        answer.get("error").is_some(),
        "premise: the plan ended in error: {answer}"
    );
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// N6: a plan that carries on past a backend's error reports it in
/// `step_errors`; the delivered answer carries that failure, so it counts
/// once as `backend`.
#[test]
fn a_plan_carrying_on_past_a_backends_error_counts_it_once() {
    let ((_, answer), text) = counted(async {
        let fx = serving(Answer::RpcError(-32001), one_step("continue")).await;
        run_p(&fx).await
    });
    let report = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        report.contains("step_errors"),
        "premise: the failure is reported: {answer}"
    );
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// N15: a single-tool `gateway_execute` delivers its step's folded backend
/// error as its own answer: it counts once as `backend`.
#[test]
fn a_single_tool_execute_of_a_backends_error_counts_as_backend() {
    let ((_, answer), text) = counted(async {
        let fx = fixture(Answer::RpcError(-32001), |_| {}).await;
        execute(&fx, false).await
    });
    folded_text(&answer);
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// N14: a chain ending on a backend's error counts once as `backend`, not as
/// the gateway's `internal`.
#[test]
fn a_chain_ending_on_a_backends_error_counts_as_backend() {
    let ((_, answer), text) = counted(async {
        let fx = fixture(Answer::RpcError(-32001), |_| {}).await;
        execute(&fx, true).await
    });
    assert!(
        answer.get("error").is_some() || answer["result"]["isError"] == true,
        "premise: the chain failed: {answer}"
    );
    assert_eq!(all(&text), BACKEND, "{answer}\n{text}");
}

/// A1 (MIK-9091.BEO.8): the audit record of a backend's -32001 refusal on
/// the direct route says `error`, not `denied`: the gateway denied nothing.
#[cfg(feature = "firewall")]
#[test]
fn a_backends_minus_32001_on_the_direct_route_is_audited_as_an_error() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let audit = scratch.path().join("audit.jsonl");
    let ((_, answer), _) = counted(async {
        let fx = super::direct_guards_fixture::fixture_firewalled_audited(
            Answer::FailsWith(peer_400),
            audit.clone(),
        )
        .await;
        post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
    });
    assert_eq!(answer["error"]["code"], -32001, "premise: {answer}");
    let records: Vec<Value> = std::fs::read_to_string(&audit)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r.get("request_hash").is_some() && r.get("outcome").is_some())
        .collect();
    assert!(
        !records.is_empty(),
        "premise: an invocation record was written"
    );
    for record in &records {
        assert_eq!(record["outcome"], "error", "{record}");
    }
}
