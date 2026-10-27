// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway decision that refuses a call (the operator kill switch, a
//! capability disable, attestation, spend) records `response_effect: refused`
//! wherever its error becomes the delivered answer, and its wire answer stays
//! byte for byte what it was.

use super::*;

const KILLED: &str = "Server 'alpha' is currently disabled by operator kill switch";

/// The delivery records in the log.
fn attempts(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect()
}

/// The invocation records in the log: they name a route and are not a
/// delivery attempt.
fn invocations(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| {
            entry.get("route").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .collect()
}

fn invoke_alpha_t() -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {"server": "alpha", "tool": "t", "arguments": {}}}})
    .to_string()
}

async fn killed_alpha() -> Fixture {
    let fx = fixture(Setup::default()).await;
    fx.state.meta_mcp.kill_switch().kill("alpha");
    fx
}

/// Pin: the operator kill switch on `/mcp` answers as it always has.
#[tokio::test]
async fn a_killed_meta_call_keeps_its_wire_answer() {
    let fx = killed_alpha().await;
    let (status, body) = post_to(&fx, "/mcp", &invoke_alpha_t(), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32000, "{body}");
    assert_eq!(
        body["error"]["message"],
        format!("JSON-RPC error -32000: {KILLED}"),
        "{body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never dispatched");
}

/// Pin: the operator kill switch on a direct call answers as it always has.
#[tokio::test]
async fn a_killed_direct_call_keeps_its_wire_answer() {
    let fx = killed_alpha().await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["error"]["code"], -32000, "{body}");
    assert_eq!(body["error"]["message"], KILLED, "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never dispatched");
    let records = invocations(&fx);
    assert!(
        records.iter().all(|r| r["outcome"] == "error"),
        "outcome class unchanged: {records:?}"
    );
}

/// The kill switch refuses a `/mcp` call: the delivery is recorded, refused.
#[tokio::test]
async fn a_killed_meta_call_records_refused() {
    let fx = killed_alpha().await;
    let (status, body) = post_to(&fx, "/mcp", &invoke_alpha_t(), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "premise: {body}");
    let all = attempts(&fx);
    let [event] = all.as_slice() else {
        panic!("one delivery record for the refused call: {all:?}");
    };
    assert_eq!(event["response_effect"], "refused", "{event}");
}

/// An error at the same `/mcp` exit that no gateway decision made is
/// recorded without an effect: no scan saw it, so nothing is claimed.
#[tokio::test]
async fn an_unrefused_meta_error_records_no_effect() {
    let fx = fixture(Setup::default()).await;
    let bad = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {"tool": "t"}}})
    .to_string();
    let (status, body) = post_to(&fx, "/mcp", &bad, &Caller::Anonymous).await;
    assert!(
        body.get("error").is_some(),
        "premise: an error answer: {status} {body}"
    );
    let all = attempts(&fx);
    let [event] = all.as_slice() else {
        panic!("one delivery record for the error: {all:?}");
    };
    assert!(event.get("response_effect").is_none(), "{event}");
    assert!(event.get("response_findings").is_none(), "{event}");
}

/// The kill switch refuses a direct call on a shared backend: refused.
#[tokio::test]
async fn a_killed_direct_call_records_refused() {
    let fx = killed_alpha().await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "premise: {body}");
    let all = attempts(&fx);
    let [event] = all.as_slice() else {
        panic!("one delivery record: {all:?}");
    };
    assert_eq!(event["response_effect"], "refused", "{event}");
}

/// The `/mcp` refusal's delivery record joins the invocation record of the
/// same call by `trace_id`, as every other `/mcp` delivery does.
#[tokio::test]
async fn a_killed_meta_call_record_joins_its_invocation() {
    let fx = killed_alpha().await;
    let (status, body) = post_to(&fx, "/mcp", &invoke_alpha_t(), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "premise: {body}");
    let (deliveries, calls) = (attempts(&fx), invocations(&fx));
    let ([delivery], [invocation]) = (deliveries.as_slice(), calls.as_slice()) else {
        panic!("one delivery and one invocation: {deliveries:?} {calls:?}");
    };
    assert_eq!(
        delivery["trace_id"], invocation["trace_id"],
        "{delivery} {invocation}"
    );
}
