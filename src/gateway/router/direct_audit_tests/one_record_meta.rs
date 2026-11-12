// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 R0 (`POST /mcp`): one `transport_finalized` record per
//! trace on the HTTP answer, the HTTP pre-dispatch refusal and the grant-slot
//! seal failure. The direct route is `one_record.rs`; the audit-unavailable
//! replacement and the replay are `one_record_replay.rs`.

use std::collections::BTreeMap;

use super::meta_replay::{keyed_invoke, post_modern};
use super::*;

/// How many `transport_finalized` records each trace holds.
pub(super) fn per_trace(fx: &Fixture) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for entry in rows(fx) {
        if entry["event"] == "response_delivery_attempt"
            && entry["response_stage"] == "transport_finalized"
        {
            let trace = entry["trace_id"].as_str().expect("a trace").to_string();
            *counts.entry(trace).or_default() += 1;
        }
    }
    counts
}

/// Every row of the log, in order.
pub(super) fn rows(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .collect()
}

/// The trace of each call's own invocation record, in order.
pub(super) fn call_traces(fx: &Fixture) -> Vec<String> {
    rows(fx)
        .iter()
        .filter(|e| e.get("request_hash").is_some() && e.get("event").is_none())
        .map(|e| e["trace_id"].as_str().expect("a trace").to_string())
        .collect()
}

fn invoke_alpha_t() -> String {
    let arguments = json!({"server": "alpha", "tool": "t", "arguments": {"q": 1}});
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": "gateway_invoke", "arguments": arguments}})
    .to_string()
}

#[tokio::test]
async fn r0_an_http_answer_writes_one_record_under_the_calls_trace() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post_to(&fx, "/mcp", &invoke_alpha_t(), &Caller::Key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "the backend ran");
    let traces = call_traces(&fx);
    assert_eq!(traces.len(), 1, "{traces:?}");
    let expected = BTreeMap::from([(traces[0].clone(), 1)]);
    assert_eq!(per_trace(&fx), expected);
}

#[tokio::test]
async fn r0_an_http_refusal_before_dispatch_writes_one_record() {
    let fx = fixture(Setup::default()).await;
    let arguments = json!({"server": "alpha", "tool": "t", "arguments": {}});
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                      "params": {"name": "gateway_invoke", "arguments": arguments,
                                 "requestState": 5}});
    let (status, answer) = post_to(&fx, "/mcp", &body.to_string(), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"]["code"], -32602, "{answer}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        0,
        "refused before dispatch"
    );
    let traces = call_traces(&fx);
    assert_eq!(traces.len(), 1, "{traces:?}");
    let expected = BTreeMap::from([(traces[0].clone(), 1)]);
    assert_eq!(per_trace(&fx), expected);
}

#[tokio::test]
async fn r0_a_seal_failure_writes_one_record_for_the_replacing_refusal() {
    use crate::gateway::meta_mcp::grant_audit::seams;
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    seams::inject_note_for_test("alpha", "t", seams::Inject::NextSlotOpen);
    seams::fail_append_at_for_test(1);
    let (_, answer) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert!(
        answer.contains("-32005"),
        "premise: the slot refused: {answer}"
    );
    let counts = per_trace(&fx);
    assert_eq!(counts.values().sum::<usize>(), 1, "{counts:?}");
    assert!(counts.values().all(|n| *n == 1), "{counts:?}");
    let traces = call_traces(&fx);
    assert!(!traces.is_empty(), "premise: the call's record is present");
    assert!(
        counts.keys().all(|t| traces.contains(t)),
        "{counts:?} vs {traces:?}"
    );
    // Guard (passes before the fixes): the one record is the replacing
    // refusal's, not the answer the slot's failure replaced.
    let delivery: Vec<Value> = rows(&fx)
        .into_iter()
        .filter(|e| e["event"] == "response_delivery_attempt")
        .collect();
    assert_eq!(delivery.len(), 1, "{delivery:?}");
    assert_eq!(delivery[0]["response_effect"], "refused", "{delivery:?}");
}
