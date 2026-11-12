// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 R0 (direct route): one `transport_finalized` record per
//! trace. The Activity join reads two such records for one trace as tamper, so
//! every writer path must write at most one under the call's own trace.

use std::collections::BTreeMap;

use super::*;

/// How many `transport_finalized` records each trace holds.
fn per_trace(fx: &Fixture) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for line in std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
    {
        let entry: Value = serde_json::from_str(line).expect("log line is JSON");
        if entry["event"] == "response_delivery_attempt"
            && entry["response_stage"] == "transport_finalized"
        {
            let trace = entry["trace_id"].as_str().expect("a trace").to_string();
            *counts.entry(trace).or_default() += 1;
        }
    }
    counts
}

#[tokio::test]
async fn r0_a_direct_answer_writes_one_record_under_the_calls_trace() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let counts = per_trace(&fx);
    assert_eq!(counts.len(), 1, "{counts:?}");
    assert!(counts.values().all(|n| *n == 1), "{counts:?}");
    let call = std::fs::read_to_string(&fx.path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|e| e.get("request_hash").is_some() && e.get("event").is_none())
        .expect("the call's own record");
    let trace = call["trace_id"].as_str().unwrap();
    assert_eq!(counts.get(trace), Some(&1), "{counts:?} vs {trace}");
}

#[tokio::test]
async fn r0_a_direct_refusal_writes_one_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, _) = post(&fx, "beta", &tools_call("t"), &Caller::Key).await;
    assert_ne!(status, StatusCode::OK);
    let counts = per_trace(&fx);
    assert_eq!(counts.len(), 1, "{counts:?}");
    assert!(counts.values().all(|n| *n == 1), "{counts:?}");
    // Guard (passes before the fixes): the record sits under the trace of the
    // invocation the refusal belongs to, not under some other trace.
    let calls = invocations(&fx);
    assert_eq!(calls.len(), 1, "premise: the call is recorded: {calls:?}");
    let trace = calls[0]["trace_id"].as_str().expect("a trace");
    assert_eq!(counts.get(trace), Some(&1), "{counts:?} vs {trace}");
}
