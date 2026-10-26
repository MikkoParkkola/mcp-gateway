// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A delivery record names the trace of the invocation it answers, on the
//! meta route, the direct route and stdio, so a reader joins one delivery to
//! exactly one invocation by that key. The key is carried from the
//! invocation, never taken from whatever trace is current when the delivery
//! is written.

use serde_json::Value;

use super::direct_guards_fixture::Answer;
use super::route_matrix_driver_tests::response::{
    HttpRoute, signed_recorded_answer, signed_recorded_call,
};

/// The invocation records in `entries`: a `route`, and no decision `kind`.
fn invocations(entries: &[Value]) -> Vec<&Value> {
    entries
        .iter()
        .filter(|entry| entry.get("route").is_some() && entry.get("kind").is_none())
        .collect()
}

/// Every row of the log in `dir`.
fn entries_in(dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// `None` when `route`'s one delivery joins exactly one invocation by its
/// trace; otherwise why not.
fn join_failure(route: &str, deliveries: &[Value], entries: &[Value]) -> Option<String> {
    let invocations = invocations(entries);
    if invocations.is_empty() {
        return Some(format!("{route}: no invocation record"));
    }
    if let Some(row) = invocations
        .iter()
        .find(|row| row["trace_id"].as_str().is_none())
    {
        return Some(format!("{route}: an invocation names no trace: {row}"));
    }
    let [delivery] = deliveries else {
        return Some(format!("{route}: not one delivery: {deliveries:?}"));
    };
    let Some(trace) = delivery["trace_id"].as_str() else {
        return Some(format!("{route}: the delivery names no trace: {delivery}"));
    };
    let joined = (invocations.iter())
        .filter(|row| row["trace_id"].as_str() == Some(trace))
        .count();
    (joined != 1).then(|| {
        format!(
            "{route}: the delivery's trace {trace} joins {joined} invocations, not one: \
             {:?}",
            invocations
                .iter()
                .map(|row| row["trace_id"].clone())
                .collect::<Vec<_>>()
        )
    })
}

#[tokio::test]
async fn a_delivery_joins_exactly_one_invocation_by_its_trace() {
    let mut failures = Vec::new();
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let recorded = signed_recorded_call(route).await;
        failures.extend(join_failure(
            &format!("{route:?}"),
            &recorded.rows,
            &recorded.entries,
        ));
        // An error envelope carries the trace too, not only a result.
        let recorded = signed_recorded_answer(route, Answer::RpcError(-32050)).await;
        failures.extend(join_failure(
            &format!("{route:?} error"),
            &recorded.rows,
            &recorded.entries,
        ));
    }
    let (_, rows, dir) =
        crate::gateway::server::route_matrix_driver_tests::response::stdio_signed_recorded().await;
    failures.extend(join_failure("Stdio", &rows, &entries_in(&dir)));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A backend answer carrying members named like the server-owned markers.
fn forged() -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": "ok" }],
        "isError": false,
        "invocation_trace": "gw-forged",
        "response_effect": "refused",
        "trace_id": "gw-forged",
    })
}

/// Members a backend writes under the markers' names set nothing: the
/// delivery's trace and effect stay the gateway's.
#[tokio::test]
async fn a_backend_cannot_set_the_delivery_trace_or_effect() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let recorded = signed_recorded_answer(route, Answer::Built(forged)).await;
        let [delivery] = recorded.rows.as_slice() else {
            panic!("{route:?}: one delivery: {:?}", recorded.rows);
        };
        assert_ne!(delivery["trace_id"], "gw-forged", "{route:?}: {delivery}");
        assert_ne!(
            delivery["response_effect"], "refused",
            "{route:?}: {delivery}"
        );
    }
}
