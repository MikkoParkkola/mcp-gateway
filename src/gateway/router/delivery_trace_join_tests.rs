// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A delivery record names the trace of the invocation it answers, on the
//! meta and the direct route, so a reader joins one delivery to exactly one
//! invocation by that key. The key is carried from the invocation, never
//! taken from whatever trace is current when the delivery is written.

use serde_json::Value;

use super::route_matrix_driver_tests::response::{HttpRoute, signed_recorded_call};

/// The invocation records in `entries`: a `route`, and no decision `kind`.
fn invocations(entries: &[Value]) -> Vec<&Value> {
    entries
        .iter()
        .filter(|entry| entry.get("route").is_some() && entry.get("kind").is_none())
        .collect()
}

#[tokio::test]
async fn a_delivery_joins_exactly_one_invocation_by_its_trace() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let recorded = signed_recorded_call(route).await;
        let invocations = invocations(&recorded.entries);
        assert!(
            invocations
                .iter()
                .all(|row| row["trace_id"].as_str().is_some()),
            "{route:?}: every invocation record names its trace: {invocations:?}"
        );
        assert_eq!(
            recorded.rows.len(),
            1,
            "{route:?}: one delivery: {:?}",
            recorded.rows
        );
        let delivery = &recorded.rows[0];
        let trace = delivery["trace_id"]
            .as_str()
            .unwrap_or_else(|| panic!("{route:?}: the delivery names a trace: {delivery}"));
        let joined: Vec<&&Value> = (invocations.iter())
            .filter(|row| row["trace_id"].as_str() == Some(trace))
            .collect();
        assert_eq!(
            joined.len(),
            1,
            "{route:?}: the delivery's trace {trace} joins exactly one invocation: {invocations:?}"
        );
    }
}
