// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 R0 (`POST /mcp`): the audit-unavailable replacement writes
//! no `transport_finalized` record and no second write follows; a replay
//! writes one under its own new trace and adds none under the original's.

use std::collections::BTreeMap;

use super::meta_replay::{keyed_invoke, post_modern};
use super::one_record_meta::{call_traces, per_trace, rows};
use super::*;

#[tokio::test]
async fn r0_an_audit_unavailable_replacement_writes_no_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log
        .fail_next_append_of_kind_for_test("response_delivery_attempt");
    let (_, answer) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert!(answer.contains("-32005"), "premise: withheld: {answer}");
    assert_eq!(
        call_traces(&fx).len(),
        1,
        "premise: the call's record landed"
    );
    let deliveries = rows(&fx)
        .into_iter()
        .filter(|e| e["event"] == "response_delivery_attempt")
        .count();
    assert_eq!(deliveries, 0, "no delivery record, and no second write");
    assert!(per_trace(&fx).is_empty());
}

#[tokio::test]
async fn r0_a_replay_writes_one_record_under_its_own_trace() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, first) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let original = call_traces(&fx);
    assert_eq!(per_trace(&fx), BTreeMap::from([(original[0].clone(), 1)]));
    let (status, second) = post_modern(&fx, &keyed_invoke(2).0).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: a replay");
    let traces = call_traces(&fx);
    assert_eq!(traces.len(), 2, "{traces:?}");
    assert_ne!(traces[0], traces[1], "the replay has its own trace");
    let expected = BTreeMap::from([(traces[0].clone(), 1), (traces[1].clone(), 1)]);
    assert_eq!(per_trace(&fx), expected, "none added under the original");
}
