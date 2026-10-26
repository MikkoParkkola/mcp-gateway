// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An answer this request did not produce (a replay, a composite's) states no
//! effect and no findings: its delivery record omits both fields rather than
//! claim `delivered` for bytes no scan of this request judged.

use super::meta_replay::{keyed_invoke, post_modern};
use super::*;

/// Every delivery record in the log, in order.
fn deliveries(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect()
}

/// The first delivery states its effect; the replay states none.
fn assert_first_vouched_replay_not(fx: &Fixture) {
    let rows = deliveries(fx);
    let [first, replay] = rows.as_slice() else {
        panic!("two delivery records: {rows:?}");
    };
    assert_eq!(first["response_effect"], "delivered", "{first}");
    for field in ["response_effect", "response_findings"] {
        assert!(replay.get(field).is_none(), "{field}: {replay}");
    }
}

/// A direct idempotent replay (7a) serves the first run's answer.
#[tokio::test]
async fn a_direct_idempotent_replay_states_no_effect() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::Idempotent,
        ..Setup::default()
    })
    .await;
    for _ in 0..2 {
        let call = direct_call("cust-1", Some("k-unvouched"));
        let (status, answer) = post_modern_as(&fx, "/mcp/alpha", &call, &Caller::ModernOidc).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: a replay");
    assert_first_vouched_replay_not(&fx);
}

/// A meta admission replay serves the first run's answer.
#[tokio::test]
async fn a_meta_admission_replay_states_no_effect() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    for id in [1, 2] {
        let (status, answer) = post_modern(&fx, &keyed_invoke(id).0).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: a replay");
    assert_first_vouched_replay_not(&fx);
}

/// A chain delivers a composite: no one step's facts describe it.
#[tokio::test]
async fn a_composite_states_no_effect() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::CodeMode,
        ..Setup::default()
    })
    .await;
    let chain = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"chain": [{"tool": "alpha:t", "arguments": {}}]}}});
    let (status, answer) = post_to(&fx, "/mcp", &chain.to_string(), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: the step ran");
    let rows = deliveries(&fx);
    let [row] = rows.as_slice() else {
        panic!("one delivery record: {rows:?}");
    };
    for field in ["response_effect", "response_findings"] {
        assert!(row.get(field).is_none(), "{field}: {row}");
    }
}
