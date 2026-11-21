// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A response gate that blocks an answer answers -32603, a code the plain
//! error mapping files under `error`. The gate decided a refusal, so the
//! invocation record says `denied`, beside the `response_gate` kind it
//! already names; the wire answer is unchanged. A backend's own error, which
//! no gate decided, still records `error`.

use super::counting::{attach, meta_invoke, totals};
use super::*;

/// The counters after one call the gateway refused: [calls 1, blocks 1,
/// errors 0, firewall refusals 0, cache hits 0].
const ONE_GATE_REFUSAL: [u64; 5] = [1, 1, 0, 0, 0];

/// The counters after one call the backend failed: [calls 1, blocks 0,
/// errors 1, firewall refusals 0, cache hits 0].
const ONE_BACKEND_ERROR: [u64; 5] = [1, 0, 1, 0, 0];

/// Which route a row sends its one call down.
#[derive(Clone, Copy, Debug)]
enum Route {
    Meta,
    Direct,
}

impl Route {
    /// The record's spelling of this route.
    const fn spelled(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Direct => "direct",
        }
    }
}

/// One anonymous call of alpha's `t` down `route`; the answer body.
async fn send_one(fx: &Fixture, route: Route) -> Value {
    let answered = match route {
        Route::Meta => {
            let call = meta_invoke("alpha", "t", &json!({}));
            post_to(fx, "/mcp", &call, &Caller::Anonymous).await
        }
        Route::Direct => post_to(fx, "/mcp/alpha", &tools_call("t"), &Caller::Anonymous).await,
    };
    answered.1
}

/// A gateway where `mode` is armed and the backend answers `reply` (its
/// default text answer when `None`) or fails with `backend_error`.
async fn gateway(mode: MetaMode, reply: Option<Value>, backend_error: Option<i32>) -> Fixture {
    let setup = Setup {
        meta_mode: mode,
        reply,
        backend_error,
        ..Setup::default()
    };
    fixture(setup).await
}

/// An answer carrying a planted access key, which response inspection in
/// action mode blocks as a critical finding.
#[cfg(feature = "firewall")]
fn planted_key_answer() -> Value {
    let key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
    json!({"content": [{"type": "text", "text": format!("key={key}")}], "isError": false})
}

/// The checks every gate-refused record shares.
fn assert_gate_denied(record: &Value, route: Route) {
    let spelled = route.spelled();
    assert_eq!(record["route"], spelled, "{record}");
    assert_eq!(
        record["decision"]["kind"], "response_gate",
        "{spelled}: {record}"
    );
    assert_eq!(record["error_code"], -32603, "{spelled}: {record}");
    assert_eq!(record["outcome"], "denied", "{spelled}: {record}");
}

/// The answer's error message, empty when it has none.
fn message_of(body: &Value) -> &str {
    body["error"]["message"].as_str().unwrap_or_default()
}

/// O2: the fail-closed response contract blocks the answer on `/mcp`. The
/// answer is the gate's -32603; the record says `denied`.
#[tokio::test]
async fn o2_a_contract_block_is_recorded_as_denied() {
    let fx = gateway(MetaMode::ContractRefuses, None, None).await;
    let store = attach(&fx);
    let body = send_one(&fx, Route::Meta).await;
    assert_eq!(totals(&store), ONE_GATE_REFUSAL, "{body}");
    assert_eq!(body["error"]["code"], -32603, "premise: {body}");
    assert!(
        message_of(&body).contains("blocked by contract gate"),
        "premise: {body}"
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "premise: the call was sent"
    );
    assert_gate_denied(&only_invocation(&fx), Route::Meta);
}

/// O4's one route: anomaly screening blocks an answer with a critical
/// finding; the record says `denied` and the counters count a block.
#[cfg(feature = "firewall")]
async fn an_anomaly_block_on(route: Route) {
    let fx = gateway(MetaMode::InspectionBlocks, Some(planted_key_answer()), None).await;
    let store = attach(&fx);
    let body = send_one(&fx, route).await;
    assert_eq!(body["error"]["code"], -32603, "{route:?} premise: {body}");
    assert!(
        message_of(&body).contains("blocked by anomaly screening"),
        "{route:?} premise: {body}"
    );
    assert_gate_denied(&only_invocation(&fx), route);
    assert_eq!(totals(&store), ONE_GATE_REFUSAL, "{route:?}");
}

/// O4 on `/mcp`.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn o4_meta_an_anomaly_block_is_recorded_as_denied() {
    an_anomaly_block_on(Route::Meta).await;
}

/// O4 on the direct route.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn o4_direct_an_anomaly_block_is_recorded_as_denied() {
    an_anomaly_block_on(Route::Direct).await;
}

/// G1's one route: a backend's own JSON-RPC error is no gate's refusal; its
/// record keeps `error` with the backend's code and no refusing check, and
/// the counters count an error.
async fn a_backend_error_on(route: Route) {
    let fx = gateway(MetaMode::Plain, None, Some(-32001)).await;
    let store = attach(&fx);
    let body = send_one(&fx, route).await;
    let record = only_invocation(&fx);
    assert_eq!(record["error_code"], -32001, "{route:?}: {body} {record}");
    assert_eq!(record["outcome"], "error", "{route:?}: {record}");
    assert_eq!(
        record["decision"]["kind"], "default_allow",
        "{route:?}: no check refused: {record}"
    );
    assert_eq!(totals(&store), ONE_BACKEND_ERROR, "{route:?}");
}

/// G1 on `/mcp`.
#[tokio::test]
async fn g1_meta_a_backend_error_still_records_error() {
    a_backend_error_on(Route::Meta).await;
}

/// G1 on the direct route.
#[tokio::test]
async fn g1_direct_a_backend_error_still_records_error() {
    a_backend_error_on(Route::Direct).await;
}
