// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A response gate that blocks an answer answers -32603, a code the plain
//! error mapping files under `error`. The gate decided a refusal, so the
//! invocation record says `denied`, beside the `response_gate` kind it
//! already names; the wire answer is unchanged. A backend's own error, which
//! no gate decided, still records `error`.

use super::*;

/// A `/mcp` `gateway_invoke` of alpha's `t` with no arguments, built field
/// by field.
fn meta_invoke() -> String {
    let mut target = serde_json::Map::new();
    target.insert("server".to_owned(), json!("alpha"));
    target.insert("tool".to_owned(), json!("t"));
    target.insert("arguments".to_owned(), json!({}));
    let mut params = serde_json::Map::new();
    params.insert("name".to_owned(), json!("gateway_invoke"));
    params.insert("arguments".to_owned(), Value::Object(target));
    let mut call = serde_json::Map::new();
    call.insert("jsonrpc".to_owned(), json!("2.0"));
    call.insert("id".to_owned(), json!(3));
    call.insert("method".to_owned(), json!("tools/call"));
    call.insert("params".to_owned(), Value::Object(params));
    Value::Object(call).to_string()
}

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
        Route::Meta => post_to(fx, "/mcp", &meta_invoke(), &Caller::Anonymous).await,
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
    let body = send_one(&fx, Route::Meta).await;
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

/// O4: anomaly screening blocks an answer with a critical finding, on each
/// route; both records say `denied`.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn o4_an_anomaly_block_is_recorded_as_denied_on_both_routes() {
    for route in [Route::Meta, Route::Direct] {
        let fx = gateway(MetaMode::InspectionBlocks, Some(planted_key_answer()), None).await;
        let body = send_one(&fx, route).await;
        assert_eq!(body["error"]["code"], -32603, "{route:?} premise: {body}");
        assert!(
            message_of(&body).contains("blocked by anomaly screening"),
            "{route:?} premise: {body}"
        );
        assert_gate_denied(&only_invocation(&fx), route);
    }
}

/// G1: a backend's own JSON-RPC error is no gate's refusal; on both routes
/// its record keeps `error`, with the backend's code.
#[tokio::test]
async fn g1_a_backend_error_still_records_error_on_both_routes() {
    for route in [Route::Meta, Route::Direct] {
        let fx = gateway(MetaMode::Plain, None, Some(-32001)).await;
        let body = send_one(&fx, route).await;
        let record = only_invocation(&fx);
        assert_eq!(record["error_code"], -32001, "{route:?}: {body} {record}");
        assert_eq!(record["outcome"], "error", "{route:?}: {record}");
    }
}
