// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7669 (MIK-7407.RESPONSE.1, .2, .5): a direct-route answer writes the
//! `response_delivery_attempt` record that `POST /mcp` and stdio write, at the
//! same point (after the outbound judge) and with the same fields.

use super::*;

/// Every delivery-attempt record in the log.
fn delivery_attempts(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect()
}

fn only_attempt(fx: &Fixture) -> Value {
    let mut all = delivery_attempts(fx);
    assert_eq!(all.len(), 1, "expected one delivery attempt: {all:?}");
    all.remove(0)
}

fn hash_of(value: &Value) -> String {
    format!("sha256:{}", crate::hashing::canonical_json_sha256(value))
}

/// The record names the body as delivered, the caller, the backend as the
/// server and the tool, under the stage and encoding the meta route uses.
#[tokio::test]
async fn a_direct_tool_call_writes_a_delivery_attempt() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event = only_attempt(&fx);
    assert_eq!(event["response_stage"], "transport_finalized", "{event}");
    assert_eq!(event["response_hash_encoding"], "sorted-json-v1");
    assert_eq!(event["response_hash"], hash_of(&body).as_str(), "{event}");
    assert_eq!(event["caller"], "alpha-client");
    assert_eq!(event["server"], "alpha");
    assert_eq!(event["tool"], "t");
    assert_eq!(event["session_id"], "");
    assert_eq!(event["outcome"], "ok", "{event}");
}

/// Every answer is recorded, not only a `tools/call`: the meta route logs
/// unscanned methods too, under the method as the tool.
#[tokio::test]
async fn a_direct_tools_list_writes_a_delivery_attempt() {
    let fx = fixture(Setup::default()).await;
    let list = json!({"jsonrpc": "2.0", "id": 6, "method": "tools/list"}).to_string();
    let (status, body) = post(&fx, "alpha", &list, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event = only_attempt(&fx);
    assert_eq!(event["response_hash"], hash_of(&body).as_str(), "{event}");
    assert_eq!(event["caller"], "anonymous");
    assert_eq!(event["tool"], "tools/list");
}

/// A refusal is an answer too: recorded with its error outcome.
#[tokio::test]
async fn a_direct_refusal_writes_a_delivery_attempt() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "beta", &tools_call("t"), &Caller::Key).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    let event = only_attempt(&fx);
    assert_eq!(event["response_hash"], hash_of(&body).as_str(), "{event}");
    assert_eq!(event["error_code"], body["error"]["code"], "{event}");
}

/// Bot-review ledger L1254: a notification refused with 429 and the body `{}`
/// carries no JSON-RPC error code, so a record read from the body alone said
/// `ok`. The HTTP status decides, as for the invocation record.
#[tokio::test]
async fn a_refused_direct_notification_is_not_recorded_as_ok() {
    let fx = fixture(Setup {
        notify_refused: true,
        ..Setup::default()
    })
    .await;
    let note =
        json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed", "params": {}});
    let (status, body) = post(&fx, "alpha", &note.to_string(), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let event = only_attempt(&fx);
    assert_ne!(
        event["outcome"], "ok",
        "a refusal recorded as delivered: {event}"
    );
}

/// Under `FailClosed` an answer whose delivery cannot be recorded is withheld,
/// as on the meta route: the audit-unavailable refusal, with the request id.
#[tokio::test]
async fn an_unrecorded_direct_delivery_is_withheld() {
    let fx = fixture(Setup {
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log
        .fail_next_append_of_kind_for_test("response_delivery_attempt");
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], -32005, "{body}");
    assert_eq!(body["id"], 5, "{body}");
    assert!(
        body.get("result").is_none(),
        "the result was delivered: {body}"
    );
}
