// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `/mcp` `gateway_invoke` refused for a missing `server` or `tool` is
//! answered as before and leaves one `invalid` -32602 record whose decision
//! kind is the request's form (`syntax`), never `unrecorded`.

use super::*;

/// `gateway_invoke` with `arguments`, numbered 5.
fn invoke_with(arguments: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": "gateway_invoke", "arguments": arguments}})
    .to_string()
}

/// The answer's text for a missing `key`, rendered by the error type the
/// refusal is built from, so the row follows its prefix.
fn missing_answer(key: &str) -> String {
    crate::Error::json_rpc(
        crate::error::rpc_codes::INVALID_PARAMS,
        format!("Missing '{key}' parameter"),
    )
    .to_string()
}

#[tokio::test]
async fn missing_server_is_recorded_as_syntax_on_mcp() {
    for (arguments, missing) in [
        (json!({"tool": "t"}), "server"),
        (json!({"server": "alpha"}), "tool"),
    ] {
        let fx = fixture(Setup::default()).await;
        let (status, answer) =
            post_to(&fx, "/mcp", &invoke_with(&arguments), &Caller::Anonymous).await;
        assert_eq!(answer["error"]["code"], -32602, "{missing}: {answer}");
        assert_eq!(
            answer["error"]["message"],
            missing_answer(missing),
            "{missing}: {answer}"
        );
        assert_eq!(answer["id"], 5, "{missing}: {answer}");
        let all = invocations(&fx);
        let [entry] = all.as_slice() else {
            panic!("{missing}: exactly one record (HTTP {status}): {all:?}; answer {answer}");
        };
        assert_eq!(entry["outcome"], "invalid", "{missing}: {entry}");
        assert_eq!(entry["error_code"], -32602, "{missing}: {entry}");
        assert_eq!(entry["decision"]["kind"], "syntax", "{missing}: {entry}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "{missing}: never sent");
    }
}

/// An admission refusal that is not a missing target: a modern (sessionless)
/// `gateway_set_profile` is refused in admission as a protocol limit. Its
/// answer is as before; it now leaves one record, outcome `invalid` (an
/// `Error::Protocol`), kind `unrecorded` (admission notes no kind for it).
#[tokio::test]
async fn an_admission_refusal_is_recorded_on_mcp() {
    let fx = fixture(Setup::default()).await;
    let call = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "gateway_set_profile", "arguments": {"profile": "p"}}});
    let (status, answer) = post_modern_as(&fx, "/mcp", &call.to_string(), &Caller::Modern).await;
    let code = crate::Error::Protocol(String::new()).to_rpc_code();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"]["code"], code, "{answer}");
    assert_eq!(answer["id"], 5, "{answer}");
    let all = invocations(&fx);
    let [entry] = all.as_slice() else {
        panic!("exactly one record (HTTP {status}): {all:?}; answer {answer}");
    };
    assert_eq!(entry["outcome"], "invalid", "{entry}");
    assert_eq!(entry["error_code"], code, "{entry}");
    assert_eq!(entry["decision"]["kind"], "unrecorded", "{entry}");
    assert_eq!(entry["tool"], "gateway_set_profile", "{entry}");
}

/// The sessionless `gateway_set_profile` refusal (it reaches admission and,
/// before the writer, was answered -32600) under a fail-closed log that
/// cannot be written: answered as the log being unavailable, with no record.
#[tokio::test]
async fn an_admission_refusal_under_an_unwritable_fail_closed_log_answers_unavailable_on_mcp() {
    let fx = fixture(Setup {
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log.set_append_failure_for_test(true);
    let call = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "gateway_set_profile", "arguments": {"profile": "p"}}});
    let (status, answer) = post_modern_as(&fx, "/mcp", &call.to_string(), &Caller::Modern).await;
    assert_eq!(
        (status, answer["error"]["code"].as_i64()),
        (StatusCode::SERVICE_UNAVAILABLE, Some(-32005)),
        "{answer}"
    );
    assert!(invocations(&fx).is_empty(), "no record: {answer}");
}

/// A keyed `tools/call` of `name` with `arguments`, numbered 5.
fn keyed(name: &str, arguments: Value, key: &str) -> String {
    let mut call = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": name,
                      "_meta": {(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key}}});
    call["params"]["arguments"] = arguments;
    call.to_string()
}

/// The one record whose code is `code`.
fn the_record(fx: &Fixture, code: i64, answer: &Value) -> Value {
    let records: Vec<Value> = invocations(fx)
        .into_iter()
        .filter(|entry| entry["error_code"] == code)
        .collect();
    let [record] = records.as_slice() else {
        panic!("exactly one {code} record: {records:?}; answer {answer}");
    };
    record.clone()
}

/// Status and data, the cross-era replay: a keyed legacy `gateway_invoke`
/// runs, the same key from the modern era is refused with HTTP 409 and its
/// gateway-authored data, as before (the cross-era rows), and now leaves one
/// record: `denied` (a noted refusal's code is promoted), kind `unrecorded`.
#[tokio::test]
async fn an_admission_refusal_keeps_its_status_and_data_on_mcp() {
    let fx = fixture(Setup::default()).await;
    let call = keyed(
        "gateway_invoke",
        json!({"server": "alpha", "tool": "t", "arguments": {}}),
        "k-era",
    );
    let (_, first) = post_to(&fx, "/mcp", &call, &Caller::Oidc).await;
    assert!(
        first.get("result").is_some(),
        "premise: the first runs: {first}"
    );
    let (status, answer) = post_modern_as(&fx, "/mcp", &call, &Caller::ModernOidc).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    let error = &answer["error"];
    assert_eq!(error["code"], 409, "{answer}");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("JSON-RPC error 409:")),
        "{answer}"
    );
    assert_eq!(
        error["data"],
        json!({"reason": "idempotency_era_mismatch", "stored_era": "legacy",
               "request_era": "modern", "already_executed": true}),
        "{answer}"
    );
    assert_eq!(answer["id"], 5, "{answer}");
    let record = the_record(&fx, 409, &answer);
    assert_eq!(record["outcome"], "denied", "{record}");
    assert_eq!(record["decision"]["kind"], "unrecorded", "{record}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "the backend ran once");
}
