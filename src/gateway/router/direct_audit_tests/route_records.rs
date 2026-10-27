// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2 route records: what one direct call writes, refusals included,
//! and which requests are not invocations at all.

use super::*;

/// MIK-7570.ATTEST.1: the attestation token is stripped from the request
/// after the audit hash, so the hash still covers the params as sent (D2-e)
/// while the token string itself never reaches the log.
#[tokio::test]
async fn direct_audit_hash_covers_the_token_as_sent() {
    let fx = fixture(Setup::default()).await;
    let token = "tok-audit-as-sent";
    let params = json!({"name": "t", "arguments": {"q": 1},
                        "_meta": {(crate::protocol::mrtr::ATTESTATION_META): token}});
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params});
    let (status, answer) = post(&fx, "alpha", &body.to_string(), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let expected = format!("sha256:{}", crate::hashing::canonical_json_sha256(&params));
    assert_eq!(only_invocation(&fx)["request_hash"], expected.as_str());
    let raw = std::fs::read_to_string(&fx.path).unwrap();
    assert!(!raw.contains(token), "the token reached the audit log");
}

/// D2-T1. A verified caller's direct tool call writes one full record.
#[tokio::test]
async fn direct_tool_call_writes_invocation_record() {
    let fx = fixture(Setup::default()).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let entry = only_invocation(&fx);
    assert_eq!(entry["route"], "direct", "{entry}");
    assert_eq!(entry["server"], "alpha");
    assert_eq!(entry["tool"], "t");
    assert_eq!(entry["outcome"], "ok");
    assert_eq!(entry["schema_version"], 2);
    assert!(entry.get("error_code").is_none(), "{entry}");
    assert_eq!(entry["who"]["subject"], "1", "{entry}");
    assert_eq!(entry["who"]["authority"], "https://a.example.invalid");
    let params = json!({"name": "t", "arguments": {"q": 1}});
    let expected = format!("sha256:{}", crate::hashing::canonical_json_sha256(&params));
    assert_eq!(
        entry["request_hash"],
        expected.as_str(),
        "hash of params as sent"
    );
    let delivered = format!("sha256:{}", crate::hashing::canonical_json_sha256(&body));
    assert_eq!(
        entry["response_hash"],
        delivered.as_str(),
        "hash of the body delivered"
    );
    let raw = std::fs::read_to_string(&fx.path).unwrap();
    assert!(
        !raw.contains("one@example.invalid"),
        "an email reached the log"
    );
}

/// D2-T1b. D1's writer names its route too.
#[tokio::test]
async fn meta_invocation_record_says_route_meta() {
    let fx = fixture(Setup::default()).await;
    let caller = MetaMcpCallerContext {
        is_modern: false,
        era: crate::protocol::meta::Era::Legacy,
        ..anonymous_caller()
    };
    let _ = fx
        .state
        .meta_mcp
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_invoke",
            json!({"server": "alpha", "tool": "t", "arguments": {}}),
            None,
            caller,
        )
        .await;
    assert_eq!(only_invocation(&fx)["route"], "meta");
}

/// D2-T2. A scope refusal is a `denied` record that names the tool. The
/// wire answers the backend miss (MIK-8387 S4); the record keeps -32003.
#[tokio::test]
async fn direct_scope_refusal_is_denied_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "beta", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], -32001, "{body}");

    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "denied", "{entry}");
    assert_eq!(entry["error_code"], -32003);
    assert_eq!(entry["server"], "beta");
    assert_eq!(entry["tool"], "t", "the refusal carries the tool name");
    assert_eq!(entry["who"]["credential_kind"], "api_key");
    assert!(entry.get("response_hash").is_none(), "{entry}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0);
}

/// D2-T3. An authorizer refusal (`denied_tools`) is `denied`.
#[tokio::test]
async fn direct_authorizer_refusal_is_denied_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(Some(vec!["t".to_string()]))),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    // MIK-8361: the caller reads the absent name; the record keeps the denial.
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(
        body["result"]["content"][0]["text"],
        crate::backend::text_absent("t"),
        "{body}"
    );
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "never dispatched");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "denied", "{entry}");
    assert_eq!(entry["tool"], "t");
}

/// D2-T5, positive control. Only tool calls are invocations.
#[tokio::test]
async fn direct_tools_list_writes_no_record() {
    let fx = fixture(Setup::default()).await;
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
    let (status, body) = post(&fx, "alpha", &list, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}

/// D2-T6. With auth on, a failed append withholds the result.
#[tokio::test]
async fn direct_append_failure_withholds_result() {
    let fx = fixture(Setup {
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log.fail_next_append_for_test();
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], -32005, "{body}");
    assert_eq!(body["id"], 5, "the caller's id is kept");
    assert!(
        body.get("result").is_none(),
        "a result was delivered: {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "the call did run");
}

/// D2-T6b, positive control. With auth off the same failure is only logged.
#[tokio::test]
async fn direct_append_failure_best_effort_still_answers() {
    let fx = fixture(Setup::default()).await;
    fx.log.fail_next_append_for_test();
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("result").is_some(), "{body}");
}

/// D2-T7, positive control. The C5 agent-identity refusal, checked before
/// the body is read, writes no record (as on the meta route).
#[tokio::test]
async fn agent_identity_refusal_writes_no_record() {
    let fx = fixture(Setup {
        agent_identity: Some(crate::config::AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec![],
            ..Default::default()
        }),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}

/// D2-T8, positive control. Moving the scope check below the body read must
/// not make a missing backend distinguishable from a forbidden one: both
/// answer the backend miss (MIK-8387 S4), and the record keeps the refusal.
#[tokio::test]
async fn scoped_key_gets_the_miss_for_a_missing_backend() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "nope", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], -32001, "{body}");
    let entry = only_invocation(&fx);
    assert_eq!(
        (&entry["outcome"], &entry["tool"]),
        (&json!("denied"), &json!("t"))
    );
}

/// D2-T9. A tools/call with no params names no tool, so there is nothing to
/// authorize: it is refused (400, -32602), never forwarded, and recorded as
/// `invalid` with no `tool`.
#[tokio::test]
async fn malformed_direct_tools_call_is_invalid() {
    let fx = fixture(Setup::default()).await;
    let bare = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}).to_string();
    let (status, body) = post(&fx, "alpha", &bare, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "reached the backend");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "invalid", "{entry}");
    assert_eq!(entry["error_code"], -32602, "{entry}");
    assert!(entry.get("tool").is_none(), "{entry}");
}

/// D2-T9c. Params with no `name`, or an empty one, are refused the same way.
/// Restoring the early `return None` in `apply_backend_tool_call_security`
/// forwards them unauthorized and turns this red.
#[tokio::test]
async fn nameless_direct_tools_call_is_refused() {
    let fx = fixture(Setup::default()).await;
    for params in [
        json!({"arguments": {}}),
        json!({"name": "", "arguments": {}}),
    ] {
        let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params});
        let (status, answer) = post(&fx, "alpha", &body.to_string(), &Caller::Anonymous).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{params}: {answer}");
        assert_eq!(answer["error"]["code"], -32602, "{params}: {answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "reached the backend");
    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    for entry in all {
        assert_eq!(entry["outcome"], "invalid", "{entry}");
        assert!(entry.get("tool").is_none(), "{entry}");
    }
}

/// D2-T9d. An envelope `parse_request` refuses (a wrong `jsonrpc` version)
/// is `invalid` too. The slot is filled before the parse, so moving the fill
/// below it turns this red.
#[tokio::test]
async fn unparseable_direct_tools_call_envelope_is_invalid() {
    let fx = fixture(Setup::default()).await;
    let bad = json!({"jsonrpc": "1.0", "id": 1, "method": "tools/call"}).to_string();
    let (status, body) = post(&fx, "alpha", &bad, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "invalid", "{entry}");
    assert_eq!(entry["error_code"], -32600, "{entry}");
    assert!(entry.get("tool").is_none(), "{entry}");
}

/// D2-T9b, positive control. A body that is not JSON has no method, so no
/// record, the same as the meta route.
#[tokio::test]
async fn non_json_body_writes_no_record() {
    let fx = fixture(Setup::default()).await;
    let (status, _) = post(&fx, "alpha", "not json", &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}
