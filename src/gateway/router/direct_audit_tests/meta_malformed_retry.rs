// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7660 AC3: a `/mcp` `tools/call` refused for malformed retry fields is
//! refused before any target is resolved, so it writes one `invalid` record
//! with no target, through the same writer as the other meta refusals.

use super::*;

/// A `gateway_invoke` of `alpha`/`t` whose `requestState` is not a string,
/// and the arguments object as sent.
fn malformed_retry() -> (String, Value) {
    let arguments = json!({"server": "alpha", "tool": "t", "arguments": {}});
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                      "params": {"name": "gateway_invoke", "arguments": arguments,
                                 "requestState": 5}});
    (body.to_string(), arguments)
}

#[tokio::test]
async fn a_malformed_retry_writes_one_invalid_record_with_no_target() {
    let fx = fixture(Setup::default()).await;
    let (body, arguments) = malformed_retry();
    let (status, answer) = post_to(&fx, "/mcp", &body, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"]["code"], -32602, "{answer}");

    let entry = only_invocation(&fx);
    assert_eq!(entry["route"], "meta", "{entry}");
    assert_eq!(entry["outcome"], "invalid", "{entry}");
    assert_eq!(entry["error_code"], -32602, "{entry}");
    assert_eq!(entry["server"], "", "{entry}");
    assert!(entry.get("tool").is_none(), "{entry}");
    let hash = format!(
        "sha256:{}",
        crate::hashing::canonical_json_sha256(&arguments)
    );
    assert_eq!(entry["request_hash"], hash.as_str(), "{entry}");
    assert!(entry.get("response_hash").is_none(), "{entry}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0);
}

/// D1-f, as for the admin path: a record that cannot be appended answers
/// 503/-32005 under `FailClosed`, and the original refusal under `BestEffort`.
#[tokio::test]
async fn a_malformed_retry_whose_record_fails_follows_the_policy() {
    for (fail_closed, status, code) in [
        (true, StatusCode::SERVICE_UNAVAILABLE, -32005),
        (false, StatusCode::BAD_REQUEST, -32602),
    ] {
        let fx = fixture(Setup {
            fail_closed,
            ..Setup::default()
        })
        .await;
        fx.log.fail_next_append_for_test();
        let (body, _) = malformed_retry();
        let (got, answer) = post_to(&fx, "/mcp", &body, &Caller::Anonymous).await;
        assert_eq!(got, status, "fail_closed {fail_closed}: {answer}");
        assert_eq!(
            answer["error"]["code"], code,
            "fail_closed {fail_closed}: {answer}"
        );
        assert_eq!(answer["id"], 5, "the request id was dropped: {answer}");
        // The injected failure was spent on this refusal's record: the next
        // refusal is recorded. A refusal that skipped its write would leave
        // the failure for the next one, which then writes nothing.
        let (_, answer) = post_to(&fx, "/mcp", &body, &Caller::Anonymous).await;
        assert_eq!(answer["error"]["code"], -32602, "{answer}");
        let entry = only_invocation(&fx);
        assert_eq!(
            entry["outcome"], "invalid",
            "fail_closed {fail_closed}: {entry}"
        );
    }
}

/// A modern-era call has no session. Its refusal is keyed by a trace id
/// minted for it, never by the empty session every such call shares (the
/// meta writer's ladder: caller trace id, session, trace id).
#[tokio::test]
async fn a_sessionless_refusal_is_keyed_by_its_own_trace_id() {
    let fx = fixture(Setup::default()).await;
    let (body, _) = malformed_retry();
    let mut body: Value = serde_json::from_str(&body).unwrap();
    body["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                     "io.modelcontextprotocol/clientCapabilities": {}});
    let body = body.to_string();
    for _ in 0..2 {
        let (status, answer) = post_to(&fx, "/mcp", &body, &Caller::Modern).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        // The retry check, not the earlier modern-metadata one (also -32602).
        let message = answer["error"]["message"].as_str().unwrap_or_default();
        assert!(message.starts_with("malformed request fields"), "{answer}");
    }
    let entries = invocations(&fx);
    assert_eq!(entries.len(), 2, "{entries:?}");
    for entry in &entries {
        assert_eq!(entry["correlation_source"], "trace_id", "{entry}");
        assert_ne!(entry["session_id"], "", "{entry}");
    }
    assert_ne!(
        entries[0]["session_id"], entries[1]["session_id"],
        "two unrelated calls share one correlation key: {entries:?}"
    );
}
