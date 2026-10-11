// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Trace correlation, non-tool methods, backend errors and the audit-failure 503 contract.

use super::*;

/// D2-T11. The correlation key is the caller's W3C trace id when it sent
/// one, else a minted trace id; never the `mcp-session-id` it sent (D2-f).
#[tokio::test]
async fn direct_record_correlates_on_trace_id() {
    let fx = fixture(Setup::default()).await;
    let otel = "4bf92f3577b34da6a3ce929d0e0e4736";
    let traced = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "t", "arguments": {},
        "_meta": {"traceparent": format!("00-{otel}-00f067aa0ba902b7-01")}}})
    .to_string();
    let _ = post(&fx, "alpha", &traced, &Caller::Anonymous).await;
    let _ = post(&fx, "alpha", &tools_call("t"), &Caller::Session).await;

    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(all[0]["correlation_source"], "otel_trace_id", "{}", all[0]);
    assert_eq!(all[0]["session_id"], otel);
    assert_eq!(all[0]["otel_trace_id"], otel);
    assert_eq!(all[1]["correlation_source"], "trace_id", "{}", all[1]);
    assert_eq!(all[1]["session_id"], all[1]["trace_id"]);
}

/// D2-T5b, positive control. D1 audits invocations only, so the direct
/// route's other caller-data methods write no record either.
#[tokio::test]
async fn direct_non_tool_methods_write_no_record() {
    let fx = fixture(Setup::default()).await;
    for (method, params) in [
        ("resources/read", json!({"uri": "file:///x"})),
        ("prompts/get", json!({"name": "p"})),
    ] {
        let body = json!({"jsonrpc": "2.0", "id": 3, "method": method, "params": params});
        let _ = post(&fx, "alpha", &body.to_string(), &Caller::Anonymous).await;
    }
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}

/// D2-T10. A backend's own -32005 is the backend's error, not the log being
/// down: it is recorded, never suppressed.
#[tokio::test]
async fn backend_503_32005_is_recorded_as_error() {
    let fx = fixture(Setup {
        backend_error: Some(-32005),
        ..Setup::default()
    })
    .await;
    let (_, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(body["error"]["code"], -32005, "{body}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "error", "{entry}");
    assert_eq!(entry["error_code"], -32005);
}

/// F20 on the direct route (added by #1092 after the F20 design): a stalled
/// audit disk withholds the result with 503 while the write is still held
/// (only the bound can do that), instead of pinning a runtime worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_append_on_a_stalled_disk_is_bounded() {
    let fx = fixture(Setup {
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    let bound = Duration::from_millis(200);
    let release = fx.log.stall_next_write_for_test(bound);
    // A 503 with the write still held is the bound: an unbounded append
    // would wait for the write and succeed.
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], -32005, "{body}");
    assert!(fx.log.is_stalled());
    release.release();
}

/// #2283. Under `FailClosed`, a refusal that answers `id: null` still owes the
/// caller the id it sent when the audit write fails and the answer becomes 503.
async fn failed_audit_503_echoes_the_request_id(
    backend: &str,
    auth: Option<AuthConfig>,
    caller: Caller,
) {
    let fx = fixture(Setup {
        auth,
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log.fail_next_append_for_test();
    let (status, body) = post(&fx, backend, &tools_call("t"), &caller).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], -32005, "{body}");
    assert_eq!(body["id"], 5, "the request id was dropped: {body}");
}

#[tokio::test]
async fn failed_audit_503_keeps_the_request_id_on_a_scope_refusal() {
    failed_audit_503_echoes_the_request_id("beta", Some(key_for_alpha(None)), Caller::Key).await;
}

#[tokio::test]
async fn failed_audit_503_keeps_the_request_id_on_an_unrecognised_backend() {
    // Unscoped, so the backend lookup is reached, not the scope refusal.
    failed_audit_503_echoes_the_request_id("nope", None, Caller::Anonymous).await;
}
