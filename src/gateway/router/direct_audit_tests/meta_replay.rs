// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2472: a meta-route call answered from a completed execution (an idempotent
//! replay) writes an invocation record like any other delivered call (D1-d).

use super::*;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// A keyed modern `gateway_invoke` of `alpha`/`t`: the frame the admission
/// lease replays when the key is re-issued.
fn keyed_invoke(id: u32) -> (String, Value) {
    let arguments = json!({"server": "alpha", "tool": "t", "arguments": {"q": 1}});
    let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                      "params": {"name": "gateway_invoke", "arguments": arguments,
                                 "_meta": {IDEMPOTENCY_KEY_META: "key-2472",
                                           "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                           "io.modelcontextprotocol/clientCapabilities": {}}}});
    (body.to_string(), arguments)
}

/// POST as key `k` on the 2026-07-28 revision.
async fn post_modern(fx: &Fixture, body: &str) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("authorization", "Bearer k")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The re-issued key is answered from the first execution without reaching
/// the backend, and still writes its own record: route `meta`, the same
/// target and request hash as the first, and a response hash for the value
/// delivered again.
#[tokio::test]
async fn meta_replay_writes_an_invocation_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (first_body, arguments) = keyed_invoke(1);
    let (status, first) = post_modern(&fx, &first_body).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = post_modern(&fx, &keyed_invoke(2).0).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second call must be a replay: {second}"
    );

    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "one record per delivered call: {all:?}");
    let (original, replay) = (&all[0], &all[1]);
    assert_eq!(replay["route"], "meta", "{replay}");
    assert_eq!(replay["outcome"], "ok", "{replay}");
    assert_eq!(replay["server"], "alpha", "{replay}");
    assert_eq!(replay["tool"], "t", "{replay}");
    assert_eq!(
        replay["request_hash"],
        format!(
            "sha256:{}",
            crate::hashing::canonical_json_sha256(&arguments)
        )
        .as_str(),
        "{replay}"
    );
    assert_eq!(replay["request_hash"], original["request_hash"], "{replay}");
    assert!(replay.get("response_hash").is_some(), "{replay}");
    assert_eq!(replay["who"]["credential_kind"], "api_key", "{replay}");
}

/// D1-f: under `FailClosed`, a replay whose record cannot be written is
/// withheld with the audit-unavailable code, as a first execution would be.
#[tokio::test]
async fn meta_replay_is_withheld_when_its_record_fails() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    let (status, first) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    fx.log.fail_next_append_for_test();
    let (_, second) = post_modern(&fx, &keyed_invoke(2).0).await;
    assert!(
        second.contains("-32005"),
        "the replay was delivered: {second}"
    );
    assert!(!second.contains("\"isError\":false"), "{second}");
}
