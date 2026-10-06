// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2472: a meta-route call answered from a completed execution (an idempotent
//! replay) writes an invocation record like any other delivered call (D1-d).
//! D1-f needs no cell of its own: a replay was already withheld on a failed
//! write through its `response_delivery_attempt` record, so a fault cell
//! passes on the base and proves nothing about this record.

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
    post_modern_named(fx, "gateway_invoke", body).await
}

/// [`post_modern`] for a `tools/call` of `name`.
async fn post_modern_named(fx: &Fixture, name: &str, body: &str) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("authorization", "Bearer k")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
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
    let (first_body, _) = keyed_invoke(1);
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
    // The request hash covers the call as the meta layer hashed it (its
    // `_meta` merged in, D1-d.1), so the replay's must equal the original's.
    assert_eq!(replay["request_hash"], original["request_hash"], "{replay}");
    assert!(replay.get("response_hash").is_some(), "{replay}");
    assert_eq!(
        replay["response_hash"], original["response_hash"],
        "{replay}"
    );
    assert_eq!(replay["who"]["credential_kind"], "api_key", "{replay}");
}

/// MIK-7641 (#2522): admission reads the tool's `arguments` as an object and
/// as the equivalent JSON string as one operation, so a retry that sends the
/// string form is a replay. Its record carries the request hash the first
/// execution hashed, not one over the retry as sent.
#[tokio::test]
async fn meta_replay_of_a_string_arguments_retry_keeps_the_original_request_hash() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, first) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let mut retry: Value = serde_json::from_str(&keyed_invoke(2).0).unwrap();
    retry["params"]["arguments"]["arguments"] = json!(json!({"q": 1}).to_string());
    let (status, second) = post_modern(&fx, &retry.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the string-form retry must be a replay: {second}"
    );

    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(all[1]["request_hash"], all[0]["request_hash"], "{all:?}");
}

/// A replayed failure is recorded as the failure it was: the delivered replay
/// wraps the tool result in a successful envelope, so the record takes the
/// first execution's own outcome, code and response hash, kept server-side.
#[tokio::test]
async fn meta_replay_of_a_failure_keeps_its_outcome() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        backend_error: Some(-32010),
        ..Setup::default()
    })
    .await;
    let (status, first) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = post_modern(&fx, &keyed_invoke(2).0).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "{second}");

    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    let (original, replay) = (&all[0], &all[1]);
    assert_ne!(
        original["outcome"], "ok",
        "the first run failed: {original}"
    );
    for field in ["outcome", "error_code", "response_hash", "request_hash"] {
        assert_eq!(replay[field], original[field], "{field}: {replay}");
    }
}

/// MIK-7735. A backend's own `-32001` / `-32004` answer is the peer's
/// refusal, not the gateway's: the first execution and its replay both
/// record `error`, with the peer's code, never `denied`.
#[tokio::test]
async fn meta_replay_of_a_peer_refusal_code_is_an_error_not_a_denial() {
    for code in [-32001, -32004] {
        let fx = fixture(Setup {
            auth: Some(key_for_alpha(None)),
            backend_error: Some(code),
            ..Setup::default()
        })
        .await;
        let (status, first) = post_modern(&fx, &keyed_invoke(1).0).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let (status, second) = post_modern(&fx, &keyed_invoke(2).0).await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "{second}");

        let all = invocations(&fx);
        assert_eq!(all.len(), 2, "{code}: {all:?}");
        for record in &all {
            assert_eq!(record["outcome"], "error", "{code}: {record}");
            assert_eq!(record["error_code"], code, "{code}: {record}");
        }
    }
}

/// MIK-7116.MIN.1 T31. A meta replay is a cached delivery: its record names
/// the delivered value's tenants (hashed) and says no backend ran for it.
/// Attribution reads the firewall's `arg_keys`, so the cell needs the feature.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn meta_replay_record_carries_delivered_tenants() {
    let rows = json!({"rows": [{"customer_id": "cust-9"}]});
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        reply: Some(
            json!({"content": [{"type": "text", "text": rows.to_string()}],
                           "isError": false}),
        ),
        tenant_limit: Some(0),
        ..Setup::default()
    })
    .await;
    for id in [1, 2] {
        let (status, answer) = post_modern(&fx, &keyed_invoke(id).0).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second call must replay"
    );

    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    let replay = &all[1];
    assert_eq!(replay["attribution"], "cached_delivery", "{replay}");
    let tenant = crate::security::hash_argument(&json!("cust-9"));
    assert!(
        replay["tenants"]
            .as_array()
            .is_some_and(|tenants| tenants.contains(&json!(tenant))),
        "{replay}"
    );
    assert!(replay.get("data_classes").is_none(), "{replay}");
}

/// MIK-7718 (#2521): the first call's invocation record cannot be written
/// under fail-closed, so its value is withheld. A replay of the same key must
/// not record that never-delivered value as delivered `ok` with its hash.
#[tokio::test]
async fn meta_replay_after_a_failed_record_is_not_ok() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log.fail_next_append_for_test();
    let (_, first) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert!(
        first.contains("-32005"),
        "the first value must be withheld: {first}"
    );
    let (_, second) = post_modern(&fx, &keyed_invoke(2).0).await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second call must be a replay: {second}"
    );
    let delivered_ok: Vec<Value> = invocations(&fx)
        .into_iter()
        .filter(|record| record["outcome"] == "ok" && record.get("response_hash").is_some())
        .collect();
    assert!(
        delivered_ok.is_empty(),
        "a never-delivered value was recorded as delivered: {delivered_ok:?}"
    );
}

/// MIK-7799: the delivery record of the first call is refused under
/// fail-closed, so its value is withheld and the stored delivery holds that
/// refusal. A replay of the key answers the refusal; it must not deliver the
/// value the first call never delivered.
#[tokio::test]
async fn meta_replay_after_a_refused_delivery_record_stays_withheld() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log
        .fail_next_append_of_kind_for_test("response_delivery_attempt");
    let (_, first) = post_modern(&fx, &keyed_invoke(1).0).await;
    assert!(
        first.contains("-32005"),
        "the first value must be withheld: {first}"
    );
    let (_, second) = post_modern(&fx, &keyed_invoke(2).0).await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second call must be a replay: {second}"
    );
    assert!(
        second.contains("-32005"),
        "the replay must not deliver the withheld value: {second}"
    );
}

/// MIK-7645 AC1: a surfaced tool called by its own name replays through the
/// same record as `gateway_invoke`: the re-issued key writes a record with
/// the original's request hash, response hash and outcome.
#[tokio::test]
async fn meta_replay_of_a_surfaced_tool_writes_an_invocation_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        meta_mode: MetaMode::SurfacedT,
        ..Setup::default()
    })
    .await;
    let body = |id: u32| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
               "params": {"name": "t", "arguments": {"q": 1},
                          "_meta": {IDEMPOTENCY_KEY_META: "key-2488",
                                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                    "io.modelcontextprotocol/clientCapabilities": {}}}})
        .to_string()
    };
    let (status, first) = post_modern_named(&fx, "t", &body(1)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = post_modern_named(&fx, "t", &body(2)).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second call must be a replay: {second}"
    );

    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "one record per delivered call: {all:?}");
    let (original, replay) = (&all[0], &all[1]);
    assert_eq!(replay["server"], "alpha", "{replay}");
    assert_eq!(replay["tool"], "t", "{replay}");
    for field in ["request_hash", "response_hash", "outcome"] {
        assert_eq!(replay[field], original[field], "{field}: {replay}");
    }
}
