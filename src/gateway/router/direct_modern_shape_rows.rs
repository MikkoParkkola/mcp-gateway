// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MIK-8022 rows, beside their harness in `direct_modern_shape_tests.rs`.

use serde_json::{Value, json};

use super::super::direct_guards_fixture::{Answer, fixture};
use super::{BACKENDS, CACHEABLE, call_params, legacy, missing, modern, params_for, post};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// DIRECT.1: a modern listing from a legacy backend carries all three fields.
#[tokio::test]
async fn a_modern_tools_list_from_a_legacy_backend_carries_the_fields() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let body = modern(&fx, "alpha", "tools/list", json!({})).await;
    assert!(body["result"]["tools"].is_array(), "a listing: {body}");
    let gone = missing(&body, true);
    assert!(gone.is_empty(), "missing {gone:?}: {body}");
}

/// DIRECT.2: a backend's own hint survives the drain and the allowlist
/// rebuild, under the shaper's cap.
#[tokio::test]
async fn a_modern_tools_list_from_a_modern_backend_keeps_the_fields() {
    let fx = fixture(Answer::ModernList, |_| {}).await;
    let body = modern(&fx, "alpha", "tools/list", json!({})).await;
    assert!(body["result"]["tools"].is_array(), "a listing: {body}");
    let gone = missing(&body, true);
    assert!(gone.is_empty(), "missing {gone:?}: {body}");
    assert_eq!(body["result"]["ttlMs"], 5000, "the backend hint: {body}");
}

/// DIRECT.1 on both dispatch arms: sanitized (`alpha`) and plain (`alpha-pt`).
#[tokio::test]
async fn a_modern_tools_call_carries_the_result_type() {
    for backend in BACKENDS {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let body = modern(&fx, backend, "tools/call", call_params()).await;
        assert!(body["result"]["content"].is_array(), "{backend}: {body}");
        let gone = missing(&body, false);
        assert!(gone.is_empty(), "{backend} missing {gone:?}: {body}");
        assert!(
            body["result"]["_meta"][crate::protocol::meta::KEY_SERVER_INFO].is_object(),
            "{backend}: the gateway names itself: {body}"
        );
    }
}

/// All five cacheable methods, not two.
#[tokio::test]
async fn every_modern_cacheable_result_carries_the_cache_pair() {
    for method in CACHEABLE {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let body = modern(&fx, "alpha", method, params_for(method)).await;
        assert!(body.get("error").is_none(), "{method}: {body}");
        let gone = missing(&body, true);
        assert!(gone.is_empty(), "{method} missing {gone:?}: {body}");
        assert_eq!(body["result"]["cacheScope"], "private", "{method}: {body}");
    }
}

/// DIRECT.3: a legacy client gains none of the fields on any method, and a
/// modern backend's carried list hint is removed again.
#[tokio::test]
async fn legacy_results_gain_no_fields() {
    for answer in [Answer::Ok, Answer::ModernList] {
        let fx = fixture(answer, |_| {}).await;
        let list = legacy(&fx, "alpha", "tools/list", json!({})).await;
        assert!(list["result"]["tools"].is_array(), "a listing: {list}");
        for key in ["resultType", "ttlMs", "cacheScope"] {
            assert!(
                list["result"].get(key).is_none(),
                "list gained {key}: {list}"
            );
        }
        for backend in BACKENDS {
            let call = legacy(&fx, backend, "tools/call", call_params()).await;
            assert!(call["result"].get("resultType").is_none(), "{call}");
            assert!(
                call["result"]["_meta"]
                    .get(crate::protocol::meta::KEY_SERVER_INFO)
                    .is_none(),
                "{call}"
            );
        }
    }
}

/// A backend hint on a legacy read is relayed as sent; only the list's
/// carried hint is removed.
#[tokio::test]
async fn a_legacy_read_keeps_the_backend_hint() {
    let fx = fixture(Answer::ModernList, |_| {}).await;
    let body = legacy(&fx, "alpha", "resources/read", json!({"uri": "res://x"})).await;
    assert_eq!(body["result"]["ttlMs"], 3000, "{body}");
    assert!(body["result"].get("resultType").is_none(), "{body}");
}

/// A modern `server/discover` relayed to a backend gains `resultType`.
#[tokio::test]
async fn a_relayed_modern_discover_gains_the_result_type() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let body = modern(&fx, "alpha", "server/discover", json!({})).await;
    assert!(body["result"].is_object(), "relayed as a result: {body}");
    assert_eq!(body["result"]["resultType"], "complete", "{body}");
}

/// The drain keeps the shortest valid hint across pages; an absent hint
/// erases nothing, `0` survives, and the shaper caps an over-long hint.
#[tokio::test]
async fn the_list_hint_is_the_shortest_page_hint_under_the_cap() {
    for ((first, second), want) in [
        ((Some(9000), Some(4000)), 4000),
        ((Some(9000), None), 9000),
        ((Some(5000), Some(0)), 0),
        (
            (Some(120_000), None),
            crate::protocol::cacheable::LIST_TTL_MS,
        ),
    ] {
        let fx = fixture(Answer::Paged(first, second), |_| {}).await;
        let body = modern(&fx, "alpha", "tools/list", json!({})).await;
        assert_eq!(
            body["result"]["ttlMs"], want,
            "{first:?}/{second:?}: {body}"
        );
    }
}

/// A call carrying an idempotency key `key`, as request `id`.
async fn keyed(
    fx: &super::super::direct_guards_fixture::Fx,
    backend: &str,
    (modern, id): (bool, i64),
    key: &str,
) -> Value {
    let meta = json!({ IDEMPOTENCY_KEY_META: key });
    post(
        fx,
        (backend, "tools/call"),
        (modern, id),
        call_params(),
        meta,
    )
    .await
}

/// A replay answers its own request: its id, and its own era's shape. The
/// cache holds the unshaped answer, so neither era leaks into the other.
#[tokio::test]
async fn a_replay_is_shaped_for_its_own_request() {
    for backend in BACKENDS {
        // Same era: the replay's result is the first delivery's.
        let fx = fixture(Answer::Ok, |_| {}).await;
        let first = keyed(&fx, backend, (true, 1), "same").await;
        let again = keyed(&fx, backend, (true, 2), "same").await;
        assert_eq!(
            again["id"], 2,
            "{backend}: the replay echoes its id: {again}"
        );
        assert_eq!(first["result"], again["result"], "{backend}");

        // Legacy first, modern replay: shaped for the modern request.
        let fx = fixture(Answer::Ok, |_| {}).await;
        let _ = keyed(&fx, backend, (false, 1), "up").await;
        let again = keyed(&fx, backend, (true, 2), "up").await;
        assert_eq!(
            again["result"]["resultType"], "complete",
            "{backend}: {again}"
        );

        // Modern first, legacy replay: the legacy body a first delivery gets.
        let fx = fixture(Answer::Ok, |_| {}).await;
        let _ = keyed(&fx, backend, (true, 1), "down").await;
        let again = keyed(&fx, backend, (false, 2), "down").await;
        let fresh = legacy(
            &fixture(Answer::Ok, |_| {}).await,
            backend,
            "tools/call",
            call_params(),
        )
        .await;
        assert!(
            again["result"].get("resultType").is_none(),
            "{backend}: {again}"
        );
        assert_eq!(again["result"], fresh["result"], "{backend}");
    }
}

/// Lead ruling 2026-10-07: a replay of a backend `"public"` scope is
/// `"private"` on the wire. The serialiser (`serialize_delivered_result`)
/// and signing both clamp; this pins the bytes a retrying caller receives.
#[tokio::test]
async fn a_replayed_public_scope_is_private_on_the_wire() {
    for backend in BACKENDS {
        let fx = fixture(Answer::PublicScope, |_| {}).await;
        for (id, era) in [(1, true), (2, true), (3, false)] {
            let body = keyed(&fx, backend, (era, id), "scoped").await;
            assert_eq!(
                body["result"]["cacheScope"], "private",
                "{backend} #{id}: {body}"
            );
        }
    }
}

/// Signing covers what is sent: the MAC recomputed over the delivered,
/// shaped body (signature removed) matches the one delivered.
#[tokio::test]
async fn signing_covers_the_shaped_body() {
    use super::super::direct_guards_fixture::{SIGNING_KEY, fixture_hardened_signed};
    use crate::gateway::meta_mcp::signing::NONCE_META;
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::Ok, true).await;
        let nonce = format!("{backend}-shape");
        let meta = json!({ NONCE_META: nonce });
        let body = post(&fx, (backend, "tools/call"), (true, 1), call_params(), meta).await;
        assert_eq!(
            body["result"]["resultType"], "complete",
            "{backend}: {body}"
        );
        let delivered = body["result"]["_signature"].clone();
        let ts = delivered["ts"].as_u64().expect("a signing time");
        let mut unsigned = body["result"].clone();
        unsigned
            .as_object_mut()
            .expect("an object")
            .remove("_signature");
        let mut again = crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            unsigned,
        );
        crate::security::message_signing::MessageSigner::new(
            SIGNING_KEY.as_bytes().to_vec(),
            None,
            "hardened".into(),
        )
        .sign_json_rpc_response_at(&mut again, Some(&nonce), ts)
        .expect("re-sign");
        let recomputed = again.result.expect("a result")["_signature"]["sig"].clone();
        assert_eq!(
            recomputed, delivered["sig"],
            "{backend}: signed a different body"
        );
    }
}

/// The route reads a request's era exactly as `/mcp` does: one
/// duplicate-safe header read, then the shared classifier. Refusal parity
/// holds only under `hardened`; elsewhere the route forwards unrefused.
#[test]
fn era_reading_matches_mcp() {
    use crate::protocol::meta::{Era, classify_request};
    let modern_meta = json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }});
    let cases: [(&str, Option<&Value>, &[&str]); 5] = [
        ("body only", Some(&modern_meta), &[]),
        ("header only", None, &["2026-07-28"]),
        ("both", Some(&modern_meta), &["2026-07-28"]),
        (
            "doubled header",
            Some(&modern_meta),
            &["2026-07-28", "2026-07-28"],
        ),
        ("neither", None, &[]),
    ];
    for (label, params, versions) in cases {
        let mut headers = axum::http::HeaderMap::new();
        for v in versions {
            headers.append("mcp-protocol-version", v.parse().expect("a header"));
        }
        let (shape, declared) =
            super::super::hardened_elicitation::classify_direct(&headers, "tools/list", params);
        assert_eq!(
            shape.era(),
            classify_request(params, declared).era(),
            "{label}"
        );
        if label == "both" {
            assert_eq!(shape.era(), Era::Modern, "{label}");
        }
    }
}
