// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8049: the remaining LOW rows of the frozen MIK-8022 design (r3b), beside
//! their harness in `direct_modern_shape_tests.rs`.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::super::direct_guards_fixture::{
    Answer, Fx, fixture, fixture_hardened_signed, send_with_headers,
};
use super::{BACKENDS, call_params, legacy, modern, post};
use crate::protocol::mrtr::{CHAIN_NONCE_META, IDEMPOTENCY_KEY_META};

/// Declares the modern revision in the body and omits `clientCapabilities`.
fn malformed_meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28"})
}

/// MIK-8040 (supersedes MIK-8022 DIRECT.3): a malformed-modern request on the
/// non-hardened route is refused before dispatch, as `/mcp` refuses it.
#[tokio::test]
async fn a_malformed_modern_request_is_refused_off_hardened() {
    for (backend, method, params) in [
        ("alpha", "tools/list", json!({})),
        ("alpha", "tools/call", call_params()),
        ("alpha-pt", "tools/call", call_params()),
    ] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let body = post(&fx, (backend, method), (false, 7), params, malformed_meta()).await;
        assert_eq!(body["error"]["code"], -32602, "{backend} {method}: {body}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "{backend} {method}");
    }
}

/// DIRECT.3: a `CachedError` replay is the stored error, byte for byte, in
/// either era, and is served without a second dispatch.
#[tokio::test]
async fn a_cached_error_replays_unchanged() {
    for backend in BACKENDS {
        for modern_era in [true, false] {
            let fx = fixture(Answer::RpcError(-32050), |_| {}).await;
            let meta = json!({ IDEMPOTENCY_KEY_META: "err" });
            let first = post(
                &fx,
                (backend, "tools/call"),
                (modern_era, 1),
                call_params(),
                meta.clone(),
            )
            .await;
            let again = post(
                &fx,
                (backend, "tools/call"),
                (modern_era, 2),
                call_params(),
                meta,
            )
            .await;
            let label = format!("{backend} modern={modern_era}");
            assert!(first["error"].is_object(), "{label}: an error: {first}");
            assert_eq!(
                (first["id"].clone(), again["id"].clone()),
                (json!(1), json!(2)),
                "{label}"
            );
            assert_eq!(again["error"], first["error"], "{label}");
            assert!(again.get("result").is_none(), "{label}: {again}");
            assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "{label}: re-dispatched");
        }
    }
}

/// `fixture` with the test signer emitting an origin link on request.
async fn chained() -> Fx {
    fixture(Answer::Ok, |meta| {
        meta.set_chain_signer(
            crate::gateway::chain_test_support::signer(),
            crate::config::ChainEmit::OnRequest,
        );
    })
    .await
}

/// Chain: a fresh modern delivery's origin link verifies over the shaped
/// body, and a same-key replay carries no new link.
#[tokio::test]
async fn the_chain_covers_the_shaped_body_and_a_replay_adds_no_link() {
    use crate::gateway::chain_test_support::{chain_of, verify_self};
    use crate::security::signature_chain::content_digest;
    for backend in BACKENDS {
        let fx = chained().await;
        let first = post(
            &fx,
            (backend, "tools/call"),
            (true, 1),
            call_params(),
            json!({ IDEMPOTENCY_KEY_META: "chained", CHAIN_NONCE_META: "nonce-1" }),
        )
        .await;
        let result = &first["result"];
        assert_eq!(result["resultType"], "complete", "{backend}: {first}");
        let chain = chain_of(result).unwrap_or_else(|| panic!("{backend}: no link: {first}"));
        let digest = content_digest(result).expect("a hashable result");
        verify_self(chain, &digest, "nonce-1")
            .unwrap_or_else(|e| panic!("{backend}: {e:?}: {first}"));

        let again = post(
            &fx,
            (backend, "tools/call"),
            (true, 2),
            call_params(),
            json!({ IDEMPOTENCY_KEY_META: "chained", CHAIN_NONCE_META: "nonce-2" }),
        )
        .await;
        assert_eq!(again["id"], 2, "{backend}: {again}");
        assert!(
            chain_of(&again["result"]).is_none(),
            "{backend}: a replay emitted a link: {again}"
        );
        // The replay is the first answer, less only the first answer's link.
        let mut unlinked = first["result"].clone();
        if let Some(meta) = unlinked["_meta"].as_object_mut() {
            meta.remove(crate::gateway::chain_test_support::CHAIN_KEY);
        }
        assert_eq!(again["result"], unlinked, "{backend}: {again}");
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            1,
            "{backend}: re-dispatched"
        );
    }
}

/// The signature the gateway would put on `body`'s result for `nonce`,
/// recomputed with the signature member removed.
fn resigned(body: &Value, nonce: &str) -> Value {
    use super::super::direct_guards_fixture::SIGNING_KEY;
    let ts = body["result"]["_signature"]["ts"]
        .as_u64()
        .unwrap_or_else(|| panic!("a signing time: {body}"));
    let id = body["id"].as_i64().expect("a numeric id");
    let mut unsigned = body["result"].clone();
    unsigned
        .as_object_mut()
        .expect("an object")
        .remove("_signature");
    let mut again =
        crate::protocol::JsonRpcResponse::success(crate::protocol::RequestId::Number(id), unsigned);
    crate::security::message_signing::MessageSigner::new(
        SIGNING_KEY.as_bytes().to_vec(),
        None,
        "hardened".into(),
    )
    .sign_json_rpc_response_at(&mut again, Some(nonce), ts)
    .expect("re-sign");
    again.result.expect("a result")["_signature"]["sig"].clone()
}

/// Each signature on a first delivery and on its replay verifies against its
/// own request's nonce, and not the other's.
#[tokio::test]
async fn each_replay_signature_answers_its_own_nonce() {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::Ok, true).await;
        let mut bodies = Vec::new();
        for (id, nonce) in [(1, "first-nonce"), (2, "second-nonce")] {
            let meta = json!({ IDEMPOTENCY_KEY_META: "signed", NONCE_META: nonce });
            let body = post(
                &fx,
                (backend, "tools/call"),
                (true, id),
                call_params(),
                meta,
            )
            .await;
            assert_eq!(body["id"], id, "{backend}: {body}");
            assert_eq!(
                body["result"]["_signature"]["sig"],
                resigned(&body, nonce),
                "{backend} #{id}: {body}"
            );
            bodies.push(body);
        }
        assert_ne!(
            bodies[1]["result"]["_signature"]["sig"],
            resigned(&bodies[1], "first-nonce"),
            "{backend}: the replay answered the first nonce"
        );
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            1,
            "{backend}: re-dispatched"
        );
    }
}

/// Refusal parity: under every posture a malformed-modern call is refused
/// before dispatch, as on `/mcp` (MIK-8040, superseding MIK-8022 DIRECT.3).
#[tokio::test]
async fn a_malformed_modern_call_is_refused_under_every_posture() {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    for backend in BACKENDS {
        let hardened = fixture_hardened_signed(Answer::Ok, false).await;
        let mut meta = malformed_meta();
        meta[NONCE_META] = json!("parity");
        let body = post(
            &hardened,
            (backend, "tools/call"),
            (false, 7),
            call_params(),
            meta,
        )
        .await;
        assert_eq!(body["error"]["code"], -32602, "{backend}: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("clientCapabilities")),
            "{backend}: refused for the missing field: {body}"
        );
        assert_eq!(hardened.calls.load(Ordering::SeqCst), 0, "{backend}");
        // The same refusal, status and body, as `/mcp` gives the same request
        // when the header mirrors the body's revision, so both routes reach
        // the shape check (a body-only declaration is MIK-8162).
        let params = json!({ "_meta": malformed_meta() });
        let mirrored = [("mcp-protocol-version", "2026-07-28")];
        let (mcp_status, mcp) = send_with_headers(
            &hardened,
            "/mcp",
            super::KEY,
            "tools/list",
            params.clone(),
            None,
            &mirrored,
        )
        .await;
        let (direct_status, direct) = send_with_headers(
            &hardened,
            &format!("/mcp/{backend}"),
            super::KEY,
            "tools/list",
            params,
            None,
            &mirrored,
        )
        .await;
        assert_eq!(mcp_status, axum::http::StatusCode::BAD_REQUEST, "{mcp}");
        assert_eq!(direct_status, mcp_status, "{backend}: {direct}");
        assert_eq!(direct["error"], mcp["error"], "{backend}");

        let open = fixture(Answer::Ok, |_| {}).await;
        let body = post(
            &open,
            (backend, "tools/call"),
            (false, 7),
            call_params(),
            malformed_meta(),
        )
        .await;
        assert_eq!(body["error"]["code"], -32602, "{backend}: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("clientCapabilities")),
            "{backend}: refused for the missing field: {body}"
        );
        assert_eq!(open.calls.load(Ordering::SeqCst), 0, "{backend}");
    }
}

/// A legacy backend's -32601 to a relayed modern `server/discover` reaches
/// the client unchanged, as it does for a legacy request.
#[tokio::test]
async fn a_legacy_backends_method_not_found_to_discover_is_relayed() {
    let fx = fixture(Answer::RpcError(-32601), |_| {}).await;
    let shaped = modern(&fx, "alpha", "server/discover", json!({})).await;
    let plain = legacy(&fx, "alpha", "server/discover", json!({})).await;
    assert_eq!(shaped["error"]["code"], -32601, "{shaped}");
    assert!(shaped.get("result").is_none(), "{shaped}");
    assert_eq!(shaped["error"], plain["error"], "{shaped} vs {plain}");
}

/// A non-numeric `ttlMs` on a later page is no hint: the valid one stands.
#[tokio::test]
async fn a_non_numeric_page_hint_is_ignored() {
    let fx = fixture(Answer::NonNumeric(7000), |_| {}).await;
    let body = modern(&fx, "alpha", "tools/list", json!({})).await;
    assert_eq!(body["result"]["ttlMs"], 7000, "{body}");
    assert!(
        body["result"]["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|t| t["name"] == "later")),
        "the second page was read: {body}"
    );
}
