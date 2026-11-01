// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 seal rules, split out of `provenance_delivery_tests.rs` for the
//! file-size ceiling: a receipt is sealed only in the request that minted it,
//! once, over the bytes as delivered.

use super::*;

#[tokio::test]
async fn replayed_receipt_at_a_results_position_is_never_sealed() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let captured = with_minted_receipts(Box::pin(async { captured_receipt(&meta).await })).await;
    let mut evil = MetaMcp::new(answering_backend(json!({
        "content": [{"type": "text", "text": "ok"}],
        "results": [{
            "step": 0,
            "tool": "x",
            "result": {"forged": true, "_meta": {"provenance": captured}},
        }],
    })));
    dual_signed_meta(&mut evil);
    let parsed = replayed_text(&evil).await;
    let step = parsed
        .pointer("/results/0/result")
        .expect("the planted step result");
    assert!(
        step.pointer("/_meta/provenance").is_some(),
        "the planted receipt survived delivery: {parsed}"
    );
    assert!(
        step.pointer("/_meta/provenance/public_signature").is_none(),
        "a receipt minted in another request is never sealed at a results position: {parsed}"
    );
}

#[tokio::test]
async fn replayed_receipt_at_an_output_position_is_never_sealed() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let captured = with_minted_receipts(Box::pin(async { captured_receipt(&meta).await })).await;
    let mut evil = MetaMcp::new(answering_backend(json!({
        "output": {"x": {"forged": true, "_meta": {"provenance": captured}}},
    })));
    dual_signed_meta(&mut evil);
    let parsed = replayed_text(&evil).await;
    let step = parsed
        .pointer("/output/x")
        .expect("the planted step output");
    assert!(
        step.pointer("/_meta/provenance").is_some(),
        "the planted receipt survived delivery: {parsed}"
    );
    assert!(
        step.pointer("/_meta/provenance/public_signature").is_none(),
        "a receipt minted in another request is never sealed at an output position: {parsed}"
    );
}

#[tokio::test]
async fn replayed_top_level_receipt_in_a_resources_read_answer_is_never_sealed() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let captured = with_minted_receipts(Box::pin(async { captured_receipt(&meta).await })).await;
    let response = JsonRpcResponse::success(
        RequestId::Number(43),
        json!({
            "contents": [{"uri": "res://x", "text": "ok"}],
            "_meta": {"provenance": captured},
        }),
    );
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "resources/read", "resources/read");
    let response = with_minted_receipts(Box::pin(async {
        meta.finalize_routed(response, &delivery, None)
    }))
    .await;
    let delivered = response.result.expect("a result");
    assert!(
        delivered.pointer("/_meta/provenance").is_some(),
        "the planted receipt survived delivery: {delivered}"
    );
    assert!(
        delivered
            .pointer("/_meta/provenance/public_signature")
            .is_none(),
        "a receipt minted in another request is never sealed on resources/read: {delivered}"
    );
}

#[tokio::test]
async fn a_receipt_not_minted_in_this_request_is_never_sealed() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let stamped = with_minted_receipts(Box::pin(async {
        meta.stamp_direct_result(
            json!({"content": [{"type": "text", "text": "ok"}]}),
            "remote_docs",
            "search",
            None,
        )
    }))
    .await;
    let mut delivered = stamped;
    with_minted_receipts(Box::pin(async {
        meta.seal_public_provenance(&mut delivered);
    }))
    .await;
    assert!(
        delivered
            .pointer("/_meta/provenance/public_signature")
            .is_none(),
        "a receipt minted in another request is never sealed: {delivered}"
    );
}

#[tokio::test]
async fn a_minted_receipt_is_sealed_at_most_once() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    with_minted_receipts(Box::pin(async {
        let stamped = meta.stamp_direct_result(
            json!({"content": [{"type": "text", "text": "a"}]}),
            "remote_docs",
            "search",
            None,
        );
        let mut first = stamped.clone();
        meta.seal_public_provenance(&mut first);
        assert!(
            first
                .pointer("/_meta/provenance/public_signature")
                .is_some(),
            "the first seal signs the minted receipt: {first}"
        );
        let echo = stamped
            .pointer("/_meta/provenance")
            .expect("a receipt")
            .clone();
        let mut second = json!({
            "content": [{"type": "text", "text": "b"}],
            "_meta": {"provenance": echo},
        });
        meta.seal_public_provenance(&mut second);
        assert!(
            second
                .pointer("/_meta/provenance/public_signature")
                .is_none(),
            "the same receipt is never sealed twice: {second}"
        );
    }))
    .await;
}

#[test]
fn a_seal_with_no_scope_fails_closed() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let mut value = meta.stamp_direct_result(
        json!({"content": [{"type": "text", "text": "ok"}]}),
        "remote_docs",
        "search",
        None,
    );
    meta.seal_public_provenance(&mut value);
    assert!(
        value
            .pointer("/_meta/provenance/public_signature")
            .is_none(),
        "a seal with no scope seals nothing and never panics: {value}"
    );
}

/// R17 (MIK-8398 C1g): a live `gateway_invoke` whose backend answer carries
/// `cacheScope: "public"` is sealed over the delivered bytes. The tool is
/// called by its surfaced name, so the backend's own envelope is the outer
/// result (Native). A `tools/call` answer may not carry `cacheScope`, so
/// ingress removes it and the delivered bytes differ from the backend's.
/// The oracle is the serialized wire form, so a seal over any other bytes,
/// or any post-seal mutation, fails.
#[tokio::test]
async fn a_public_scope_is_sealed_as_delivered_on_the_meta_route() {
    with_minted_receipts(Box::pin(async {
        let mut meta = MetaMcp::new(answering_backend(json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
            "cacheScope": "public",
        })))
        .with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "remote_docs".to_string(),
            tool: "search".to_string(),
        }]);
        dual_signed_meta(&mut meta);
        let trust = trust_set();
        let caller = allow_all_ctx_named(Some("alice"), None);
        let response = meta
            .handle_tools_call(
                RequestId::Number(17),
                "search",
                json!({}),
                Some("session-1"),
                caller,
            )
            .await;
        let targets: Vec<ResponsePolicyTarget> = Vec::new();
        let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
        let response = meta.finalize_routed(response, &delivery, None);
        let wire = serde_json::to_value(&response).expect("the wire form serializes");
        let delivered = &wire["result"];
        // A `tools/call` answer may not carry `cacheScope`: ingress removed
        // it, so the delivered bytes differ from the backend's.
        assert_eq!(
            delivered.get("cacheScope"),
            None,
            "ingress removed the backend's scope: {wire}"
        );
        let prov = delivered
            .pointer("/_meta/provenance")
            .expect("the outer result carries the receipt")
            .clone();
        assert!(
            prov.get("public_signature").is_some(),
            "the outer receipt carries a public signature: {delivered}"
        );
        let verified = verify_public(&prov, &trust, Some(delivered)).expect("the receipt verifies");
        assert_eq!(verified.status, VerifyStatus::Bound);
    }))
    .await;
}

/// R20 (MIK-8398 C1g): a chain step's bytes are unchanged by the seal. Step
/// results sit inside `content[0].text`, which the wire never clamps, and
/// the step's seal verifies against those bytes. A `tools/call` step can no
/// longer carry `cacheScope` (ingress removes it), so a clamp at the step
/// seal sites has nothing to change there.
#[tokio::test]
async fn chain_step_bytes_are_unchanged_by_the_seal() {
    with_minted_receipts(Box::pin(async {
        let mut meta = MetaMcp::new(answering_backend(json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
            "cacheScope": "public",
        })))
        .with_code_mode(true);
        dual_signed_meta(&mut meta);
        let trust = trust_set();
        let caller = allow_all_ctx_named(Some("alice"), None);
        let response = meta
            .handle_tools_call(
                RequestId::Number(20),
                "gateway_execute",
                json!({"chain": [
                    {"tool": "remote_docs:search", "arguments": {}},
                ]}),
                Some("session-1"),
                caller,
            )
            .await;
        let targets: Vec<ResponsePolicyTarget> = Vec::new();
        let delivery = delivery_ctx(&targets, "tools/call", "gateway_execute");
        let response = meta.finalize_routed(response, &delivery, None);
        let delivered = response.result.expect("a result");
        let text = delivered
            .pointer("/content/0/text")
            .and_then(|v| v.as_str())
            .expect("a wrapped reply carries text");
        let parsed: serde_json::Value =
            serde_json::from_str(text).expect("the text parses as JSON");
        let step_result = parsed.pointer("/results/0/result").expect("a step result");
        // Ingress removed the backend's scope before the step was recorded,
        // so there is no scope left for a step clamp to change.
        assert_eq!(
            step_result.get("cacheScope"),
            None,
            "ingress removed the backend's scope: {parsed}"
        );
        let prov = step_result
            .pointer("/_meta/provenance")
            .expect("a step receipt");
        let verified =
            verify_public(prov, &trust, Some(step_result)).expect("the step receipt verifies");
        assert_eq!(verified.status, VerifyStatus::Bound);
    }))
    .await;
}
