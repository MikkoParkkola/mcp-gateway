// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `/mcp` receipt rides on the outer result (MIK-8398): the wrapped reply
//! lifts `_meta.provenance` out of `content[0].text`, and `tasks/get` seals
//! the stored result it serves.
use super::*;
use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::gateway::meta_mcp::response_security::{
    ResponseCorrelation, ResponseDeliveryContext, ResponsePolicyTarget,
};
use crate::protocol::{ChainSource, JsonRpcResponse};
use crate::trust::provenance_public::{
    ProvenancePublicSigner, TrustSet, VerifyStatus, verify_public,
};

fn dual_signed_meta(meta: &mut MetaMcp) {
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    meta.enable_public_provenance(ProvenancePublicSigner::from_seed_for_test(
        [7u8; 32],
        "prov-test-1",
    ));
}

fn trust_set() -> TrustSet {
    let signer = ProvenancePublicSigner::from_seed_for_test([7u8; 32], "prov-test-1");
    let jwk_text = serde_json::to_string(&signer.public_jwk()).expect("jwk serializes");
    TrustSet::from_json(&jwk_text).expect("trust loads")
}

fn delivery_ctx<'a>(
    targets: &'a [ResponsePolicyTarget],
    method: &'a str,
    external_tool: &'a str,
) -> ResponseDeliveryContext<'a> {
    ResponseDeliveryContext {
        method,
        targets,
        correlation: ResponseCorrelation {
            session_id: "s",
            caller: "test",
            external_server: "gateway",
            external_tool,
            subject: None,
        },
        signing: None,
        chain_source: ChainSource::NotEligible,
        chain_nonce: None,
    }
}

fn invoke_args() -> serde_json::Value {
    json!({"server": "remote_docs", "tool": "search", "arguments": {}})
}

fn outer_receipt(delivered: &serde_json::Value) -> serde_json::Value {
    delivered
        .pointer("/_meta/provenance")
        .expect("the outer result carries the receipt")
        .clone()
}

fn assert_bound(prov: &serde_json::Value, trust: &TrustSet, bound_to: &serde_json::Value) {
    let verified = verify_public(prov, trust, Some(bound_to)).expect("the receipt verifies");
    assert_eq!(verified.status, VerifyStatus::Bound);
}

fn assert_text_carries_no_receipt(delivered: &serde_json::Value) {
    let text = delivered
        .pointer("/content/0/text")
        .and_then(|v| v.as_str())
        .expect("a wrapped reply carries text");
    let parsed: serde_json::Value = serde_json::from_str(text).expect("the text parses as JSON");
    assert!(
        parsed.pointer("/_meta/provenance").is_none(),
        "the text carries no receipt: {text}"
    );
}

#[tokio::test]
async fn gateway_invoke_modern_reply_carries_a_bound_public_signature() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let trust = trust_set();
    let caller = allow_all_ctx_named(Some("alice"), None);
    let mut response = meta
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_invoke",
            invoke_args(),
            Some("session-1"),
            caller,
        )
        .await;
    crate::gateway::router::shape_modern_response(&mut response, "tools/call");
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
    let response = meta.finalize_routed(response, &delivery, None);
    let delivered = response.result.expect("a result");
    assert_eq!(delivered["resultType"], "complete");
    assert!(
        delivered
            .pointer("/_meta/provenance/public_signature")
            .is_some(),
        "the outer receipt carries a public signature: {delivered}"
    );
    let prov = outer_receipt(&delivered);
    assert_bound(&prov, &trust, &delivered);
    assert_eq!(
        prov.pointer("/receipt/cache").and_then(|v| v.as_str()),
        Some("miss")
    );
    assert_text_carries_no_receipt(&delivered);
}

#[tokio::test]
async fn gateway_invoke_legacy_reply_carries_a_bound_public_signature() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let trust = trust_set();
    let caller = allow_all_ctx_named(Some("alice"), None);
    let response = meta
        .handle_tools_call(
            RequestId::Number(2),
            "gateway_invoke",
            invoke_args(),
            Some("session-1"),
            caller,
        )
        .await;
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
    let response = meta.finalize_routed(response, &delivery, None);
    let delivered = response.result.expect("a result");
    assert!(
        delivered
            .pointer("/_meta/provenance/public_signature")
            .is_some(),
        "the outer receipt carries a public signature: {delivered}"
    );
    let prov = outer_receipt(&delivered);
    assert_bound(&prov, &trust, &delivered);
    assert_eq!(
        prov.pointer("/receipt/cache").and_then(|v| v.as_str()),
        Some("miss")
    );
    assert_text_carries_no_receipt(&delivered);
}

#[tokio::test]
async fn gateway_invoke_response_cache_hit_carries_a_bound_public_signature() {
    let mut meta = MetaMcp::with_features(
        provenance_test_backend(),
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    dual_signed_meta(&mut meta);
    let trust = trust_set();
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
    let first = meta
        .handle_tools_call(
            RequestId::Number(3),
            "gateway_invoke",
            invoke_args(),
            Some("session-1"),
            allow_all_ctx_named(Some("alice"), None),
        )
        .await;
    let _ = meta.finalize_routed(first, &delivery, None);
    let second = meta
        .handle_tools_call(
            RequestId::Number(3),
            "gateway_invoke",
            invoke_args(),
            Some("session-1"),
            allow_all_ctx_named(Some("alice"), None),
        )
        .await;
    let response = meta.finalize_routed(second, &delivery, None);
    let delivered = response.result.expect("a result");
    assert!(
        delivered
            .pointer("/_meta/provenance/public_signature")
            .is_some(),
        "the cached reply carries a public signature: {delivered}"
    );
    let prov = outer_receipt(&delivered);
    assert_eq!(
        prov.pointer("/receipt/cache").and_then(|v| v.as_str()),
        Some("hit")
    );
    assert_bound(&prov, &trust, &delivered);
    assert_text_carries_no_receipt(&delivered);
}

#[tokio::test]
async fn gateway_invoke_idempotent_replay_carries_a_bound_public_signature() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    let trust = trust_set();
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("k-8398".to_owned()),
        ..Default::default()
    };
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "tools/call", "gateway_invoke");
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..allow_all_ctx_named(Some("alice"), None)
    };
    let first = meta
        .handle_tools_call(
            RequestId::Number(4),
            "gateway_invoke",
            invoke_args(),
            Some("session-1"),
            caller,
        )
        .await;
    let _ = meta.finalize_routed(first, &delivery, None);
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..allow_all_ctx_named(Some("alice"), None)
    };
    let second = meta
        .handle_tools_call(
            RequestId::Number(4),
            "gateway_invoke",
            invoke_args(),
            Some("session-1"),
            caller,
        )
        .await;
    let response = meta.finalize_routed(second, &delivery, None);
    let delivered = response.result.expect("a result");
    assert!(
        delivered
            .pointer("/_meta/provenance/public_signature")
            .is_some(),
        "the replayed reply carries a public signature: {delivered}"
    );
    let prov = outer_receipt(&delivered);
    assert_eq!(
        prov.pointer("/receipt/cache").and_then(|v| v.as_str()),
        Some("hit")
    );
    assert_bound(&prov, &trust, &delivered);
}

#[test]
fn tasks_get_delivers_a_bound_public_signature_on_the_stored_result() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let trust = trust_set();
    let stamped = meta.stamp_recovered_result(
        json!({"content": [{"type": "text", "text": "ok"}]}),
        "remote_docs",
        "search",
        None,
    );
    let mut task = crate::protocol::tasks::Task::create("search").expect("a task");
    task.complete(&stamped).expect("completes");
    let mut envelope = serde_json::to_value(task.wire()).expect("wire");
    envelope["resultType"] = json!("complete");
    let response = JsonRpcResponse::success(RequestId::Number(5), envelope);
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "tasks/get", "gateway_invoke");
    let response = meta.finalize_routed(response, &delivery, None);
    let delivered = response.result.expect("a result");
    let prov = delivered
        .pointer("/result/_meta/provenance")
        .expect("the stored result carries the receipt")
        .clone();
    assert!(
        prov.get("public_signature").is_some(),
        "the stored receipt carries a public signature: {delivered}"
    );
    let verified = verify_public(&prov, &trust, Some(&delivered["result"])).expect("it verifies");
    assert_eq!(verified.status, VerifyStatus::Bound);
}
