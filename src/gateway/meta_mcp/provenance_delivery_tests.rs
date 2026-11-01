// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `/mcp` receipt rides on the outer result (MIK-8398): the wrapped reply
//! lifts `_meta.provenance` out of `content[0].text`, a task's stored result
//! is sealed at creation, and a receipt is publicly signed only in the request
//! that minted it, once (C1c).
use super::*;
use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::gateway::meta_mcp::invoke::with_minted_receipts;
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
            trace_id: None,
            key: crate::security::response_policy::KeyOf::NotKnown,
        },
        signing: None,
        chain_source: ChainSource::NotEligible,
        chain_nonce: None,
        generation: None,
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

/// A genuine receipt from one live `gateway_invoke` reply, with its public
/// seal dropped, so a replay row can plant it where it was never minted.
async fn captured_receipt(meta: &MetaMcp) -> serde_json::Value {
    let caller = allow_all_ctx_named(Some("alice"), None);
    let response = meta
        .handle_tools_call(
            RequestId::Number(41),
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
    let mut prov = outer_receipt(&delivered);
    prov.as_object_mut()
        .expect("a receipt object")
        .remove("public_signature");
    prov
}

/// A registry whose `remote_docs` backend answers `result` to every `tools/call`.
fn answering_backend(result: serde_json::Value) -> Arc<BackendRegistry> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::transport::Transport;

    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "remote_docs",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn Transport> = Arc::new(ToolCallTestTransport { result });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);
    registry
}

/// A plain `gateway_invoke` reply from `meta`, delivered inside one minted
/// scope: the parsed `content[0].text`, after checking the scope sealed this
/// request's own top-level mint.
async fn replayed_text(meta: &MetaMcp) -> serde_json::Value {
    with_minted_receipts(Box::pin(async {
        let caller = allow_all_ctx_named(Some("alice"), None);
        let response = meta
            .handle_tools_call(
                RequestId::Number(42),
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
            "the scope seals this request's own mint: {delivered}"
        );
        let text = delivered
            .pointer("/content/0/text")
            .and_then(|v| v.as_str())
            .expect("a wrapped reply carries text");
        serde_json::from_str(text).expect("the text parses as JSON")
    }))
    .await
}

/// A `tasks/get` envelope serving `stored` as its completed result.
fn task_envelope(stored: &serde_json::Value) -> JsonRpcResponse {
    let mut task = crate::protocol::tasks::Task::create("search").expect("a task");
    task.complete(stored).expect("completes");
    let mut envelope = serde_json::to_value(task.wire()).expect("wire");
    envelope["resultType"] = json!("complete");
    JsonRpcResponse::success(RequestId::Number(5), envelope)
}

#[tokio::test]
async fn gateway_invoke_modern_reply_carries_a_bound_public_signature() {
    with_minted_receipts(Box::pin(async {
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
    }))
    .await;
}

#[tokio::test]
async fn gateway_invoke_legacy_reply_carries_a_bound_public_signature() {
    with_minted_receipts(Box::pin(async {
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
    }))
    .await;
}

#[tokio::test]
async fn gateway_invoke_response_cache_hit_carries_a_bound_public_signature() {
    with_minted_receipts(Box::pin(async {
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
    }))
    .await;
}

#[tokio::test]
async fn gateway_invoke_idempotent_replay_carries_a_bound_public_signature() {
    with_minted_receipts(Box::pin(async {
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
    }))
    .await;
}

#[tokio::test]
async fn tasks_get_delivers_a_bound_public_signature_on_the_stored_result() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let trust = trust_set();
    // Sealed at creation: the stored result carries its seal before delivery.
    let stamped = with_minted_receipts(Box::pin(async {
        meta.recover_task_result(
            "remote_docs",
            "search",
            None,
            "trace-8398",
            json!({"content": [{"type": "text", "text": "ok"}]}),
        )
    }))
    .await
    .expect("nothing in the result trips a gate");
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "tasks/get", "gateway_invoke");
    let response = with_minted_receipts(Box::pin(async {
        meta.finalize_routed(task_envelope(&stamped), &delivery, None)
    }))
    .await;
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
    // Delivery seals nothing nested: a result stored unsealed stays unsealed.
    let unsealed = meta
        .recover_task_result(
            "remote_docs",
            "search",
            None,
            "trace-8398",
            json!({"content": [{"type": "text", "text": "ok"}]}),
        )
        .expect("nothing in the result trips a gate");
    let response = with_minted_receipts(Box::pin(async {
        meta.finalize_routed(task_envelope(&unsealed), &delivery, None)
    }))
    .await;
    let delivered = response.result.expect("a result");
    let prov = delivered
        .pointer("/result/_meta/provenance")
        .expect("the stored result carries the receipt");
    assert!(
        prov.get("public_signature").is_none(),
        "delivery seals no nested receipt: {delivered}"
    );
}

/// C1i twin of `tasks_get_delivers_a_bound_public_signature_on_the_stored_result`:
/// a recovered result carrying `cacheScope: "public"` is sealed over the
/// delivered bytes. The oracle is the serialized `tasks/get` response, so a
/// seal over `public` fails Bound against the delivered `private`, even when
/// the in-memory envelope already clamped.
#[tokio::test]
async fn tasks_get_with_a_public_scope_is_sealed_as_delivered() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let trust = trust_set();
    let stamped = with_minted_receipts(Box::pin(async {
        meta.recover_task_result(
            "remote_docs",
            "search",
            None,
            "trace-8398",
            json!({
                "content": [{"type": "text", "text": "ok"}],
                "cacheScope": "public",
            }),
        )
    }))
    .await
    .expect("nothing in the result trips a gate");
    let targets: Vec<ResponsePolicyTarget> = Vec::new();
    let delivery = delivery_ctx(&targets, "tasks/get", "gateway_invoke");
    let response = with_minted_receipts(Box::pin(async {
        meta.finalize_routed(task_envelope(&stamped), &delivery, None)
    }))
    .await;
    let wire = serde_json::to_value(&response).expect("the wire form serializes");
    let delivered = &wire["result"]["result"];
    assert_eq!(
        delivered.get("cacheScope").and_then(|v| v.as_str()),
        Some("private"),
        "the wire clamp delivers private: {wire}"
    );
    let prov = delivered
        .pointer("/_meta/provenance")
        .expect("the stored result carries the receipt")
        .clone();
    assert!(
        prov.get("public_signature").is_some(),
        "the stored receipt carries a public signature: {delivered}"
    );
    let verified = verify_public(&prov, &trust, Some(delivered)).expect("it verifies");
    assert_eq!(verified.status, VerifyStatus::Bound);
}

#[tokio::test]
async fn chain_answer_step_receipts_carry_bound_public_signatures() {
    with_minted_receipts(Box::pin(async {
        let mut meta = MetaMcp::new(provenance_test_backend()).with_code_mode(true);
        dual_signed_meta(&mut meta);
        let trust = trust_set();
        let caller = allow_all_ctx_named(Some("alice"), None);
        let response = meta
            .handle_tools_call(
                RequestId::Number(6),
                "gateway_execute",
                json!({"chain": [
                    {"tool": "remote_docs:search", "arguments": {}},
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
        let results = parsed
            .get("results")
            .and_then(|v| v.as_array())
            .expect("a chain answer carries results");
        assert_eq!(results.len(), 2, "two steps ran: {parsed}");
        for (i, element) in results.iter().enumerate() {
            let step_result = element.get("result").expect("a step result");
            let prov = step_result
                .pointer("/_meta/provenance")
                .expect("a step receipt");
            assert!(
                prov.get("public_signature").is_some(),
                "step {i} carries a public signature: {parsed}"
            );
            let verified =
                verify_public(prov, &trust, Some(step_result)).expect("the step receipt verifies");
            assert_eq!(verified.status, VerifyStatus::Bound);
        }
    }))
    .await;
}

#[tokio::test]
async fn playbook_answer_step_receipts_carry_bound_public_signatures() {
    with_minted_receipts(Box::pin(async {
        let mut meta = MetaMcp::new(provenance_test_backend());
        dual_signed_meta(&mut meta);
        let trust = trust_set();
        let definition: crate::playbook::PlaybookDefinition = crate::yaml::from_str(
            r"
name: two_search
description: two searches with no output mapping
on_error: abort
steps:
  - name: first
    server: remote_docs
    tool: search
  - name: second
    server: remote_docs
    tool: search
",
        )
        .expect("playbook fixture must parse");
        let name = definition.name.clone();
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
        let caller = allow_all_ctx_named(Some("alice"), None);
        let response = meta
            .handle_tools_call(
                RequestId::Number(7),
                "gateway_run_playbook",
                json!({"name": name, "arguments": {}}),
                Some("session-1"),
                caller,
            )
            .await;
        let targets: Vec<ResponsePolicyTarget> = Vec::new();
        let delivery = delivery_ctx(&targets, "tools/call", "gateway_run_playbook");
        let response = meta.finalize_routed(response, &delivery, None);
        let delivered = response.result.expect("a result");
        let text = delivered
            .pointer("/content/0/text")
            .and_then(|v| v.as_str())
            .expect("a wrapped reply carries text");
        let parsed: serde_json::Value =
            serde_json::from_str(text).expect("the text parses as JSON");
        let output = parsed
            .get("output")
            .expect("a playbook answer carries output");
        for step in ["first", "second"] {
            let step_value = output.get(step).expect("a step output");
            let prov = step_value
                .pointer("/_meta/provenance")
                .expect("a step receipt");
            assert!(
                prov.get("public_signature").is_some(),
                "step {step} carries a public signature: {parsed}"
            );
            let verified =
                verify_public(prov, &trust, Some(step_value)).expect("the step receipt verifies");
            assert_eq!(verified.status, VerifyStatus::Bound);
        }
    }))
    .await;
}

#[test]
fn seal_refuses_a_receipt_this_gateway_did_not_sign() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let other = BnautAttestationSigner::new(b"other-key".to_vec(), "unit")
        .with_audience("test-gateway")
        .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO);
    let receipt = crate::trust::RuntimeProvenanceReceipt::observed(
        "remote_docs",
        "search",
        "2026-10-22T00:00:00Z",
        crate::trust::CacheOutcome::Miss,
        true,
    );
    let signed = receipt.sign(&other);
    let prov_value = serde_json::to_value(&signed).expect("a receipt serializes");
    let mut value = json!({
        "content": [{"type": "text", "text": "ok"}],
        "_meta": {"provenance": prov_value},
    });
    meta.seal_public_provenance(&mut value);
    assert!(
        value
            .pointer("/_meta/provenance/public_signature")
            .is_none(),
        "a receipt this gateway did not sign must not be sealed: {value}"
    );
}

#[tokio::test]
async fn forged_nested_receipt_is_never_sealed() {
    let mut meta = MetaMcp::new(provenance_test_backend());
    dual_signed_meta(&mut meta);
    let other = BnautAttestationSigner::new(b"other-key".to_vec(), "unit")
        .with_audience("test-gateway")
        .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO);
    let receipt = crate::trust::RuntimeProvenanceReceipt::observed(
        "remote_docs",
        "search",
        "2026-10-22T00:00:00Z",
        crate::trust::CacheOutcome::Miss,
        true,
    );
    let signed = receipt.sign(&other);
    let prov_value = serde_json::to_value(&signed).expect("a receipt serializes");
    let mut content = json!({
        "steps": 1,
        "results": [{
            "step": 0,
            "tool": "remote_docs:search",
            "result": {
                "content": [{"type": "text", "text": "ok"}],
                "_meta": {"provenance": prov_value},
            },
        }],
    });
    with_minted_receipts(Box::pin(async {
        let step = content
            .pointer_mut("/results/0/result")
            .expect("a step result");
        meta.seal_public_provenance(step);
    }))
    .await;
    assert!(
        content
            .pointer("/results/0/result/_meta/provenance/public_signature")
            .is_none(),
        "a nested receipt this gateway did not sign must not be sealed: {content}"
    );
}

#[path = "provenance_seal_rules_tests.rs"]
mod seal_rules;
