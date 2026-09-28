// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ASI07 increment 2, meta/stdio route: origin-link emission at the shared
//! delivery finalizer. Red-first: every test fails until emission exists.

use std::sync::Arc;

use serde_json::{Value, json};

use super::super::MetaMcp;
use super::super::signing::SigningInvocationContext;
use super::{ChainSource, ResponseCorrelation, ResponseDeliveryContext, ResponsePolicyTarget};
use crate::backend::BackendRegistry;
use crate::config::ChainEmit;
use crate::gateway::chain_test_support::{
    CHAIN_KEY, KEY_ID, carries_chain, chain_of, origin_link, signer, verify_self,
};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::response_policy::ResponseMutationPolicy;
use crate::security::signature_chain::{LinkSource, content_digest};

const NONCE: &str = "chain-nonce-1";
const INVOKE_NONCE: &str = "invoke-nonce-1";

fn meta(emit: Option<ChainEmit>) -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    if let Some(emit) = emit {
        meta.set_chain_signer(signer(), emit);
    }
    meta
}

fn body() -> Value {
    json!({"content": [{"type": "text", "text": "hello"}], "isError": false})
}

async fn deliver(
    meta: &MetaMcp,
    response: JsonRpcResponse,
    source: ChainSource,
    nonce: Option<&str>,
    signing: Option<&SigningInvocationContext>,
) -> JsonRpcResponse {
    meta.finalize_response_for_delivery(
        response,
        &ResponseDeliveryContext {
            method: "tools/call",
            targets: &[ResponsePolicyTarget {
                server: "backend".into(),
                tool: "echo".into(),
            }],
            correlation: ResponseCorrelation {
                session_id: "chain-session",
                caller: "caller",
                external_server: "gateway",
                external_tool: "gateway_invoke",
            },
            mutation: ResponseMutationPolicy::Redact,
            signing,
            chain_source: source,
            chain_nonce: nonce,
        },
    )
    .await
}

async fn deliver_body(
    emit: Option<ChainEmit>,
    source: ChainSource,
    nonce: Option<&str>,
) -> (Value, JsonRpcResponse) {
    let original = body();
    let out = deliver(
        &meta(emit),
        JsonRpcResponse::success(RequestId::Number(1), original.clone()),
        source,
        nonce,
        None,
    )
    .await;
    (original, out)
}

fn result_of(response: &JsonRpcResponse) -> &Value {
    response.result.as_ref().expect("success result")
}

fn code_of(response: &JsonRpcResponse) -> i32 {
    response.error.as_ref().expect("error response").code
}

#[tokio::test]
async fn origin_link_emitted_on_request_meta() {
    let (original, out) = deliver_body(
        Some(ChainEmit::OnRequest),
        ChainSource::Backend,
        Some(NONCE),
    )
    .await;
    let chain = chain_of(result_of(&out)).expect("chain emitted");
    let digest = content_digest(&original).expect("digest");
    assert_eq!(
        verify_self(chain, &digest, NONCE).expect("verifies").len(),
        1
    );
    let link = origin_link(chain, LinkSource::Live, Some(NONCE));
    assert_eq!(link.out.as_deref(), Some(digest.as_str()));
}

#[tokio::test]
async fn no_link_without_nonce_on_request() {
    let (_, out) = deliver_body(Some(ChainEmit::OnRequest), ChainSource::Backend, None).await;
    assert!(!carries_chain(result_of(&out)));
}

#[tokio::test]
async fn emit_always_links_with_null_nonce() {
    let (original, out) = deliver_body(Some(ChainEmit::Always), ChainSource::Backend, None).await;
    let chain = chain_of(result_of(&out)).expect("chain emitted");
    let link = origin_link(chain, LinkSource::Live, None);
    let digest = content_digest(&original).expect("digest");
    assert_eq!(link.out.as_deref(), Some(digest.as_str()));
}

#[tokio::test]
async fn off_by_default_byte_identical() {
    let (original, out) = deliver_body(None, ChainSource::Backend, Some(NONCE)).await;
    assert_eq!(result_of(&out), &original);
    assert!(!carries_chain(result_of(&out)));
}

#[tokio::test]
async fn is_error_backend_result_chained() {
    let mut error_result = body();
    error_result["isError"] = json!(true);
    let out = deliver(
        &meta(Some(ChainEmit::OnRequest)),
        JsonRpcResponse::success(RequestId::Number(1), error_result),
        ChainSource::Backend,
        Some(NONCE),
        None,
    )
    .await;
    assert!(chain_of(result_of(&out)).is_some());
}

#[tokio::test]
async fn dispatch_error_wrapper_not_chained() {
    let (_, out) = deliver_body(
        Some(ChainEmit::Always),
        ChainSource::NotEligible,
        Some(NONCE),
    )
    .await;
    assert!(!carries_chain(result_of(&out)));
    assert_eq!(ChainSource::default(), ChainSource::NotEligible);
}

#[tokio::test]
async fn json_rpc_error_not_chained() {
    let out = deliver(
        &meta(Some(ChainEmit::Always)),
        JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "backend failed"),
        ChainSource::Backend,
        Some(NONCE),
        None,
    )
    .await;
    assert!(out.result.is_none());
    assert!(!serde_json::to_string(&out).unwrap().contains(CHAIN_KEY));
}

#[tokio::test]
async fn replay_link_rebinds_nonce_meta() {
    let (original, out) = deliver_body(
        Some(ChainEmit::OnRequest),
        ChainSource::Replay,
        Some("second-nonce"),
    )
    .await;
    let chain = chain_of(result_of(&out)).expect("replay is chained");
    let link = origin_link(chain, LinkSource::Replay, Some("second-nonce"));
    let digest = content_digest(&original).expect("digest");
    assert_eq!(link.out.as_deref(), Some(digest.as_str()));
}

/// Signing on and off: the invoke nonce is the chain nonce only when the
/// request carried no chain nonce, and never a trigger on its own.
async fn deliver_with_invoke(
    signing_on: bool,
    emit: ChainEmit,
    chain_nonce: Option<&str>,
) -> (Value, JsonRpcResponse) {
    let mut gateway = meta(Some(emit));
    if signing_on {
        gateway.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"chain-emission-key-sentinel-0123456789abcdef".to_vec(),
                None,
                "chain-current".into(),
            ),
            std::time::Duration::from_secs(300),
            false,
        );
    }
    let invoke = SigningInvocationContext::external_for_test(Some(INVOKE_NONCE));
    let original = body();
    let out = deliver(
        &gateway,
        JsonRpcResponse::success(RequestId::Number(1), original.clone()),
        ChainSource::Backend,
        chain_nonce,
        Some(&invoke),
    )
    .await;
    (original, out)
}

#[tokio::test]
async fn gateway_invoke_nonce_fallback() {
    for signing_on in [true, false] {
        let (_, fallback) = deliver_with_invoke(signing_on, ChainEmit::Always, None).await;
        let chain = chain_of(result_of(&fallback)).expect("fallback link");
        origin_link(chain, LinkSource::Live, Some(INVOKE_NONCE));
        let (_, both) = deliver_with_invoke(signing_on, ChainEmit::Always, Some(NONCE)).await;
        let chain = chain_of(result_of(&both)).expect("explicit link");
        origin_link(chain, LinkSource::Live, Some(NONCE));
    }
}

#[tokio::test]
async fn invoke_nonce_alone_does_not_trigger_on_request() {
    for signing_on in [true, false] {
        let (_, out) = deliver_with_invoke(signing_on, ChainEmit::OnRequest, None).await;
        assert!(!carries_chain(result_of(&out)), "signing_on={signing_on}");
    }
}

#[tokio::test]
async fn chain_and_hmac_coexist_meta() {
    let (original, out) = deliver_with_invoke(true, ChainEmit::OnRequest, Some(NONCE)).await;
    let result = result_of(&out);
    assert!(result.get("_signature").is_some(), "v2 MAC present");
    let chain = chain_of(result).expect("chain present under the MAC");
    let digest = content_digest(&original).expect("digest");
    let link = origin_link(chain, LinkSource::Live, Some(NONCE));
    assert_eq!(
        link.out.as_deref(),
        Some(digest.as_str()),
        "out ignores _signature"
    );
    assert_eq!(link.gw, KEY_ID);
}

#[tokio::test]
async fn unhashable_final_content_refused() {
    let mut unhashable = body();
    unhashable["structuredContent"] = json!({"n": 9_007_199_254_740_993_u64});
    let out = deliver(
        &meta(Some(ChainEmit::Always)),
        JsonRpcResponse::success(RequestId::Number(1), unhashable),
        ChainSource::Backend,
        Some(NONCE),
        None,
    )
    .await;
    assert_eq!(code_of(&out), -32001);
    assert!(!serde_json::to_string(&out).unwrap().contains(CHAIN_KEY));
}

#[tokio::test]
async fn oversized_outgoing_link_refused() {
    let control_nonce = "\0".repeat(256);
    let (_, out) = deliver_body(
        Some(ChainEmit::Always),
        ChainSource::Backend,
        Some(&control_nonce),
    )
    .await;
    assert_eq!(code_of(&out), -32001);
}

#[cfg(feature = "firewall")]
#[tokio::test]
async fn link_out_covers_firewall_redaction_stdio() {
    use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};
    const CANARY: &str = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz1234567890");
    let mut gateway = meta(Some(ChainEmit::OnRequest));
    gateway.set_firewall(Some(Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_requests: false,
            scan_responses: true,
            rules: vec![FirewallRule {
                tool_match: "echo".into(),
                action: FirewallAction::Allow,
                scan: vec![],
                reason: None,
            }],
            ..FirewallConfig::default()
        },
        None,
    ))));
    let mut leaky = body();
    leaky["content"][0]["text"] = json!(format!("hello {CANARY}"));
    let out = deliver(
        &gateway,
        JsonRpcResponse::success(RequestId::Number(1), leaky),
        ChainSource::Backend,
        Some(NONCE),
        None,
    )
    .await;
    let delivered = result_of(&out);
    assert!(!delivered.to_string().contains(CANARY), "firewall redacted");
    let mut stripped = delivered.clone();
    stripped["_meta"]
        .as_object_mut()
        .expect("meta")
        .remove(CHAIN_KEY);
    if stripped["_meta"]
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        stripped.as_object_mut().expect("object").remove("_meta");
    }
    let digest = content_digest(&stripped).expect("digest");
    let chain = chain_of(delivered).expect("chain emitted after redaction");
    assert_eq!(
        origin_link(chain, LinkSource::Live, Some(NONCE)).out,
        Some(digest)
    );
}
