// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T3 to T7: the meta route's chain receipt, chain
//! link, delivery record, signing and provenance receipt on a host clock that
//! reads before 1970. A recorder never stamps 0 or a 1969 date.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::config::{ChainEmit, ChainMode};
use crate::gateway::chain_test_support::{KEY_ID, carries_chain, signer, trusted_self};
use crate::gateway::meta_mcp::response_security::ResponseDeliveryContext;
use crate::gateway::meta_mcp::response_security::chain_receipt::{ChainReceipt, ChainSlot};
use crate::protocol::{ChainSource, JsonRpcResponse, RequestId};
use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};
use crate::security::signature_chain::{Hop, LinkSource, Upstream, attach_link};

fn body() -> Value {
    json!({"content": [{"type": "text", "text": "hello"}], "isError": false})
}

fn chained(emit: Option<ChainEmit>) -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    if let Some(emit) = emit {
        meta.set_chain_signer(signer(), emit);
        meta.set_chain_trust(8, trusted_self(), 300);
    }
    meta
}

/// T3. A receipt dated inside [0, 60] is what `now() == 0` would accept as
/// fresh; the real host clock would call it stale. Neither may decide: on a
/// clock before 1970 the receipt is refused as a clock refusal.
/// MIK-8202 ACCESS rule (P2 row 3). Mutant: `now()` back to `map_or(0)`.
#[test]
fn t3_a_chain_receipt_on_an_unreadable_clock_is_refused_as_a_clock_refusal() {
    // GIVEN: a chained backend whose reply link is dated at second 30
    let meta = chained(Some(ChainEmit::OnRequest));
    let nonce = "t3-nonce";
    let mut result = body();
    let hop = Hop {
        prefix: &[],
        up: Upstream::None,
        input: None,
    };
    attach_link(
        &signer(),
        &mut result,
        &hop,
        LinkSource::Live,
        Some(nonce),
        30,
        8,
    )
    .expect("the link attaches");
    let origins = [KEY_ID.to_owned()];
    let slot = ChainSlot::default();
    // WHEN: received on a clock before 1970
    let _clock = crate::clock::test_clock::before_epoch();
    let outcome = meta.chain_receive(
        (ChainMode::Require, &origins, Some(KEY_ID)),
        &mut result,
        Some(nonce),
        &slot,
    );
    // THEN: refused, and not as a freshness verdict
    let message = outcome
        .expect_err("an undatable receipt is refused")
        .to_string();
    assert!(
        !message.contains("Stale") && !message.contains("Future"),
        "{message}"
    );
    assert!(message.to_lowercase().contains("clock"), "{message}");
    assert!(matches!(*slot.lock(), ChainReceipt::Refused));
}

async fn deliver(
    meta: &MetaMcp,
    response: JsonRpcResponse,
    nonce: Option<&str>,
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
                session_id: "t4-session",
                caller: "caller",
                external_server: "gateway",
                external_tool: "gateway_invoke",
                subject: None,
            },
            signing: None,
            chain_source: ChainSource::Backend,
            chain_nonce: nonce,
        },
    )
    .await
}

fn ok_response() -> JsonRpcResponse {
    JsonRpcResponse::success(RequestId::Number(1), body())
}

/// T4. With a chain required, a link that cannot be dated is a refused
/// delivery, never a link at 0 and never an unlinked success.
/// MIK-8202 RECORDER rule (P2 row 5). Mutants: link at 0; unlinked success.
#[tokio::test]
async fn t4_a_required_chain_link_on_an_unreadable_clock_refuses_the_delivery() {
    let meta = chained(Some(ChainEmit::Always));
    let _clock = crate::clock::test_clock::before_epoch();
    let out = deliver(&meta, ok_response(), None).await;
    let error = out.error.as_ref().expect("the delivery is refused");
    assert_eq!(error.code, -32001, "{error:?}");
    assert!(out.result.as_ref().is_none_or(|r| !carries_chain(r)));
}

/// T4: a verified upstream prefix is never relabelled when the new link
/// cannot be dated: the delivery is refused, no `unverified` link replaces it.
#[tokio::test]
async fn t4_a_verified_prefix_is_refused_not_relabelled_on_an_unreadable_clock() {
    let meta = chained(Some(ChainEmit::Always));
    let mut response = ok_response();
    response.chain_upstream = Some(Arc::new(crate::protocol::UpstreamChain {
        links: Vec::new(),
        received: "sha256:upstream".to_owned(),
        state: crate::protocol::UpstreamState::Verified,
    }));
    let _clock = crate::clock::test_clock::before_epoch();
    let out = deliver(&meta, response, None).await;
    assert!(out.error.is_some(), "{out:?}");
    assert!(out.result.as_ref().is_none_or(|r| !carries_chain(r)));
}

/// T4 control: with no link required the delivery goes out unlinked on that
/// clock (chain off, or on-request with no nonce).
#[tokio::test]
async fn t4_control_no_required_link_delivers_unlinked_on_an_unreadable_clock() {
    let _clock = crate::clock::test_clock::before_epoch();
    for meta in [chained(None), chained(Some(ChainEmit::OnRequest))] {
        let out = deliver(&meta, ok_response(), None).await;
        assert!(out.error.is_none(), "{out:?}");
        assert!(!carries_chain(out.result.as_ref().expect("result")));
    }
}

/// T6. Signing on a clock before 1970 fails with the existing clock message
/// and never signs at 0. MIK-8202 RECORDER rule (P2 row 7). Mutant: sign at 0.
#[tokio::test]
async fn t6_signing_on_an_unreadable_clock_is_refused_and_leaves_the_response_unsigned() {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"t6-signing-key-0123456789abcdef-0123456789".to_vec(),
            None,
            "t6".into(),
        ),
        Duration::from_secs(300),
        false,
    );
    let mut response = ok_response();
    let _clock = crate::clock::test_clock::before_epoch();
    let outcome = meta.finalize_gateway_invoke_response(&mut response, Some("t6-nonce"));
    let message = outcome.expect_err("signing is refused").to_string();
    assert!(message.contains("Signing clock is invalid"), "{message}");
    let result = response.result.expect("the result is untouched");
    assert!(result.get("_signature").is_none(), "{result}");
}

/// T7. A provenance receipt cannot be dated: none is written, and no receipt
/// carries a 1969 `observed_at`. MIK-8202 RECORDER rule (P2 row 8).
/// Mutant: receipt stamped at 1969.
#[test]
fn t7_a_provenance_receipt_on_an_unreadable_clock_is_not_written() {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_provenance_stamping(
        crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO),
    );
    let _clock = crate::clock::test_clock::before_epoch();
    let stamped = meta.stamp_recovered_result(body(), "backend", "tool", None);
    let receipt = stamped.pointer("/_meta/provenance");
    assert!(
        receipt.is_none(),
        "no receipt on an undatable clock: {stamped}"
    );
    assert!(!stamped.to_string().contains("1969"), "{stamped}");
}
