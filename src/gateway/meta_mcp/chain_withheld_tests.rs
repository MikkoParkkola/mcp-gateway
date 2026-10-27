// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ingress strips an upstream gateway's own verdict members, which
//! its chain link signed. The chain is still verified over the result the
//! upstream signed, through what ingress withheld, and the stripped members
//! are still never delivered.

use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::config::{ChainEmit, ChainMode};
use crate::gateway::chain_test_support::{KEY_ID, signer, trusted_self};
use crate::gateway::meta_mcp::response_security::chain_receipt::{ChainReceipt, ChainSlot};
use crate::protocol::reserved_members::strip_ingress;
use crate::protocol::{JsonRpcResponse, RequestId, UpstreamState};
use crate::security::signature_chain::{Hop, LinkSource, Upstream, attach_link};

const NONCE: &str = "withheld-nonce";

fn chained() -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_chain_signer(signer(), ChainEmit::OnRequest);
    meta.set_chain_trust(8, trusted_self(), 300);
    meta
}

/// An upstream gateway's answer: its own finding, signed into its link.
fn signed_upstream_answer() -> JsonRpcResponse {
    let mut result = json!({
        "content": [{"type": "text", "text": "hello"}],
        "isError": false,
        "_security_findings": ["the upstream gateway's own finding"],
    });
    let hop = Hop {
        prefix: &[],
        up: Upstream::None,
        input: None,
    };
    let now = crate::clock::unix_secs().expect("a readable clock");
    attach_link(
        &signer(),
        &mut result,
        &hop,
        LinkSource::Live,
        Some(NONCE),
        now,
        8,
    )
    .expect("the link attaches");
    let mut response = JsonRpcResponse::success(RequestId::Number(1), result);
    strip_ingress("upstream", "tools/call", &mut response);
    response
}

fn receive(
    meta: &MetaMcp,
    result: &mut Value,
    withheld: Option<&serde_json::Map<String, Value>>,
) -> (crate::Result<()>, ChainReceipt) {
    let origins = [KEY_ID.to_owned()];
    let slot = ChainSlot::default();
    let outcome = meta.chain_receive(
        (ChainMode::Require, &origins, Some(KEY_ID)),
        (result, withheld),
        Some(NONCE),
        &slot,
    );
    let receipt = std::mem::take(&mut *slot.lock());
    (outcome, receipt)
}

/// A signed upstream verdict is withheld, the chain still verifies, and the
/// verdict is not delivered.
#[test]
fn a_chain_verifies_over_what_ingress_withheld() {
    let meta = chained();
    let response = signed_upstream_answer();
    let mut result = response.result.clone().expect("a result");
    assert!(
        result.get("_security_findings").is_none(),
        "ingress removed the member: {result}"
    );
    let withheld = response
        .ingress_withheld
        .as_deref()
        .map(crate::protocol::reserved_members::Withheld::members);
    let (outcome, receipt) = receive(&meta, &mut result, withheld);
    outcome.expect("the chain verifies over the signed result");
    let ChainReceipt::Checked(Some(upstream)) = receipt else {
        panic!("a checked receipt");
    };
    assert_eq!(upstream.state, UpstreamState::Verified);
    assert!(result.get("_security_findings").is_none(), "{result}");
}

/// Control and mutant kill: the same answer verified without the withheld
/// members is not what the upstream signed, so `require` refuses it.
#[test]
fn without_the_withheld_members_the_chain_does_not_verify() {
    let meta = chained();
    let response = signed_upstream_answer();
    let mut result = response.result.clone().expect("a result");
    let (outcome, _) = receive(&meta, &mut result, None);
    assert!(
        outcome.is_err(),
        "the digest must not match the stripped result"
    );
}
