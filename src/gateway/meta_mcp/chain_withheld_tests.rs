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
    signed(
        "tools/call",
        json!({
            "content": [{"type": "text", "text": "hello"}],
            "isError": false,
            "_security_findings": ["the upstream gateway's own finding"],
        }),
    )
}

/// `result`, signed into an upstream link, as ingress leaves it for `method`.
fn signed(method: &str, mut result: Value) -> JsonRpcResponse {
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
    strip_ingress(
        "upstream",
        method,
        crate::protocol::member_scope::Declared::Nothing,
        &mut response,
    );
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

/// Verify `response` over what ingress withheld; the chain must hold.
fn verifies(response: &JsonRpcResponse) -> Value {
    let meta = chained();
    let mut result = response.result.clone().expect("a result");
    let withheld = response
        .ingress_withheld
        .as_deref()
        .map(crate::protocol::reserved_members::Withheld::members);
    let (outcome, _) = receive(&meta, &mut result, withheld);
    outcome.expect("the chain verifies over the signed result");
    result
}

/// A scoped member removed at the root alone is withheld for the chain.
#[test]
fn a_scoped_removal_at_the_root_still_verifies() {
    let response = signed(
        "prompts/get",
        json!({"messages": [], "resultType": "complete", "cacheScope": "private"}),
    );
    let result = verifies(&response);
    assert!(result.get("cacheScope").is_none(), "{result}");
}

/// A scoped member removed from a task envelope's slot alone still verifies.
#[test]
fn a_scoped_removal_in_the_task_slot_still_verifies() {
    let response = signed(
        "tasks/result",
        json!({"result": {"content": [], "taskId": "inner"}}),
    );
    let result = verifies(&response);
    assert_eq!(result["result"], json!({"content": []}));
}

/// A gateway-only and a scoped removal in one slot: one snapshot covers both.
#[test]
fn a_gateway_only_and_a_scoped_removal_in_one_slot_still_verify() {
    let response = signed(
        "tasks/result",
        json!({"result": {"content": [], "ttlMs": 5, "_security_findings": ["f"]}}),
    );
    let result = verifies(&response);
    assert_eq!(result["result"], json!({"content": []}));
}

const NEEDLE: &str = "signed-echo-secret-2f9b";

/// A signed answer that echoes an injected value, as the transport scrub and
/// then ingress leave it. `tamper` changes the signed content first.
fn signed_echo(tamper: bool) -> JsonRpcResponse {
    let hop = Hop {
        prefix: &[],
        up: Upstream::None,
        input: None,
    };
    let mut result = json!({
        "content": [{"type": "text", "text": format!("key {NEEDLE}")}],
        "isError": false,
        "_security_findings": ["the upstream gateway's own finding"],
    });
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
    if tamper {
        result["isError"] = json!(true);
    }
    let mut response = JsonRpcResponse::success(RequestId::Number(1), result);
    let needles =
        crate::security::needles::NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
    needles.insert("upstream", NEEDLE);
    crate::security::needles::scrub_response_with(&needles, &mut response);
    strip_ingress(
        "upstream",
        "tools/call",
        crate::protocol::member_scope::Declared::Nothing,
        &mut response,
    );
    response
}

/// MIK-9035 T1.29 (DELTA-13): the chain of a signed answer echoing an
/// injected value verifies over the bytes the backend signed, the
/// provenance is recorded as verified, and the value never reaches the
/// result.
#[test]
fn a_signed_echo_verifies_over_what_the_backend_signed() {
    let meta = chained();
    let response = signed_echo(false);
    let mut result = response.result.clone().expect("a result");
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
    let text = result.to_string();
    assert!(
        !text.contains(NEEDLE),
        "the value reached the result: {text}"
    );
    assert!(text.contains("[redacted]"), "not redacted: {text}");
}

/// T1.29 mutant kill: verified over the scrubbed result alone, the digest is
/// not what the backend signed and `require` refuses.
#[test]
fn a_signed_echo_does_not_verify_over_the_scrubbed_result() {
    let meta = chained();
    let mut result = signed_echo(false).result.expect("a result");
    let (outcome, _) = receive(&meta, &mut result, None);
    assert!(
        outcome.is_err(),
        "the scrubbed result matched the signature"
    );
}

/// T1.29 control: a signed answer changed after signing is refused, kept
/// members or not.
#[test]
fn a_tampered_signed_echo_is_refused() {
    let meta = chained();
    let response = signed_echo(true);
    let mut result = response.result.clone().expect("a result");
    let withheld = response
        .ingress_withheld
        .as_deref()
        .map(crate::protocol::reserved_members::Withheld::members);
    let (outcome, _) = receive(&meta, &mut result, withheld);
    assert!(outcome.is_err(), "a tampered answer verified");
}

/// G8 (lead ruling): a signed answer whose top-level key name holds an
/// injected value is refused with the fixed refusal; no view of it, scrubbed
/// or as-sent, is served or verified.
#[test]
fn a_signed_answer_with_a_value_in_a_key_name_is_refused() {
    let hop = Hop {
        prefix: &[],
        up: Upstream::None,
        input: None,
    };
    let mut result = json!({
        "content": [{"type": "text", "text": "fine"}],
        NEEDLE: "a key named by the secret",
    });
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
    let needles =
        crate::security::needles::NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
    needles.insert("upstream", NEEDLE);
    let answer = crate::security::needles::scrub_answer(
        &needles,
        Ok(JsonRpcResponse::success(RequestId::Number(1), result)),
    );
    let text = format!("{answer:?}");
    assert!(
        matches!(answer, Err(crate::Error::JsonRpc { code: -32603, .. })),
        "not the fixed refusal: {text}"
    );
    assert!(!text.contains(NEEDLE), "{text}");
}
