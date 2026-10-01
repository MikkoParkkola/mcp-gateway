// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH1942.HARDEN.1 row 7: the signing scope under `hardened`. Every
//! `tools/call` gets a context whose nonce comes from `_meta`; only a context
//! whose nonce was admitted signs; a stored copy keeps no `_signature`; and a
//! direct-route result the primitive cannot sign is refused, never delivered
//! unsigned.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::MetaMcp;
use super::{NONCE_META, SigningDelivery, SigningInvocationContext, SigningScope};
use crate::backend::BackendRegistry;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::message_signing::MessageSigner;

const KEY: &str = "signing-scope-key-sentinel-0123456789abcdef";

fn meta() -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_message_signing(
        MessageSigner::new(KEY.as_bytes().to_vec(), None, "scope-current".into()),
        Duration::from_secs(300),
        false,
    );
    meta
}

fn call(name: &str, arguments: &Value, nonce: Option<&str>) -> Value {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {}}});
    if let Some(nonce) = nonce {
        request["params"]["_meta"][NONCE_META] = json!(nonce);
    }
    request
}

/// Under `EveryToolCall` a non-invoke `tools/call` is signed and its stored copy
/// is stripped; under `InvokeOnly` it is neither. The nonce leaves the request.
#[test]
fn hardened_capture_signs_every_tool_call() {
    let mut request = call("gateway_list_servers", &json!({}), Some("scope-nonce"));
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    assert!(
        context.owns_signature(),
        "a hardened tool call signs, so its stored copy is stripped"
    );
    assert!(
        request["params"]["_meta"].get(NONCE_META).is_none(),
        "the nonce is taken off the request before sanitization: {request}"
    );

    let mut request = call("gateway_list_servers", &json!({}), Some("scope-nonce"));
    let context = SigningInvocationContext::capture_scoped(&mut request, SigningScope::InvokeOnly);
    assert!(
        !context.owns_signature(),
        "standard signs gateway_invoke only"
    );
    assert!(
        matches!(context.delivery(), Ok(SigningDelivery::Unsigned)),
        "standard delivers a non-invoke call unsigned"
    );
}

/// Only an admitted context signs; one that never passed admission (the
/// task-gate's challenge) is delivered unsigned and leaves its nonce unspent.
#[tokio::test]
async fn task_gate_answer_is_unsigned_and_keeps_its_nonce() {
    let meta = meta();
    let mut request = call(
        "gateway_kill_server",
        &json!({"server": "x"}),
        Some("gate-nonce"),
    );
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    assert!(
        matches!(context.delivery(), Ok(SigningDelivery::Unsigned)),
        "an unadmitted context must not sign"
    );
    meta.admit_signing_nonce(Some("gate-nonce"), "caller")
        .expect("the follow-up can still spend the nonce the challenge left unspent");
    assert!(
        meta.admit_signing_nonce(Some("gate-nonce"), "caller")
            .is_err(),
        "once spent, the nonce is a replay"
    );
}

/// A `gateway_invoke` carrying both an argument nonce and a `_meta` nonce is
/// refused: one call never has two replay identities.
#[test]
fn gateway_invoke_with_two_nonces_refused() {
    let mut request = call(
        "gateway_invoke",
        &json!({"server": "s", "tool": "t", "arguments": {}, "nonce": "argument-nonce"}),
        Some("meta-nonce"),
    );
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let error = context.delivery().err().expect("two nonces cannot deliver");
    assert_eq!(error.to_rpc_code(), -32602, "{error}");
    assert!(error.to_string().contains("two signing nonces"), "{error}");

    // One of either is accepted.
    for (arguments, nonce) in [
        (
            json!({"server": "s", "tool": "t", "nonce": "argument-nonce"}),
            None,
        ),
        (json!({"server": "s", "tool": "t"}), Some("meta-nonce")),
    ] {
        let mut request = call("gateway_invoke", &arguments, nonce);
        let context =
            SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
        assert!(context.delivery().is_ok(), "a single nonce is well formed");
    }
}

/// A direct-route result the v2 primitive refuses (here a non-object result)
/// becomes `-32603`, never an unsigned success.
#[tokio::test]
async fn hardened_direct_signing_failure_fails_closed() {
    let meta = meta();
    let mut response =
        JsonRpcResponse::success(RequestId::Number(9), json!(["not", "an", "object"]));
    meta.sign_direct_delivery(&mut response, Some("direct-nonce"));
    assert!(
        response.result.is_none(),
        "an unsignable result left unsigned"
    );
    let error = response.error.as_ref().expect("refused");
    assert_eq!(error.code, -32603);
    assert_eq!(error.message, "Response signing failed");

    let mut response = JsonRpcResponse::success(RequestId::Number(9), json!({"content": []}));
    meta.sign_direct_delivery(&mut response, Some("direct-nonce"));
    assert!(
        response
            .result
            .as_ref()
            .and_then(|r| r.get("_signature"))
            .is_some(),
        "an object result is signed: {response:?}"
    );
}
