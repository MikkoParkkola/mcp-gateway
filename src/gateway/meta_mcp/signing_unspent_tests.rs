// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7698: under `hardened`, a call the dispatcher will refuse before the
//! tool acts leaves its nonce unregistered, so the same nonce carries a later
//! call. Each case then proves the nonce is real: the later call admits it,
//! and a third presentation is refused as a replay.

use std::time::Duration;

use serde_json::{Value, json};

use super::super::MetaMcp;
use super::{NONCE_META, SigningInvocationContext, SigningScope};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::security::message_signing::MessageSigner;

/// Signing on, over one counted backend `alpha` that answers `read`.
fn meta() -> MetaMcp {
    let (registry, _calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.enable_message_signing(
        MessageSigner::new(
            b"signing-unspent-key-0123456789abcdef".to_vec(),
            None,
            "unspent-current".into(),
        ),
        Duration::from_secs(300),
        false,
    );
    meta
}

/// A hardened `tools/call` captured as the adapters capture it.
fn captured(name: &str, arguments: Value, nonce: &str) -> (SigningInvocationContext, Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): nonce}}});
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let arguments = request["params"]["arguments"].clone();
    (context, arguments)
}

/// `refused` is answered without registering `nonce`; a permitted call then
/// admits it, and it replays as refused.
fn assert_unspent(meta: &MetaMcp, refused: (&str, Value), caller: &MetaMcpCallerContext<'_>) {
    const NONCE: &str = "unspent-nonce";
    let (mut first, arguments) = captured(refused.0, refused.1, NONCE);
    meta.prepare_signing_invocation(&mut first, &arguments, None, caller)
        .expect("the refusal is the dispatcher's to answer");
    assert!(
        !first.admitted,
        "{}: a call the dispatcher refuses must not register its nonce",
        refused.0
    );

    let permitted = ctx(&AllowAll);
    let (mut later, arguments) = captured("gateway_list_servers", json!({}), NONCE);
    meta.prepare_signing_invocation(&mut later, &arguments, None, &permitted)
        .expect("the refused call left the nonce unspent");
    assert!(later.admitted, "the later call admits it");

    let (mut replay, arguments) = captured("gateway_list_servers", json!({}), NONCE);
    assert!(
        meta.prepare_signing_invocation(&mut replay, &arguments, None, &permitted)
            .is_err(),
        "and the nonce is a real one: its replay is refused"
    );
}

#[tokio::test]
async fn an_admin_refusal_leaves_the_nonce_unspent() {
    let caller = ctx(&AllowAll);
    assert!(!caller.is_admin);
    assert_unspent(&meta(), ("gateway_get_stats", json!({})), &caller);
}

/// An admin caller with no way to be asked (stdio and task contexts): the
/// destructive gate refuses without an exchange.
#[tokio::test]
async fn an_unconfirmable_destructive_call_leaves_the_nonce_unspent() {
    let mut caller = ctx(&AllowAll);
    caller.is_admin = true;
    assert_unspent(
        &meta(),
        ("gateway_kill_server", json!({"server": "x"})),
        &caller,
    );
}

/// Exposure applies to `gateway_invoke` too: a hidden one is refused before
/// its policy or its nonce is read.
#[tokio::test]
async fn a_hidden_gateway_invoke_leaves_the_nonce_unspent() {
    let meta = meta().with_exposed_meta_tools(&["gateway_list_servers".to_string()]);
    assert_unspent(
        &meta,
        (
            "gateway_invoke",
            json!({"server": "alpha", "tool": "read", "arguments": {}}),
        ),
        &ctx(&AllowAll),
    );
}

/// The fail-safe: a signed call left unadmitted that the gates let through is
/// refused before it acts, never served on an unspent nonce.
#[tokio::test]
async fn dispatch_refuses_a_signed_call_left_unadmitted() {
    let meta = meta();
    let (context, arguments) = captured("gateway_list_servers", json!({}), "never-admitted");
    let mut caller = ctx(&AllowAll);
    caller.signing = Some(&context);
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(7),
        "gateway_list_servers",
        arguments,
        None,
        caller,
    ))
    .await;
    let wire = serde_json::to_value(&response).expect("a response serializes");
    assert_eq!(wire["error"]["code"], -32603, "{wire}");
    assert!(wire.get("result").is_none(), "{wire}");
}
