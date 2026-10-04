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
fn captured(name: &str, arguments: &Value, nonce: &str) -> (SigningInvocationContext, Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): nonce}}});
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let arguments = request["params"]["arguments"].clone();
    (context, arguments)
}

/// `refused` is answered without registering `nonce`; a permitted call then
/// admits it, and it replays as refused.
fn assert_unspent(meta: &MetaMcp, refused: (&str, &Value), caller: &MetaMcpCallerContext<'_>) {
    const NONCE: &str = "unspent-nonce";
    let (mut first, arguments) = captured(refused.0, refused.1, NONCE);
    meta.prepare_signing_for_call(&mut first, refused.0, &arguments, None, caller)
        .expect("the refusal is the dispatcher's to answer");
    assert!(
        !first.admitted,
        "{}: a call the dispatcher refuses must not register its nonce",
        refused.0
    );

    let permitted = ctx(&AllowAll);
    let (mut later, arguments) = captured("gateway_list_servers", &json!({}), NONCE);
    meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &permitted,
    )
    .expect("the refused call left the nonce unspent");
    assert!(later.admitted, "the later call admits it");

    let (mut replay, arguments) = captured("gateway_list_servers", &json!({}), NONCE);
    assert!(
        meta.prepare_signing_for_call(
            &mut replay,
            "gateway_list_servers",
            &arguments,
            None,
            &permitted
        )
        .is_err(),
        "and the nonce is a real one: its replay is refused"
    );
}

#[tokio::test]
async fn an_admin_refusal_leaves_the_nonce_unspent() {
    let caller = ctx(&AllowAll);
    assert!(!caller.is_admin);
    assert_unspent(&meta(), ("gateway_get_stats", &json!({})), &caller);
}

/// An admin caller with no way to be asked (stdio and task contexts): the
/// destructive gate refuses without an exchange.
#[tokio::test]
async fn an_unconfirmable_destructive_call_leaves_the_nonce_unspent() {
    let mut caller = ctx(&AllowAll);
    caller.is_admin = true;
    assert_unspent(
        &meta(),
        ("gateway_kill_server", &json!({"server": "x"})),
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
            &json!({"server": "alpha", "tool": "read", "arguments": {}}),
        ),
        &ctx(&AllowAll),
    );
}

/// The fail-safe: a signed call left unadmitted that the gates let through is
/// refused before it acts, never served on an unspent nonce.
#[tokio::test]
async fn dispatch_refuses_a_signed_call_left_unadmitted() {
    let meta = meta();
    let (context, arguments) = captured("gateway_list_servers", &json!({}), "never-admitted");
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

/// A hidden tool presenting no nonce is still answered by dispatch's exposure
/// refusal, never by its own argument checks: the exposure prediction does not
/// depend on a nonce being presented.
#[tokio::test]
async fn a_hidden_gateway_invoke_without_a_nonce_is_left_to_dispatch() {
    let meta = meta().with_exposed_meta_tools(&["gateway_list_servers".to_string()]);
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {}}});
    let mut context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    meta.prepare_signing_for_call(
        &mut context,
        "gateway_invoke",
        &json!({}),
        None,
        &ctx(&AllowAll),
    )
    .expect("the hidden tool is dispatch's to answer, not its arguments'");
    assert!(!context.admitted);
}

/// A destructive call confirmed by elicitation, its question asked of the
/// session `""` (which no stream can answer: nothing is delivered).
fn elicit_caller(
    proxy: &crate::gateway::ProxyManager,
    policy: crate::gateway::destructive_confirmation::ConfirmationPolicy,
) -> MetaMcpCallerContext<'_> {
    use crate::gateway::destructive_confirmation::ConfirmationChannel;
    let mut caller = ctx(&AllowAll);
    caller.is_admin = true;
    caller.confirmation = ConfirmationChannel::Elicit { proxy, policy };
    caller
}

fn undeliverable_proxy() -> crate::gateway::ProxyManager {
    crate::gateway::ProxyManager::new(std::sync::Arc::new(
        crate::gateway::NotificationMultiplexer::new(
            std::sync::Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::StreamingConfig::default(),
        ),
    ))
}

/// Runs `gateway_kill_server` signed with `NONCE` through the dispatcher.
async fn kill_with_nonce(
    meta: &MetaMcp,
    proxy: &crate::gateway::ProxyManager,
    policy: crate::gateway::destructive_confirmation::ConfirmationPolicy,
    session: &str,
) -> Value {
    const NAME: &str = "gateway_kill_server";
    let (mut context, arguments) = captured(NAME, &json!({"server": "x"}), "elicit-nonce");
    let mut caller = elicit_caller(proxy, policy);
    meta.prepare_signing_for_call(&mut context, NAME, &arguments, Some(session), &caller)
        .expect("the confirmation is the dispatcher's to ask");
    caller.signing = Some(&context);
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(7),
        NAME,
        arguments,
        Some(session),
        caller,
    ))
    .await;
    serde_json::to_value(&response).expect("a response serializes")
}

/// Whether `elicit-nonce` is still free: an ordinary call presenting it is
/// admitted.
fn nonce_is_free(meta: &MetaMcp) -> bool {
    let (mut later, arguments) = captured("gateway_list_servers", &json!({}), "elicit-nonce");
    meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &ctx(&AllowAll),
    )
    .is_ok()
}

/// MIK-7869.NONCE.1: the question could not be delivered, the call is refused,
/// and the retry carries the same nonce.
#[tokio::test]
async fn a_failed_elicitation_leaves_the_nonce_unspent() {
    use crate::gateway::destructive_confirmation::ConfirmationPolicy;
    let (meta, proxy) = (meta(), undeliverable_proxy());
    let wire = kill_with_nonce(&meta, &proxy, ConfirmationPolicy::for_modern(), "").await;
    assert!(
        wire.get("error").is_some() || wire["result"]["isError"] == true,
        "{wire}"
    );
    assert_ne!(
        wire["error"]["code"], -32603,
        "not the unadmitted fail-safe: {wire}"
    );
    assert!(nonce_is_free(&meta), "a refused delivery spent the nonce");
}

/// MIK-7869.NONCE.2: a call the question let through spends it.
#[tokio::test]
async fn a_call_let_through_after_the_question_spends_the_nonce() {
    use crate::gateway::destructive_confirmation::ConfirmationPolicy;
    let (meta, proxy) = (meta(), undeliverable_proxy());
    let wire = kill_with_nonce(&meta, &proxy, ConfirmationPolicy::for_legacy(), "").await;
    assert_ne!(wire["error"]["code"], -32603, "{wire}");
    assert!(!nonce_is_free(&meta), "the call ran, so its nonce is spent");
}

/// A question that was delivered and answered with `action`: the answer is
/// the operator's, so what it does to the nonce does not depend on delivery.
async fn answered_with(action: &str) -> bool {
    use crate::gateway::destructive_confirmation::ConfirmationPolicy;
    let mux = std::sync::Arc::new(crate::gateway::NotificationMultiplexer::new(
        std::sync::Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    ));
    let mut stream = mux.seed_session("answering-session");
    let proxy = crate::gateway::ProxyManager::new(std::sync::Arc::clone(&mux));
    let meta = meta();
    let operator = async {
        let question = stream.recv().await.expect("the question is delivered");
        let id = question.data["id"].as_str().expect("an elicitation id");
        assert!(proxy.resolve_pending(id, "answering-session", json!({"action": action})));
    };
    let (wire, ()) = tokio::join!(
        kill_with_nonce(
            &meta,
            &proxy,
            ConfirmationPolicy::for_modern(),
            "answering-session"
        ),
        operator
    );
    assert_ne!(wire["error"]["code"], -32603, "{wire}");
    nonce_is_free(&meta)
}

#[tokio::test]
async fn a_declined_or_accepted_question_keeps_the_nonce_spent() {
    assert!(!answered_with("decline").await, "decline");
    assert!(!answered_with("accept").await, "accept");
}

/// A question that was delivered and then went unanswered: `cancel` kills its
/// channel, otherwise it times out. The operator may have seen it, so the
/// refusal is not "nobody was asked" and the nonce stays spent; only proven
/// non-delivery gives it back.
async fn delivered_then_unanswered(cancel: bool) -> bool {
    use crate::gateway::destructive_confirmation::ConfirmationPolicy;
    let mux = std::sync::Arc::new(crate::gateway::NotificationMultiplexer::new(
        std::sync::Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    ));
    let mut stream = mux.seed_session("asked-session");
    let proxy = crate::gateway::ProxyManager::new(std::sync::Arc::clone(&mux));
    let meta = meta();
    let operator = async {
        let question = stream.recv().await.expect("the question is delivered");
        if cancel {
            let id = question.data["id"].as_str().expect("an elicitation id");
            proxy.cancel_pending(id);
        }
    };
    let (wire, ()) = tokio::join!(
        kill_with_nonce(
            &meta,
            &proxy,
            ConfirmationPolicy::for_modern(),
            "asked-session"
        ),
        operator
    );
    assert!(
        wire.get("error").is_some() || wire["result"]["isError"] == true,
        "{wire}"
    );
    assert_ne!(wire["error"]["code"], -32603, "{wire}");
    nonce_is_free(&meta)
}

#[tokio::test]
async fn a_delivered_question_whose_channel_dies_keeps_the_nonce_spent() {
    assert!(
        !delivered_then_unanswered(true).await,
        "a cancelled, delivered question gave the nonce back"
    );
}

#[tokio::test(start_paused = true)]
async fn a_delivered_question_left_unanswered_keeps_the_nonce_spent() {
    assert!(
        !delivered_then_unanswered(false).await,
        "a timed-out, delivered question gave the nonce back"
    );
}
