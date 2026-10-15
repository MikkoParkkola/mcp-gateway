// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7698: under `hardened`, a call the dispatcher will refuse before the
//! tool acts leaves its nonce unregistered, so the same nonce carries a later
//! call. Each case then proves the nonce is real: the later call admits it,
//! and a third presentation is refused as a replay.

use std::time::Duration;

use serde_json::{Value, json};

use super::super::MetaMcp;
use super::{NONCE_META, RefundWitness, SigningInvocationContext, SigningScope};
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
        && later.admitted
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

/// Signs `gateway_run_playbook` of an unknown playbook under `elicit-nonce`,
/// keyed, with or without a task intent, and has execution admission refuse it
/// (the plan check) holding `witness`, with the spent veto set per `veto`.
/// Returns whether the nonce is free afterwards.
async fn admission_refusal_frees_nonce(
    task: bool,
    witness: Option<RefundWitness>,
    veto: Veto,
) -> bool {
    use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
    use crate::gateway::task_service::{StoreLimits, TaskExecutor, TaskIntent, TaskService};
    use crate::idempotency::admission::ExecutionAdmission;
    use std::sync::Arc;
    const TOOL: &str = "gateway_run_playbook";
    const OWNER: &str = "unspent-owner";
    const KEY: &str = "unspent-key";
    let meta = meta();
    let dir = tempfile::tempdir().expect("a task store root");
    let service = Arc::new(
        TaskService::open(
            &dir.path().join("tasks"),
            StoreLimits::default(),
            ExecutionAdmission::new(Arc::new(|| 1_000)),
        )
        .await
        .expect("the task store opens"),
    );
    let refused = json!({"name": "absent-plan"});
    let intent = task.then(|| TaskIntent {
        executor: TaskExecutor::new(
            Arc::clone(&service),
            Arc::new(SubscriptionRegistry::new(
                DEFAULT_MAX_LISTENERS,
                crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
            )),
            1,
        ),
        owned: crate::gateway::task_service::execution::OwnedCallerContext::new(
            crate::gateway::task_service::host::TaskHost::Http(std::sync::Weak::new()),
            crate::gateway::router::OwnedRouterAuthorizer::capture(None, None, None),
            None,
            None,
            None,
            None,
            None,
            OWNER.to_owned(),
            crate::gateway::meta_mcp::Authentication::Anonymous,
            crate::security::audit::CredentialKind::None,
            false,
            crate::protocol::meta::Declared::NONE,
            None,
            None,
            None,
        ),
        request: crate::gateway::meta_mcp::task_admission_request(
            OWNER.to_owned(),
            KEY.to_owned(),
            TOOL,
            &refused,
        ),
        options: crate::protocol::tasks::TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    });
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some(KEY.to_owned()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let (mut signing, arguments) = captured(TOOL, &refused, "elicit-nonce");
    let mut caller = ctx(&AllowAll);
    caller.retry = &retry;
    caller.task = intent;
    meta.prepare_signing_for_call(&mut signing, TOOL, &arguments, None, &caller)
        .expect("signing admits the call; admission is the one to refuse it");
    assert!(signing.admitted, "premise: the nonce was admitted");
    if matches!(veto, Veto::Marked) {
        signing.mark_spent();
    }
    caller.signing = Some(&signing);
    let admitted = meta.admit_meta_sync(
        crate::gateway::meta_mcp::AdmissionOwner::for_test(caller.owner_principal()),
        &caller,
        TOOL,
        &arguments,
        None,
        &crate::protocol::RequestId::Number(7),
        witness,
    );
    assert!(admitted.is_err(), "premise: admission refused the call");
    nonce_is_free(&meta)
}

/// MIK-8353 (r4 amendment L2): a task call refused by admission that no longer
/// holds its witness (X14 spent its grant) keeps the nonce spent. Mutant: the
/// give-back taken without the witness.
#[tokio::test]
async fn a_task_call_refused_without_its_witness_keeps_its_nonce() {
    assert!(
        !admission_refusal_frees_nonce(true, None, Veto::Clear).await,
        "a refusal with no witness gave the nonce back"
    );
}

/// MIK-8353.NONCEFX.4a: the same task call, still holding its witness (nothing
/// consumed), gets its nonce back. Mutant mGuard: MIK-8150's task guard kept.
#[tokio::test]
async fn a_task_call_refused_with_its_witness_gives_its_nonce_back() {
    let witness = Some(RefundWitness::at_capture());
    assert!(
        admission_refusal_frees_nonce(true, witness, Veto::Clear).await,
        "a task call refused with nothing spent kept its nonce"
    );
}

/// Control: the same refusal of a synchronous call gives the nonce back
/// (MIK-8150 NONCE.1).
#[tokio::test]
async fn a_sync_call_refused_by_admission_gives_its_nonce_back() {
    let witness = Some(RefundWitness::at_capture());
    assert!(
        admission_refusal_frees_nonce(false, witness, Veto::Clear).await,
        "a synchronous call's admission refusal kept its nonce"
    );
}

/// Whether a test marks the call spent before admission refuses it.
enum Veto {
    Clear,
    Marked,
}

/// MIK-8353 VETO-1: a call marked spent gives nothing back, even holding its
/// witness: the veto only ever stops a refund. Mutant mVeto: the veto check in
/// `give_back_nonce` removed.
#[tokio::test]
async fn a_spent_mark_vetoes_a_witnessed_refund() {
    let witness = Some(RefundWitness::at_capture());
    assert!(
        !admission_refusal_frees_nonce(false, witness, Veto::Marked).await,
        "a call marked spent gave its nonce back"
    );
}

/// MIK-8353 slice 3a (W3): a refund asked with nothing dispatched is due only
/// while the call still holds its witness. Without one (a may-effect step
/// dropped it), the nonce stays spent.
#[test]
fn a_refund_is_due_only_with_the_witness() {
    let (context, _) = captured("gateway_invoke", &json!({}), "w3-nonce");
    context.want_refund();
    assert!(!context.refund_due(), "a refund with no witness was due");
    context.keep_witness(RefundWitness::at_capture());
    assert!(context.refund_due(), "the witness was kept");
    assert!(
        context.take_witness().is_some(),
        "and can be taken by the next step"
    );
    assert!(
        !context.refund_due(),
        "a taken witness no longer covers the refund"
    );
}

/// R0 (MIK-8392 Busy parity control): a kept witness, a refund asked, and
/// no dispatch: the refund is due.
#[test]
fn r0_a_kept_witness_asked_and_undispatched_is_due() {
    let (context, _) = captured("gateway_invoke", &json!({}), "r0-nonce");
    context.keep_witness(RefundWitness::at_capture());
    context.want_refund();
    assert!(context.refund_due(), "R0: the control refund was not due");
}

/// R1 (MIK-8392): dispatched with the witness kept — the state today's
/// send cannot leave (it spends the witness first), built directly so
/// the `!dispatched` clause of `refund_due` is pinned on its own.
#[test]
fn r1_a_dispatched_call_with_its_witness_kept_is_not_due() {
    let (context, _) = captured("gateway_invoke", &json!({}), "r1-nonce");
    context.keep_witness(RefundWitness::at_capture());
    context.mark_dispatched();
    context.want_refund();
    assert!(
        !context.refund_due(),
        "R1: a dispatched call's refund was due"
    );
}

/// R2 (MIK-8392): the witness taken and spent, as the send spends it, with
/// no dispatch marked: no refund is due on the witness clause alone.
#[test]
fn r2_a_spent_witness_undispatched_is_not_due() {
    let (context, _) = captured("gateway_invoke", &json!({}), "r2-nonce");
    context.keep_witness(RefundWitness::at_capture());
    let taken = context
        .take_witness()
        .expect("premise: the kept witness is taken");
    taken.spend();
    context.want_refund();
    assert!(
        !context.refund_due(),
        "R2: a spent witness still covered the refund"
    );
}

/// R3 (MIK-8392): the real send order in `invoke_tool_traced` — take the
/// witness, spend it, then mark dispatched: no refund is due, under
/// either guard.
#[test]
fn r3_the_send_order_spent_then_dispatched_is_not_due() {
    let (context, _) = captured("gateway_invoke", &json!({}), "r3-nonce");
    context.keep_witness(RefundWitness::at_capture());
    let taken = context
        .take_witness()
        .expect("premise: the kept witness is taken");
    taken.spend();
    context.mark_dispatched();
    context.want_refund();
    assert!(!context.refund_due(), "R3: the send-order refund was due");
}
