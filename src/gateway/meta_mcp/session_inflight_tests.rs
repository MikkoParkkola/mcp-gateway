// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7682.GH2568.2: a call in flight when its session ends writes under the
//! ended id after the first cleanup pass; the grace pass removes what it wrote.
//!
//! The call runs the real `invoke_tool` path against a backend that parks the
//! `tools/call` until released, and the session ends while it is parked.
//!
//! MIK-7996: the grace pass bounds the leak only for a call shorter than
//! `END_GRACE`. The rows below it run through the dispatch tail and hold the
//! end handlers to the call's own end, whenever that is.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::Notify;

use super::{MetaMcp, MetaMcpCallerContext};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, StreamingConfig};
use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
use crate::gateway::session_lifecycle::{
    END_GRACE, SessionLifecycle, now_unix, wire_meta_session_cleanup,
};
use crate::gateway::streaming::NotificationMultiplexer;
use crate::protocol::meta::classify_request;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use crate::transition::TransitionTracker;

const SESSION: &str = "session-ended-mid-call";

/// A backend whose `tools/call` signals arrival, then waits for release.
/// With `panics` set, a released call panics instead of answering.
#[derive(Default)]
pub(crate) struct Parked {
    pub(crate) arrived: Notify,
    pub(crate) release: Notify,
    pub(crate) panics: bool,
    /// Calls that reached the backend, so a row can wait for a count rather
    /// than for a `Notify` permit an earlier call may have left behind.
    pub(crate) calls: AtomicUsize,
}

impl Parked {
    pub(crate) async fn arrivals(&self, n: usize) {
        while self.calls.load(Ordering::SeqCst) < n {
            let _ = tokio::time::timeout(Duration::from_millis(20), self.arrived.notified()).await;
        }
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for Parked {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            let tools = json!({"tools": [{"name": "act", "inputSchema": {"type": "object"}}]});
            return Ok(JsonRpcResponse::success(RequestId::Number(1), tools));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.arrived.notify_one();
        self.release.notified().await;
        assert!(!self.panics, "the backend panics while its call is held");
        let done = json!({"content": [{"type": "text", "text": "done"}], "isError": false});
        Ok(JsonRpcResponse::success(RequestId::Number(1), done))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A client the call never needs to ask.
struct Silent;

#[async_trait::async_trait]
impl ClientChannel for Silent {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        Ok(json!({"jsonrpc": "2.0", "result": {}}))
    }
}

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

/// The legacy caller every row runs as.
fn context(retry: &crate::protocol::mrtr::RetryFields) -> MetaMcpCallerContext<'_> {
    let declared = classify_request(None, None).declared_capabilities();
    MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &Silent,
    }
}

/// Run one call under the legacy session `SESSION`.
async fn call(meta: &MetaMcp) -> crate::Result<Value> {
    let retry = crate::protocol::mrtr::RetryFields::default();
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    meta.invoke_tool(&args, Some(SESSION), &context(&retry))
        .await
}

/// Run `tool` under `SESSION` through the dispatch tail the request thread
/// and the task worker share, so whatever that tail holds is held here too.
async fn tail(meta: &MetaMcp, tool: &str, args: Value) -> JsonRpcResponse {
    let retry = crate::protocol::mrtr::RetryFields::default();
    meta.dispatch_below_gate(
        RequestId::Number(7),
        tool,
        args,
        Some(SESSION),
        &context(&retry),
        false,
    )
    .await
}

fn invoke_args() -> Value {
    json!({"server": "svc", "tool": "act", "arguments": {}})
}

#[tokio::test]
async fn a_call_in_flight_when_its_session_ends_leaves_no_state_after_the_grace_pass() {
    let wire = Arc::new(Parked::default());
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend));
    let meta = Arc::new(MetaMcp::new(registry));
    let tracker = Arc::new(TransitionTracker::new());
    meta.set_transition_tracker(Arc::clone(&tracker));
    let lifecycle = Arc::new(SessionLifecycle::new());
    wire_meta_session_cleanup(&lifecycle, &meta);

    let call = call(&meta);
    tokio::pin!(call);
    tokio::select! {
        outcome = &mut call => panic!("the call finished early: {outcome:?}"),
        () = wire.arrived.notified() => {}
    }
    // The session ends while its call is at the backend.
    lifecycle.on_disconnect(SESSION);
    wire.release.notify_one();
    call.await.expect("the call completes");

    let cost = || meta.cost_tracker.session_snapshot(SESSION).is_some();
    assert!(cost(), "the call wrote its cost under the ended session");
    assert_eq!(tracker.key_count(), 1, "and its last tool");
    #[cfg(feature = "spec-preview")]
    assert!(
        meta.session_promoted.contains_key(SESSION),
        "and its promoted tool"
    );

    lifecycle.reap(now_unix());
    assert!(cost(), "the grace pass waits for its deadline");

    lifecycle.reap(now_unix() + END_GRACE.as_secs() + 1);
    assert!(!cost(), "the grace pass took the late cost bucket");
    assert_eq!(tracker.key_count(), 0, "and the late last tool");
    #[cfg(feature = "spec-preview")]
    assert!(
        !meta.session_promoted.contains_key(SESSION),
        "and the late promoted tool"
    );
}

// =====================================================================
// MIK-7996: a hold on the session reclaims what a call writes after the end
// =====================================================================

/// One gateway wired the production way, plus a session-end handler that
/// counts how often the end handlers ran for `SESSION`.
struct Wired {
    wire: Arc<Parked>,
    backends: Arc<BackendRegistry>,
    meta: Arc<MetaMcp>,
    tracker: Arc<TransitionTracker>,
    lifecycle: Arc<SessionLifecycle>,
    fired: Arc<AtomicUsize>,
}

fn wired(panics: bool) -> Wired {
    let wire = Arc::new(Parked {
        panics,
        ..Parked::default()
    });
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    let backends = Arc::new(BackendRegistry::new());
    assert!(backends.register(backend));
    let profiles = HashMap::from([("focus".to_owned(), RoutingProfileConfig::default())]);
    let meta = Arc::new(
        MetaMcp::new(Arc::clone(&backends))
            .with_profile_registry(ProfileRegistry::from_config(&profiles, "default")),
    );
    let tracker = Arc::new(TransitionTracker::new());
    meta.set_transition_tracker(Arc::clone(&tracker));
    let lifecycle = Arc::new(SessionLifecycle::new());
    wire_meta_session_cleanup(&lifecycle, &meta);
    let fired = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&fired);
    lifecycle.register_session_end("count", move |id| {
        if id == SESSION {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    });
    Wired {
        wire,
        backends,
        meta,
        tracker,
        lifecycle,
        fired,
    }
}

impl Wired {
    /// Both cleanup passes: the end itself and the grace pass after it.
    fn end_with_both_passes(&self) {
        self.lifecycle.on_disconnect(SESSION);
        self.lifecycle.reap(now_unix() + END_GRACE.as_secs() + 1);
    }

    /// Writes all five session-keyed stores under `SESSION` through the tail:
    /// the profile, the workflow state, then one backend call (cost, last
    /// tool and, under spec-preview, a promoted tool). The backend call is
    /// let through at once.
    async fn write_all_five(&self) {
        for (tool, args) in [
            ("gateway_set_profile", json!({"profile": "focus"})),
            ("gateway_set_state", json!({"state": "triage"})),
        ] {
            let answer = tail(&self.meta, tool, args).await;
            assert!(answer.error.is_none(), "{tool} is answered: {answer:?}");
        }
        self.wire.release.notify_one();
        let answer = tail(&self.meta, "gateway_invoke", invoke_args()).await;
        assert!(answer.error.is_none(), "the invoke is answered: {answer:?}");
    }

    /// Nothing remains under `SESSION` in any of the five stores.
    fn assert_nothing_left(&self, why: &str) {
        let meta = &self.meta;
        assert!(
            meta.cost_tracker.session_snapshot(SESSION).is_none(),
            "{why}: cost bucket"
        );
        assert_eq!(self.tracker.key_count(), 0, "{why}: last tool");
        assert_eq!(meta.session_profiles.len(), 0, "{why}: profile");
        assert_eq!(meta.session_state.len(), 0, "{why}: workflow state");
        #[cfg(feature = "spec-preview")]
        assert!(
            !meta.session_promoted.contains_key(SESSION),
            "{why}: promoted tool"
        );
    }

    fn fired(&self) -> usize {
        self.fired.load(Ordering::SeqCst)
    }
}

/// A multiplexer paired with the lifecycle the way the server pairs them,
/// holding `SESSION` as a live HTTP session.
fn live_multiplexer(w: &Wired) -> Arc<NotificationMultiplexer> {
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&w.backends),
        StreamingConfig::default(),
    ));
    multiplexer.spawn_reaper_on(Arc::clone(&w.lifecycle));
    drop(multiplexer.seed_session(SESSION));
    multiplexer
}

/// The call under `SESSION` that parks at the backend, spawned so a row can
/// abort it or watch it panic.
fn spawn_invoke(w: &Wired) -> tokio::task::JoinHandle<JsonRpcResponse> {
    let meta = Arc::clone(&w.meta);
    tokio::spawn(async move { tail(&meta, "gateway_invoke", invoke_args()).await })
}

#[tokio::test]
async fn a_call_held_past_both_cleanup_passes_leaves_nothing_once_it_returns() {
    let w = wired(false);
    let call = spawn_invoke(&w);
    w.wire.arrivals(1).await;

    w.end_with_both_passes();
    w.wire.release.notify_one();
    let answer = call.await.expect("the call completes");
    assert!(answer.error.is_none(), "the call is answered: {answer:?}");

    w.assert_nothing_left("a call that outlived both passes");
}

#[tokio::test]
async fn a_dispatch_that_starts_after_its_session_ended_leaves_nothing() {
    let w = wired(false);
    let multiplexer = live_multiplexer(&w);
    // DELETE and the reaper both take the session out of the multiplexer
    // first, then end it.
    multiplexer.remove_session(SESSION);
    w.end_with_both_passes();

    // A delayed task worker, an input-round resume or a call released from
    // a long confirmation: its dispatch begins after both passes.
    w.write_all_five().await;

    w.assert_nothing_left("a dispatch that began after the end");
}

#[tokio::test]
async fn a_live_session_keeps_what_its_calls_wrote() {
    let w = wired(false);
    let _multiplexer = live_multiplexer(&w);

    w.write_all_five().await;

    let meta = &w.meta;
    assert!(
        meta.cost_tracker.session_snapshot(SESSION).is_some(),
        "cost"
    );
    assert_eq!(w.tracker.key_count(), 1, "last tool");
    assert_eq!(meta.session_profiles.len(), 1, "profile");
    assert_eq!(meta.session_state.len(), 1, "workflow state");
    #[cfg(feature = "spec-preview")]
    assert!(meta.session_promoted.contains_key(SESSION), "promoted tool");
    assert_eq!(w.fired(), 0, "a live session is never ended by a call");
}

/// The end handlers run once at the end, again when the late call's hold
/// drops, and again at the grace pass: every run after the first finds less
/// or nothing, and none of them may fail on what an earlier one removed.
#[tokio::test]
async fn the_end_handlers_run_again_for_a_late_write_and_are_idempotent() {
    let w = wired(false);
    w.write_all_five().await;
    let call = spawn_invoke(&w);
    w.wire.arrivals(2).await;

    w.lifecycle.on_disconnect(SESSION);
    assert_eq!(w.fired(), 1, "the end");
    w.assert_nothing_left("the first pass");

    w.wire.release.notify_one();
    call.await.expect("the late call completes");
    assert_eq!(
        w.fired(),
        2,
        "the late call's hold ran the end handlers again"
    );
    w.assert_nothing_left("the second run took the late write");

    w.lifecycle.reap(now_unix() + END_GRACE.as_secs() + 1);
    w.lifecycle.on_disconnect(SESSION);
    assert_eq!(w.fired(), 4, "the grace pass and a repeated end");
    w.assert_nothing_left("runs on empty stores");
    assert_eq!(
        w.meta.cost_tracker.aggregate().total_calls,
        2,
        "every run kept both calls in the operator's total"
    );
}

/// The session ends while its call is at the backend; how the call then
/// stops is the variable. Each way must release the hold, which ends the
/// session a second time.
#[tokio::test]
async fn a_cancelled_call_releases_its_hold() {
    let w = wired(false);
    {
        let call = tail(&w.meta, "gateway_invoke", invoke_args());
        tokio::pin!(call);
        tokio::select! {
            outcome = &mut call => panic!("the call finished early: {outcome:?}"),
            () = w.wire.arrivals(1) => {}
        }
        w.lifecycle.on_disconnect(SESSION);
        assert_eq!(w.fired(), 1, "the end");
    }
    assert_eq!(w.fired(), 2, "dropping the call future released its hold");
    w.assert_nothing_left("after a cancel");
}

#[tokio::test]
async fn an_aborted_call_releases_its_hold() {
    let w = wired(false);
    let call = spawn_invoke(&w);
    w.wire.arrivals(1).await;
    w.lifecycle.on_disconnect(SESSION);

    call.abort();
    let stopped = call.await.expect_err("the call was aborted");
    assert!(stopped.is_cancelled(), "aborted, not finished: {stopped:?}");
    assert_eq!(w.fired(), 2, "the abort released the hold");
    w.assert_nothing_left("after an abort");
}

#[tokio::test]
async fn a_call_that_panics_releases_its_hold() {
    let w = wired(true);
    let call = spawn_invoke(&w);
    w.wire.arrivals(1).await;
    w.lifecycle.on_disconnect(SESSION);

    w.wire.release.notify_one();
    let stopped = call.await.expect_err("the backend panicked");
    assert!(stopped.is_panic(), "a panic, not a cancel: {stopped:?}");
    assert_eq!(w.fired(), 2, "unwinding released the hold");
    w.assert_nothing_left("after a panic");
}

/// Two calls hold one session when it ends. The first to finish leaves the
/// other still writing, so only the last one runs the end handlers again.
#[tokio::test]
async fn only_the_last_of_two_overlapping_holds_ends_the_session_again() {
    let w = wired(false);
    let calls = vec![spawn_invoke(&w), spawn_invoke(&w)];
    w.wire.arrivals(2).await;
    w.lifecycle.on_disconnect(SESSION);

    w.wire.release.notify_one();
    let (first, _, rest) = futures::future::select_all(calls).await;
    first.expect("one call completes");
    assert_eq!(w.fired(), 1, "a hold remains, so nothing ran again");

    w.wire.release.notify_one();
    for call in rest {
        call.await.expect("the other call completes");
    }
    assert_eq!(w.fired(), 2, "the last hold ran the end handlers again");
    w.assert_nothing_left("after both calls");
}

/// `initialize` binds a profile outside the dispatch tail. One that lands
/// after its session ended must not leave the binding behind.
#[tokio::test]
async fn an_initialize_after_its_session_ended_leaves_no_profile() {
    let w = wired(false);
    let multiplexer = live_multiplexer(&w);
    multiplexer.remove_session(SESSION);
    w.end_with_both_passes();

    let answer = w.meta.handle_initialize(
        RequestId::Number(1),
        None,
        Some(SESSION),
        Some("focus"),
        crate::protocol::meta::Era::Legacy,
        super::InvokeScope::unscoped(crate::gateway::router::CallerStanding::Admin),
    );
    assert!(answer.error.is_none(), "initialize is answered: {answer:?}");

    assert_eq!(w.meta.session_profiles.len(), 0, "the late binding is gone");
}
