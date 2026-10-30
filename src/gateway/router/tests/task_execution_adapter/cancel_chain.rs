// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8264.CANCELCHAIN.1: an owner's cancel racing a task reply whose
//! receipt fails `chain_receive` on a chained `Require` backend (design
//! R10.3).
//!
//! The peer answers the parked submission with a valid task envelope
//! (`taskId` "cand"). Dispatch runs `chain_receive` before the submission
//! slot's `offer`, so a refused receipt leaves the slot empty: the rescue
//! poll after the cancel finds no handle, and nothing is cancelled
//! upstream. The `Off` control runs the identical rig and reply with the
//! chain mode off, where the same envelope is offered and cancelled once.
//!
//! The rows here begin their tasks on the executor directly, because a
//! router-POST creation on a `Require` backend is refused at admission
//! and never parks a dispatch. The cancel and every read still go through
//! the real route, as the task's owner.
use super::super::*;
use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::config::{ChainEmit, ChainMode};
use crate::gateway::chain_test_support::{KEY_ID, NONCE_KEY, signer, trusted_self};
use crate::gateway::meta_mcp::task_admission_request;
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::task_service::execution::{
    BeginOutcome, OwnedCallerContext, TaskCall, TaskIntent,
};
use crate::gateway::task_service::{
    CancelDelivery, CommitObserver, CommitStage, UpstreamAnswer, UpstreamHandle, UpstreamRecovery,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::meta::Declared;
use crate::protocol::tasks::{Task, TaskOptions};

/// The handle the peer's task envelope carries.
const CANDIDATE: &str = "cand";

struct GatedPeer {
    gate: Mutex<Option<oneshot::Receiver<()>>>,
    parked: Arc<tokio::sync::Notify>,
    /// The submission ran past its gate: it was polled after the release.
    delivered: Arc<AtomicBool>,
    /// The `params` of the one submission, recorded as it arrived.
    seen: Arc<Mutex<Vec<Value>>>,
}

impl GatedPeer {
    /// The answers every fixture peer gives outside the submission.
    fn plain(method: &str) -> JsonRpcResponse {
        let body = match method {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock", "version": "0" }
            }),
            "tools/list" => json!({
                "tools": [{ "name": TOOL, "description": "d", "inputSchema": { "type": "object" } }]
            }),
            _ => json!({}),
        };
        JsonRpcResponse::success(RequestId::Number(1), body)
    }
}

#[async_trait::async_trait]
impl Transport for GatedPeer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        Ok(Self::plain(method))
    }

    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<JsonRpcResponse> {
        if method != "tools/call" {
            return Ok(Self::plain(method));
        }
        self.seen.lock().push(params.unwrap_or(Value::Null));
        // The HTTP transport's contract, played here: the mark is set once
        // the response head is in, never before. This peer's head is in
        // when it parks, so a cancel's rescue poll may collect its reply.
        crate::transport::submit_mark::arm();
        crate::transport::submit_mark::response_head_received();
        let gate = self
            .gate
            .lock()
            .take()
            .expect("the rig makes one submission, so its gate is present");
        self.parked.notify_one();
        let _ = gate.await;
        self.delivered.store(true, Ordering::SeqCst);
        crate::transport::submit_mark::disarm();
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({ "resultType": "task", "taskId": CANDIDATE, "status": "working" }),
        ))
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

/// Claims the fixture backend, answers every follow query `Live`, and records
/// every handle it is asked to cancel.
struct Recovery(Arc<Mutex<Vec<String>>>, Arc<tokio::sync::Notify>);

#[async_trait::async_trait]
impl UpstreamRecovery for Recovery {
    async fn cancel(&self, handle: &UpstreamHandle, _deadline: Duration) -> CancelDelivery {
        self.0.lock().push(handle.handle.clone());
        self.1.notify_one();
        CancelDelivery::Confirmed
    }

    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        UpstreamAnswer::Live
    }
}

/// Releases the parked submission when the cancel commits, if armed to.
struct ReleaseOnCancel(Mutex<Option<oneshot::Sender<()>>>);

#[async_trait::async_trait]
impl CommitObserver for ReleaseOnCancel {
    async fn reached(&self, stage: CommitStage, _task_id: &str) {
        if stage == CommitStage::Transitioned
            && let Some(release) = self.0.lock().take()
        {
            let _ = release.send(());
        }
    }
}

/// Whether the observer releases the submission at the cancel.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Release {
    OnCancel,
    /// Open before the submission is sent: the reply is immediate.
    Immediately,
}

struct Rig {
    state: Arc<AppState>,
    _store: crate::gateway::router::tests::FixtureDir,
    parked: Arc<tokio::sync::Notify>,
    delivered: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Value>>>,
    cancels: Arc<Mutex<Vec<String>>>,
    /// Notified on every upstream cancel the adapter is asked to send.
    sent: Arc<tokio::sync::Notify>,
}

/// The suite state with a chain identity installed before it is shared:
/// this gateway signs as [`KEY_ID`] and verifies upstream chains against
/// that same key. Whether a dispatch is chained then rests on the
/// backend's own `signature_chain` mode alone.
async fn chained_state() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.set_chain_signer(signer(), ChainEmit::OnRequest);
            meta.set_chain_trust(8, trusted_self(), 300);
            meta
        },
    )
    .await
}

async fn rig(mode: ChainMode, release: Release) -> Rig {
    let (state, store) = chained_state().await;
    let (open, gate) = oneshot::channel();
    let parked = Arc::new(tokio::sync::Notify::new());
    let delivered = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            signature_chain: mode,
            chain_origins: vec![KEY_ID.to_owned()],
            chain_signer: Some(KEY_ID.to_owned()),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(GatedPeer {
        gate: Mutex::new(Some(gate)),
        parked: Arc::clone(&parked),
        delivered: Arc::clone(&delivered),
        seen: Arc::clone(&seen),
    }));
    std::assert!(
        state.backends.register(backend),
        "the fixture backend registers under a name nothing else holds"
    );
    let cancels = Arc::new(Mutex::new(Vec::new()));
    let sent = Arc::new(tokio::sync::Notify::new());
    std::assert!(
        state
            .task_executor
            .install_recovery(Arc::new(Recovery(Arc::clone(&cancels), Arc::clone(&sent)))),
        "the recovery adapter installs on a fresh executor"
    );
    let releaser = match release {
        Release::OnCancel => Some(open),
        Release::Immediately => {
            let _ = open.send(());
            None
        }
    };
    state
        .task_executor
        .observe_commits(Arc::new(ReleaseOnCancel(Mutex::new(releaser))));
    Rig {
        state,
        _store: store,
        parked,
        delivered,
        seen,
        cancels,
        sent,
    }
}

/// The task owner `key-a` acts as on the route: its verified alice
/// identity, rendered the way `route_task_owner` renders it, so the
/// router-POST cancel below is judged the task's owner.
fn owner() -> String {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@adapter.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.adapter.test".to_string(),
    }
    .stable_actor_id()
}

/// The record options, spelled out so nothing here depends on a default
/// that could move.
fn options() -> TaskOptions {
    TaskOptions {
        ttl_ms: Some(86_400_000),
        poll_interval_ms: Some(1_000),
    }
}

/// The arguments a `gateway_invoke` task carries, at the fixture backend.
fn arguments() -> Value {
    json!({ "server": BACKEND, "tool": TOOL, "arguments": {} })
}

/// One task-augmented `gateway_invoke`, built the way the production
/// admission site builds it: the same `task_admission_request` renderer,
/// the same owner string on the admission request and on the caller
/// context.
fn intent(state: &Arc<AppState>, key: &str, arguments: &Value) -> TaskIntent {
    let owner = owner();
    TaskIntent {
        executor: Arc::clone(&state.task_executor),
        owned: OwnedCallerContext::new(
            crate::gateway::task_service::host::TaskHost::Http(Arc::downgrade(state)),
            OwnedRouterAuthorizer::capture(None, None, None),
            None,
            None,
            None,
            None,
            None,
            owner.clone(),
            crate::gateway::record_principal::RecordPrincipal::none(),
            crate::gateway::meta_mcp::Authentication::Anonymous,
            crate::security::audit::CredentialKind::None,
            false,
            Declared::NONE,
            None,
            None,
            None,
        ),
        request: task_admission_request(owner, key.to_owned(), "gateway_invoke", arguments),
        options: options(),
    }
}

fn call(arguments: &Value) -> TaskCall {
    TaskCall {
        tool: "gateway_invoke".to_owned(),
        arguments: arguments.clone(),
        surfaced_server: None,
    }
}

/// Begin the task on the executor directly and return its id. The worker
/// never re-checks the backend's chain mode, so this parks the same
/// dispatch a created task would, on a backend whose mode would have
/// refused the creation at admission.
async fn begin_task(rig: &Rig, key: &str) -> String {
    let arguments = arguments();
    let task = Task::create_at(
        "gateway_invoke",
        crate::clock::utc_now().expect("the fixture clock is not before the Unix epoch"),
        options(),
    );
    let id = task.id().to_owned();
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        rig.state.task_executor.begin(
            intent(&rig.state, key, &arguments),
            task,
            BACKEND.to_owned(),
            call(&arguments),
        ),
    )
    .await
    .expect("the direct begin answers within the bound")
    .expect("the executor admits the directly begun task");
    std::assert!(
        matches!(outcome, BeginOutcome::Created(_)),
        "the direct begin creates a fresh task rather than replaying or refusing one"
    );
    id
}

/// Begin the task, wait for its submission to park, and cancel it as its
/// owner through the route. The caller then waits with [`settle`].
async fn begin_park_cancel(rig: &Rig, key: &str) -> String {
    let task = begin_task(rig, key).await;
    tokio::time::timeout(Duration::from_secs(10), rig.parked.notified())
        .await
        .expect("the submission reached the gated peer");
    let cancelled = post(
        &rig.state,
        "key-a",
        task_method(2, "tasks/cancel", json!({ "taskId": task })),
    )
    .await;
    std::assert!(
        cancelled.get("error").is_none(),
        "precondition: the owner's cancel is accepted: {cancelled}"
    );
    task
}

/// Waits on events, never a window. By the time this runs, the owner's
/// cancel post has returned, and the transition's claim is taken inside
/// it. The executor then drains, so every worker has ended and every
/// claim and inline send it made is done. A row that expects a send also
/// waits for it to land, in case the transition won the claim and sent
/// detached. The bounds are hang guards, not pass/fail windows.
async fn settle(rig: &Rig, sends: usize) {
    let drained = rig.state.task_executor.drain(Duration::from_secs(60)).await;
    std::assert!(!drained.timed_out, "every worker ends");
    if sends > 0 {
        tokio::time::timeout(Duration::from_secs(60), rig.sent.notified())
            .await
            .expect("the upstream cancel lands");
    }
}

/// Whether a recorded submission carried this dispatch's chain challenge:
/// the nonce `chain_challenge` writes into `params._meta` for a chained
/// backend, which an unchained dispatch never writes.
fn carries_chain_nonce(params: &Value) -> bool {
    params
        .get("_meta")
        .and_then(|meta| meta.get(NONCE_KEY))
        .and_then(Value::as_str)
        .is_some_and(|nonce| !nonce.is_empty())
}

fn assert_chained_submission(rig: &Rig) {
    let seen = rig.seen.lock();
    std::assert!(
        seen.iter().any(carries_chain_nonce),
        "precondition: the submission carried the chain challenge, so the \
         dispatch was chained: {seen:?}"
    );
}

/// MIK-8264.CANCELCHAIN.1. Premise: on a `Require` backend the buffered
/// reply is a valid task envelope for "cand", and the owner's cancel lands
/// while it is buffered past the response head. Oracle: no upstream
/// `tasks/cancel` is sent, no handle is durable, and the task reads
/// `cancelled` — `chain_receive` refused the reply before `offer` could
/// store its handle, so the rescue poll finds the slot empty. Mutant
/// "skip `chain_receive` before `offer`" offers "cand" and sends exactly
/// one upstream `tasks/cancel` for it.
///
/// Creating the task through `executor.begin` is an internal ORDERING
/// test, not HTTP admission coverage: router-POST creation on a `Require`
/// backend is refused at admission and would never park a dispatch.
/// `gateway_execute` and `gateway_run_playbook` tasks cannot reach this
/// path: `direct_job` excludes them, so their submission slot is never
/// armed.
///
/// Under `Require`, `chain_receive` refuses every task envelope as
/// "interim" before any signature bytes are read (Verify mode accepts it
/// unverified). So "interim" is the faithful case of a reply that fails
/// `chain_receive`, and the no-cancel twin below proves this exact reply
/// fails it.
#[tokio::test]
async fn a_cancel_racing_a_chain_refused_task_reply_cancels_nothing_upstream() {
    let rig = rig(ChainMode::Require, Release::OnCancel).await;
    let task = begin_park_cancel(&rig, "cancel-chain-main").await;
    settle(&rig, 0).await;
    std::assert!(
        rig.delivered.load(Ordering::SeqCst),
        "precondition: the buffered reply was read"
    );
    assert_chained_submission(&rig);
    std::assert!(
        rig.cancels.lock().is_empty(),
        "no upstream tasks/cancel may be sent for a reply the chain receipt \
         refused: {:?}",
        rig.cancels.lock()
    );
    std::assert!(
        rig.state
            .task_executor
            .durable_upstream_for_test(&task)
            .is_none(),
        "no upstream handle may be durable for a reply the chain receipt refused"
    );
    std::assert_eq!(
        status_of(&get_task(&rig.state, "key-a", &task).await),
        "cancelled",
        "the owner's cancel is the settlement the task reads back"
    );
}

/// The main row's premise, proven on the same rig and reply. Premise: the
/// gate is open and no cancel is sent, so the reply runs its ordinary
/// course. Oracle: the task settles `failed` with a body carrying
/// "signature chain did not verify: interim" — this exact reply fails
/// `chain_receive`, so the main row's empty slot is the refusal's doing
/// and not a reply that never carried a candidate handle.
#[tokio::test]
async fn the_same_task_reply_without_a_cancel_fails_the_chain_receipt() {
    let rig = rig(ChainMode::Require, Release::Immediately).await;
    let task = begin_task(&rig, "cancel-chain-twin").await;
    let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
    std::assert_eq!(
        status_of(&settled),
        "failed",
        "without a cancel, the chain-refused reply fails the task: {settled}"
    );
    std::assert!(
        settled
            .to_string()
            .contains("signature chain did not verify: interim"),
        "the failure is the chain receipt's refusal in its own words: {settled}"
    );
}

/// The control. Premise: the identical rig and reply on an unchained
/// (`Off`) backend, where `chain_receive` passes the envelope through to
/// `offer`, and the same owner cancel lands while it is buffered. Oracle:
/// exactly one upstream `tasks/cancel`, for "cand" — the reply the main
/// row refuses is a live handle here, so the rig can tell a refused
/// receipt from a submission that never carried one. No durable handle
/// is expected afterwards: the cancel claim consumes the descriptor it
/// sends on.
#[tokio::test]
async fn the_same_task_reply_on_an_unchained_backend_cancels_the_upstream_job_once() {
    let rig = rig(ChainMode::Off, Release::OnCancel).await;
    begin_park_cancel(&rig, "cancel-chain-control").await;
    settle(&rig, 1).await;
    std::assert!(
        rig.delivered.load(Ordering::SeqCst),
        "precondition: the rescue poll took the reply"
    );
    std::assert_eq!(
        *rig.cancels.lock(),
        vec![CANDIDATE.to_owned()],
        "unchained, the same reply's handle is cancelled upstream exactly once"
    );
}
