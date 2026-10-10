// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7642 PR.D: an owner's cancel racing the upstream task submission.
//!
//! A gated peer parks the task-augmented `tools/call`; the commit observer
//! releases it at the cancel's `Transitioned` stage, so the worker next runs
//! with both its cancel and the buffered reply ready (design r7 T2b / r9 T2c).
//! Held, it is never released (T3); unmarked, it stands for send progress
//! before the response head (T0).
use super::super::*;
use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::gateway::task_service::{
    CommitObserver, CommitStage, UpstreamAnswer, UpstreamHandle, UpstreamRecovery,
};

const HANDLE: &str = "peer-job-1";

/// Whether the peer's response head has arrived when it parks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Head {
    Received,
    Held,
}

/// What the released submission answers. Every one carries a `taskId`.
#[derive(Clone, Copy)]
enum Reply {
    Task,
    ErrorWithCandidate,
    CompleteWithCandidate,
}

struct Flag(Arc<AtomicBool>);

impl Drop for Flag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct GatedPeer {
    head: Head,
    reply: Reply,
    gate: Mutex<Option<oneshot::Receiver<()>>>,
    parked: Arc<tokio::sync::Notify>,
    /// The submission ran past its gate: it was polled after the release.
    delivered: Arc<AtomicBool>,
    /// The submission future was dropped.
    dropped: Arc<AtomicBool>,
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
        _params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<JsonRpcResponse> {
        if method != "tools/call" {
            return Ok(Self::plain(method));
        }
        // The HTTP transport's contract, played here: the mark is set once the
        // response head is in, never before.
        if self.head == Head::Received {
            crate::transport::submit_mark::arm();
            crate::transport::submit_mark::response_head_received();
        }
        let _dropped = Flag(Arc::clone(&self.dropped));
        let gate = self.gate.lock().take().expect("one submission");
        self.parked.notify_one();
        let _ = gate.await;
        self.delivered.store(true, Ordering::SeqCst);
        crate::transport::submit_mark::disarm();
        let candidate = json!({ "resultType": "task", "taskId": HANDLE, "status": "working" });
        Ok(match self.reply {
            Reply::Task => JsonRpcResponse::success(RequestId::Number(1), candidate),
            Reply::ErrorWithCandidate => {
                let mut response = JsonRpcResponse::success(RequestId::Number(1), candidate);
                response.error = Some(crate::protocol::JsonRpcError {
                    code: -32000,
                    message: "refused".to_owned(),
                    data: None,
                });
                response
            }
            Reply::CompleteWithCandidate => JsonRpcResponse::success(
                RequestId::Number(1),
                // Every other envelope field a task needs is present: only
                // `resultType` says this is no task.
                json!({ "resultType": "complete", "taskId": HANDLE, "status": "working", "content": [] }),
            ),
        })
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
struct Recovery(Arc<Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl UpstreamRecovery for Recovery {
    async fn cancel(&self, handle: &UpstreamHandle, _deadline: Duration) {
        self.0.lock().push(handle.handle.clone());
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
    Never,
    /// Open before the submission is sent: the reply is immediate.
    Immediately,
}

struct Rig {
    state: Arc<AppState>,
    _store: tempfile::TempDir,
    parked: Arc<tokio::sync::Notify>,
    delivered: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    cancels: Arc<Mutex<Vec<String>>>,
    /// Kept alive so a `Never` gate stays pending rather than closing.
    _held: Option<oneshot::Sender<()>>,
}

async fn rig(head: Head, reply: Reply, release: Release) -> Rig {
    let (state, store) = fixture_state(&two_principal_auth()).await;
    let (open, gate) = oneshot::channel();
    let parked = Arc::new(tokio::sync::Notify::new());
    let delivered = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(GatedPeer {
        head,
        reply,
        gate: Mutex::new(Some(gate)),
        parked: Arc::clone(&parked),
        delivered: Arc::clone(&delivered),
        dropped: Arc::clone(&dropped),
    }));
    std::assert!(state.backends.register(backend));
    let cancels = Arc::new(Mutex::new(Vec::new()));
    std::assert!(
        state
            .task_executor
            .install_recovery(Arc::new(Recovery(Arc::clone(&cancels))))
    );
    let (releaser, keep_open) = match release {
        Release::OnCancel => (Some(open), None),
        Release::Never => (None, Some(open)),
        Release::Immediately => {
            let _ = open.send(());
            (None, None)
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
        dropped,
        cancels,
        _held: keep_open,
    }
}

/// Start `key-a`'s task, wait for its submission to park, cancel it, and give
/// any upstream cancel time to land (and a duplicate time to follow it).
async fn start_park_cancel(rig: &Rig, before_cancel: impl FnOnce(&str)) -> String {
    let created = post(
        &rig.state,
        "key-a",
        task_invoke(1, "upstream-cancel", json!({})),
    )
    .await;
    let task = task_id(&created);
    tokio::time::timeout(Duration::from_secs(10), rig.parked.notified())
        .await
        .expect("the submission reached the gated peer");
    before_cancel(&task);
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while rig.cancels.lock().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    task
}

/// T2b (covers r7 T2'' too: the rescue poll resumes `dispatch` wherever past
/// the head it is parked). The reply is buffered and unpolled when the cancel
/// lands: one upstream `tasks/cancel` with the job's handle. Mutant "the cancel
/// arm drops without the extra poll" sends none.
#[tokio::test]
async fn a_cancel_with_the_reply_buffered_cancels_the_upstream_job_once() {
    let rig = rig(Head::Received, Reply::Task, Release::OnCancel).await;
    start_park_cancel(&rig, |_| {}).await;
    std::assert!(
        rig.delivered.load(Ordering::SeqCst),
        "the rescue poll took the reply"
    );
    std::assert_eq!(*rig.cancels.lock(), vec![HANDLE.to_owned()]);
}

/// T2c (r9 R9.2): the worker's coop budget is spent inside the cancel arm,
/// right before the rescue poll, and the buffered reply is still collected.
/// Mutant "no `unconstrained`" sees Pending and sends none.
#[tokio::test]
async fn a_spent_coop_budget_cannot_hide_a_buffered_reply() {
    let rig = rig(Head::Received, Reply::Task, Release::OnCancel).await;
    let task = start_park_cancel(&rig, |task| {
        crate::gateway::task_service::execution::rescue_seam::exhaust_before_rescue(task);
    })
    .await;
    std::assert!(
        crate::gateway::task_service::execution::rescue_seam::was_exhausted(&task),
        "precondition: the budget was spent before the rescue poll"
    );
    std::assert_eq!(*rig.cancels.lock(), vec![HANDLE.to_owned()]);
}

/// T3: past the head but no reply deliverable when the cancel lands. The
/// dispatch is dropped (its stream closed), nothing is sent upstream, and the
/// row is cancelled without a handle.
#[tokio::test]
async fn a_cancel_before_the_reply_sends_nothing_upstream() {
    let rig = rig(Head::Received, Reply::Task, Release::Never).await;
    let task = start_park_cancel(&rig, |_| {}).await;
    std::assert!(
        rig.dropped.load(Ordering::SeqCst),
        "the submission was dropped"
    );
    std::assert!(!rig.delivered.load(Ordering::SeqCst));
    std::assert!(rig.cancels.lock().is_empty(), "{:?}", rig.cancels.lock());
    std::assert!(
        rig.state
            .task_executor
            .durable_upstream_for_test(&task)
            .is_none()
    );
}

/// T0 (r10 R10.2): before the response head, a cancel drops the submission
/// with no further progress, even when that progress became ready at the
/// cancel. Mutant "rescue without the submit mark" polls it, delivers, and
/// cancels upstream.
#[tokio::test]
async fn a_cancel_before_the_head_makes_no_further_progress() {
    let rig = rig(Head::Held, Reply::Task, Release::OnCancel).await;
    start_park_cancel(&rig, |_| {}).await;
    std::assert!(
        !rig.delivered.load(Ordering::SeqCst),
        "no progress after the cancel"
    );
    std::assert!(rig.dropped.load(Ordering::SeqCst));
    std::assert!(rig.cancels.lock().is_empty(), "{:?}", rig.cancels.lock());
}

/// R1x (r10 R10.3), JSON-RPC error: a reply with an error and a candidate
/// `taskId` yields no handle, so nothing is cancelled upstream. Mutant "skip
/// the error check before `offer`" cancels "peer-job-1".
#[tokio::test]
async fn a_refused_reply_with_a_candidate_handle_cancels_nothing() {
    let rig = rig(Head::Received, Reply::ErrorWithCandidate, Release::OnCancel).await;
    start_park_cancel(&rig, |_| {}).await;
    std::assert!(
        rig.delivered.load(Ordering::SeqCst),
        "precondition: the reply was read"
    );
    std::assert!(rig.cancels.lock().is_empty(), "{:?}", rig.cancels.lock());
}

/// R1x, non-task envelope: `resultType: "complete"` carrying a `taskId` is not
/// a handle. Mutant "drop the `resultType` test in `upstream_task_handle`"
/// cancels "peer-job-1".
#[tokio::test]
async fn a_complete_reply_with_a_candidate_handle_cancels_nothing() {
    let rig = rig(
        Head::Received,
        Reply::CompleteWithCandidate,
        Release::OnCancel,
    )
    .await;
    start_park_cancel(&rig, |_| {}).await;
    std::assert!(
        rig.delivered.load(Ordering::SeqCst),
        "precondition: the reply was read"
    );
    std::assert!(rig.cancels.lock().is_empty(), "{:?}", rig.cancels.lock());
}

/// Has the owner cancel the task at the worker's `BeforeCapture` stage: after
/// the peer answered with a task, before its handle is durable (r5 T1).
struct CancelAtCapture {
    state: Mutex<std::sync::Weak<AppState>>,
    fired: AtomicBool,
}

#[async_trait::async_trait]
impl CommitObserver for CancelAtCapture {
    async fn reached(&self, stage: CommitStage, task_id: &str) {
        if stage != CommitStage::BeforeCapture || self.fired.swap(true, Ordering::SeqCst) {
            return;
        }
        let app = self
            .state
            .lock()
            .upgrade()
            .expect("the suite state is alive");
        let cancelled = post(
            &app,
            "key-a",
            task_method(3, "tasks/cancel", json!({ "taskId": task_id })),
        )
        .await;
        std::assert!(cancelled.get("error").is_none(), "{cancelled}");
    }
}

/// T1: the cancel transition finds no descriptor (none was captured yet), so
/// it claims nothing; the capture is refused on the cancelled row, and the
/// follow's cancel arm offers the handle and sends the one upstream
/// `tasks/cancel`. Mutant "the follow arm does not offer" sends none.
#[tokio::test]
async fn a_cancel_between_the_task_answer_and_its_capture_cancels_once() {
    let rig = rig(Head::Received, Reply::Task, Release::Immediately).await;
    rig.state
        .task_executor
        .observe_commits(Arc::new(CancelAtCapture {
            state: Mutex::new(Arc::downgrade(&rig.state)),
            fired: AtomicBool::new(false),
        }));
    let created = post(
        &rig.state,
        "key-a",
        task_invoke(1, "upstream-cancel-t1", json!({})),
    )
    .await;
    let task = task_id(&created);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while rig.cancels.lock().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    std::assert_eq!(*rig.cancels.lock(), vec![HANDLE.to_owned()]);
    std::assert_eq!(
        status_of(&get_task(&rig.state, "key-a", &task).await),
        "cancelled"
    );
}

/// Commits the task's Cancel at `BeforeCapture` without signalling the worker:
/// the instant between a cancel's commit and its signal.
struct CommitCancelAtCapture {
    state: Mutex<std::sync::Weak<AppState>>,
}

#[async_trait::async_trait]
impl CommitObserver for CommitCancelAtCapture {
    async fn reached(&self, stage: CommitStage, task_id: &str) {
        if stage != CommitStage::BeforeCapture {
            return;
        }
        let app = self
            .state
            .lock()
            .upgrade()
            .expect("the suite state is alive");
        app.task_executor
            .commit_cancel_unsignalled_for_test(task_id)
            .await;
    }
}

/// T1b (delta-2 review): the cancel has committed but not yet signalled when
/// the capture is refused. The worker's follow finds the row settled
/// (`Overtaken`) with no cancel seen, and still offers the handle it holds,
/// the only one anywhere: one upstream `tasks/cancel`. Mutant "Overtaken does
/// not offer" sends none.
#[tokio::test]
async fn a_cancel_committed_before_its_signal_still_cancels_upstream_once() {
    let rig = rig(Head::Received, Reply::Task, Release::Immediately).await;
    rig.state
        .task_executor
        .observe_commits(Arc::new(CommitCancelAtCapture {
            state: Mutex::new(Arc::downgrade(&rig.state)),
        }));
    post(
        &rig.state,
        "key-a",
        task_invoke(1, "upstream-cancel-t1b", json!({})),
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while rig.cancels.lock().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    std::assert_eq!(*rig.cancels.lock(), vec![HANDLE.to_owned()]);
}
