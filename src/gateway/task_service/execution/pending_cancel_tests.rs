// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8347: a claimed upstream `tasks/cancel` that is not confirmed stays
//! pending and is retried, once per row at a time, until the peer answers or
//! a bound gives it up.
//!
//! Real store, real executor, one real created task, a scripted adapter.

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::json;
use tokio::sync::{Notify, broadcast, oneshot};

use super::super::{
    CancelDelivery, TaskExecutor, UpstreamAnswer, UpstreamCapture, UpstreamHandle,
    UpstreamRecovery,
};
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::store::targets::UpstreamCancelState;
use crate::gateway::task_service::{CreateOutcome, StoreLimits, Task, TaskOptions, TaskService};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::test_wait::{HANG_BOUND, wait_until};

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";
const TOOL: &str = "slow_echo";
const HANDLE: &str = "upstream-7";

/// Answers each cancel from its script (`Confirmed` once the script is
/// empty), records every answer it gave, and can hold one send open.
pub(super) struct ScriptedPeer {
    script: Mutex<VecDeque<CancelDelivery>>,
    pub(super) calls: Mutex<Vec<CancelDelivery>>,
    pub(super) called: Notify,
    gate: Mutex<Option<oneshot::Receiver<()>>>,
    pub(super) parked: Notify,
    pub(super) started: broadcast::Sender<String>,
}

impl ScriptedPeer {
    pub(super) fn new(script: impl IntoIterator<Item = CancelDelivery>) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
            called: Notify::new(),
            gate: Mutex::new(None),
            parked: Notify::new(),
            started: broadcast::channel(8).0,
        })
    }

    /// Hold the next send open until the returned sender fires or drops.
    pub(super) fn hold_next(&self) -> oneshot::Sender<()> {
        let (release, gate) = oneshot::channel();
        *self.gate.lock() = Some(gate);
        release
    }

    pub(super) fn count(&self) -> usize {
        self.calls.lock().len()
    }

    pub(super) fn confirmed(&self) -> usize {
        self.calls
            .lock()
            .iter()
            .filter(|c| **c == CancelDelivery::Confirmed)
            .count()
    }
}

#[async_trait::async_trait]
impl UpstreamRecovery for ScriptedPeer {
    async fn cancel(&self, handle: &UpstreamHandle, _deadline: Duration) -> CancelDelivery {
        assert_eq!(handle.handle, HANDLE, "only the row's own handle is cancelled");
        let gate = self.gate.lock().take();
        if let Some(gate) = gate {
            self.parked.notify_one();
            let _ = gate.await;
        }
        let answer = self
            .script
            .lock()
            .pop_front()
            .unwrap_or(CancelDelivery::Confirmed);
        self.calls.lock().push(answer);
        self.called.notify_one();
        answer
    }

    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        UpstreamAnswer::Live
    }

    fn started(&self) -> Option<broadcast::Receiver<String>> {
        Some(self.started.subscribe())
    }
}

pub(super) struct Fixture {
    pub(super) service: Arc<TaskService>,
    pub(super) executor: Arc<TaskExecutor>,
    pub(super) id: String,
    pub(super) owner_digest: String,
    pub(super) dir: tempfile::TempDir,
}

pub(super) fn executor_over(service: &Arc<TaskService>) -> Arc<TaskExecutor> {
    TaskExecutor::new(
        Arc::clone(service),
        Arc::new(SubscriptionRegistry::new(
            DEFAULT_MAX_LISTENERS,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        )),
        1,
    )
}

pub(super) async fn open_service(dir: &std::path::Path) -> Arc<TaskService> {
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    Arc::new(
        TaskService::open(&dir.join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("the fixture store opens"),
    )
}

/// Whether the fixture row's upstream handle reached the disk.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Handle {
    Durable,
    /// Held only by a worker whose capture was refused.
    Held,
}

/// A working row whose upstream handle is durable, with `ttl_ms` retention
/// (`None` is unlimited).
pub(super) async fn fixture(ttl_ms: Option<u64>) -> Fixture {
    fixture_with(ttl_ms, Handle::Durable).await
}

pub(super) async fn fixture_with(ttl_ms: Option<u64>, handle: Handle) -> Fixture {
    let dir = tempfile::tempdir().expect("a fixture store root");
    let service = open_service(dir.path()).await;
    let executor = executor_over(&service);
    let (operation, representation) = (json!({"backend": BACKEND, "tool": TOOL}), json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let task = Task::create_at(
        TOOL,
        chrono::Utc::now(),
        TaskOptions {
            ttl_ms,
            poll_interval_ms: Some(1_000),
        },
    );
    let created = service
        .create(
            Request {
                principal: OWNER,
                key: "mik-8347",
                operation: &operation,
                representation: &representation,
                mode: Mode::Task,
            },
            &task,
            BACKEND,
            move || workers.try_acquire_owned().ok(),
        )
        .await
        .expect("the fixture store accepts a create");
    let CreateOutcome::Created { task, slot } = created else {
        panic!("the fixture row must originate in a real committed task");
    };
    drop(slot);
    let id = task.task.id().to_owned();
    assert!(
        handle == Handle::Held
            || executor
            .capture_upstream(
                OWNER,
                &id,
                task.revision,
                UpstreamCapture {
                    backend: BACKEND.to_owned(),
                    tool: TOOL.to_owned(),
                    arguments: json!({}),
                    handle: HANDLE.to_owned(),
                },
            )
            .await,
        "the fixture handle is durable"
    );
    let owner_digest = service
        .owner(OWNER)
        .expect("the fixture principal hashes")
        .as_digest()
        .to_owned();
    Fixture {
        service,
        executor,
        id,
        owner_digest,
        dir,
    }
}

impl Fixture {
    /// The owner's cancel, through the real path (its upstream send detaches).
    pub(super) async fn owner_cancels(&self) {
        let revision = self
            .service
            .get(OWNER, &self.id)
            .expect("row is readable")
            .revision;
        self.executor
            .cancel(OWNER, &self.id, revision)
            .await
            .expect("a working row cancels");
    }

    pub(super) fn state(&self) -> Option<UpstreamCancelState> {
        self.service
            .store
            .upstream_cancel_state(&self.owner_digest, &self.id)
    }

    /// Wait until the row's cancel state is `want`.
    pub(super) async fn state_becomes(&self, want: UpstreamCancelState) {
        let reached = wait_until(HANG_BOUND, || {
            let now = self.state();
            let step = if now.as_ref() == Some(&want) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(format!("{now:?}, waiting for {want:?}"))
            };
            async move { step }
        })
        .await;
        reached.expect("the cancel state is reached");
        self.executor.cancel_send_idle(&self.id).await;
    }

    /// Move the store clock `by` past now.
    pub(super) fn advance_store_clock(&self, by: Duration) {
        let now = self.service.store.now().expect("a clock after 1970");
        let by = chrono::Duration::from_std(by).expect("a representable step");
        self.service.store.set_clock_for_test(Some(now + by));
    }
}

/// Wait until `peer` has answered at least `n` sends.
pub(super) async fn sends_reach(peer: &ScriptedPeer, n: usize) {
    let reached = wait_until(HANG_BOUND, || {
        let count = peer.count();
        let step = if count >= n {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(format!("{count} of {n} sends"))
        };
        async move { step }
    })
    .await;
    reached.expect("the sends land");
}

/// Await every retry a flush spawned.
pub(super) async fn settle(handles: Vec<tokio::task::JoinHandle<()>>) {
    for handle in handles {
        handle.await.expect("a retry task ends cleanly");
    }
}

use super::MAX_CANCEL_ATTEMPTS;
use CancelDelivery::{Failed, NotReady};
use UpstreamCancelState::{Done, Pending};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const HOUR: Duration = Duration::from_secs(60 * 60);

/// T2. Red at base. A first send that fails stays pending, and the sweep's
/// flush once it is due sends exactly one more, which confirms.
/// Mutant: "the sweep ignores Pending".
#[tokio::test]
async fn a_failed_first_send_is_retried_once_due_and_then_done() {
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let peer = ScriptedPeer::new([Failed]);
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 1 }).await;
    // Not yet due: nothing is sent.
    settle(f.executor.flush_pending_cancels(None)).await;
    assert_eq!(peer.count(), 1, "a retry before its back-off is due");
    f.advance_store_clock(HOUR);
    settle(f.executor.flush_pending_cancels(None)).await;
    f.state_becomes(Done).await;
    assert_eq!((peer.count(), peer.confirmed()), (2, 1));
}

/// T1a. Red at base. A send the backend was not ready for is retried when the
/// adapter says that backend's start succeeded, with no sweep.
/// Mutant: "no retry on the start signal".
#[tokio::test]
async fn a_not_ready_send_is_retried_when_its_backend_starts() {
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let peer = ScriptedPeer::new([NotReady]);
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 0 }).await;
    let _ = peer.started.send("other".to_owned());
    let _ = peer.started.send(BACKEND.to_owned());
    f.state_becomes(Done).await;
    assert_eq!((peer.count(), peer.confirmed()), (2, 1));
}

/// T3'. Guard. A flush that runs while the first send is still in flight
/// sends nothing of its own. Mutant: "a flush ignores the row's send lock".
#[tokio::test]
async fn a_flush_during_an_in_flight_send_sends_nothing() {
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    let release = peer.hold_next();
    let parked = peer.parked.notified();
    f.owner_cancels().await;
    parked.await;
    f.advance_store_clock(HOUR);
    settle(f.executor.flush_pending_cancels(Some(BACKEND))).await;
    settle(f.executor.flush_pending_cancels(None)).await;
    let _ = release.send(());
    f.state_becomes(Done).await;
    sends_reach(&peer, 1).await;
    assert_eq!(peer.count(), 1, "one send per row at a time");
}

/// T3''. Guard. A flush between the owner's cancel and the first poll of its
/// detached send finds the row locked. Mutant: "the lock is taken inside the
/// spawned send", which leaves the freshly claimed, already-due row unlocked.
#[tokio::test]
async fn a_flush_before_the_detached_send_is_polled_sends_nothing() {
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    // No yield since the cancel returned: its spawned send has not run.
    let flushed = f.executor.flush_pending_cancels(Some(BACKEND));
    settle(flushed).await;
    f.state_becomes(Done).await;
    sends_reach(&peer, 1).await;
    assert_eq!(peer.count(), 1, "one send per row at a time");
}

/// T7. Guard. The owner's answer does not wait on the peer.
/// Mutant: "the owner's cancel awaits its upstream send".
#[tokio::test]
async fn the_owners_cancel_returns_before_the_peer_answers() {
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    let release = peer.hold_next();
    let answered = tokio::time::timeout(HANG_BOUND, f.owner_cancels()).await;
    assert!(answered.is_ok(), "the owner's cancel waited on the peer");
    assert_eq!(peer.count(), 0, "the peer has not answered yet");
    let _ = release.send(());
    f.state_becomes(Done).await;
}

/// T7b. Guard. A repeated owner cancel while the row's send is in flight
/// answers at once and sends nothing (r3.3: the request path never queues on
/// the row's send lock). Mutant: "the request path waits for the lock".
#[tokio::test]
async fn a_repeated_owner_cancel_does_not_wait_on_the_send_in_flight() {
    use super::super::upstream::CancelSend;
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    let release = peer.hold_next();
    let parked = peer.parked.notified();
    f.owner_cancels().await;
    parked.await;
    let again = tokio::time::timeout(
        HANG_BOUND,
        f.executor
            .cancel_upstream_once(&f.owner_digest, &f.id, None, CancelSend::Detach),
    )
    .await;
    assert_eq!(again, Ok(false), "a repeat waited, or claimed again");
    let _ = release.send(());
    f.state_becomes(Done).await;
    sends_reach(&peer, 1).await;
    assert_eq!(peer.count(), 1);
}

/// T5a. Red at base. Failed sends stop at `MAX_CANCEL_ATTEMPTS`: the row is
/// given up, and nothing is sent after. Mutant: "unbounded retry".
#[tokio::test]
async fn failed_sends_stop_at_the_attempt_bound() {
    let f = fixture(Some((30 * DAY).as_millis() as u64)).await;
    let peer = ScriptedPeer::new(std::iter::repeat_n(Failed, 20));
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    for attempts in 1..MAX_CANCEL_ATTEMPTS {
        f.state_becomes(Pending { attempts }).await;
        f.advance_store_clock(3 * HOUR);
        settle(f.executor.flush_pending_cancels(None)).await;
    }
    f.state_becomes(Done).await;
    assert_eq!(peer.count(), usize::from(MAX_CANCEL_ATTEMPTS));
    f.advance_store_clock(3 * HOUR);
    settle(f.executor.flush_pending_cancels(None)).await;
    settle(f.executor.flush_pending_cancels(Some(BACKEND))).await;
    assert_eq!(peer.count(), usize::from(MAX_CANCEL_ATTEMPTS), "a send after the bound");
}

/// T5b. Red at base. Under unlimited retention a backend that is never ready
/// is given up at `MAX_CANCEL_PENDING_AGE`, without another send.
/// Mutant: "the age cap is the row's retention".
#[tokio::test]
async fn a_never_ready_backend_is_given_up_by_age_under_unlimited_retention() {
    let f = fixture(None).await;
    let peer = ScriptedPeer::new(std::iter::repeat_n(NotReady, 50));
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 0 }).await;
    f.advance_store_clock(DAY + HOUR);
    settle(f.executor.flush_pending_cancels(None)).await;
    f.state_becomes(Done).await;
    assert_eq!(peer.count(), 1, "an aged-out row was sent again");
    settle(f.executor.flush_pending_cancels(Some(BACKEND))).await;
    assert_eq!(peer.count(), 1, "a send after the age cap");
}

/// T9. Red at base. Not-ready attempts do not spend the bound: past more of
/// them than `MAX_CANCEL_ATTEMPTS`, a ready backend still gets the cancel.
/// Mutant: "NotReady counted as an attempt".
#[tokio::test]
async fn not_ready_attempts_do_not_spend_the_bound() {
    let f = fixture(Some((30 * DAY).as_millis() as u64)).await;
    let waits = usize::from(MAX_CANCEL_ATTEMPTS) + 2;
    let peer = ScriptedPeer::new(std::iter::repeat_n(NotReady, waits));
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    for sent in 1..=waits {
        let reached = wait_until(HANG_BOUND, || {
            let count = peer.count();
            async move {
                if count >= sent {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(format!("{count} of {sent} sends"))
                }
            }
        })
        .await;
        reached.expect("each not-ready send is retried");
        f.state_becomes(Pending { attempts: 0 }).await;
        f.advance_store_clock(HOUR);
        settle(f.executor.flush_pending_cancels(None)).await;
    }
    f.state_becomes(Done).await;
    assert_eq!(peer.confirmed(), 1);
}

/// T10. Red at base (it needs a retry to hold). The expiry sweep spawns a due
/// retry and never awaits it, so shutdown is not held by a hanging peer.
/// Mutant: "the sweep awaits its sends".
#[tokio::test]
async fn shutdown_is_not_held_by_a_hanging_retry() {
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let peer = ScriptedPeer::new([Failed]);
    assert!(f.executor.install_recovery(peer.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 1 }).await;
    f.advance_store_clock(HOUR);
    let _held = peer.hold_next();
    let parked = peer.parked.notified();
    let sweep = f
        .executor
        .start_expiry(Duration::from_millis(20))
        .expect("a sweep starts");
    tokio::time::timeout(HANG_BOUND, parked)
        .await
        .expect("the sweep retried the due row");
    tokio::time::timeout(HANG_BOUND, sweep.shutdown())
        .await
        .expect("shutdown is not held by the retry")
        .expect("a clean stop");
}

/// T11a. Red at base. A pending cancel survives a restart: the reopened
/// gateway sends it once, then never again. Mutant: "Pending not persisted".
#[tokio::test]
async fn a_pending_cancel_survives_a_restart_and_is_sent_once() {
    let f = fixture(Some(DAY.as_millis() as u64)).await;
    let first = ScriptedPeer::new([Failed]);
    assert!(f.executor.install_recovery(first.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 1 }).await;
    f.service.shutdown().await.expect("the first gateway stops");
    for sends in [1, 0] {
        let service = open_service(f.dir.path()).await;
        let executor = executor_over(&service);
        let peer = ScriptedPeer::new([]);
        assert!(executor.install_recovery(peer.clone()));
        settle(executor.flush_pending_cancels(Some(BACKEND))).await;
        assert_eq!(peer.count(), sends, "sends after this restart");
        assert_eq!(
            service.store.upstream_cancel_state(&f.owner_digest, &f.id),
            Some(Done)
        );
        service.shutdown().await.expect("the gateway stops");
    }
}

/// T11b. Red at base. The claim time and the failed count survive a restart,
/// so the age cap still applies to a row claimed before it.
/// Mutant: "the claim time is re-stamped on load".
#[tokio::test]
async fn a_pending_cancel_keeps_its_age_across_a_restart() {
    let f = fixture(None).await;
    let first = ScriptedPeer::new([Failed]);
    assert!(f.executor.install_recovery(first.clone()));
    f.owner_cancels().await;
    f.state_becomes(Pending { attempts: 1 }).await;
    let later = f.service.store.now().expect("a clock after 1970")
        + chrono::Duration::from_std(DAY + HOUR).expect("a representable step");
    f.service.shutdown().await.expect("the first gateway stops");
    let service = open_service(f.dir.path()).await;
    assert_eq!(
        service.store.upstream_cancel_state(&f.owner_digest, &f.id),
        Some(Pending { attempts: 1 }),
        "the failed count survives"
    );
    service.store.set_clock_for_test(Some(later));
    let executor = executor_over(&service);
    let peer = ScriptedPeer::new([]);
    assert!(executor.install_recovery(peer.clone()));
    settle(executor.flush_pending_cancels(None)).await;
    assert_eq!(peer.count(), 0, "an aged-out row was sent after the restart");
    assert_eq!(
        service.store.upstream_cancel_state(&f.owner_digest, &f.id),
        Some(Done)
    );
}

/// The worker's offer of the only handle, for a fixture with a held handle.
fn held_offer(f: &Fixture) -> crate::gateway::task_service::record::UpstreamRecord {
    let job = crate::gateway::meta_mcp::upstream::DirectJob {
        server: BACKEND.to_owned(),
        tool: TOOL.to_owned(),
        arguments: json!({}),
    };
    f.executor
        .offered_descriptor(&f.owner_digest, &f.id, &job, HANDLE.to_owned())
        .expect("the row is readable")
}

use super::Hook;

/// Whether the owner repeats its cancel while the worker is paused.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Repeat {
    Once,
    Twice,
}

/// T12 and T12c: the worker's claim finds the row working and is paused
/// under the lock; the owner cancels (and, for T12c, cancels again), then
/// the worker goes on. Exactly one cancel reaches the peer.
async fn owner_cancel_meets_a_paused_offer(repeat: Repeat, hook: Hook) {
    use super::super::upstream::CancelSend;
    let f = fixture_with(Some(DAY.as_millis() as u64), Handle::Held).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    let offer = held_offer(&f);
    let pause = f.service.cancel_sends.pause_at(hook);
    let reached = pause.reached.notified();
    let worker = tokio::spawn({
        let executor = Arc::clone(&f.executor);
        let owner = f.owner_digest.clone();
        let id = f.id.clone();
        async move {
            executor
                .cancel_upstream_once(&owner, &id, Some(offer), CancelSend::Inline)
                .await
        }
    });
    tokio::time::timeout(HANG_BOUND, reached)
        .await
        .expect("the worker's claim decided while the row was working");
    tokio::time::timeout(HANG_BOUND, f.owner_cancels())
        .await
        .expect("the owner's cancel answers at once");
    if repeat == Repeat::Twice {
        let again = tokio::time::timeout(
            HANG_BOUND,
            f.executor
                .cancel_upstream_once(&f.owner_digest, &f.id, None, CancelSend::Detach),
        )
        .await;
        assert!(again.is_ok(), "the repeat waited on the worker");
    }
    pause.release.notify_one();
    let _ = tokio::time::timeout(HANG_BOUND, worker)
        .await
        .expect("the worker's offer ends");
    f.state_becomes(Done).await;
    sends_reach(&peer, 1).await;
    assert_eq!(peer.confirmed(), 1, "the owner's cancel was lost or doubled");
}

/// T12 (r3.4). Red at base (its pause seam is the stub). Mutant:
/// "contention returns without the holder re-checking".
#[tokio::test]
async fn an_owner_cancel_meeting_a_held_offer_is_not_lost() {
    owner_cancel_meets_a_paused_offer(Repeat::Once, Hook::AfterClaim).await;
}

/// T12c (r3.5). Red at base (the same seam). Mutant: "a contender clears
/// the holder's re-check".
#[tokio::test]
async fn a_repeated_owner_cancel_does_not_erase_the_held_offers_recheck() {
    owner_cancel_meets_a_paused_offer(Repeat::Twice, Hook::AfterClaim).await;
}

/// T12d (r3.5). Red at base (its pause seam is the stub). The worker has
/// released the lock and is paused before its re-check; the owner wins the
/// lock in that gap. Covered twice on purpose (the parked offer and the
/// re-check each close it): its mutant is the r3.4 protocol, a winner that
/// clears the re-check with no parked offer.
#[tokio::test]
async fn an_owner_winning_the_lock_before_the_workers_recheck_still_cancels() {
    owner_cancel_meets_a_paused_offer(Repeat::Once, Hook::AfterRelease).await;
}

/// T12b (r3.5). Red at base. A worker's offer that finished on a working row
/// is kept, so the owner's later cancel still names the handle.
/// Mutant: "a NotOurs offer is dropped".
#[tokio::test]
async fn an_offer_made_before_the_owners_cancel_is_kept_for_it() {
    use super::super::upstream::CancelSend;
    let f = fixture_with(Some(DAY.as_millis() as u64), Handle::Held).await;
    let peer = ScriptedPeer::new([]);
    assert!(f.executor.install_recovery(peer.clone()));
    let offered = f
        .executor
        .cancel_upstream_once(&f.owner_digest, &f.id, Some(held_offer(&f)), CancelSend::Inline)
        .await;
    assert!(!offered, "premise: a working row is not claimed");
    f.owner_cancels().await;
    f.state_becomes(Done).await;
    sends_reach(&peer, 1).await;
    assert_eq!(peer.confirmed(), 1);
}
