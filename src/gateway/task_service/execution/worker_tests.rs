// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker's settlement retry, dispatch marker, poll budget and create
//! failure (MIK-8195 wave 3). Real store, real executor, one real working
//! task. The conflict is forced by moving the row on before settling at the
//! revision the caller read, so nothing races and nothing sleeps.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;

use super::{Followed, Marker, WORKER_POLL_BUDGET, poll_to_terminal};
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::execution::{
    TaskExecutor, UpstreamAnswer, UpstreamHandle, UpstreamRecovery,
};
use crate::gateway::task_service::store::CommitStage;
use crate::gateway::task_service::{
    CreateOutcome, StoreLimits, Task, TaskOptions, TaskService, TaskStatus, TaskTransition,
};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";

struct Fixture {
    service: Arc<TaskService>,
    executor: Arc<TaskExecutor>,
    id: String,
    revision: u64,
    owner_digest: String,
    _dir: tempfile::TempDir,
}

/// A freshly created working row, owned by [`OWNER`].
async fn fixture(key: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("a fixture store root");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("the fixture store opens"),
    );
    let executor = TaskExecutor::new(
        Arc::clone(&service),
        Arc::new(SubscriptionRegistry::new(
            DEFAULT_MAX_LISTENERS,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        )),
        1,
    );
    let (operation, representation) = (json!({"backend": BACKEND, "tool": "echo"}), json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let task = Task::create_at(
        "echo",
        chrono::Utc::now(),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    let created = service
        .create(
            Request {
                principal: OWNER,
                key,
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
    let owner_digest = service
        .owner(OWNER)
        .expect("the fixture principal hashes")
        .as_digest()
        .to_owned();
    Fixture {
        service,
        executor,
        id: task.task.id().to_owned(),
        revision: task.revision,
        owner_digest,
        _dir: dir,
    }
}

impl Fixture {
    fn status(&self) -> TaskStatus {
        self.service
            .get(OWNER, &self.id)
            .expect("the owner reads its task")
            .task
            .status()
    }

    fn stored_revision(&self) -> u64 {
        self.service
            .get(OWNER, &self.id)
            .expect("the owner reads its task")
            .revision
    }

    /// Move the row on at `revision` without settling it, so a settlement
    /// holding the old revision loses its first compare-and-set.
    async fn move_on(&self, event: TaskTransition) {
        self.service
            .store
            .transition(
                &self.owner_digest,
                &self.id,
                self.revision,
                event,
                chrono::Utc::now(),
            )
            .await
            .expect("the row moves on at the revision read");
    }

    /// Fail every store write from now on, counting the attempts.
    async fn fail_writes(&self) -> Arc<AtomicUsize> {
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&attempts);
        self.service
            .store
            .set_hook(Some(Arc::new(move |stage| {
                if matches!(stage, CommitStage::Write) {
                    seen.fetch_add(1, Ordering::SeqCst);
                    return Err(std::io::Error::other("injected write failure"));
                }
                Ok(())
            })))
            .await;
        attempts
    }
}

fn complete() -> TaskTransition {
    TaskTransition::Complete(json!({"content": [{"type": "text", "text": "done"}]}))
}

/// A settlement that loses its first compare-and-set re-reads the row and
/// commits at the revision it now holds. Mutant: the conflict is treated as a
/// failure and the retry is dropped, leaving the row working.
#[tokio::test]
async fn a_settlement_that_lost_its_revision_retries_at_the_current_one() {
    let fx = fixture("cas-retry").await;
    fx.move_on(TaskTransition::StatusMessage(Some("busy".into())))
        .await;
    assert_ne!(fx.stored_revision(), fx.revision, "control: the row moved");

    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete())
        .await;

    assert!(delivered, "the retried settlement stored backend output");
    assert_eq!(fx.status(), TaskStatus::Completed);
}

/// A row that went terminal while the settlement was in flight keeps its
/// outcome: the retry stops and reports nothing delivered. Mutant: the
/// terminal check is dropped and the second write overwrites the outcome.
#[tokio::test]
async fn a_settlement_that_lost_to_a_terminal_row_leaves_it_alone() {
    let fx = fixture("cas-terminal").await;
    let first = json!({"content": [{"type": "text", "text": "first"}]});
    fx.move_on(TaskTransition::Complete(first)).await;
    let attempts = fx.fail_writes().await;

    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete())
        .await;

    assert!(!delivered, "the later settlement delivered nothing");
    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    assert_eq!(stored.task.status(), TaskStatus::Completed);
    let result = stored.task.result().expect("a result").to_string();
    assert!(
        result.contains("first"),
        "the first outcome stands: {result}"
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "no second write was attempted against a terminal row"
    );
}

/// A retry that loses its second compare-and-set (here a failed write) gives
/// up without claiming delivery, after exactly one write attempt.
#[tokio::test]
async fn a_settlement_whose_retry_also_fails_reports_nothing_delivered() {
    let fx = fixture("cas-second").await;
    fx.move_on(TaskTransition::StatusMessage(Some("busy".into())))
        .await;
    let attempts = fx.fail_writes().await;

    let delivered = fx
        .executor
        .settle_cas(OWNER, &fx.id, fx.revision, complete())
        .await;

    assert!(!delivered);
    assert_eq!(fx.status(), TaskStatus::Working, "the row was not settled");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "the stale first write never reached the disk; only the retry did"
    );
}

/// A marker write at a revision the row has left, or on a settled row, is
/// refused; the same call at the live revision marks. Mutant: a refusal is
/// reported as a store failure (which would settle the row interrupted).
#[tokio::test]
async fn a_marker_on_a_moved_or_settled_row_is_refused() {
    let fx = fixture("marker-refused").await;
    fx.move_on(TaskTransition::StatusMessage(Some("busy".into())))
        .await;

    let stale = fx
        .executor
        .mark_dispatched(OWNER, &fx.id, fx.revision)
        .await;
    assert!(matches!(stale, Marker::Refused), "a moved revision refuses");
    let live = fx
        .executor
        .mark_dispatched(OWNER, &fx.id, fx.stored_revision())
        .await;
    assert!(
        matches!(live, Marker::Marked),
        "control: the live one marks"
    );

    assert!(
        fx.executor
            .settle_cas(OWNER, &fx.id, fx.stored_revision(), complete())
            .await
    );
    let settled = fx
        .executor
        .mark_dispatched(OWNER, &fx.id, fx.stored_revision())
        .await;
    assert!(matches!(settled, Marker::Refused), "a settled row refuses");
}

/// A marker that cannot be made durable, or a principal that cannot be hashed,
/// is a failure the worker answers by settling interrupted.
#[tokio::test]
async fn a_marker_that_cannot_be_written_or_owned_fails() {
    let fx = fixture("marker-failed").await;

    let nobody = fx.executor.mark_dispatched("", &fx.id, fx.revision).await;
    assert!(matches!(nobody, Marker::Failed), "an unhashable principal");

    let attempts = fx.fail_writes().await;
    let unwritable = fx
        .executor
        .mark_dispatched(OWNER, &fx.id, fx.revision)
        .await;
    assert!(matches!(unwritable, Marker::Failed), "a failed write");
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "the write was tried");
}

/// Always answers `Live`, counting its queries.
struct LivePeer {
    queries: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl UpstreamRecovery for LivePeer {
    async fn claims(&self, _backend: &str) -> bool {
        true
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        self.queries.fetch_add(1, Ordering::SeqCst);
        UpstreamAnswer::Live
    }
}

fn handle() -> UpstreamHandle {
    UpstreamHandle {
        backend: BACKEND.to_owned(),
        handle: "job-1".to_owned(),
    }
}

/// A job that stays live is queried again and again until the worker's budget
/// is spent, then handed back retained. Paused time makes the 300 s budget
/// instant. Mutant: the budget check is dropped and the loop never ends.
#[tokio::test(start_paused = true)]
async fn a_job_that_stays_live_is_retained_when_the_budget_runs_out() {
    let fx = fixture("poll-budget").await;
    let queries = Arc::new(AtomicUsize::new(0));
    let adapter: Arc<dyn UpstreamRecovery> = Arc::new(LivePeer {
        queries: Arc::clone(&queries),
    });

    let followed =
        poll_to_terminal(&fx.executor, &fx.owner_digest, &fx.id, &adapter, &handle()).await;

    assert!(matches!(followed, Followed::Retained));
    assert!(
        queries.load(Ordering::SeqCst) >= 2,
        "a live answer is retried within the budget"
    );
    assert!(
        queries.load(Ordering::SeqCst) as u64 <= WORKER_POLL_BUDGET.as_secs() + 1,
        "and never beyond it"
    );
    assert_eq!(
        fx.status(),
        TaskStatus::Working,
        "nothing was faked terminal"
    );
}

/// A row already settled when the worker reaches the front of the slot queue
/// is never queried: the peer sees zero calls. Control: the live row is.
#[tokio::test(start_paused = true)]
async fn a_row_settled_before_the_poll_is_never_queried() {
    let fx = fixture("poll-overtaken").await;
    let queries = Arc::new(AtomicUsize::new(0));
    let adapter: Arc<dyn UpstreamRecovery> = Arc::new(LivePeer {
        queries: Arc::clone(&queries),
    });
    fx.move_on(TaskTransition::Cancel).await;

    let followed =
        poll_to_terminal(&fx.executor, &fx.owner_digest, &fx.id, &adapter, &handle()).await;

    assert!(matches!(followed, Followed::Overtaken));
    assert_eq!(queries.load(Ordering::SeqCst), 0, "the peer was not asked");
}
