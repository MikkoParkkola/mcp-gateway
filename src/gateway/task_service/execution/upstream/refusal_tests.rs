// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The refusals of upstream capture and read-time recovery (MIK-7324.COV.3).
//!
//! Real store, real executor, one real created task. Every refusal is paired
//! with a positive control on the same row, so a path that always refuses (or
//! always accepts) fails one side of the pair.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::super::{TaskExecutor, UpstreamAnswer, UpstreamHandle, UpstreamRecovery};
use super::{RecoveredRead, RecoveryRefusal, UpstreamCapture};
use crate::gateway::meta_mcp::upstream::DirectJob;
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::{CreateOutcome, StoreLimits, Task, TaskOptions, TaskService};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::protocol::JsonRpcError;

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";
const TOOL: &str = "slow_echo";

/// Counts queries; claims only `BACKEND` unless built to claim nothing.
struct CountingPeer {
    claims: bool,
    queries: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl UpstreamRecovery for CountingPeer {
    /// This suite asserts nothing about upstream cancels (MIK-7642 PR.D rows do).
    async fn cancel(&self, _handle: &UpstreamHandle, _deadline: Duration) {}

    async fn claims(&self, backend: &str) -> bool {
        self.claims && backend == BACKEND
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        self.queries.fetch_add(1, Ordering::SeqCst);
        UpstreamAnswer::Live
    }
}

struct Fixture {
    service: Arc<TaskService>,
    executor: Arc<TaskExecutor>,
    id: String,
    revision: u64,
    owner_digest: String,
    _dir: tempfile::TempDir,
}

fn executor_over(service: &Arc<TaskService>) -> Arc<TaskExecutor> {
    TaskExecutor::new(
        Arc::clone(service),
        Arc::new(SubscriptionRegistry::new(
            DEFAULT_MAX_LISTENERS,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        )),
        1,
    )
}

/// A freshly created working row with no upstream descriptor yet.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("a fixture store root");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("the fixture store opens"),
    );
    let executor = executor_over(&service);
    let (operation, representation) = (json!({"backend": BACKEND, "tool": TOOL}), json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let task = Task::create_at(
        TOOL,
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
                key: "cov-c-refusals",
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

fn capture(handle: &str) -> UpstreamCapture {
    UpstreamCapture {
        backend: BACKEND.to_owned(),
        tool: TOOL.to_owned(),
        arguments: json!({}),
        handle: handle.to_owned(),
    }
}

/// Move the fixture row to a terminal state through the real cancel path.
async fn cancel(f: &Fixture) {
    let revision = f
        .service
        .get(OWNER, &f.id)
        .expect("row is readable")
        .revision;
    f.executor
        .cancel(OWNER, &f.id, revision)
        .await
        .expect("a working row cancels");
}

#[tokio::test]
async fn capture_refuses_an_unattributable_principal_an_absent_row_and_a_stale_revision() {
    let f = fixture().await;
    let undone = |f: &Fixture| f.executor.durable_upstream_for_test(&f.id).is_none();

    assert!(
        !f.executor
            .capture_upstream("", &f.id, f.revision, capture("h"))
            .await,
        "a principal admission refuses to hash owns no row"
    );
    assert!(undone(&f));
    assert!(
        !f.executor
            .capture_upstream(OWNER, "task-absent", f.revision, capture("h"))
            .await,
        "an absent row has no admitted digest to bind to"
    );
    assert!(undone(&f));
    assert!(
        !f.executor
            .capture_upstream(OWNER, &f.id, f.revision + 1, capture("h"))
            .await,
        "a moved revision refuses and leaves the row as it was"
    );
    assert!(undone(&f));

    // Control: the right owner and revision is accepted and durable.
    assert!(
        f.executor
            .capture_upstream(OWNER, &f.id, f.revision, capture("upstream-1"))
            .await
    );
    let durable = f.executor.durable_upstream_for_test(&f.id);
    assert_eq!(durable.map(|d| d.handle).as_deref(), Some("upstream-1"));
}

#[tokio::test]
async fn recovery_target_tells_absent_from_unavailable() {
    let f = fixture().await;
    let target = |digest: &str, id: &str| f.executor.recovery_target(digest, id).map(|r| r.handle);

    assert_eq!(
        target(&f.owner_digest, "task-absent"),
        Err(RecoveryRefusal::NotRecoverable)
    );
    assert_eq!(
        target(&f.owner_digest, &f.id),
        Err(RecoveryRefusal::NotRecoverable),
        "a working row with no descriptor is not recoverable"
    );
    assert!(
        f.executor
            .capture_upstream(OWNER, &f.id, f.revision, capture("upstream-2"))
            .await
    );
    let stranger = f.service.owner("someone-else").expect("hashes");
    assert_eq!(
        target(stranger.as_digest(), &f.id),
        Err(RecoveryRefusal::NotRecoverable),
        "a foreign owner is told the row is absent"
    );
    // Control: the owner reads the captured descriptor.
    assert_eq!(target(&f.owner_digest, &f.id), Ok("upstream-2".to_owned()));

    cancel(&f).await;
    assert_eq!(
        target(&f.owner_digest, &f.id),
        Err(RecoveryRefusal::NotRecoverable),
        "a terminal row is served unchanged, never recovered"
    );

    f.service.shutdown().await.expect("custody is released");
    assert_eq!(
        target(&f.owner_digest, &f.id),
        Err(RecoveryRefusal::Unavailable),
        "an unreadable store is unavailable, not absent"
    );
}

/// Callbacks that fail the test if recovery reaches the settlement stage.
async fn recover(
    f: &Fixture,
    executor: &TaskExecutor,
    authorized: bool,
) -> Result<RecoveredRead, RecoveryRefusal> {
    executor
        .recover_upstream_read(
            &f.owner_digest,
            &f.id,
            authorized,
            |_: Value| -> Result<Value, JsonRpcError> { panic!("no result may be processed") },
            |_: JsonRpcError| -> (JsonRpcError, crate::gateway::task_service::ErrorAuthor) {
                panic!("no error may be processed")
            },
            |event, _notes| std::future::ready((event, true)),
            Duration::from_secs(5),
        )
        .await
}

#[tokio::test]
async fn recovery_issues_no_query_without_a_claiming_adapter() {
    let f = fixture().await;
    assert!(
        f.executor
            .capture_upstream(OWNER, &f.id, f.revision, capture("upstream-3"))
            .await
    );

    // No adapter installed on this executor.
    assert_eq!(
        recover(&f, &f.executor, true).await,
        Err(RecoveryRefusal::Unclaimed)
    );

    // An adapter that does not claim the backend now.
    let silent = Arc::new(AtomicUsize::new(0));
    let declining = executor_over(&f.service);
    assert!(declining.install_recovery(Arc::new(CountingPeer {
        claims: false,
        queries: Arc::clone(&silent),
    })));
    assert_eq!(
        recover(&f, &declining, true).await,
        Err(RecoveryRefusal::Unclaimed)
    );
    assert_eq!(silent.load(Ordering::SeqCst), 0, "refused before the wire");

    // Control: a claiming adapter is queried exactly once and the live job is
    // retained.
    let queried = Arc::new(AtomicUsize::new(0));
    let claiming = executor_over(&f.service);
    assert!(claiming.install_recovery(Arc::new(CountingPeer {
        claims: true,
        queries: Arc::clone(&queried),
    })));
    assert_eq!(
        recover(&f, &claiming, true).await,
        Ok(RecoveredRead::Retained)
    );
    assert_eq!(queried.load(Ordering::SeqCst), 1);

    // The reader's own verdict is final: unauthorized issues no further query.
    assert_eq!(
        recover(&f, &claiming, false).await,
        Err(RecoveryRefusal::Denied)
    );
    assert_eq!(queried.load(Ordering::SeqCst), 1, "denied before the wire");
    assert_eq!(
        f.executor
            .recovery_target(&f.owner_digest, &f.id)
            .map(|r| r.handle),
        Ok("upstream-3".to_owned()),
        "a live job keeps its handle and its working row"
    );
}

#[tokio::test]
async fn a_handle_is_live_only_for_a_readable_working_row_that_matches() {
    let f = fixture().await;
    let handle = |backend: &str, handle: &str| UpstreamHandle {
        backend: backend.to_owned(),
        handle: handle.to_owned(),
    };
    let live = |f: &Fixture, id: &str, h: &UpstreamHandle| {
        f.executor.handle_still_live(&f.owner_digest, id, h)
    };

    assert!(
        !live(&f, "task-absent", &handle(BACKEND, "any")),
        "a row the store cannot read is not live"
    );
    assert!(
        live(&f, &f.id, &handle(BACKEND, "any")),
        "a working row with no descriptor is still followed"
    );
    assert!(
        f.executor
            .capture_upstream(OWNER, &f.id, f.revision, capture("upstream-4"))
            .await
    );
    assert!(live(&f, &f.id, &handle(BACKEND, "upstream-4")));
    assert!(!live(&f, &f.id, &handle(BACKEND, "other-handle")));
    assert!(!live(&f, &f.id, &handle("other-backend", "upstream-4")));

    cancel(&f).await;
    assert!(
        !live(&f, &f.id, &handle(BACKEND, "upstream-4")),
        "a settled row is no longer followed"
    );

    f.service.shutdown().await.expect("custody is released");
    assert!(
        !live(&f, &f.id, &handle(BACKEND, "upstream-4")),
        "an unreadable store cannot authorize a query"
    );
}

#[tokio::test]
async fn the_descriptor_preflight_refuses_what_it_cannot_measure_or_fit() {
    let f = fixture().await;
    let job = |arguments: Value| DirectJob {
        server: BACKEND.to_owned(),
        tool: TOOL.to_owned(),
        arguments,
    };
    let small = job(json!({"q": 1}));

    assert!(!f.executor.upstream_descriptor_fits("", &f.id, &small));
    assert!(
        !f.executor
            .upstream_descriptor_fits(OWNER, "task-absent", &small)
    );
    // Control: the owner's row takes a small descriptor.
    assert!(f.executor.upstream_descriptor_fits(OWNER, &f.id, &small));
    let huge = job(json!({"blob": "x".repeat(StoreLimits::default().record_bytes)}));
    assert!(!f.executor.upstream_descriptor_fits(OWNER, &f.id, &huge));
}
