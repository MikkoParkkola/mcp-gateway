// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The refusals of parking an input round and of closing a late one
//! (MIK-8195): each store or owner failure settles or leaves the row as the
//! design says, and the logs say so. Real store, real executor, one real
//! working task; a real HTTP `AppState` supplies the Meta-MCP.

use std::sync::Arc;

use serde_json::{Value, json};

use super::Settling;
use crate::gateway::router::{AppState, OwnedRouterAuthorizer};
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::execution::{OwnedCallerContext, TaskCall, TaskExecutor};
use crate::gateway::task_service::host::{LiveHost, TaskHost};
use crate::gateway::task_service::{
    CreateOutcome, StoreLimits, Task, TaskOptions, TaskService, TaskStatus,
};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::InputRequired;

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";

struct Fixture {
    service: Arc<TaskService>,
    executor: Arc<TaskExecutor>,
    state: Arc<AppState>,
    id: String,
    revision: u64,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// A freshly created working row owned by [`OWNER`], beside a live host.
async fn fixture() -> Fixture {
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
    let (state, state_dir) = crate::gateway::router::tests::direct_route_state_with_identity(
        crate::config::AgentIdentityConfig::default(),
    )
    .await;
    let (id, revision) = create_row(&service).await;
    Fixture {
        service,
        executor,
        state,
        id,
        revision,
        _dirs: (dir, state_dir),
    }
}

async fn create_row(service: &Arc<TaskService>) -> (String, u64) {
    let (operation, representation) = (json!({"backend": BACKEND, "tool": "echo"}), json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let task = Task::create_at(
        "echo",
        crate::clock::utc_now().expect("the test host's clock reads after 1970"),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    let request = Request {
        principal: OWNER,
        key: "park-key",
        operation: &operation,
        representation: &representation,
        mode: Mode::Task,
    };
    let created = service
        .create(request, &task, BACKEND, move || {
            workers.try_acquire_owned().ok()
        })
        .await
        .expect("the fixture store accepts a create");
    let CreateOutcome::Created { task, slot } = created else {
        panic!("the fixture row must originate in a real committed task");
    };
    drop(slot);
    (task.task.id().to_owned(), task.revision)
}

fn owned_context(fx: &Fixture) -> OwnedCallerContext {
    OwnedCallerContext::new(
        TaskHost::Http(Arc::downgrade(&fx.state)),
        OwnedRouterAuthorizer::capture(None, None, None),
        None,
        None,
        None,
        None,
        None,
        OWNER.to_owned(),
        crate::gateway::meta_mcp::Authentication::Anonymous,
        crate::security::audit::CredentialKind::None,
        false,
        Declared::NONE,
        None,
        None,
        None,
    )
}

fn status(fx: &Fixture) -> TaskStatus {
    fx.service
        .get(OWNER, &fx.id)
        .expect("the owner reads its task")
        .task
        .status()
}

fn call(tool: &str, arguments: Value) -> TaskCall {
    TaskCall {
        tool: tool.to_owned(),
        arguments,
    }
}

fn round() -> InputRequired {
    InputRequired {
        requests: vec![("k".into(), json!({"method": "roots/list"}))],
        request_state: None,
    }
}

/// Where the settling worker believes the row is: which principal, id and
/// revision it settles under.
struct Ids<'a> {
    principal: &'a str,
    id: &'a str,
    revision: u64,
}

/// Run `park` for `ids`, with `tool` and `arguments` as the parked call.
async fn park(fx: &Fixture, ids: Ids<'_>, tool: &str, arguments: Value) {
    let owned = owned_context(fx);
    let host = LiveHost::Http(Arc::clone(&fx.state));
    let call = call(tool, arguments);
    Settling::new(
        &fx.executor,
        &host,
        &owned,
        &call,
        ids.principal,
        ids.id,
        ids.revision,
    )
    .park(round())
    .await;
}

/// Run `body` on a current-thread runtime and return every record it logged.
fn logged(body: impl std::future::Future<Output = ()>) -> Vec<Value> {
    crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(body);
    })
}

/// The records at `level` whose message contains `text`.
fn at_level<'a>(records: &'a [Value], level: &str, text: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|r| {
            r["level"] == level
                && r["fields"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains(text))
        })
        .collect()
}

/// `park_targets` for the given ids and tool, on `fx`.
async fn park_targets(fx: &Fixture, ids: Ids<'_>, tool: &str) -> bool {
    let owned = owned_context(fx);
    let host = LiveHost::Http(Arc::clone(&fx.state));
    let call = call(tool, json!({}));
    Settling::new(
        &fx.executor,
        &host,
        &owned,
        &call,
        ids.principal,
        ids.id,
        ids.revision,
    )
    .park_targets()
    .await
}

fn own(fx: &Fixture) -> Ids<'_> {
    Ids {
        principal: OWNER,
        id: &fx.id,
        revision: fx.revision,
    }
}

/// A plan's calls are written to the row, so the round may be parked; a row a
/// cancel already moved is not parked either way, and is not a failure.
/// Mutant: the store result is not read, or a conflict counts as a failure.
#[tokio::test]
async fn a_plans_calls_are_durable_or_the_row_has_already_moved() {
    let fx = fixture().await;

    let stored = park_targets(&fx, own(&fx), "gateway_execute").await;
    let stale = Ids {
        revision: fx.revision + 9,
        ..own(&fx)
    };
    let moved = park_targets(&fx, stale, "gateway_run_playbook").await;

    assert!(stored, "the calls were written, so the round may park");
    assert!(moved, "a moved row is settled by its own commit");
}

/// A plan whose owner cannot be resolved cannot record its calls, so the
/// round must not be parked. Mutant: the owner failure reads as durable.
#[tokio::test]
async fn a_plan_with_no_resolvable_owner_is_not_durable() {
    let fx = fixture().await;
    let nobody = Ids {
        principal: "",
        ..own(&fx)
    };

    assert!(!park_targets(&fx, nobody, "gateway_execute").await);
}

/// A plan whose calls the store cannot write is not durable either.
/// Mutant: any store error reads as durable.
#[tokio::test]
async fn a_plan_the_closed_store_cannot_record_is_not_durable() {
    let fx = fixture().await;
    fx.service.shutdown().await.expect("the store closes");

    assert!(!park_targets(&fx, own(&fx), "gateway_execute").await);
}

/// A plan that cannot record its calls is not parked: no round write is
/// attempted, so no commit failure is logged.
/// Mutant: the round is committed after a failed target write.
#[test]
fn a_plan_that_cannot_record_its_calls_is_not_parked() {
    let records = logged(async {
        let fx = fixture().await;
        fx.service.shutdown().await.expect("the store closes");
        park(&fx, own(&fx), "gateway_execute", json!({})).await;
    });

    assert!(at_level(&records, "WARN", "input round not committed").is_empty());
}

/// An owner that cannot be resolved leaves the row unparked.
/// Mutant: the round is parked without an owner to write it under.
#[tokio::test]
async fn a_round_with_no_resolvable_owner_is_not_parked() {
    let fx = fixture().await;
    let nobody = Ids {
        principal: "",
        ..own(&fx)
    };

    park(&fx, nobody, "echo", json!({})).await;

    assert_eq!(status(&fx), TaskStatus::Working);
}

/// Control: a well-formed round for the owned row parks as `input_required`.
#[tokio::test]
async fn a_well_formed_round_parks_the_row() {
    let fx = fixture().await;

    park(&fx, own(&fx), "echo", json!({})).await;

    assert_eq!(status(&fx), TaskStatus::InputRequired);
}

/// A continuation that does not fit the record settles today's abandoned
/// result instead of parking. Mutant: the capacity refusal leaves the row
/// `working`, or parks it.
#[tokio::test]
async fn a_round_too_large_for_the_record_settles_abandoned() {
    let fx = fixture().await;
    let huge = json!({"blob": "x".repeat(600 * 1024)});

    park(&fx, own(&fx), "echo", huge).await;

    assert_eq!(status(&fx), TaskStatus::Completed);
    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    let result = stored.task.result().expect("a result").to_string();
    assert!(result.contains("input_round_unavailable"), "{result}");
}

/// A cancel that already moved the row is the answer: nothing more is
/// written and no failure is logged. Mutant: the revision conflict is treated
/// as a write failure.
#[test]
fn a_round_for_a_row_that_moved_leaves_it_alone() {
    let mut after = None;
    let records = logged(async {
        let fx = fixture().await;
        let stale = Ids {
            revision: fx.revision + 9,
            ..own(&fx)
        };
        park(&fx, stale, "echo", json!({})).await;
        after = Some(status(&fx));
    });

    assert_eq!(after, Some(TaskStatus::Working));
    assert!(at_level(&records, "WARN", "input round not committed").is_empty());
}

/// A row that is gone is likewise left alone, without a logged failure.
#[test]
fn a_round_for_a_row_that_is_gone_writes_nothing() {
    let mut after = None;
    let records = logged(async {
        let fx = fixture().await;
        let gone = Ids {
            id: "no-such-task",
            ..own(&fx)
        };
        park(&fx, gone, "echo", json!({})).await;
        after = Some(status(&fx));
    });

    assert_eq!(after, Some(TaskStatus::Working));
    assert!(at_level(&records, "WARN", "input round not committed").is_empty());
}

/// A round the store cannot write is logged with the task and the cause.
/// Mutant: the failure is swallowed silently.
#[test]
fn a_round_the_store_cannot_write_is_logged_with_its_cause() {
    let mut task_id = String::new();
    let records = logged(async {
        let fx = fixture().await;
        task_id.clone_from(&fx.id);
        fx.service.shutdown().await.expect("the store closes");
        park(&fx, own(&fx), "echo", json!({})).await;
    });

    let warned = at_level(&records, "WARN", "input round not committed");
    assert_eq!(warned.len(), 1, "{records:?}");
    assert_eq!(warned[0]["fields"]["task_id"], task_id.as_str());
    assert_eq!(warned[0]["fields"]["error"], "task store unavailable");
}

/// A late round whose owner cannot be resolved closes nothing.
/// Mutant: the round is closed (or an error logged) without an owner.
#[tokio::test]
async fn a_late_round_with_no_resolvable_owner_is_left_open() {
    let fx = fixture().await;

    fx.executor
        .close_late_round("", &fx.id, fx.revision, 10)
        .await;

    assert_eq!(status(&fx), TaskStatus::Working);
}

/// A close that fails for a reason other than a moved row is tried again, and
/// when it fails again it is logged with the task. Mutant: no retry, or the
/// second failure is silent.
#[test]
fn a_late_round_that_cannot_be_closed_twice_is_logged() {
    let records = logged(async {
        let fx = fixture().await;
        fx.executor
            .close_late_round(OWNER, "no-such-task", fx.revision, 10)
            .await;
    });

    let warned = at_level(&records, "WARN", "a late input round was not closed");
    assert_eq!(warned.len(), 1, "{records:?}");
    assert_eq!(warned[0]["fields"]["task_id"], "no-such-task");
}

/// A close that finds the row moved is final: not retried, not logged.
/// Mutant: a moved row is treated as a failure.
#[test]
fn a_late_round_for_a_moved_row_is_not_retried_or_logged() {
    let records = logged(async {
        let fx = fixture().await;
        fx.executor
            .close_late_round(OWNER, &fx.id, fx.revision + 9, 10)
            .await;
        assert_eq!(status(&fx), TaskStatus::Working);
    });

    assert!(at_level(&records, "WARN", "a late input round was not closed").is_empty());
}

/// A close whose first write fails is retried once, and the retry settles the
/// round cancelled without logging a failure. Mutant: no second attempt, so
/// the row stays `working`.
#[test]
fn a_late_round_whose_first_close_write_fails_is_closed_by_the_retry() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::gateway::task_service::store::CommitStage;

    let failed_once = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&failed_once);
    let mut closed = None;
    let records = logged(async {
        let fx = fixture().await;
        fx.service
            .store
            .set_hook(Some(Arc::new(move |stage| {
                if stage == CommitStage::Write && !seen.swap(true, Ordering::SeqCst) {
                    return Err(std::io::Error::other("injected first-write failure"));
                }
                Ok(())
            })))
            .await;
        fx.executor
            .close_late_round(OWNER, &fx.id, fx.revision, 10)
            .await;
        closed = Some(status(&fx));
    });

    assert!(
        failed_once.load(Ordering::SeqCst),
        "control: the first write failed"
    );
    assert_eq!(closed, Some(TaskStatus::Cancelled));
    assert!(at_level(&records, "WARN", "a late input round was not closed").is_empty());
}
