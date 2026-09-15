// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The periodic expiry owner the gateway runtime starts and stops.
//!
//! Expiry is a startup-owned loop, not a call: the runtime starts it after the
//! recovered runtime exists and joins it before the store closes. So these rows
//! drive [`TaskExecutor::start_expiry`] and its guard, never `TaskStore::expire`
//! directly — an implementation that only exposes the atomic deletion has not
//! implemented the owner these rows are about.
//!
//! What each row pins:
//!
//! * every terminal shape whose TTL ran out is deleted, record AND retained
//!   idempotency key together, so the original key admits a NEW task and the
//!   capacity the record reserved comes back;
//! * an unexpired record, a null-TTL record, and old Working / `InputRequired`
//!   records are retained unchanged while expired sentinels are actually swept;
//! * the guard's shutdown joins a deletion that is already in flight.
//!
//! TTL is measured from `createdAt`. Every seeded row is created deliberately
//! old and settled at `Utc::now()`, so a deadline anchored on `lastUpdatedAt`
//! would retain rows these assertions require gone.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Waker};
use std::time::Duration;

use chrono::Utc;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::super::store::{CommitHook, CommitStage};
use super::test_subscriptions;
use crate::gateway::task_service::{
    CreateOutcome, ServiceError, StoreLimits, Task, TaskOptions, TaskService, TaskStatus,
    TaskTransition, open_runtime_with_admission,
};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::protocol::mrtr::InputRequired;

const OWNER: &str = "verified-owner";
/// Every wait in this file is bounded by a real timeout: a sweep that never
/// happens must fail at the assertion that names it, not hang the harness.
const BUDGET: Duration = Duration::from_secs(5);
/// Short enough that a row's deletion is observed within `BUDGET`, long enough
/// that the loop is a periodic owner rather than a spin.
const TICK: Duration = Duration::from_millis(20);
/// A TTL every seeded row is already past, given a creation time an hour back.
const SHORT_TTL_MS: u64 = 60_000;
const DAY_MS: u64 = 86_400_000;

fn operation() -> Value {
    json!({"backend": "fixture", "tool": "write"})
}

fn representation() -> Value {
    json!({"wire": "modern"})
}

fn request<'a>(key: &'a str, operation: &'a Value, representation: &'a Value) -> Request<'a> {
    Request {
        principal: OWNER,
        key,
        operation,
        representation,
        mode: Mode::Task,
    }
}

fn fresh_admission() -> Arc<ExecutionAdmission> {
    ExecutionAdmission::new(Arc::new(|| 1_000))
}

/// How a seeded row was left, once its record was committed.
#[derive(Clone, Copy, Debug)]
enum Settle {
    Completed,
    Failed,
    Cancelled,
    /// Left running: expiry is not a way to end work that never stopped.
    Working,
    /// Left mid-exchange, which is equally not expiry's to end.
    InputRequired,
}

/// One committed row, as the store answered for it.
struct Seeded {
    id: String,
    /// The committed wire projection at seed time; retention rows compare
    /// against this rather than against a value the test constructed.
    wire: Value,
}

/// Commit one row through the ordinary create facade of an ALREADY-OPEN
/// runtime, then settle it at `Utc::now()`.
///
/// `age_ms` moves only `createdAt`: the settlement is recent on purpose, so the
/// TTL anchor under test is creation and cannot be `lastUpdatedAt`.
async fn seed(
    service: &Arc<TaskService>,
    workers: &Arc<Semaphore>,
    key: &str,
    age_ms: i64,
    ttl_ms: Option<u64>,
    settle: Settle,
) -> Seeded {
    let (operation, representation) = (operation(), representation());
    let created_at = Utc::now() - chrono::Duration::milliseconds(age_ms);
    let task = Task::create_at(
        "write",
        created_at,
        TaskOptions {
            ttl_ms,
            poll_interval_ms: Some(1_000),
        },
    );
    let slot = Arc::clone(workers);
    let created = service
        .create(
            request(key, &operation, &representation),
            &task,
            "fixture",
            move || slot.try_acquire_owned().ok(),
        )
        .await
        .expect("the fixture store accepts a create");
    let CreateOutcome::Created { task, slot } = created else {
        panic!("row {key} must originate in a real committed task");
    };
    // The permit belongs to a worker that never runs here.
    drop(slot);
    let id = task.task.id().to_owned();
    let owner = service
        .owner(OWNER)
        .expect("admission hashes the fixture principal")
        .as_digest()
        .to_owned();
    let event = match settle {
        Settle::Working => None,
        Settle::Completed => Some(TaskTransition::Complete(
            json!({"content": [{"type": "text", "text": "settled"}], "isError": false}),
        )),
        Settle::Failed => Some(TaskTransition::Fail(crate::protocol::JsonRpcError {
            code: -32042,
            message: "persisted terminal failure".to_owned(),
            data: None,
        })),
        Settle::Cancelled => Some(TaskTransition::Cancel),
        Settle::InputRequired => Some(TaskTransition::RequireInput(InputRequired {
            requests: vec![(
                "confirm".to_owned(),
                json!({"method": "elicitation/create", "params": {}}),
            )],
            request_state: Some("still outstanding".to_owned()),
        })),
    };
    if let Some(event) = event {
        service
            .store
            .transition(&owner, &id, task.revision, event, Utc::now())
            .await
            .expect("the fixture settles a seeded row");
    }
    let committed = service.get(OWNER, &id).expect("the seeded row is readable");
    Seeded {
        id,
        wire: serde_json::to_value(committed.task.wire()).unwrap(),
    }
}

/// The record file a task id owns. Deletion has to be durable, so absence from
/// the readable view alone is never the whole assertion.
fn record_path(dir: &std::path::Path, id: &str) -> std::path::PathBuf {
    dir.join(format!("{id}.json"))
}

/// Poll the REAL service and the directory until the row is gone from both,
/// bounded as a whole. No sleep stands in for the sweep: the loop ends on the
/// observation it is waiting for, or on the budget.
async fn swept(service: &Arc<TaskService>, dir: &std::path::Path, id: &str) -> bool {
    timeout(BUDGET, async {
        loop {
            let readable = service.get(OWNER, id);
            if matches!(readable, Err(ServiceError::NotFound)) && !record_path(dir, id).exists() {
                return;
            }
            tokio::time::sleep(TICK / 2).await;
        }
    })
    .await
    .is_ok()
}

/// A row is retained exactly as committed: same handle, same wire.
fn assert_retained(service: &Arc<TaskService>, dir: &std::path::Path, row: &Seeded, what: &str) {
    let held = service
        .get(OWNER, &row.id)
        .unwrap_or_else(|error| panic!("{what} must survive expiry, got {error:?}"));
    assert_eq!(
        serde_json::to_value(held.task.wire()).unwrap(),
        row.wire,
        "{what} was rewritten by a sweep that should not have touched it"
    );
    assert!(
        record_path(dir, &row.id).exists(),
        "{what} lost its durable record"
    );
}

/// One-shot TIMED seam at a store commit stage, after the store idiom in
/// `store_tests/admission.rs`: a bounded wait, and a dropped sender ends it, so
/// a failed assertion cannot strand the blocking thread.
fn paused_at(
    stage: CommitStage,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    CommitHook,
) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let receiver = Mutex::new(release_rx);
    let arrivals = AtomicUsize::new(0);
    let hook: CommitHook = Arc::new(move |fired| {
        if fired == stage && arrivals.fetch_add(1, Ordering::SeqCst) == 0 {
            let _ = entered_tx.send(());
            receiver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv_timeout(BUDGET)
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    });
    (entered_rx, release_tx, hook)
}

/// Wait for a seam on a blocking thread. The async runtime is never blocked:
/// the sweep this test is waiting for needs it.
async fn wait_for(entered: std::sync::mpsc::Receiver<()>, stage: &str) {
    let reached = tokio::task::spawn_blocking(move || entered.recv_timeout(BUDGET))
        .await
        .unwrap();
    assert!(reached.is_ok(), "the {stage} seam was never reached");
}

mod cases;
