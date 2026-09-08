// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failing tests for S2 — the `TaskService` facade over admission and the store.
//!
//! Scope is the ready plan's S2 and nothing beyond it: `create`, `get`, `cancel`
//! and `update` (accept-and-acknowledge only). Input-required rounds,
//! notifications, subscription filtering, expiry and cost accounting are
//! deliberately out, each with its own AC rows.
//!
//! Local copies of the store suite's `task`/`at` shape: that helper is
//! `pub(super)` inside `store_tests` and is not a sibling import. Durability
//! stays the store suite's job.
//!
//! Acceptance criteria these rows bind, by identifier:
//!   MIK-7272.TASK.1.1  a created task resolves immediately through `get`
//!   MIK-7272.TASK.1.3  `tasks/update` acknowledges, and changes no lifetime
//!   MIK-7272.TASK.1.8  an identical retry recovers the one task
//!   MIK-7272.TASK.1.11 another principal's request is indistinguishable from absence
//!
//! `.1` is vacuous alone — any stub returning a handle satisfies it — so `.11`
//! and the retry row are what make it mean something. That is why they are here
//! together and not split across increments.
//!
//! NOTE for whoever wires startup: every CLI fixture must set its own
//! `tasks.store_dir` under the temporary directory it already creates. The store
//! takes an EXCLUSIVE directory lease and its default is persistent, so a shared
//! path makes parallel fixtures fight over one lease and lets one test's records
//! become another's startup input.

use std::sync::{Arc, LazyLock};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::service::{CreateOutcome, ServiceError, TaskService};
use super::store::StoreLimits;
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::protocol::tasks::{Task, TaskOptions, TaskStatus};

mod adapter_facade;

static OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create"}));
static REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": false}));

const ALICE: &str = "oidc:acme:alice";
const MALLORY: &str = "oidc:acme:mallory";
const BACKEND: &str = "fixture";
const TTL_MS: u64 = 86_400_000;
const POLL_INTERVAL_MS: u64 = 1_000;
const ABSENT_ID: &str = "task-00000000-0000-4000-8000-000000000000";

fn at(second: u32) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-09-07T00:00:{second:02}Z"))
        .unwrap()
        .with_timezone(&Utc)
}

fn options() -> TaskOptions {
    TaskOptions {
        ttl_ms: Some(TTL_MS),
        poll_interval_ms: Some(POLL_INTERVAL_MS),
    }
}

fn task() -> Task {
    Task::create_at("private-tool", at(0), options())
}

fn other_task() -> Task {
    Task::create_at("other-private-tool", at(0), options())
}

fn request<'a>(principal: &'a str, key: &'a str) -> Request<'a> {
    Request {
        principal,
        key,
        operation: &OPERATION,
        representation: &REPRESENTATION,
        mode: Mode::Task,
    }
}

/// Existing rows do not exercise worker saturation; each call gets its own permit.
fn allow_worker() -> impl FnOnce() -> Option<OwnedSemaphorePermit> + Send {
    let workers = Arc::new(Semaphore::new(1));
    move || workers.try_acquire_owned().ok()
}

/// Numeric lifetime on the public wire. Equality of two missing fields is not
/// an oracle: the fixture plants `Some` values and the assertion demands them.
fn lifetime(task: &Task) -> (u64, u64) {
    let wire = serde_json::to_value(task.wire()).expect("public wire serializes");
    // `Task::wire` is `TaskWire` with serde camelCase: `ttl_ms` -> `ttlMs`.
    // The protocol names `ttl` / `pollInterval` are absent here; reading them
    // would be `Null == Null` and would not prove immutability.
    let ttl = wire["ttlMs"]
        .as_u64()
        .expect("fixture tasks carry a numeric TTL");
    let poll = wire["pollIntervalMs"]
        .as_u64()
        .expect("fixture tasks carry a numeric poll interval");
    (ttl, poll)
}

fn assert_fixture_lifetime(task: &Task) {
    assert_eq!(lifetime(task), (TTL_MS, POLL_INTERVAL_MS));
}

/// A service over a fresh store in its own temporary directory, with its own
/// admission index. One directory per fixture: the store's lease is exclusive.
async fn service(dir: &std::path::Path) -> TaskService {
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    TaskService::open(&dir.join("tasks"), StoreLimits::default(), admission)
        .await
        .expect("a fresh directory opens")
}

/// MIK-7272.TASK.1.1 — a created task resolves immediately, and it is owned by
/// the principal that asked for it rather than by anything the service invented.
#[tokio::test]
async fn service_01_a_created_task_resolves_immediately_for_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let task = task();
    assert_fixture_lifetime(&task);

    let created = match service
        .create(request(ALICE, "k-1"), &task, BACKEND, allow_worker())
        .await
        .expect("a fresh key creates a task")
    {
        CreateOutcome::Created { task, slot: _ } => task,
        _ => panic!("a fresh key must be Created"),
    };

    assert_eq!(created.task.id(), task.id());
    assert_eq!(created.revision, 1);
    assert_fixture_lifetime(&created.task);
    let fetched = service
        .get(ALICE, task.id())
        .expect("the creating principal reads its own task");
    assert_eq!(fetched.task.id(), task.id());
    assert_eq!(fetched.task.status(), TaskStatus::Working);
    assert_eq!(fetched.revision, 1);
    assert_fixture_lifetime(&fetched.task);
    service.close().await.unwrap();
}

/// MIK-7272.TASK.1.11 — another principal's request is indistinguishable from a
/// task that does not exist. Not a different error: the SAME one.
#[tokio::test]
async fn service_02_another_principal_cannot_tell_the_task_apart_from_absence() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let task = task();
    assert!(matches!(
        service
            .create(request(ALICE, "k-1"), &task, BACKEND, allow_worker())
            .await
            .unwrap(),
        CreateOutcome::Created { .. }
    ));

    let foreign = service.get(MALLORY, task.id()).unwrap_err();
    let absent_to_foreign = service.get(MALLORY, ABSENT_ID).unwrap_err();
    let absent_to_owner = service.get(ALICE, ABSENT_ID).unwrap_err();

    assert_eq!(foreign, ServiceError::NotFound);
    assert_eq!(absent_to_foreign, ServiceError::NotFound);
    assert_eq!(absent_to_owner, ServiceError::NotFound);
    assert_eq!(foreign, absent_to_foreign);
    assert_eq!(foreign, absent_to_owner);
    // And the owner still sees it: the refusal above is scoping, not deletion.
    let owned = service
        .get(ALICE, task.id())
        .expect("the owner still reads the live task");
    assert_eq!(owned.task.id(), task.id());
    assert_eq!(owned.revision, 1);
    service.close().await.unwrap();
}

/// MIK-7272.TASK.1.8 — a retried identical call recovers the ONE task, and does
/// not mint a second. This is the row that stops `.1` being satisfiable by a
/// stub that hands out a fresh handle every time.
#[tokio::test]
async fn service_03_an_identical_retry_recovers_the_one_task() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let first = task();
    let second = other_task();
    assert_ne!(
        first.id(),
        second.id(),
        "the retry oracle needs two distinct task values"
    );
    assert_ne!(first.tool(), second.tool());

    let created = match service
        .create(request(ALICE, "k-1"), &first, BACKEND, allow_worker())
        .await
        .unwrap()
    {
        CreateOutcome::Created { task, slot: _ } => task,
        _ => panic!("a fresh key must be Created"),
    };

    // A DIFFERENT task value under the same key: the service must return the
    // task the key already owns, not create this one.
    let retried = match service
        .create(request(ALICE, "k-1"), &second, BACKEND, allow_worker())
        .await
        .expect("an identical retry is not a refusal")
    {
        CreateOutcome::Existing(committed) => committed,
        _ => panic!("an identical retry must recover Existing"),
    };

    assert_eq!(retried.task.id(), created.task.id());
    assert_eq!(retried.task.id(), first.id());
    assert_ne!(retried.task.id(), second.id());
    assert_eq!(retried.task.tool(), first.tool());
    assert_eq!(retried.revision, created.revision);
    assert!(matches!(
        service.get(ALICE, second.id()),
        Err(ServiceError::NotFound)
    ));
    assert_eq!(
        service.get(ALICE, first.id()).unwrap().task.id(),
        first.id()
    );
    service.close().await.unwrap();
}

/// A cancel drives the task terminal, and the terminal view is what `get`
/// returns afterwards.
#[tokio::test]
async fn service_04_a_cancel_is_terminal_and_visible_to_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let task = task();
    assert!(matches!(
        service
            .create(request(ALICE, "k-1"), &task, BACKEND, allow_worker())
            .await
            .unwrap(),
        CreateOutcome::Created { .. }
    ));

    let cancelled = service
        .cancel(ALICE, task.id(), 1, at(1))
        .await
        .expect("the owner may cancel a running task");

    assert_eq!(cancelled.task.status(), TaskStatus::Cancelled);
    assert_eq!(cancelled.revision, 2);
    assert_eq!(cancelled.task.id(), task.id());
    assert_eq!(
        service.get(ALICE, task.id()).unwrap().task.status(),
        TaskStatus::Cancelled
    );
    // A foreign cancel is refused exactly as a foreign read is.
    assert_eq!(
        service
            .cancel(MALLORY, task.id(), 2, at(2))
            .await
            .unwrap_err(),
        ServiceError::NotFound
    );
    assert_eq!(
        service
            .cancel(MALLORY, ABSENT_ID, 1, at(2))
            .await
            .unwrap_err(),
        ServiceError::NotFound
    );
    assert_eq!(
        service
            .cancel(ALICE, ABSENT_ID, 1, at(2))
            .await
            .unwrap_err(),
        ServiceError::NotFound
    );
    assert_eq!(
        service.get(ALICE, task.id()).unwrap().task.status(),
        TaskStatus::Cancelled
    );
    service.close().await.unwrap();
}

/// MIK-7272.TASK.1.3 — `tasks/update` is accept-and-acknowledge. It changes no
/// lifetime: §13.3 fixes TTL and poll interval as immutable in 4.0, so an update
/// that moved either would be a contract change wearing an acknowledgement.
#[tokio::test]
async fn service_05_an_update_acknowledges_without_moving_ttl_or_poll_interval() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let task = task();
    assert_fixture_lifetime(&task);
    assert!(matches!(
        service
            .create(request(ALICE, "k-1"), &task, BACKEND, allow_worker())
            .await
            .unwrap(),
        CreateOutcome::Created { .. }
    ));
    let before = service.get(ALICE, task.id()).unwrap();
    assert_fixture_lifetime(&before.task);
    let before_life = lifetime(&before.task);
    assert_eq!(before_life, (TTL_MS, POLL_INTERVAL_MS));

    let updated = service
        .update(ALICE, task.id(), 1, json!({"status": "working"}))
        .await
        .expect("an update from the owner is acknowledged");

    assert_eq!(updated.task.id(), before.task.id());
    assert_eq!(updated.task.status(), before.task.status());
    assert_eq!(lifetime(&updated.task), before_life);
    assert_eq!(updated.revision, before.revision);
    assert_eq!(
        serde_json::to_value(updated.task.wire()).unwrap(),
        serde_json::to_value(before.task.wire()).unwrap()
    );

    let after = service.get(ALICE, task.id()).unwrap();
    assert_eq!(after.task.id(), before.task.id());
    assert_eq!(after.task.status(), TaskStatus::Working);
    assert_eq!(lifetime(&after.task), before_life);
    assert_eq!(lifetime(&after.task), (TTL_MS, POLL_INTERVAL_MS));
    assert_eq!(after.revision, before.revision);
    service.close().await.unwrap();
}

/// An update naming a task the caller does not own is refused with the same
/// answer as absence — the dispatcher must not leak existence through update
/// either, which is the arm a create/get-only implementation forgets.
#[tokio::test]
async fn service_06_a_foreign_update_is_refused_as_absence() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let task = task();
    assert!(matches!(
        service
            .create(request(ALICE, "k-1"), &task, BACKEND, allow_worker())
            .await
            .unwrap(),
        CreateOutcome::Created { .. }
    ));

    let refused = service
        .update(MALLORY, task.id(), 1, json!({"status": "working"}))
        .await
        .unwrap_err();
    let absent_foreign = service
        .update(MALLORY, ABSENT_ID, 1, json!({"status": "working"}))
        .await
        .unwrap_err();
    let absent_owner = service
        .update(ALICE, ABSENT_ID, 1, json!({"status": "working"}))
        .await
        .unwrap_err();

    assert_eq!(refused, ServiceError::NotFound);
    assert_eq!(absent_foreign, ServiceError::NotFound);
    assert_eq!(absent_owner, ServiceError::NotFound);
    assert_eq!(refused, absent_foreign);
    assert_eq!(refused, absent_owner);
    let owned = service.get(ALICE, task.id()).unwrap();
    assert_eq!(owned.revision, 1);
    assert_eq!(owned.task.status(), TaskStatus::Working);
    assert_fixture_lifetime(&owned.task);
    service.close().await.unwrap();
}

/// Port of `protocol::task_store::owns_all_is_all_or_nothing`: a missing peer
/// id refuses the whole set, so a subscription cannot learn which ids exist.
#[tokio::test]
async fn service_07_owns_all_is_all_or_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let task = task();
    assert!(matches!(
        service
            .create(request(ALICE, "k-1"), &task, BACKEND, allow_worker())
            .await
            .unwrap(),
        CreateOutcome::Created { .. }
    ));
    assert!(service.owns_all(ALICE, [task.id()]));
    assert!(!service.owns_all(ALICE, [task.id(), ABSENT_ID]));
    assert!(!service.owns_all(MALLORY, [task.id()]));
    assert!(service.owns_all(ALICE, std::iter::empty::<&str>()));
    service.close().await.unwrap();
}
