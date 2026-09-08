// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Startup recovery of records a previous process left mid-flight.
//!
//! A restart inherits a directory, not a process. Whatever a task was doing when
//! the gateway went away, nobody can continue it: the backend call, if it
//! happened at all, happened somewhere this process cannot reach, and an input
//! round belongs to an exchange that no longer has two ends. So the constructor
//! the gateway itself calls — [`open_runtime_with_admission`] — has to settle
//! those rows before it returns ready to serve, and settle them by what the
//! record can still prove:
//!
//! * a modern record that never recorded a dispatch is a task the backend never
//!   saw, and may say so exactly: `not_executed`;
//! * a dispatched record, a legacy record that could not have recorded the fact,
//!   and an abandoned input round are all tasks whose effect is unknown, and
//!   claiming otherwise would tell a caller their side effect never happened.
//!
//! Nothing is re-invoked and nothing is resubmitted. Terminal records are left
//! exactly as the process that settled them wrote them.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::test_subscriptions;
use crate::gateway::task_service::{
    CreateOutcome, StoreLimits, Task, TaskOptions, TaskService, TaskTransition,
    open_runtime_with_admission,
};
use crate::idempotency::admission::{Admission, ExecutionAdmission, Mode, Refusal, Request};
use crate::protocol::mrtr::InputRequired;

const OWNER: &str = "verified-owner";
/// Every await in this file is bounded by a real timeout rather than by the
/// harness giving up: a restart that hangs is a failure with a name.
const BUDGET: Duration = Duration::from_secs(5);

/// The standard interrupted tool-result envelope used by the reviewed adapter.
const OUTCOME: &str = "/_meta/io.mcp-gateway~1executionOutcome";
const REASON: &str = "/_meta/io.mcp-gateway~1reason";

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

/// How a previous process left one record behind.
#[derive(Clone, Copy, Debug)]
enum Seed {
    /// Committed, never dispatched. The one case the gateway can be exact about.
    Undispatched,
    /// The durable dispatch marker was written; the answer never came back.
    Dispatched,
    /// A v1 row, which had no marker to write. Seeded as `Undispatched` and then
    /// rewritten on disk to the legacy shape.
    Legacy,
    /// The backend asked a question the client can no longer answer.
    InputRequired,
    /// Already settled. Startup has nothing to do here and must do nothing.
    Terminal,
    Failed,
    Cancelled,
}

/// What the row should look like after the constructor returns.
struct Expected {
    outcome: &'static str,
    reason: &'static str,
    /// Revision after the single recovery rewrite.
    revision: u64,
}

/// What the previous process committed for the already-settled row.
fn terminal_result() -> Value {
    json!({
        "content": [{"type": "text", "text": "the first process finished this"}],
        "isError": false,
    })
}

fn rows() -> Vec<(&'static str, Seed, Option<Expected>)> {
    vec![
        (
            "x6a-undispatched",
            Seed::Undispatched,
            Some(Expected {
                outcome: "not_executed",
                reason: "gateway_restart_before_dispatch",
                revision: 2,
            }),
        ),
        (
            "x6b-dispatched",
            Seed::Dispatched,
            Some(Expected {
                outcome: "unknown",
                reason: "gateway_restart_after_dispatch",
                revision: 2,
            }),
        ),
        (
            "x6c-legacy-v1",
            Seed::Legacy,
            Some(Expected {
                outcome: "unknown",
                reason: "gateway_restart_after_dispatch",
                revision: 2,
            }),
        ),
        (
            "x6d-input-required",
            Seed::InputRequired,
            // Seeded at revision 2 by the input round itself, so one rewrite
            // lands on 3. `dispatched` is false on this row on purpose: an
            // abandoned exchange is unknown regardless of the marker.
            Some(Expected {
                outcome: "unknown",
                reason: "gateway_restart_after_dispatch",
                revision: 3,
            }),
        ),
        ("x6e-terminal", Seed::Terminal, None),
        ("x6f-failed", Seed::Failed, None),
        ("x6g-cancelled", Seed::Cancelled, None),
    ]
}

/// One row as the previous process left it: its real handle and its committed
/// wire projection, both captured from the store rather than constructed.
struct Seeded {
    key: &'static str,
    seed: Seed,
    expected: Option<Expected>,
    id: String,
    revision: u64,
    wire: Value,
}

/// Commit every row through the ordinary create facade on a service opened
/// directly — not through the runtime constructor, which is the thing under
/// test. Returns after custody has been released and every owner dropped.
async fn seed_store(
    dir: &std::path::Path,
    rows: Vec<(&'static str, Seed, Option<Expected>)>,
) -> Vec<Seeded> {
    let operation = operation();
    let representation = representation();
    let admission = fresh_admission();
    let service = TaskService::open(dir, StoreLimits::default(), Arc::clone(&admission))
        .await
        .expect("the seeding authority opens the fixture store");
    let workers = Arc::new(Semaphore::new(rows.len()));
    let owner = service
        .owner(OWNER)
        .expect("admission hashes the fixture principal")
        .as_digest()
        .to_owned();
    let mut seeded = Vec::new();
    for (key, seed, expected) in rows {
        let task = Task::create_at(
            "write",
            chrono::Utc::now(),
            TaskOptions {
                ttl_ms: Some(86_400_000),
                poll_interval_ms: Some(1_000),
            },
        );
        let slot = Arc::clone(&workers);
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
        // The permit belongs to the worker that never ran; a restart fixture
        // holds none of it.
        drop(slot);
        let id = task.task.id().to_owned();
        let mut revision = task.revision;
        match seed {
            Seed::Undispatched | Seed::Legacy => {}
            Seed::Dispatched => {
                service
                    .store
                    .mark_dispatched(&owner, &id, revision)
                    .await
                    .expect("the dispatch marker is durable");
            }
            Seed::InputRequired => {
                let round = InputRequired {
                    requests: vec![(
                        "confirm".to_owned(),
                        json!({"method": "elicitation/create", "params": {}}),
                    )],
                    request_state: Some("opaque-to-the-previous-process".to_owned()),
                };
                revision = service
                    .store
                    .transition(
                        &owner,
                        &id,
                        revision,
                        TaskTransition::RequireInput(round),
                        chrono::Utc::now(),
                    )
                    .await
                    .expect("the fixture opens an input round")
                    .revision;
            }
            Seed::Terminal | Seed::Failed | Seed::Cancelled => {
                let event = match seed {
                    Seed::Terminal => TaskTransition::Complete(terminal_result()),
                    Seed::Failed => TaskTransition::Fail(crate::protocol::JsonRpcError {
                        code: -32042,
                        message: "persisted terminal failure".to_owned(),
                        data: Some(json!({"marker": "failed-before-restart"})),
                    }),
                    Seed::Cancelled => TaskTransition::Cancel,
                    _ => unreachable!("the terminal match arm contains only terminal seeds"),
                };
                revision = service
                    .store
                    .transition(&owner, &id, revision, event, chrono::Utc::now())
                    .await
                    .expect("the fixture settles a task")
                    .revision;
            }
        }
        let committed = service.get(OWNER, &id).expect("the seeded row is readable");
        seeded.push(Seeded {
            key,
            seed,
            expected,
            id,
            revision: committed.revision,
            wire: serde_json::to_value(committed.task.wire()).unwrap(),
        });
        assert_eq!(seeded.last().unwrap().revision, revision);
    }
    service.close().await.expect("custody is released");
    drop(admission);
    for row in &seeded {
        if matches!(row.seed, Seed::Legacy) {
            rewrite_as_v1(dir, &row.id);
        }
    }
    seeded
}

/// Turn one committed record into the legacy shape, in place: version 1 and no
/// `dispatched` field, with every other byte — admission digests, owner, model,
/// backend, revision — carried across unchanged and proved so on read-back.
///
/// A v1 row is not "a row whose marker says false". It is a row from a format
/// that could not record the fact, and this is the only way to produce one
/// without a second, invented writer.
fn rewrite_as_v1(dir: &std::path::Path, id: &str) {
    let path = dir.join(format!("{id}.json"));
    let before: Value = serde_json::from_slice(&std::fs::read(&path).unwrap())
        .expect("the committed record parses");
    assert_eq!(before["version"], json!(2), "the fixture starts modern");
    assert_eq!(
        before.get("dispatched"),
        Some(&json!(false)),
        "a modern never-dispatched row serializes its marker"
    );
    let mut after = before.clone();
    let object = after.as_object_mut().unwrap();
    object.insert("version".to_owned(), json!(1));
    object.remove("dispatched");
    std::fs::write(&path, serde_json::to_vec(&after).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // The loader accepts only an owner-only record; a fixture that lost the
        // mode would fail as an unsafe store rather than as recovery.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let back: Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("the legacy record parses");
    assert_eq!(back["version"], json!(1), "the record on disk is v1");
    assert!(
        back.get("dispatched").is_none(),
        "a v1 record carries no dispatch marker at all"
    );
    for field in ["admission", "backend", "revision", "model"] {
        assert_eq!(
            back[field], before[field],
            "only the record version changed on disk"
        );
    }
}

/// Every recovery expectation for one row, as disagreements rather than a
/// panic: a first bad row must not hide the other four.
fn judge(row: &Seeded, task: &crate::gateway::task_service::Task, revision: u64) -> Vec<String> {
    use crate::gateway::task_service::TaskStatus;

    let mut problems: Vec<String> = Vec::new();
    let wire = serde_json::to_value(task.wire()).unwrap();
    if task.id() != row.id {
        problems.push(format!(
            "{}: the recovered task changed handle: {} became {}",
            row.key,
            row.id,
            task.id()
        ));
    }
    for field in ["ttlMs", "pollIntervalMs", "createdAt"] {
        if wire[field] != row.wire[field] {
            problems.push(format!(
                "{}: {field} moved across a restart: {} became {}",
                row.key, row.wire[field], wire[field]
            ));
        }
    }
    let Some(expected) = row.expected.as_ref() else {
        // A terminal row is retained byte for byte, including its result.
        if wire != row.wire {
            problems.push(format!(
                "{}: a settled record was rewritten at startup: {} became {wire}",
                row.key, row.wire
            ));
        }
        if revision != row.revision {
            problems.push(format!(
                "{}: a settled record's revision moved: {} became {revision}",
                row.key, row.revision
            ));
        }
        return problems;
    };
    if task.status() != TaskStatus::Completed {
        problems.push(format!(
            "{}: an interrupted row must be settled as Completed, not {:?}",
            row.key,
            task.status()
        ));
    }
    if revision != expected.revision {
        problems.push(format!(
            "{}: recovery must be exactly one rewrite: expected revision {}, found {revision}",
            row.key, expected.revision
        ));
    }
    let Some(result) = task.result() else {
        problems.push(format!(
            "{}: a completed row carries no result at all",
            row.key
        ));
        return problems;
    };
    if result.pointer("/isError") != Some(&json!(true)) {
        problems.push(format!(
            "{}: an interrupted result is a tool error: {result}",
            row.key
        ));
    }
    if result.pointer(OUTCOME) != Some(&json!(expected.outcome)) {
        problems.push(format!(
            "{}: executionOutcome must be {:?}: {result}",
            row.key, expected.outcome
        ));
    }
    if result.pointer(REASON) != Some(&json!(expected.reason)) {
        problems.push(format!(
            "{}: reason must be {:?}: {result}",
            row.key, expected.reason
        ));
    }
    problems
}

mod cases;
