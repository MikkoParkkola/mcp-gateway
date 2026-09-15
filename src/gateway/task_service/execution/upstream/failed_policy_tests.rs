// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A recovered upstream FAILURE settles through the configured response policy.
//!
//! Real store, real `TaskExecutor` commit, real `MetaMcp` gates, and the same
//! two callbacks `tasks/get` builds — only the peer is a stub, because the
//! property under test is what reaches disk, not how a peer is reached.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::{TaskExecutor, UpstreamAnswer, UpstreamHandle, UpstreamRecovery};
use super::{RecoveredRead, UpstreamCapture};
use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::upstream::RECOVERED_ERROR_WITHHELD;
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::{CreateOutcome, StoreLimits, Task, TaskOptions, TaskService};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::protocol::JsonRpcError;

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";
const TOOL: &str = "slow_echo";
/// Matches the shipped CRITICAL `secret` rule the product's response
/// inspection carries, so the reaction here is the configured policy's.
const MARKER: &str = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

/// What the stub peer answers one `tasks/get` with.
#[derive(Clone, Copy)]
enum Reply {
    /// The marker in BOTH the message and the nested data.
    FailedSecret,
    FailedBenign,
    Completed,
}

struct StubPeer(Reply);

#[async_trait::async_trait]
impl UpstreamRecovery for StubPeer {
    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        match self.0 {
            Reply::FailedSecret => UpstreamAnswer::Failed(JsonRpcError {
                code: -32001,
                message: format!("upstream failed with {MARKER}"),
                data: Some(json!({"context": {"token": MARKER}})),
            }),
            Reply::FailedBenign => UpstreamAnswer::Failed(JsonRpcError {
                code: -32042,
                message: "the tool could not read row 7".into(),
                data: Some(json!({"row": 7})),
            }),
            Reply::Completed => UpstreamAnswer::Completed(json!({
                "content": [{"type": "text", "text": "finished upstream"}],
                "isError": false,
            })),
        }
    }
}

/// Seed a fixture store with one row already captured under an upstream
/// handle, ready for `recover_upstream_read` to settle.
async fn seed_capturable_task(
    reply: Reply,
) -> (
    Arc<TaskService>,
    Arc<TaskExecutor>,
    String,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().expect("a fixture store root");
    let store_dir = directory.path().join("tasks");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&store_dir, StoreLimits::default(), admission)
            .await
            .expect("the fixture store opens"),
    );
    let executor = TaskExecutor::new(
        Arc::clone(&service),
        Arc::new(SubscriptionRegistry::new(DEFAULT_MAX_LISTENERS)),
        1,
    );
    assert!(executor.install_recovery(Arc::new(StubPeer(reply))));

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
                key: "i5-failed-policy",
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
    // The permit belongs to a worker that never ran here: this fixture drives
    // the reader's recovery path, not a dispatch.
    drop(slot);
    let id = task.task.id().to_owned();
    assert!(
        executor
            .capture_upstream(
                OWNER,
                &id,
                task.revision,
                UpstreamCapture {
                    backend: BACKEND.to_owned(),
                    tool: TOOL.to_owned(),
                    arguments: json!({}),
                    handle: "upstream-handle-1".to_owned(),
                },
            )
            .await,
        "the row is recoverable only once its handle is durable"
    );

    (service, executor, id, directory)
}

/// Recover one seeded working row and return its committed wire projection,
/// plus the store directory so the bytes on disk can be read back.
async fn recover(reply: Reply) -> (Value, tempfile::TempDir) {
    let (service, executor, id, directory) = seed_capturable_task(reply).await;

    // The gateway a reader would face: the product's own gates, in the mode an
    // operator enables to act on a finding rather than annotate it.
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_response_inspection_action_mode();
    let meta = Arc::new(meta);
    let owner_digest = service
        .owner(OWNER)
        .expect("admission hashes the fixture principal")
        .as_digest()
        .to_owned();
    // Both callbacks are exactly the pair `handlers::tasks::recover_from_upstream`
    // builds, over the same implementations.
    let (result_policy, error_policy) = (Arc::clone(&meta), Arc::clone(&meta));
    let trace = id.clone();
    let settled = executor
        .recover_upstream_read(
            &owner_digest,
            &id,
            true,
            move |result| {
                result_policy
                    .recover_task_result(BACKEND, TOOL, None, &trace, result)
                    .map_err(|error| JsonRpcError {
                        code: -32603,
                        message: error.to_string(),
                        data: None,
                    })
            },
            move |error| error_policy.recover_task_error(BACKEND, TOOL, None, "trace", error),
            Duration::from_secs(5),
        )
        .await;
    assert!(matches!(settled, Ok(RecoveredRead::Settled)));

    let committed = service
        .get(OWNER, &id)
        .expect("the settled row is readable");
    let wire = serde_json::to_value(committed.task.wire()).expect("the wire projection serializes");
    drop(executor);
    Arc::try_unwrap(service)
        .ok()
        .expect("the executor released its service owner")
        .close()
        .await
        .expect("custody is released");
    (wire, directory)
}

/// Every byte the store wrote, so "before disk" is asserted against disk.
fn stored_bytes(directory: &tempfile::TempDir) -> String {
    let mut seen = String::new();
    let mut pending = vec![directory.path().to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                seen.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
    }
    assert!(!seen.is_empty(), "the fixture must have written a record");
    seen
}

#[tokio::test]
async fn a_secret_bearing_upstream_failure_is_screened_before_it_is_persisted() {
    let (wire, directory) = recover(Reply::FailedSecret).await;
    assert_eq!(
        wire.pointer("/status").and_then(Value::as_str),
        Some("failed")
    );
    assert_eq!(
        wire.pointer("/error/message").and_then(Value::as_str),
        Some(RECOVERED_ERROR_WITHHELD)
    );
    assert_eq!(
        wire.pointer("/error/code").and_then(Value::as_i64),
        Some(-32001),
        "the failure keeps the peer's code"
    );
    assert!(
        wire.pointer("/error/data").is_none_or(Value::is_null),
        "the peer's data is withheld, not carried"
    );
    assert!(
        !stored_bytes(&directory).contains(MARKER),
        "neither the message nor the nested data may reach the durable record"
    );
}

#[tokio::test]
async fn a_benign_upstream_failure_keeps_its_error_semantics() {
    let (wire, _directory) = recover(Reply::FailedBenign).await;
    assert_eq!(
        wire.pointer("/status").and_then(Value::as_str),
        Some("failed")
    );
    assert_eq!(
        wire.pointer("/error/message").and_then(Value::as_str),
        Some("the tool could not read row 7")
    );
    assert_eq!(
        wire.pointer("/error/code").and_then(Value::as_i64),
        Some(-32042)
    );
    assert_eq!(
        wire.pointer("/error/data/row").and_then(Value::as_i64),
        Some(7)
    );
}

#[tokio::test]
async fn a_recovered_success_still_settles_completed() {
    let (wire, _directory) = recover(Reply::Completed).await;
    assert_eq!(
        wire.pointer("/status").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        wire.pointer("/result/content/0/text")
            .and_then(Value::as_str),
        Some("finished upstream")
    );
}
