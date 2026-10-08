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
use super::{RecoveredRead, RecoveryRefusal, UpstreamCapture};
use crate::backend::BackendRegistry;
use crate::gateway::authz::HTTP_STATUS_DATA_KEY;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::upstream::RECOVERED_ERROR_WITHHELD;
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::{
    CommittedTask, CreateOutcome, ErrorAuthor, StoreLimits, Task, TaskOptions, TaskService,
};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};
use crate::protocol::JsonRpcError;

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";
const TOOL: &str = "slow_echo";
const SUBSTITUTE: &str = "the upstream task was cancelled";
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
    /// A completed result whose text carries the marker.
    CompletedSecret,
    /// The job was cancelled: the gateway's own words stand in for the peer's.
    Substituted,
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
            Reply::CompletedSecret => UpstreamAnswer::Completed(json!({
                "content": [{"type": "text", "text": format!("finished upstream with {MARKER}")}],
                "isError": false,
            })),
            // Only the transport's HTTP status in its data: the settlement
            // strips it, so nothing of the data survives.
            Reply::Substituted => UpstreamAnswer::Substituted(JsonRpcError {
                code: -32603,
                message: SUBSTITUTE.into(),
                data: Some(json!({ HTTP_STATUS_DATA_KEY: 503 })),
            }),
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
        Arc::new(SubscriptionRegistry::new(
            DEFAULT_MAX_LISTENERS,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        )),
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
    // The gateway a reader would face: the product's own gates, in the mode an
    // operator enables to act on a finding rather than annotate it.
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_response_inspection_action_mode();
    recover_with(reply, meta).await
}

/// [`recover`] against a caller-built gateway.
async fn recover_with(reply: Reply, meta: MetaMcp) -> (Value, tempfile::TempDir) {
    let (committed, directory) = recover_committed(reply, meta).await;
    let wire = serde_json::to_value(committed.task.wire()).expect("the wire projection serializes");
    (wire, directory)
}

/// [`recover_with`], returning the whole committed row.
async fn recover_committed(reply: Reply, meta: MetaMcp) -> (CommittedTask, tempfile::TempDir) {
    let (service, executor, id, directory) = seed_capturable_task(reply).await;
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
                    .map_err(|error| {
                        crate::gateway::meta_mcp::response_security::recovered_result_error(&error)
                    })
            },
            move |error| error_policy.recover_task_error_with(BACKEND, TOOL, None, "trace", error),
            // No transparency log here: the settlement record is a no-op.
            |event, _notes| std::future::ready((event, true)),
            Duration::from_secs(5),
        )
        .await;
    assert!(matches!(settled, Ok(RecoveredRead::Settled)));

    let committed = service
        .get(OWNER, &id)
        .expect("the settled row is readable");
    drop(executor);
    Arc::try_unwrap(service)
        .ok()
        .expect("the executor released its service owner")
        .close()
        .await
        .expect("custody is released");
    (committed, directory)
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

/// A gateway whose ONLY armed gate is the response firewall: no inspection
/// action mode, so the recovery call to `inspect_task_result` is the one thing
/// that can refuse a recovered result.
#[cfg(feature = "firewall")]
fn firewall_only_gateway() -> MetaMcp {
    use crate::security::firewall::{Firewall, FirewallConfig};

    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_firewall(Some(Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            ..FirewallConfig::default()
        },
        None,
    ))));
    meta
}

/// MIK-7706.GH2439.1: a recovered completed upstream result holding a
/// credential is refused by the firewall, and the credential is never stored.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_secret_bearing_recovered_result_is_refused_by_the_firewall() {
    let (wire, directory) = recover_with(Reply::CompletedSecret, firewall_only_gateway()).await;
    assert_eq!(
        wire.pointer("/status").and_then(Value::as_str),
        Some("failed"),
        "{wire}"
    );
    assert_eq!(
        wire.pointer("/error/message").and_then(Value::as_str),
        Some("Response blocked by security firewall"),
        "{wire}"
    );
    // MIK-7667: the native path's -32600 refusal, not an internal error.
    assert_eq!(wire.pointer("/error/code"), Some(&json!(-32600)), "{wire}");
    assert!(wire.pointer("/result").is_none_or(Value::is_null), "{wire}");
    assert!(
        !wire.to_string().contains(MARKER) && !stored_bytes(&directory).contains(MARKER),
        "the canary reached the wire projection or the durable record"
    );
}

/// The refusal above is the firewall's verdict on the credential, not a
/// refusal of every recovered result.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_benign_recovered_result_passes_the_firewall() {
    let (wire, _directory) = recover_with(Reply::Completed, firewall_only_gateway()).await;
    assert_eq!(
        wire.pointer("/status").and_then(Value::as_str),
        Some("completed"),
        "{wire}"
    );
}

/// MIK-7887.RECEIPT.1: a cancelled upstream job settles failed with the
/// gateway's substitute, recorded as the gateway's words and never served as
/// the peer's error. The benign peer failure is the control: its author is the
/// peer, so the author follows the answer and is not fixed.
#[tokio::test]
async fn a_recovered_substitute_settles_as_the_gateways_own_error() {
    let meta = || {
        let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
        meta.enable_response_inspection_action_mode();
        meta
    };
    let (substituted, _directory) = recover_committed(Reply::Substituted, meta()).await;
    let wire =
        serde_json::to_value(substituted.task.wire()).expect("the wire projection serializes");
    assert_eq!(
        wire.pointer("/status").and_then(Value::as_str),
        Some("failed")
    );
    assert_eq!(
        wire.pointer("/error/message").and_then(Value::as_str),
        Some(SUBSTITUTE)
    );
    assert_eq!(
        wire.pointer("/error/code").and_then(Value::as_i64),
        Some(-32603)
    );
    assert!(
        wire.pointer("/error/data").is_none_or(Value::is_null),
        "the transport's HTTP status is stripped before the row settles: {wire}"
    );
    // Only the peer's authorship is recorded; absent is the gateway's.
    assert_eq!(substituted.error_author, None);
    assert!(
        substituted.backend_error().is_none(),
        "a substitute is never handed out as the peer's error"
    );

    let (peer, _directory) = recover_committed(Reply::FailedBenign, meta()).await;
    assert_eq!(peer.error_author, Some(ErrorAuthor::Peer));
    assert!(peer.backend_error().is_some());
}

/// A store that closes between the revision re-read and the commit refuses
/// the read as unavailable: it neither claims a settlement nor serves the row
/// as retained.
#[tokio::test]
async fn a_recovery_whose_commit_fails_is_unavailable() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (service, executor, id, _directory) = seed_capturable_task(Reply::Completed).await;
    let owner_digest = service
        .owner(OWNER)
        .expect("admission hashes the fixture principal")
        .as_digest()
        .to_owned();
    let settled = Arc::new(AtomicBool::new(false));
    let (closing, reached) = (Arc::clone(&service), Arc::clone(&settled));
    let outcome = executor
        .recover_upstream_read(
            &owner_digest,
            &id,
            true,
            |result: Value| -> Result<Value, JsonRpcError> { Ok(result) },
            |error: JsonRpcError| (error, ErrorAuthor::Peer),
            move |event, _notes| async move {
                reached.store(true, Ordering::SeqCst);
                closing.shutdown().await.expect("the store closes");
                (event, true)
            },
            Duration::from_secs(5),
        )
        .await;
    assert!(
        settled.load(Ordering::SeqCst),
        "the refusal must come from the commit, after settlement was recorded"
    );
    assert_eq!(outcome, Err(RecoveryRefusal::Unavailable));
}

/// `MIK-7993` (r2 CRITICAL): a result an owner's read recovers is stored
/// with the record of what the gateway wrote while processing it (here the
/// observe-mode anomaly findings), so a later read's receipt leaves exactly
/// those out.
#[tokio::test]
async fn a_recovered_result_keeps_the_gateways_write_record() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let (committed, _directory) = crate::gateway::meta_mcp::invoke::relay::collecting(
        recover_committed(Reply::CompletedSecret, meta),
    )
    .await;
    let wire = serde_json::to_value(committed.task.wire()).expect("serializes");
    assert!(
        wire.to_string().contains("_security_findings"),
        "premise: the gateway annotated the recovered result: {wire}"
    );
    let stored = serde_json::to_value(&committed.gateway_writes).expect("serializes");
    assert!(
        stored.as_array().is_some_and(|entries| entries
            .iter()
            .any(|entry| entry["dest"] == json!(["_security_findings"]))),
        "the recovered row did not record the gateway's findings: {stored}"
    );
}

/// MIK-7993: a result recovered on its owner's read is stored with the record
/// of what the gateway wrote into it on the way (here the response contract's
/// annotations), so a later read's receipt leaves those members out. Run in a
/// write scope, as `tasks/get` runs with relay detection on.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_recovered_result_is_stored_with_the_gateways_writes() {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_response_contract(crate::config::ResponseContractConfig {
        enabled: true,
        action_mode: false,
        fail_closed: true,
        ..Default::default()
    });
    let (committed, _directory) = crate::gateway::meta_mcp::invoke::relay::collecting(
        recover_committed(Reply::Completed, meta),
    )
    .await;
    let record = serde_json::to_value(&committed.gateway_writes).expect("the record serializes");
    let dests: Vec<&Value> = record
        .as_array()
        .expect("a list")
        .iter()
        .map(|entry| &entry["dest"])
        .collect();
    assert!(
        dests.contains(&&json!(["_contract_violation"])),
        "the recovered row does not record the contract annotation: {record}"
    );
}
