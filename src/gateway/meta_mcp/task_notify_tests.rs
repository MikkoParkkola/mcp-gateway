// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7778 PAYLOAD.1: the delivery evidence a task notification leaves.

use std::sync::Arc;

use serde_json::{Value, json};

use super::MetaMcp;
use super::grant_audit_fixture::{entries, logger};
use super::response_security::DeliveryCredential;
use super::task_notify::Reader;
use crate::backend::BackendRegistry;
use crate::protocol::RequestId;
use crate::protocol::subscriptions::SubscriptionId;
use crate::security::audit::AuditFailurePolicy;

fn published() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks",
        "params": { "taskId": "t-1", "status": "completed" },
    })
}

fn reader() -> Reader<'static> {
    Reader {
        caller: "key-a",
        session_id: "s-1",
        subject: None,
        credential: DeliveryCredential::of(
            None,
            &crate::gateway::record_principal::test_record_key(),
        ),
    }
}

fn gateway(
    dir: &Arc<tempfile::TempDir>,
    policy: AuditFailurePolicy,
) -> (MetaMcp, Arc<crate::security::TransparencyLogger>) {
    let log = logger(dir, policy);
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_transparency_log(Arc::clone(&log));
    (meta, log)
}

/// A frame is tagged with the subscription and written to the log as sent.
#[tokio::test]
async fn a_delivered_task_frame_is_tagged_and_logged_as_sent() {
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let (meta, _log) = gateway(&dir, AuditFailurePolicy::FailClosed);
    let subscription = SubscriptionId::of_request(RequestId::Number(5));

    let pending = meta
        .task_notification_frame(&published(), None, |_| None, &subscription)
        .await
        .expect("a frame is built");
    let frame = pending.frame.clone();
    assert!(
        meta.finish_task_frame(pending, &frame, &reader()).await,
        "an auditable frame is delivered"
    );
    assert_eq!(frame["params"]["taskId"], json!("t-1"), "{frame}");
    assert_eq!(
        frame["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        json!(5),
        "{frame}"
    );
    let rows = entries(&dir);
    assert!(
        rows.iter().any(|row| {
            row["event"] == json!("response_delivery_attempt")
                && row["response_stage"] == json!("notification_delivered")
        }),
        "the frame's delivery is on the log: {rows:?}"
    );
}

/// Under a fail-closed policy a frame whose delivery cannot be logged is not
/// delivered, as a `tasks/get` response is not.
#[tokio::test]
async fn a_task_frame_that_cannot_be_logged_is_withheld_when_fail_closed() {
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let (meta, log) = gateway(&dir, AuditFailurePolicy::FailClosed);
    let subscription = SubscriptionId::of_request(RequestId::Number(6));
    log.fail_next_append_for_test();

    let pending = meta
        .task_notification_frame(&published(), None, |_| None, &subscription)
        .await
        .expect("a frame is built");
    let frame = pending.frame.clone();
    assert!(
        !meta.finish_task_frame(pending, &frame, &reader()).await,
        "withheld, not delivered unlogged"
    );
}

/// `MIK-7858.FRAMES.1`: a frame carries the task as it is when the frame is
/// built, never a mix. A notification published while the task was working,
/// delivered after it completed, is sent as the completed task, whole.
#[tokio::test]
async fn a_frame_carries_the_task_as_it_is_at_delivery() {
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let (meta, _log) = gateway(&dir, AuditFailurePolicy::FailClosed);
    let subscription = SubscriptionId::of_request(RequestId::Number(7));
    let mut task = crate::protocol::tasks::Task::create("gateway_invoke")
        .expect("the test clock reads after 1970");
    let working = json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks",
        "params": { "taskId": task.id(), "status": "working" },
    });
    task.complete(&json!({ "content": [{ "type": "text", "text": "done" }] }))
        .expect("a live task takes its outcome");
    let stored = crate::gateway::task_service::CommittedTask {
        task,
        revision: 2,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: Box::default(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
        replay_snapshot: None,
    };

    let mut expected = serde_json::to_value(stored.task.wire()).expect("the task serializes");
    let pending = meta
        .task_notification_frame(
            &working,
            // No sealed question in this task, so no holds to carry.
            Some(super::sealed_hold::Held::new(
                stored,
                super::sealed_hold::CarriedHolds::none(),
            )),
            |_| None,
            &subscription,
        )
        .await
        .expect("a frame is built");
    expected["_meta"] = pending.frame["params"]["_meta"].clone();
    assert_eq!(
        pending.frame["params"], expected,
        "the frame is not the stored task as it is now"
    );
    assert_eq!(pending.frame["params"]["status"], json!("completed"));
}

/// A gateway whose registry holds backend `alpha`, so it keeps a value set.
fn gateway_with_alpha(dir: &Arc<tempfile::TempDir>) -> (MetaMcp, Arc<BackendRegistry>) {
    let registry = Arc::new(BackendRegistry::new());
    let alpha = crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig {
            transport: crate::config::TransportConfig::Stdio {
                command: "/nonexistent-mcp-binary".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..crate::config::BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: registers the backend whose value set the row marks"
    )]
    let registered = registry.register(Arc::new(alpha));
    assert!(registered, "premise: registered");
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let mut meta = MetaMcp::new(Arc::clone(&registry));
    meta.enable_transparency_log(log);
    (meta, registry)
}

/// A completed task whose stored result says `text`.
fn completed(text: &str) -> crate::gateway::task_service::CommittedTask {
    let mut task = crate::protocol::tasks::Task::create("gateway_invoke")
        .expect("the test clock reads after 1970");
    task.complete(&json!({ "content": [{ "type": "text", "text": text }] }))
        .expect("a live task takes its outcome");
    crate::gateway::task_service::CommittedTask {
        task,
        revision: 2,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: Box::default(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
        replay_snapshot: None,
    }
}

/// The frame a subscriber gets for `stored`, built on one thread.
async fn frame_for(meta: &MetaMcp, stored: crate::gateway::task_service::CommittedTask) -> Value {
    let subscription = SubscriptionId::of_request(RequestId::Number(7));
    meta.task_notification_frame(
        &published(),
        Some(super::sealed_hold::Held::new(
            stored,
            super::sealed_hold::CarriedHolds::none(),
        )),
        |_| None,
        &subscription,
    )
    .await
    .expect("a frame is built")
    .frame
}

const MARKED: &str = "marked-after-storing-9105";

/// A task notification carries stored output scrubbed against the values
/// current when it is sent: a value marked after the task was stored is
/// removed.
#[tokio::test]
async fn a_notification_removes_a_value_marked_after_the_task_was_stored() {
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let (meta, registry) = gateway_with_alpha(&dir);
    let stored = completed(&format!("done {MARKED}"));
    registry.mark_for_test("alpha", MARKED);
    let frame = frame_for(&meta, stored).await;
    let text = frame.to_string();
    assert!(
        !text.contains(MARKED),
        "the notification carries the value: {frame}"
    );
    assert!(
        text.contains("[redacted]"),
        "the output was dropped, not redacted: {frame}"
    );
}

/// When the scrub refuses (a full value set), the notification goes out
/// status-only, and the log says why the output was withheld.
#[test]
fn a_refused_scrub_sends_the_status_only_notification_and_says_why() {
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let (frame, logs) = crate::test_log_capture::capture_warnings(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async {
                let (meta, registry) = gateway_with_alpha(&dir);
                registry.overflow_for_test("alpha");
                frame_for(&meta, completed(&format!("done {MARKED}"))).await
            })
    });
    assert!(
        frame["params"].get("result").is_none(),
        "the withheld output was sent: {frame}"
    );
    assert_eq!(
        frame["params"]["status"],
        json!("completed"),
        "not the published status: {frame}"
    );
    assert!(
        logs.contains("stored task output withheld"),
        "the log does not say why: {logs}"
    );
    assert!(
        !logs.contains(MARKED),
        "the log carries stored output: {logs}"
    );
}

/// Stored task output the scrub redacts is not the stored text any more, so
/// the scan says it was rewritten: a notification carrying it commits no
/// relay receipts for the original. Output with nothing to remove still
/// reads as delivered.
#[tokio::test]
async fn a_stored_output_the_scrub_redacts_reads_as_rewritten() {
    use super::invoke::egress::EgressOutcome;
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let (meta, registry) = gateway_with_alpha(&dir);
    registry.mark_for_test("alpha", MARKED);
    let marked = completed(&format!("done {MARKED}"));
    let mut value = marked.delivered_wire();
    assert_eq!(
        meta.scan_stored_task(&marked, None, &mut value),
        EgressOutcome::Rewritten,
        "a redacted stored output read as delivered: {value}"
    );
    assert!(
        !value.to_string().contains(MARKED),
        "premise: the value was removed: {value}"
    );
    let clean = completed("done, nothing secret");
    let mut value = clean.delivered_wire();
    assert_eq!(
        meta.scan_stored_task(&clean, None, &mut value),
        EgressOutcome::Delivered,
        "clean stored output read as rewritten: {value}"
    );
}
