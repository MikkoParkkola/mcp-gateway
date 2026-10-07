// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7778 PAYLOAD.1: the delivery evidence a task notification leaves.

use std::sync::Arc;

use serde_json::{Value, json};

use super::MetaMcp;
use super::grant_audit_fixture::{entries, logger};
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
    }
}

fn gateway(
    dir: &tempfile::TempDir,
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
    let dir = tempfile::tempdir().expect("tempdir");
    let (meta, _log) = gateway(&dir, AuditFailurePolicy::FailClosed);
    let subscription = SubscriptionId::of_request(RequestId::Number(5));

    let pending = meta
        .task_notification_frame(&published(), None, |_| false, &subscription)
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
    let dir = tempfile::tempdir().expect("tempdir");
    let (meta, log) = gateway(&dir, AuditFailurePolicy::FailClosed);
    let subscription = SubscriptionId::of_request(RequestId::Number(6));
    log.fail_next_append_for_test();

    let pending = meta
        .task_notification_frame(&published(), None, |_| false, &subscription)
        .await
        .expect("a frame is built");
    let frame = pending.frame.clone();
    assert!(
        !meta.finish_task_frame(pending, &frame, &reader()).await,
        "withheld, not delivered unlogged"
    );
}
