// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task-status notification whose stored output is withheld because a
//! check refused it records that check, and the rule when a configured rule
//! decided, in the frame's delivery record (MIK-9191.RULEID.3). Withholding
//! itself is decided as before: a withheld frame with no policy refusal
//! (a removed backend) names nothing.

use serde_json::{Value, json};

use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, entries, grant};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use super::response_security::DeliveryCredential;
use super::task_notify::Reader;
use super::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::authz::ToolPolicyAuthorizer;
use crate::gateway::task_service::{CommittedTask, Target, Task};
use crate::protocol::RequestId;
use crate::protocol::subscriptions::SubscriptionId;
use crate::security::audit::AuditFailurePolicy;
use crate::security::rule_id::{RuleId, RuleKey};

const ALICE: (&str, &str) = ("api_key", "alice");
const DENIED: &str = "personal_caps:calendar_read_day";

fn key() -> RuleKey {
    RuleKey::from_derived([7; 32])
}

fn denying() -> crate::security::ToolPolicy {
    let config = crate::security::policy::ToolPolicyConfig {
        deny: vec![DENIED.to_owned()],
        ..Default::default()
    };
    crate::security::ToolPolicy::from_config_keyed(&config, &key())
}

fn deny_entry_id() -> RuleId {
    let bytes = serde_json::to_vec(&("deny", DENIED)).expect("serialises");
    RuleId::of("tool_policy", &key(), &bytes)
}

/// A finished task whose recorded targets are `targets`.
fn finished(targets: Vec<Target>) -> CommittedTask {
    let mut task = Task::create("gateway_invoke").expect("the test clock reads after 1970");
    task.complete(&json!({ "content": [{ "type": "text", "text": "stored" }] }))
        .expect("a live task takes its outcome");
    CommittedTask {
        task,
        revision: 1,
        targets,
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: Box::default(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
        vouching: crate::gateway::task_service::Vouching::Vouched,
        replay_snapshot: None,
    }
}

fn alice_target() -> Target {
    Target {
        server: CAPS.to_owned(),
        tool: PERSONAL.to_owned(),
    }
}

fn reader() -> Reader<'static> {
    Reader {
        caller: "alice",
        session_id: "s-1",
        subject: None,
        credential: DeliveryCredential::of(
            None,
            &crate::gateway::record_principal::test_record_key(),
        ),
    }
}

/// Build and send the notification for `stored`, re-authorized for `caller`
/// as the HTTP stream does (router/handlers/tasks.rs). The frame sent, and
/// the frame's delivery record.
async fn notify(
    meta: &MetaMcp,
    dir: &tempfile::TempDir,
    stored: CommittedTask,
    caller: &MetaMcpCallerContext<'_>,
) -> (Value, Value) {
    let published = json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks",
        "params": { "taskId": stored.task.id(), "status": "completed" },
    });
    let subscription = SubscriptionId::of_request(RequestId::Number(5));
    let request = RequestId::Number(0);
    let pending = meta
        .task_notification_frame(
            &published,
            Some(super::sealed_hold::Held::new(
                stored,
                super::sealed_hold::CarriedHolds::none(),
            )),
            |stored| meta.refuse_stored_delivery(&request, stored, None, Some("s-1"), caller),
            &subscription,
        )
        .await
        .expect("a frame is built");
    let frame = pending.frame.clone();
    assert!(meta.finish_task_frame(pending, &frame, &reader()).await);
    let record = entries(dir)
        .into_iter()
        .rev()
        .find(|row| row["response_stage"] == json!("notification_delivered"))
        .expect("the frame's delivery record");
    (frame, record)
}

/// A withheld frame is the published notification only: its params carry
/// the task id, the status and the subscription tag, and nothing stored.
fn assert_withheld(frame: &Value) {
    let keys: std::collections::BTreeSet<&str> = frame["params"]
        .as_object()
        .expect("params")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        ["_meta", "status", "taskId"].into_iter().collect(),
        "premise: withheld to the published status: {frame}"
    );
}

async fn alice_gateway(dir: &std::sync::Arc<tempfile::TempDir>) -> (Endpoint, MetaMcp) {
    let endpoint = Endpoint::start(false).await;
    let meta = gateway(
        &endpoint,
        vec![grant("g-notify", ALICE, ALICE)],
        Some(dir),
        AuditFailurePolicy::FailClosed,
    );
    (endpoint, meta)
}

/// The tool policy now denies the task's tool: the frame is withheld (the
/// published status only) and its record names the deny entry.
#[tokio::test]
async fn a_withheld_notification_names_the_deny_entry() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let policy = denying();
    let authorizer = ToolPolicyAuthorizer {
        tool_policy: &policy,
        generation: None,
    };
    let alice = api_key("alice");
    let caller = MetaMcpCallerContext {
        authorizer: &authorizer,
        ..context(&alice)
    };
    let (frame, record) = notify(&meta, &dir, finished(vec![alice_target()]), &caller).await;
    assert_withheld(&frame);
    let id = deny_entry_id();
    let hex = id.as_str().trim_start_matches("tool_policy:");
    assert!(!frame.to_string().contains(hex), "{frame}");
    assert_eq!(
        record["refused_by"],
        json!({"kind": "tool_policy", "rule_id": id.as_str()}),
        "{record}"
    );
}

/// A recorded target whose backend is gone: withheld as a miss, which is no
/// policy refusal, so the record names nothing.
#[tokio::test]
async fn a_notification_withheld_for_a_removed_backend_names_nothing() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let alice = api_key("alice");
    let caller = context(&alice);
    let gone = Target {
        server: "gone_backend".to_owned(),
        tool: "read".to_owned(),
    };
    let (frame, record) = notify(&meta, &dir, finished(vec![gone]), &caller).await;
    assert_withheld(&frame);
    assert!(record.get("refused_by").is_none(), "{record}");
}

/// A read the checks admit is served whole and names no refusal.
#[tokio::test]
async fn a_served_notification_names_nothing() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let alice = api_key("alice");
    let caller = context(&alice);
    let (frame, record) = notify(&meta, &dir, finished(vec![alice_target()]), &caller).await;
    assert!(
        frame.to_string().contains("stored"),
        "premise: served: {frame}"
    );
    assert!(record.get("refused_by").is_none(), "{record}");
}

/// A stored result no longer served under its recorded bindings: withheld,
/// and its record names the provenance check, with no rule id.
#[tokio::test]
async fn a_notification_withheld_for_provenance_names_it() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let alice = api_key("alice");
    let caller = context(&alice);
    let stored = CommittedTask {
        bindings_recorded: false,
        replay_snapshot: None,
        ..finished(vec![alice_target()])
    };
    let (frame, record) = notify(&meta, &dir, stored, &caller).await;
    assert_withheld(&frame);
    assert_eq!(
        record["refused_by"],
        json!({"kind": "provenance"}),
        "{record}"
    );
}

/// No stored task to read: the published status goes out, the stored-read
/// judgement never runs, and the record names nothing.
#[tokio::test]
async fn a_notification_without_its_stored_task_names_nothing() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let published = json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks",
        "params": { "taskId": "t-gone", "status": "completed" },
    });
    let subscription = SubscriptionId::of_request(RequestId::Number(6));
    let pending = meta
        .task_notification_frame(
            &published,
            None,
            |_| panic!("no stored task, so no re-authorization"),
            &subscription,
        )
        .await
        .expect("a frame is built");
    let frame = pending.frame.clone();
    assert!(meta.finish_task_frame(pending, &frame, &reader()).await);
    assert_withheld(&frame);
    let record = entries(&dir)
        .into_iter()
        .rev()
        .find(|row| row["response_stage"] == json!("notification_delivered"))
        .expect("the frame's delivery record");
    assert!(record.get("refused_by").is_none(), "{record}");
}
