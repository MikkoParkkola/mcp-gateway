// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8315 (SUBMITAUTHZ.1-3, rows 1a-1d, 3, 6): a task submit passes the
//! authorization the synchronous call of the same tool passes, before any
//! task or idempotency key exists. Every refusal is compared with the sync
//! answer of the same caller on the same fixture; no code, message or status
//! is written from reading the source. Signing is off in every fixture.
use super::super::*;
use super::grant_decision_tasks::{as_task, continuing_playbook};
use super::grant_decisions::{Armed, OWNER, armed, personal_chain, personal_invoke, surfaced};
use super::support::*;

use crate::gateway::meta_mcp::grant_audit_fixture::{CAPS, PERSONAL, decisions, grant, grants};
use crate::security::audit::AuditFailurePolicy;

pub(super) fn committed(row: &Armed) -> usize {
    row.state.task_executor.service.store.committed_count_for_test()
}

fn playbook_call(id: i64, key: &str) -> Value {
    keyed(
        modern(
            id,
            "tools/call",
            json!({ "name": "gateway_run_playbook", "arguments": { "name": "d3a-continue" } }),
            true,
        ),
        key,
    )
}

fn surfaced_call(id: i64) -> Value {
    modern(id, "tools/call", json!({ "name": PERSONAL, "arguments": {} }), true)
}

fn code_plan(id: i64, key: &str) -> Value {
    keyed(personal_chain(id), key)
}

/// An ungranted `key-a` row with the playbook registered.
pub(super) async fn ungranted(configure: fn(MetaMcp) -> MetaMcp) -> Armed {
    let row = armed(false, false, AuditFailurePolicy::BestEffort, configure).await;
    row.state.meta_mcp.set_playbook_engine(continuing_playbook());
    row
}

pub(super) fn give_grant(row: &Armed) {
    row.state
        .meta_mcp
        .set_identity_grants(grants(vec![grant("g1", OWNER, OWNER)]));
}

fn code_of(body: &Value) -> Option<i64> {
    body.pointer("/error/code").and_then(Value::as_i64)
}

fn message_of(body: &Value) -> Option<String> {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Row 1: the task submit answers what the sync call answers, creates no
/// row, writes the same number of audit records, and does not keep its key:
/// once the grant is given the same key starts a new task.
pub(super) async fn refused_like_sync_then_granted(row: &Armed, sync: Value, task: Value) {
    let rows = refused_like_sync(row, sync, task.clone()).await;
    give_grant(row);
    let created = post(&row.state, "key-a", task).await;
    let settled = poll_until_terminal(&row.state, "key-a", &task_id(&created)).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(committed(row), rows + 1, "the key was admitted by the refused submit");
}

/// The refusal half of row 1; returns the committed row count.
pub(super) async fn refused_like_sync(row: &Armed, sync: Value, task: Value) -> usize {
    let before = decisions(&row.dir).len();
    let (sync_status, sync_answer) = post_full(&row.state, "key-a", sync).await;
    assert!(sync_answer.get("error").is_some(), "the sync call is refused: {sync_answer}");
    let sync_records = decisions(&row.dir).len() - before;
    let (rows, before) = (committed(row), decisions(&row.dir).len());

    let (status, answer) = post_full(&row.state, "key-a", task.clone()).await;

    assert!(
        answer.pointer("/result/taskId").is_none(),
        "a task handle was returned for a call the sync path refuses: {answer}"
    );
    std::assert_eq!(status, sync_status, "{answer}");
    std::assert_eq!(code_of(&answer), code_of(&sync_answer), "{answer}");
    std::assert_eq!(message_of(&answer), message_of(&sync_answer), "{answer}");
    std::assert_eq!(committed(row), rows, "a task row was committed");
    std::assert_eq!(decisions(&row.dir).len() - before, sync_records, "refusal audit records");
    std::assert_eq!(row.endpoint.arrivals(), 0, "the refused call reached nothing");
    rows
}

/// 1a. `gateway_invoke`.
#[tokio::test]
async fn ungranted_invoke_submit_is_refused_like_the_sync_call() {
    let row = ungranted(|meta| meta).await;
    let task = as_task(personal_invoke(2), "sa-1a");
    refused_like_sync_then_granted(&row, personal_invoke(1), task).await;
}

/// The route-check matrix's `TaskSubmit` x `Authorize` driver: row 1a's
/// refusal, compared with the sync call on the same fixture. Gated as the
/// matrix rows are (`route_check_matrix_tests.rs` `mod rows`).
#[cfg(feature = "firewall")]
pub(crate) async fn matrix_ungranted_invoke_submit() {
    let row = ungranted(|meta| meta).await;
    let task = as_task(personal_invoke(2), "sa-matrix");
    refused_like_sync(&row, personal_invoke(1), task).await;
}

/// 1b. The capability's surfaced name (the sync answer is the concealment).
#[tokio::test]
async fn ungranted_surfaced_submit_is_refused_like_the_sync_call() {
    let row = ungranted(surfaced).await;
    let task = as_task(surfaced_call(2), "sa-1b");
    refused_like_sync_then_granted(&row, surfaced_call(1), task).await;
}

/// 1c. A keyed playbook whose step names the capability.
#[tokio::test]
async fn ungranted_playbook_submit_is_refused_like_the_sync_call() {
    let row = ungranted(|meta| meta).await;
    let task = as_task(playbook_call(2, "sa-1c"), "sa-1c");
    refused_like_sync_then_granted(&row, playbook_call(1, "sa-1c-sync"), task).await;
}

/// 1d. A keyed `gateway_execute` code plan calling the capability.
#[tokio::test]
async fn ungranted_code_plan_submit_is_refused_like_the_sync_call() {
    let row = ungranted(|meta| meta).await;
    let task = as_task(code_plan(2, "sa-1d"), "sa-1d");
    refused_like_sync_then_granted(&row, code_plan(1, "sa-1d-sync"), task).await;
}

/// Whether a committed status is one a task never leaves.
pub(super) fn settled(status: crate::protocol::tasks::TaskStatus) -> bool {
    use crate::protocol::tasks::TaskStatus;
    matches!(
        status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

pub(super) fn alice() -> String {
    crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@adapter.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.adapter.test".to_string(),
    }
    .stable_actor_id()
}

/// Row 3. The grant is revoked inside the task's commit, after the submit
/// check and before the worker starts: the worker's own check still refuses.
/// Read from the committed store and the log file, never `tasks/get`.
#[tokio::test]
async fn a_grant_revoked_after_submit_is_still_refused_by_the_worker() {
    use super::grant_audit_order::Terminal;
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let terminal = Arc::new(Terminal(tokio::sync::Notify::new()));
    row.state.task_executor.observe_commits(
        Arc::clone(&terminal) as Arc<dyn crate::gateway::task_service::CommitObserver>
    );
    let meta = Arc::clone(&row.state.meta_mcp);
    let fired = std::sync::atomic::AtomicBool::new(false);
    row.state
        .task_executor
        .barrier_on_publication(Arc::new(move || {
            if !fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                meta.set_identity_grants(grants(vec![]));
            }
        }))
        .await;
    let created = post(&row.state, "key-a", as_task(personal_invoke(1), "sa-3")).await;
    let id = task_id(&created);
    tokio::time::timeout(Duration::from_secs(10), terminal.0.notified())
        .await
        .expect("the worker commits a transition");
    let stored = loop {
        let stored = row.state.tasks.get(&alice(), &id).expect("the committed task");
        if settled(stored.task.status()) {
            break stored;
        }
        tokio::task::yield_now().await;
    };
    let error = stored.task.error().expect("the worker's refusal is stored");
    let records = decisions(&row.dir);
    std::assert_eq!(row.endpoint.arrivals(), 0, "the backend saw a call");
    assert!(
        records.iter().any(|r| r["outcome"] == json!("denied")),
        "the worker's refusal is on record: {records:#?}"
    );
    let sync = post(&row.state, "key-a", personal_invoke(2)).await;
    std::assert_eq!(Some(i64::from(error.code)), code_of(&sync), "{sync}");
    std::assert_eq!(Some(error.message.clone()), message_of(&sync), "{sync}");
}

/// Row 6. Replay after revoke: the same request and key, resubmitted once the
/// grant is gone, is refused and nothing stored is served. On the base the
/// refusal comes from the Existing branch (HTTP 200); status is not compared.
async fn resubmit_after_revoke(hold: bool) {
    let row = armed(true, hold, AuditFailurePolicy::BestEffort, |meta| meta).await;
    let task = as_task(personal_invoke(1), "sa-6");
    let created = post(&row.state, "key-a", task.clone()).await;
    let id = task_id(&created);
    if hold {
        row.endpoint.wait_for_arrivals(1).await;
    } else {
        std::assert_eq!(
            status_of(&poll_until_terminal(&row.state, "key-a", &id).await),
            "completed"
        );
    }
    row.state.meta_mcp.set_identity_grants(grants(vec![]));
    let sync = post(&row.state, "key-a", personal_invoke(2)).await;
    let again = post(&row.state, "key-a", task).await;
    row.endpoint.release();
    assert!(again.get("result").is_none(), "a stored task was served: {again}");
    std::assert_eq!(code_of(&again), code_of(&sync), "{again}");
    std::assert_eq!(row.endpoint.arrivals(), 1, "the worker ran once");
}

/// 6a. The task is still Working when the grant is revoked.
#[tokio::test]
async fn resubmitting_a_working_task_after_revoke_is_refused() {
    resubmit_after_revoke(true).await;
}

/// 6b. The task completed before the grant was revoked.
#[tokio::test]
async fn resubmitting_a_completed_task_after_revoke_is_refused() {
    resubmit_after_revoke(false).await;
}

const WEBHOOK: &str = "register_webhook";

/// A capability that registers a caller-addressed destination with a third
/// party: `admin_capability_rule` classifies it as an admin action.
fn webhook_backend() -> Arc<crate::capability::CapabilityBackend> {
    let definition = crate::capability::parse_capability(&format!(
        "name: {WEBHOOK}\n\
         description: registers a caller-supplied address with a third party\n\
         schema:\n\
         \x20 input:\n\
         \x20   type: object\n\
         \x20   properties:\n\
         \x20     url:\n\
         \x20       type: string\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://localhost:1\n\
         \x20     path: /hooks\n\
         \x20     method: POST\n"
    ))
    .expect("the webhook capability parses");
    let executor = Arc::new(crate::capability::CapabilityExecutor::new());
    let backend = Arc::new(crate::capability::CapabilityBackend::new(CAPS, executor));
    backend
        .register_capability(definition)
        .expect("the webhook capability registers");
    backend
}

fn webhook_invoke(id: i64) -> Value {
    modern(
        id,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": {
                "server": CAPS,
                "tool": WEBHOOK,
                "arguments": { "url": "https://attacker.example/collect" }
            }
        }),
        true,
    )
}

/// 2. A non-admin task submit of an admin capability answers the sync
/// refusal (Forbidden) and creates no task.
#[tokio::test]
async fn non_admin_webhook_submit_is_refused_like_the_sync_call() {
    let row = ungranted(|meta| meta).await;
    row.state.meta_mcp.set_capabilities(webhook_backend());
    let sync = post_full(&row.state, "key-a", webhook_invoke(1)).await;
    std::assert_eq!(sync.0, StatusCode::FORBIDDEN, "the sync control: {}", sync.1);
    refused_like_sync(&row, webhook_invoke(1), as_task(webhook_invoke(2), "sa-2")).await;
}
