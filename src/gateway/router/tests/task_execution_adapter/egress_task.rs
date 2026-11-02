// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress matrix on the task route (design `2026-10-08-one-egress-scan.md`,
//! MIK-8139 family): a credential a backend plants in a task's result, a
//! result leaf, or its failure never reaches the client that creates the task
//! or reads it with `tasks/get`.
use super::super::*;
use super::support::*;

use crate::gateway::egress_fixture::secret;
use crate::security::firewall::{Firewall, FirewallConfig};

async fn firewalled(
    mock: &Arc<MockBackend>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let (state, store) = firewalled_state().await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// The firewalled gateway with no backend registered yet.
async fn firewalled_state() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_responses: true,
                scan_requests: false,
                credential_redaction: true,
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    );
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.share_keyring_with_for_test(&firewall);
            meta.set_firewall(Some(firewall));
            meta
        },
    )
    .await;
    (state, store)
}

#[tokio::test]
async fn egress_no_planted_credential_reaches_a_task_client() {
    let leak = secret();
    let answers = [
        (
            "result text",
            Answer::Result(json!({"content": [{"type": "text", "text": leak}], "isError": false})),
        ),
        (
            "result leaf",
            Answer::Result(json!({
                "content": [{"type": "text", "text": "ok"}],
                "structuredContent": {"note": leak}
            })),
        ),
        ("failure", Answer::FirstCallFails(leak.clone())),
    ];
    let mut failures = Vec::new();
    for (at, answer) in answers {
        let mock = MockBackend::answering(answer);
        let (state, _store) = firewalled(&mock).await;
        let created = post(&state, "key-a", task_invoke(1, "egress-task", json!({}))).await;
        let task = task_id(&created);
        let settled = poll_until_terminal(&state, "key-a", &task).await;
        if mock.calls() == 0 {
            failures.push(format!("{at}: never reached the backend"));
        }
        for (read, body) in [("created", &created), ("tasks/get", &settled)] {
            if body.to_string().contains(&leak) {
                failures.push(format!("{at}: credential delivered by {read}: {body}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// MIK-8139 `ERRSCAN.FW.3`, tasks-worker arm: what an A2A agent plants in a
/// task's answer (its text, its one data part, or a failed task's status) is
/// screened by the worker before the task is committed. The row reads the
/// committed record, not only `tasks/get`: a read rescans what it serves, so
/// a client-visible check alone would pass with the worker's scan gone. The
/// agent is registered under `BACKEND` with `transport: a2a`, so the call takes
/// the A2A transport and `Backend::is_a2a` holds. The agent's own JSON-RPC
/// error is a cell too: `gateway_invoke` folds a dispatch error into an
/// `isError` result carrying its message (`invoke/post_dispatch.rs`,
/// `dispatch_error_result`), so the worker's scan sees it as a result.
#[cfg(feature = "a2a")]
#[tokio::test]
async fn egress_an_a2a_agent_credential_is_screened_by_the_task_worker() {
    use crate::config::TransportConfig;
    use futures::future::BoxFuture;
    let leak = secret();
    let cells: [(&str, Value); 4] = [
        ("text", json!([{"text": leak}])),
        ("data part", json!([{"data": {"note": leak}}])),
        ("failed", json!([{"text": leak}])),
        ("agent error", json!(leak)),
    ];
    let mut failures = Vec::new();
    for (at, parts) in cells {
        let state_name = if at == "failed" {
            "TASK_STATE_FAILED"
        } else {
            "TASK_STATE_COMPLETED"
        };
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&sends);
        let base = crate::a2a::test_agent::serve(move |body: Value| -> BoxFuture<'static, Value> {
            if body["method"] == "SendMessage" {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let reply = if at == "agent error" {
                json!({"jsonrpc": "2.0", "id": body["id"],
                    "error": {"code": -32001, "message": parts.clone()}})
            } else {
                json!({"jsonrpc": "2.0", "id": body["id"], "result": {"task": {
                    "id": "t-1", "contextId": "c-1",
                    "status": {"state": state_name, "message": {
                        "messageId": "m", "role": "ROLE_AGENT", "parts": parts.clone()}}}}})
            };
            Box::pin(async move { reply })
        })
        .await;
        let (state, _store) = firewalled_state().await;
        let backend = Arc::new(Backend::new(
            BACKEND,
            BackendConfig {
                enabled: true,
                transport: TransportConfig::A2a {
                    a2a_url: base.clone(),
                    a2a_agent_card_path: None,
                },
                ..BackendConfig::default()
            },
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        assert!(backend.is_a2a(), "{at}: the backend must be an A2A backend");
        backend.set_transport_for_test(crate::a2a::test_agent::started(&base).await);
        assert!(state.backends.register(backend), "{at}: registration");

        let mut call = task_invoke(1, "egress-a2a-task", json!({}));
        call["params"]["arguments"]["tool"] = json!("send_message");
        call["params"]["arguments"]["arguments"] = json!({"message": "hi"});
        let created = post(&state, "key-a", call).await;
        let task = task_id(&created);
        // The committed record is the oracle: a `tasks/get` rescans, and
        // refuses, whatever the worker left unscreened, so it can't be.
        let owner = admission_principal();
        let committed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(committed) = state.tasks.get(&owner, &task) {
                    use crate::protocol::tasks::TaskStatus;
                    if matches!(
                        committed.task.status(),
                        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                    ) {
                        return committed;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{at}: the task never settled"));
        let settled = get_task(&state, "key-a", &task).await;
        if sends.load(std::sync::atomic::Ordering::SeqCst) != 1 {
            failures.push(format!("{at}: the agent was not reached once: {created}"));
        }
        let stored = format!(
            "{}{}",
            serde_json::to_string(&committed.backend_result()).unwrap_or_default(),
            serde_json::to_string(&committed.backend_error()).unwrap_or_default()
        );
        if stored.contains(&leak) {
            failures.push(format!(
                "{at}: the worker committed the credential unscreened: {stored}"
            ));
        }
        for (read, body) in [("created", &created), ("tasks/get", &settled)] {
            if body.to_string().contains(&leak) {
                failures.push(format!("{at}: credential delivered by {read}: {body}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The firewalled gateway whose response rule for the backend tool takes
/// `action`, with its audit log at `log`.
async fn ruled_state(
    action: crate::security::firewall::FirewallAction,
    log: Arc<crate::security::TransparencyLogger>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    use crate::security::firewall::FirewallRule;
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_responses: true,
                scan_requests: false,
                credential_redaction: true,
                rules: vec![FirewallRule {
                    tool_match: TOOL.to_string(),
                    action,
                    reason: None,
                    scan: Vec::new(),
                    servers: None,
                    keys: None,
                    except: None,
                    allowed_roots: None,
                    path_args: None,
                }],
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    );
    super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.share_keyring_with_for_test(&firewall);
            meta.set_firewall(Some(firewall));
            meta.enable_transparency_log(log);
            meta
        },
    )
    .await
}

/// One task-augmented call answered with `answer` under a rule taking
/// `action`, run to its terminal state: the task id, its terminal read, and
/// every record in the log once the writes landed.
async fn settled_task_log(
    action: crate::security::firewall::FirewallAction,
    answer: Answer,
) -> (String, Value, Vec<Value>) {
    settled_task_log_for(action, answer, task_invoke(2, "settle-task", json!({}))).await
}

/// [`settled_task_log`] for the task-augmented call `request`.
async fn settled_task_log_for(
    action: crate::security::firewall::FirewallAction,
    answer: Answer,
    request: Value,
) -> (String, Value, Vec<Value>) {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let (_dir, log) = temp_log(None);
    let (state, _store) = ruled_state(action, Arc::clone(&log)).await;
    let mock = MockBackend::answering(answer);
    register(&state, BACKEND, &mock);
    let created = post(&state, "key-a", request).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert!(mock.calls() > 0, "premise: the worker reached the backend");
    let _ = delivery_rows(&log).await;
    let entries = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    (task, settled, entries)
}

/// The task's `task_settlement` records.
fn settlement_records<'a>(entries: &'a [Value], task: &str) -> Vec<&'a Value> {
    entries
        .iter()
        .filter(|entry| entry["route"] == "task_settlement" && entry["task_id"] == task)
        .collect()
}

/// Every record's route, event, outcome, trace and field names, for a failure
/// message.
fn dump(entries: &[Value]) -> String {
    entries
        .iter()
        .map(|entry| {
            let keys: Vec<&str> = entry
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect())
                .unwrap_or_default();
            format!(
                "event={} route={} outcome={} trace_id={} task_id={} keys={keys:?}",
                entry["event"],
                entry["route"],
                entry["outcome"],
                entry["trace_id"],
                entry["task_id"]
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A task worker's egress refusal is recorded on the task's own record (the
/// settlement record the worker writes), never on a task read's delivery, and
/// that record joins the worker's dispatch record by its trace alone. The
/// synchronous twin is the premise: the same answer through the same rule is
/// refused.
#[tokio::test]
async fn a_worker_egress_refusal_is_recorded_on_the_tasks_own_record() {
    use crate::gateway::router::route_matrix_driver_tests::response::temp_log;
    use crate::security::firewall::FirewallAction;
    let leak = secret();
    let planted =
        || Answer::Result(json!({"content": [{"type": "text", "text": leak}], "isError": false}));

    let (_sync_dir, sync_log) = temp_log(None);
    let (sync_state, _sync_store) = ruled_state(FirewallAction::Block, sync_log).await;
    register(&sync_state, BACKEND, &MockBackend::answering(planted()));
    let refused = post(&sync_state, "key-a", sync_invoke(1, json!({}))).await;
    assert!(
        refused.get("error").is_some() && !refused.to_string().contains(&leak),
        "premise: the rule refuses the answer: {refused}"
    );

    let (task, settled, entries) = settled_task_log(FirewallAction::Block, planted()).await;
    assert!(
        !settled.to_string().contains(&leak),
        "premise: the task read carries no credential: {settled}"
    );
    let records = settlement_records(&entries, &task);
    let [record] = records.as_slice() else {
        panic!(
            "task {task}: one task_settlement record:\n{}",
            dump(&entries)
        );
    };
    assert!(record["response_effect"] == "refused", "{record}");
    assert!(record["outcome"] == "denied", "{record}");
    assert!(!record.to_string().contains(&leak), "no content: {record}");
    let dispatches: Vec<&Value> = entries
        .iter()
        .filter(|entry| entry["route"] == "meta" && entry["trace_id"] == record["trace_id"])
        .collect();
    assert!(
        dispatches.len() == 1,
        "the record's trace names exactly the worker's dispatch record:\n{}",
        dump(&entries)
    );
}

/// A redaction at settlement records `rewritten` with its finding, and keeps the
/// completed task's outcome.
#[tokio::test]
async fn a_worker_redaction_is_recorded_as_rewritten() {
    use crate::security::firewall::FirewallAction;
    let leak = secret();
    let (task, settled, entries) = settled_task_log(
        FirewallAction::Warn,
        Answer::Result(json!({"content": [{"type": "text", "text": leak}], "isError": false})),
    )
    .await;
    assert!(
        !settled.to_string().contains(&leak),
        "premise: redacted: {settled}"
    );
    let records = settlement_records(&entries, &task);
    let [record] = records.as_slice() else {
        panic!(
            "task {task}: one task_settlement record:\n{}",
            dump(&entries)
        );
    };
    assert!(record["response_effect"] == "rewritten", "{record}");
    assert!(record["outcome"] == "ok", "{record}");
    let findings = record["response_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        findings.iter().any(|f| f["kind"]
            .as_str()
            .is_some_and(|k| k.starts_with("firewall:"))),
        "the redaction's finding: {record}"
    );
    assert!(!record.to_string().contains(&leak), "no content: {record}");
}

/// A backend's own failure is not a gateway decision: no settlement record.
#[tokio::test]
async fn a_backend_failure_writes_no_settlement_record() {
    use crate::security::firewall::FirewallAction;
    let (task, _settled, entries) = settled_task_log(FirewallAction::Block, Answer::Failure).await;
    assert!(
        settlement_records(&entries, &task).is_empty(),
        "task {task}: a backend failure is recorded as the gateway's:\n{}",
        dump(&entries)
    );
}

/// An input request the settlement inspection refuses is replaced by an error
/// that ends the task, so it is a terminal refusal and is recorded: whether an
/// answer is interim is read after the inspection.
#[tokio::test]
async fn a_refused_input_request_is_recorded_as_a_terminal_refusal() {
    use super::input_round::{STATE_1, ask, create};
    use crate::security::firewall::FirewallAction;
    let leak = secret();
    let mut asked = ask("k1", STATE_1);
    asked["content"] = json!([{"type": "text", "text": leak}]);

    let (task, settled, entries) = settled_task_log_for(
        FirewallAction::Block,
        Answer::Result(asked),
        create(2, "settle-task"),
    )
    .await;
    assert!(
        !settled.to_string().contains(&leak),
        "premise: the task read carries no credential: {settled}"
    );
    let records = settlement_records(&entries, &task);
    let [record] = records.as_slice() else {
        panic!(
            "task {task}: one task_settlement record:\n{}",
            dump(&entries)
        );
    };
    assert!(record["response_effect"] == "refused", "{record}");
    assert!(record["outcome"] == "denied", "{record}");
}

/// A clean answer under the same rule writes no settlement record: only a
/// refusal or a rewrite does.
#[tokio::test]
async fn a_clean_task_answer_writes_no_settlement_record() {
    use crate::security::firewall::FirewallAction;
    let (task, settled, entries) = settled_task_log(FirewallAction::Block, Answer::ok()).await;
    assert!(
        status_of(&settled) == "completed",
        "premise: the clean task completes: {settled}"
    );
    assert!(
        settlement_records(&entries, &task).is_empty(),
        "a clean settlement wrote a record:\n{}",
        dump(&entries)
    );
}

/// Under fail-closed audit, a settlement record that cannot be written
/// withholds the answer: the task settles on `-32005` with no content. Only
/// the settlement append fails; the worker's dispatch record is written.
#[tokio::test]
async fn a_failed_settlement_write_under_fail_closed_withholds_the_answer() {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    use crate::security::audit::AuditFailurePolicy;
    use crate::security::firewall::FirewallAction;
    let leak = secret();
    let (_dir, log) = temp_log(Some(AuditFailurePolicy::FailClosed));
    let (state, _store) = ruled_state(FirewallAction::Warn, Arc::clone(&log)).await;
    let mock = MockBackend::answering(Answer::Result(
        json!({"content": [{"type": "text", "text": leak}], "isError": false}),
    ));
    register(&state, BACKEND, &mock);
    log.fail_next_append_of_kind_for_test("task_settlement");

    let created = post(&state, "key-a", task_invoke(2, "settle-task", json!({}))).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert!(mock.calls() > 0, "premise: the worker reached the backend");
    let _ = delivery_rows(&log).await;
    let entries: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    assert!(
        entries.iter().any(|entry| entry["route"] == "meta"),
        "premise: the dispatch record was written:\n{}",
        dump(&entries)
    );
    assert!(
        settlement_records(&entries, &task).is_empty(),
        "premise: the settlement append failed:\n{}",
        dump(&entries)
    );
    assert!(
        settled.to_string().contains("-32005"),
        "a failed settlement write withholds the answer: {settled}"
    );
    assert!(
        !settled.to_string().contains(&leak) && !settled.to_string().contains("[REDACTED"),
        "no content of the answer, redacted or not: {settled}"
    );
}

/// An input request the inspection rewrote but did not refuse is still an
/// interim answer: the task waits for input and no settlement record is written.
#[tokio::test]
async fn a_rewritten_input_request_writes_no_settlement_record() {
    use super::input_round::{STATE_1, ask, create, wait_input_required};
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    use crate::security::firewall::FirewallAction;
    let leak = secret();
    let mut asked = ask("k1", STATE_1);
    asked["content"] = json!([{"type": "text", "text": leak}]);
    let (_dir, log) = temp_log(None);
    let (state, _store) = ruled_state(FirewallAction::Warn, Arc::clone(&log)).await;
    let mock = MockBackend::answering(Answer::Result(asked));
    register(&state, BACKEND, &mock);

    let created = post(&state, "key-a", create(2, "settle-task")).await;
    let task = task_id(&created);
    let parked = wait_input_required(&state, &task).await;
    assert!(
        !parked.to_string().contains(&leak),
        "premise: the input request was redacted: {parked}"
    );
    let _ = delivery_rows(&log).await;
    let entries: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert!(
        settlement_records(&entries, &task).is_empty(),
        "an interim answer wrote a settlement record:\n{}",
        dump(&entries)
    );
}
