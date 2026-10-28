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

async fn firewalled(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = firewalled_state().await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// The firewalled gateway with no backend registered yet.
async fn firewalled_state() -> (Arc<AppState>, tempfile::TempDir) {
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

/// The firewalled gateway whose response rule blocks the backend tool, with
/// its audit log at `log`.
async fn blocking_state(
    log: Arc<crate::security::TransparencyLogger>,
) -> (Arc<AppState>, tempfile::TempDir) {
    use crate::security::firewall::{FirewallAction, FirewallRule};
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_responses: true,
                scan_requests: false,
                credential_redaction: true,
                rules: vec![FirewallRule {
                    tool_match: TOOL.to_string(),
                    action: FirewallAction::Block,
                    reason: None,
                    scan: Vec::new(),
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

/// A task worker's egress refusal is recorded on the task's own record (the
/// audit or terminal-state record the worker writes), never on a task read's
/// delivery. The synchronous twin is the premise: the same answer through the
/// same rule is refused.
#[tokio::test]
async fn a_worker_egress_refusal_is_recorded_on_the_tasks_own_record() {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let leak = secret();
    let answer = || {
        MockBackend::answering(Answer::Result(
            json!({"content": [{"type": "text", "text": leak}], "isError": false}),
        ))
    };

    let (_sync_dir, sync_log) = temp_log(None);
    let (sync_state, _sync_store) = blocking_state(Arc::clone(&sync_log)).await;
    register(&sync_state, BACKEND, &answer());
    let refused = post(&sync_state, "key-a", sync_invoke(1, json!({}))).await;
    assert!(
        refused.get("error").is_some() && !refused.to_string().contains(&leak),
        "premise: the rule refuses the answer: {refused}"
    );

    let (_dir, log) = temp_log(None);
    let (state, _store) = blocking_state(Arc::clone(&log)).await;
    let mock = answer();
    register(&state, BACKEND, &mock);
    let created = post(&state, "key-a", task_invoke(2, "refuse-task", json!({}))).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert!(mock.calls() > 0, "premise: the worker reached the backend");
    assert!(
        !settled.to_string().contains(&leak),
        "premise: the task read carries no credential: {settled}"
    );

    let _ = delivery_rows(&log).await;
    let entries: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let recorded = entries.iter().any(|entry| {
        entry["event"] != "response_delivery_attempt" && entry["response_effect"] == "refused"
    });
    let dump: Vec<String> = entries
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
        .collect();
    assert!(
        recorded,
        "task {task}: no record of the task carries response_effect=refused:\n{}",
        dump.join("\n")
    );
}
