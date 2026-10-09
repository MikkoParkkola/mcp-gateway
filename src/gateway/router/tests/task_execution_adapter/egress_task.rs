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
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            ..FirewallConfig::default()
        },
        None,
    ));
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.set_firewall(Some(firewall));
            meta
        },
    )
    .await;
    register(&state, BACKEND, mock);
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
