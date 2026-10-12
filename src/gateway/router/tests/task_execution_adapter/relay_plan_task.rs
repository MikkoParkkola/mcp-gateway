// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7934.PLANRCPT.1 on the task route: a task-augmented `gateway_execute`
//! plan whose stored result the Meta-MCP redacts at settlement keeps each
//! step's receipt for the text the task still delivers.
use super::super::*;
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallAction, FirewallConfig, FirewallRule,
};

/// Credential-shaped text the redactor removes (a fake token, spelled in two
/// pieces).
const CANARY: &str = concat!("ghp", "_abcdefghijklmnopqrstuvwxyz1234567890");

/// Step A's prose, stored beside the canary.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

/// Step B's prose, stored unchanged.
const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale.";

fn text(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// The Meta-MCP firewall both redacts credentials in what a task settles and
/// runs the `block` relay detector over every `mock` tool.
async fn plan_state(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                enabled: true,
                scan_responses: true,
                scan_requests: false,
                credential_redaction: true,
                // Allowed, so the credential is redacted rather than the result refused.
                rules: vec![FirewallRule {
                    tool_match: "*".to_string(),
                    action: FirewallAction::Allow,
                    reason: None,
                    scan: Vec::new(),
                }],
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    sources: vec![format!("{BACKEND}:*")],
                    ..CollusionConfig::default()
                },
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
    register(&state, BACKEND, mock);
    (state, store)
}

/// `key-b` sends `text` until refused or out of time, never reading the task:
/// a `tasks/get` could renew a receipt and hide a missing settlement commit.
async fn relay_until_refused(state: &Arc<AppState>, first_id: i64, text: &str) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut id = first_id;
    loop {
        let answer = post(state, "key-b", sync_invoke(id, json!({"text": text}))).await;
        if answer["error"]["code"] == -32002 || tokio::time::Instant::now() >= deadline {
            return answer;
        }
        id += 1;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_redacted_task_plan_keeps_each_steps_delivered_text() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        text(&format!("{PROSE} {CANARY}")),
        text(OTHER_PROSE),
        text("ok"),
    ]));
    let (state, _store) = plan_state(&mock).await;
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}});
    let plan = keyed(
        modern(
            1,
            "tools/call",
            json!({
                "name": "gateway_execute",
                "arguments": {"chain": [step, step]},
                "task": {}
            }),
            true,
        ),
        "relay-plan-task",
    );
    let created = post(&state, "key-a", plan).await;
    let task = task_id(&created);
    // The relays below call the same backend: they wait until both plan
    // steps have taken their answers, so the plan gets A then B.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while mock.calls() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the plan never ran both steps"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let relayed_b = relay_until_refused(&state, 100, OTHER_PROSE).await;
    assert_eq!(
        relayed_b["error"]["code"], -32002,
        "step B was stored unchanged and kept its receipt: {relayed_b}"
    );
    let relayed_a = relay_until_refused(&state, 200, PROSE).await;

    // Read only after both relays: a read could renew a receipt.
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "base: {settled}");
    let stored = settled["result"]["result"].to_string();
    assert_eq!(
        relayed_a["error"]["code"], -32002,
        "step A's unredacted text kept its receipt: {relayed_a}; stored: {stored}"
    );
    assert!(
        stored.contains("north slope")
            && stored.contains("harbour committee")
            && !stored.contains(CANARY),
        "base: settlement redacted the canary and kept both steps: {stored}"
    );
}
