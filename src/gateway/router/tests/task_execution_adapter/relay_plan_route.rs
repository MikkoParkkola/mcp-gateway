// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.2 at the POST route: a `gateway_execute` plan whose answer
//! the router's response pass redacts keeps each step's receipt for the text
//! the caller still got, through the route's own restage and final rebuild.
use super::super::*;
use super::support::*;
use pretty_assertions::assert_eq;

use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallAction, FirewallConfig, FirewallRule,
};

/// Credential-shaped text the router's redactor removes (a fake token,
/// spelled in two pieces).
const CANARY: &str = concat!("ghp", "_abcdefghijklmnopqrstuvwxyz1234567890");

/// Step A's prose, delivered beside the canary.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

/// Step B's prose, delivered unchanged.
const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale.";

fn text(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// The router redacts credentials in what it delivers; the Meta-MCP runs the
/// `block` relay detector over every `mock` tool and redacts nothing, so the
/// answer changes only in the router's response pass.
async fn plan_state(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let router = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            // Allowed, so the credential is redacted rather than the answer refused.
            rules: vec![FirewallRule {
                tool_match: "*".to_string(),
                action: FirewallAction::Allow,
                reason: None,
                scan: Vec::new(),
            }],
            ..FirewallConfig::default()
        },
        None,
    ));
    let relay = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec![format!("{BACKEND}:*")],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        &two_principal_auth(),
        None,
        Some(router),
        |mut meta| {
            meta.set_firewall(Some(relay));
            meta
        },
    )
    .await;
    register(&state, BACKEND, mock);
    (state, store)
}

#[tokio::test]
async fn a_redacted_plan_answer_keeps_each_steps_delivered_text() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        text(&format!("{PROSE} {CANARY}")),
        text(OTHER_PROSE),
        text("ok"),
    ]));
    let (state, _store) = plan_state(&mock).await;
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}});
    let plan = modern(
        1,
        "tools/call",
        json!({"name": "gateway_execute", "arguments": {"chain": [step, step]}}),
        false,
    );

    let read = post(&state, "key-a", plan).await;
    assert!(
        read.get("error").is_none(),
        "base: the plan is delivered: {read}"
    );
    let delivered = read["result"].to_string();
    assert!(
        delivered.contains("north slope") && delivered.contains("harbour committee"),
        "base: both steps are in the answer: {read}"
    );
    assert!(
        !delivered.contains(CANARY),
        "base: the router redacted the canary: {read}"
    );

    let relayed_b = post(
        &state,
        "key-b",
        sync_invoke(2, json!({"text": OTHER_PROSE})),
    )
    .await;
    assert_eq!(
        relayed_b["error"]["code"], -32002,
        "step B was delivered unchanged and kept its receipt: {relayed_b}"
    );
    let relayed_a = post(&state, "key-b", sync_invoke(3, json!({"text": PROSE}))).await;
    assert_eq!(
        relayed_a["error"]["code"], -32002,
        "step A's unredacted text kept its receipt: {relayed_a}"
    );
}
