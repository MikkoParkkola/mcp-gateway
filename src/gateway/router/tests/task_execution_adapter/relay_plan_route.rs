// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.2 at the POST route: a `gateway_execute` plan whose answer
//! the router's response pass redacts keeps each step's receipt for the text
//! the caller still got, through the route's own restage and final rebuild.
//! A `gateway_invoke` answer the pass rewrites keeps its receipt too
//! (MIK-7998).
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
                // One shared fingerprint. Sampling keeps one k-gram in four,
                // so a run of n k-grams keeps none with odds (3/4)^n: the
                // probes below are long enough to make a miss negligible.
                min_matches: 1,
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

/// A note whose lines are each shorter than a k-gram: only the text as the
/// caller reads it, real newlines included, matches it.
fn note() -> String {
    (0..40)
        .map(|i| format!("row {i:02}: late pears, north slope"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A database URL of 80 k-grams, so a receipt that kept it would match a
/// relay of it under all but about 1e-10 of hash keys (MIK-8083).
const DSN: &str = "postgres://ledger:pw@db.local/orchard-archive-of-the-north-slope-pear-rows-and-the-south-terrace-quince-rows-kept-by-the-estate";

/// The gateway's recovery advice for a tool error it reads as a parameter
/// problem: the gateway's text, longer than a k-gram.
const SUGGEST: &str =
    "Check the tool's input schema, correct the offending parameter(s), and retry.";

/// `MIK-7998.DECODE.1`: the redactor's database-URL match runs to the next
/// whitespace, so in the wrapper's pretty print it takes the note's closing
/// quote with it and the block is no longer JSON. The receipt still holds
/// the note as the caller reads it, and not the redacted URL (I3).
#[tokio::test]
async fn a_rewritten_invoke_wrapper_keeps_its_decoded_receipt() {
    let note = note();
    let answer = text(&format!("{note} {DSN}"));
    let mock = MockBackend::answering(Answer::Sequence(vec![answer, text("ok"), text("ok")]));
    let (state, _store) = plan_state(&mock).await;

    let read = post(&state, "key-a", sync_invoke(1, json!({}))).await;
    let block = read["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        block.contains("REDACTED") && serde_json::from_str::<Value>(block).is_err(),
        "base: the redaction broke the wrapper's JSON: {read}"
    );

    let control = post(&state, "key-a", sync_invoke(2, json!({"text": note}))).await;
    assert!(
        control.get("error").is_none(),
        "control: the holder's own relay is excused: {control}"
    );
    let relayed = post(&state, "key-b", sync_invoke(3, json!({"text": note}))).await;
    assert_eq!(
        relayed["error"]["code"], -32002,
        "the receipt read the escaped wrapper, not the note: {relayed}"
    );
    let secret = post(&state, "key-b", sync_invoke(4, json!({"text": DSN}))).await;
    assert!(
        secret.get("error").is_none(),
        "the redacted URL was never delivered, so no receipt holds it: {secret}"
    );
}

/// `MIK-7998.DECODE.2`: a tool error the gateway answers with recovery
/// advice, redacted the same way. The receipt holds the note but not the
/// gateway's advice (I2), though both are in the delivered text.
#[tokio::test]
async fn a_rewritten_tool_error_keeps_the_gateways_advice_out_of_its_receipt() {
    let note = note();
    let answer = json!({
        "content": [{"type": "text", "text": format!("{note} {DSN}")}],
        "isError": true
    });
    let mock = MockBackend::answering(Answer::Sequence(vec![answer, text("ok"), text("ok")]));
    let (state, _store) = plan_state(&mock).await;

    let read = post(&state, "key-a", sync_invoke(1, json!({}))).await;
    let block = read["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        block.contains("REDACTED")
            && block.contains(SUGGEST)
            && serde_json::from_str::<Value>(block).is_err(),
        "base: the advice was delivered in a wrapper the redaction broke: {read}"
    );

    let relayed = post(&state, "key-b", sync_invoke(2, json!({"text": note}))).await;
    assert_eq!(
        relayed["error"]["code"], -32002,
        "control: the note kept its receipt: {relayed}"
    );
    let advice = post(&state, "key-b", sync_invoke(3, json!({"text": SUGGEST}))).await;
    assert!(
        advice.get("error").is_none(),
        "the gateway's advice is not backend text, so no receipt holds it: {advice}"
    );
}

/// Two short text blocks, each one char under a k-gram, so every
/// fingerprint across them spans the two backend leaves, and the about 48
/// k-grams across them all go unsampled under about 1e-6 of keys (MIK-8083).
const FIELD_X: &str = "north slope rows seven to twelve, late pears ok";
const FIELD_Y: &str = "south terrace rows one to six, early quinces ok";

/// `MIK-8043.JOIN.4`: a rewritten wrapper is read member by member, so two
/// short backend fields the caller got intact keep the receipt across them.
/// The third block's URL is redacted with its closing quote, so the wrapper
/// no longer parses; bob relaying the two fields is refused, alice is not.
#[tokio::test]
async fn a_rewritten_wrapper_keeps_its_fields_receipted_across_them() {
    let answer = json!({"content": [
        {"type": "text", "text": FIELD_X},
        {"type": "text", "text": FIELD_Y},
        {"type": "text", "text": DSN},
    ], "isError": false});
    let mock = MockBackend::answering(Answer::Sequence(vec![answer, text("ok"), text("ok")]));
    let (state, _store) = plan_state(&mock).await;

    let read = post(&state, "key-a", sync_invoke(1, json!({}))).await;
    let block = read["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        block.contains("REDACTED") && serde_json::from_str::<Value>(block).is_err(),
        "base: the redaction broke the wrapper's JSON: {read}"
    );
    let parts = json!({"parts": ["text", FIELD_X, "text", FIELD_Y]});
    let control = post(&state, "key-a", sync_invoke(2, parts.clone())).await;
    assert!(
        control.get("error").is_none(),
        "control: the holder's own relay is excused: {control}"
    );
    let relayed = post(&state, "key-b", sync_invoke(3, parts)).await;
    assert_eq!(
        relayed["error"]["code"], -32002,
        "the receipt lost the run across the two fields: {relayed}"
    );
}
