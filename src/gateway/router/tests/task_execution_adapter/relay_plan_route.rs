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
    plan_state_with(mock, &two_principal_auth()).await
}

/// [`plan_state`] under `auth`.
async fn plan_state_with(
    mock: &Arc<MockBackend>,
    auth: &AuthConfig,
) -> (Arc<AppState>, tempfile::TempDir) {
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
    // Every k-gram kept: any 48-char run holds a fingerprint under any hash
    // key, so with one shared fingerprint a relay of the URL or the advice
    // is always refused if receipted (MIK-8083).
    let relay = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: vec![format!("{BACKEND}:*")],
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keeping_every_kgram(),
    );
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta_and_firewall(
        auth,
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

/// A database URL longer than a k-gram, so a receipt that kept it would
/// match a relay of it.
const DSN: &str = "postgres://ledger:pw@db.local/orchard-archive-of-the-north-slope-pear-rows";

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

/// Two short text blocks, each under a k-gram, so every fingerprint across
/// them spans the two backend leaves.
const FIELD_X: &str = "north slope rows seven to twelve, pears";
const FIELD_Y: &str = "south terrace rows one to six, quinces";

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

/// `MIK-8209` K6: three chain steps each return one 32-char `part` beside a
/// `kind` field. No part is a k-gram alone, so only the 96-char join of the
/// `results[].result.part` key path, which spans all three steps, is
/// evidence: key-b relaying it is refused, and key-a, who was delivered the
/// chain, re-joining the parts is excused by the same seam receipt.
#[tokio::test]
async fn a_key_path_join_across_chain_steps_is_seam_evidence_and_excuse() {
    let parts = [
        "abcdefghij klmnopqrst uvwxyz0123",
        "fourscore and seven years ago ou",
        "r fathers brought forth on this ",
    ];
    let joined = parts.concat();
    assert!(
        parts.iter().all(|p| p.len() < 48),
        "premise: no part is a k-gram"
    );
    let mock = MockBackend::answering(Answer::Sequence(
        parts
            .iter()
            .map(|p| json!({"part": p, "kind": "chunk", "isError": false}))
            .chain(std::iter::repeat_with(|| text("ok")).take(6))
            .collect(),
    ));
    let (state, _store) = plan_state(&mock).await;
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}});
    let plan = modern(
        1,
        "tools/call",
        json!({"name": "gateway_execute", "arguments": {"chain": [step, step, step]}}),
        false,
    );
    let read = post(&state, "key-a", plan).await;
    assert!(
        read.get("error").is_none(),
        "base: the chain is delivered: {read}"
    );
    let relayed = post(&state, "key-b", sync_invoke(2, json!({"text": joined}))).await;
    assert_eq!(
        relayed["error"]["code"], -32002,
        "the cross-step join was not receipted: {relayed}"
    );
    let own = post(&state, "key-a", sync_invoke(3, json!({"text": joined}))).await;
    assert!(own.get("error").is_none(), "the holder was refused: {own}");
}

/// `MIK-8209` Q2 (gpt's shape at the route): each chain step returns its
/// `part` beside `x` and twenty more `"x"` copies. A chain answer carries
/// each step's result exactly once, so a step's span never holds more
/// copies than the step staged, and the cross-step join is still recorded
/// and excused. The copies are staged with the step (`xs`), so this row
/// confirms K6 under repeats within a result; the copies a late redaction
/// adds are `late_redaction_copies_keep_the_cross_step_join` (MIK-8251).
#[tokio::test]
async fn repeated_metadata_in_chain_steps_keeps_the_cross_step_join() {
    let parts = [
        "abcdefghij klmnopqrst uvwxyz0123",
        "fourscore and seven years ago ou",
        "r fathers brought forth on this ",
    ];
    let joined = parts.concat();
    assert!(
        parts.iter().all(|p| p.len() < 48),
        "premise: no part is a k-gram"
    );
    let mock = MockBackend::answering(Answer::Sequence(
        parts
            .iter()
            .map(|p| json!({"part": p, "x": "x", "xs": vec!["x"; 20], "isError": false}))
            .chain(std::iter::repeat_with(|| text("ok")).take(6))
            .collect(),
    ));
    let (state, _store) = plan_state(&mock).await;
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}});
    let plan = modern(
        1,
        "tools/call",
        json!({"name": "gateway_execute", "arguments": {"chain": [step, step, step]}}),
        false,
    );
    let read = post(&state, "key-a", plan).await;
    assert!(
        read.get("error").is_none(),
        "base: the chain is delivered: {read}"
    );
    let relayed = post(&state, "key-b", sync_invoke(2, json!({"text": joined}))).await;
    assert_eq!(
        relayed["error"]["code"], -32002,
        "the cross-step join was not receipted: {relayed}"
    );
    let own = post(&state, "key-a", sync_invoke(3, json!({"text": joined}))).await;
    assert!(own.get("error").is_none(), "the holder was refused: {own}");
}

/// `MIK-8209` Q2, gpt's counterexample: the router redacts each step's
/// thousand credentials after staging, so the answer repeats the staged
/// marker `b` a thousand times in the step's span. Each step must still
/// keep its `part` whole, so the cross-step join is recorded and excused.
/// Red until MIK-8251: the copies spend the room and `part` is lost.
#[tokio::test]
#[ignore = "MIK-8251: late redaction copies of a staged leaf crowd out a step's part"]
async fn late_redaction_copies_keep_the_cross_step_join() {
    let parts = ["a".repeat(32), "b".repeat(32), "c".repeat(32)];
    let joined = parts.concat();
    assert!(
        parts.iter().all(|p| p.len() < 48),
        "premise: no part is a k-gram"
    );
    // An AWS access key id shape, built so no literal key sits in the source.
    let key = format!("{}{}", "AK".to_owned() + "IA", "0".repeat(16));
    let mock = MockBackend::answering(Answer::Sequence(
        parts
            .iter()
            .map(|p| {
                json!({
                    "a": vec![key.as_str(); 1000],
                    "b": "[REDACTED:credential]",
                    "part": p,
                    "isError": false,
                })
            })
            .chain(std::iter::repeat_with(|| text("ok")).take(6))
            .collect(),
    ));
    let (state, _store) = plan_state(&mock).await;
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}});
    let plan = modern(
        1,
        "tools/call",
        json!({"name": "gateway_execute", "arguments": {"chain": [step, step, step]}}),
        false,
    );
    let read = post(&state, "key-a", plan).await;
    assert!(
        read.get("error").is_none(),
        "base: the chain is delivered: {read}"
    );
    assert!(
        !read.to_string().contains(&key),
        "premise: the router redacted the keys"
    );
    let relayed = post(&state, "key-b", sync_invoke(2, json!({"text": joined}))).await;
    assert_eq!(
        relayed["error"]["code"], -32002,
        "the cross-step join was not receipted: {relayed}"
    );
    let own = post(&state, "key-a", sync_invoke(3, json!({"text": joined}))).await;
    assert!(own.get("error").is_none(), "the holder was refused: {own}");
}

/// `MIK-8205` (S4): a plan's final answer delivers key-a three labelled parts;
/// the same tool delivers key-c the join of parts 1 and 3 on its own call.
/// Key-a forwarding that subset is not refused: the answer's own run gives
/// her the one-gap seam. Key-b, delivered nothing, is refused.
#[tokio::test]
async fn a_subset_of_a_plan_answers_parts_against_the_tools_exact_join_is_not_refused() {
    let p = |k: usize| -> String { format!("piece{k}-").repeat(10).chars().take(47).collect() };
    let joined = format!("{}{}", p(0), p(2));
    let parts: Vec<Value> = (0..3)
        .map(|k| json!({"part": p(k), "kind": "chunk"}))
        .collect();
    let mock = MockBackend::answering(Answer::Sequence(
        std::iter::once(json!({"parts": parts, "isError": false}))
            // key-c's copy is a single leaf: a content item (`{"text": .., "type": ..}`)
            // would put a separator after the join, and the window "tail + separator"
            // is a separate, pre-existing edge (MIK-8290), not this row's.
            .chain(std::iter::once(json!({"note": joined, "isError": false})))
            .chain(std::iter::repeat_with(|| text("ok")).take(4))
            .collect(),
    ));
    let (state, _store) = plan_state_with(&mock, &three_principal_auth()).await;
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}});
    let plan = modern(
        1,
        "tools/call",
        json!({"name": "gateway_execute", "arguments": {"chain": [step]}}),
        false,
    );
    let read = post(&state, "key-a", plan).await;
    assert!(
        read.get("error").is_none(),
        "base: the plan is delivered: {read}"
    );
    let held = post(&state, "key-c", sync_invoke(2, json!({}))).await;
    assert!(
        held.get("error").is_none(),
        "base: key-c is delivered the join: {held}"
    );
    let bob = post(&state, "key-b", sync_invoke(3, json!({"text": joined}))).await;
    assert_eq!(
        bob["error"]["code"], -32002,
        "control: key-b was not refused: {bob}"
    );
    let alice = post(&state, "key-a", sync_invoke(4, json!({"text": joined}))).await;
    assert!(
        alice.get("error").is_none(),
        "key-a's subset forward was refused: {alice}"
    );
}
