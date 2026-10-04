// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.2 for plans: a plan stages one receipt per step, and a
//! change to the plan's answer keeps each step's receipt for the text the
//! caller still got. A plan receipt is never rebuilt from the plan's answer,
//! which holds text the engine wrote.

use serde_json::{Value, json};

use super::{OTHER_PROSE, PROSE, relay_meta, text_result};
use crate::gateway::meta_mcp::invoke::relay::{AnswerShape, GatewayStamps, RelayKey, plan_step};
use crate::security::firewall::{Firewall, RelayCaller};

/// Text a redaction removes from step A, long enough to be matched alone.
const SECRET: &str = "Account recovery phrase for the vineyard terminal: amber kettle \
    seventeen lantern quiet harbour violet anchor, rotated after the September audit.";

/// What the playbook engine writes into a plan's answer itself.
const ENGINE: &str = "Step two was skipped because its condition was false; the playbook \
    substituted the configured fallback summary for the missing upstream output here.";

/// Whether `who` sending `text` through `alpha:send` is refused as a relay.
fn refused(firewall: &Firewall, who: &str, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    !firewall
        .check_relay(
            RelayCaller::Keyed(who),
            "alpha",
            "send",
            &params,
            ("s", who),
        )
        .allowed
}

/// `carol` independently receives `text` from `alpha:tool`: what makes a later
/// relay of it by another principal a match.
fn carol_holds(firewall: &Firewall, tool: &str, text: &str) {
    firewall.record_delivery(
        RelayCaller::Keyed("carol"),
        "alpha",
        tool,
        &text_result(text),
    );
}

/// A plan's answer as `wrap_tool_success` serves it: the step outputs, pretty
/// JSON in one text block.
fn plan_answer(steps: &Value) -> Value {
    json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(steps).unwrap()}]})
}

/// Stage each `(tool, text)` as one plan step of `alice`'s plan, then run the
/// production sequence on `answer` as finally `delivered`: the restage after a
/// final check, then the final rebuild, then the commit.
async fn deliver_plan(
    meta: &std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>,
    steps: &[(&str, &str)],
    answer: &Value,
    delivered: &Value,
) {
    let ((), staged) = meta
        .collecting_staged(async {
            for (tool, text) in steps {
                plan_step(async {
                    meta.stage_relay_receipt(
                        RelayKey::new("alice", true),
                        ("alpha", tool),
                        &text_result(text),
                    );
                })
                .await;
            }
            let snapshot = meta.relay_snapshot(answer);
            meta.restage_if_changed(snapshot, Some(delivered));
            meta.rebuild_receipt_from_final(
                Some(delivered),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    staged.commit(true);
}

/// A redaction inside step A keeps step B's receipt, keeps A's unredacted
/// text, and receipts none of the removed text.
#[tokio::test]
async fn a_redaction_in_one_step_keeps_the_other_steps_receipt() {
    let (meta, firewall) = relay_meta();
    let a = format!("{PROSE} {SECRET}");
    let answer = plan_answer(&json!({"a": text_result(&a), "b": text_result(OTHER_PROSE)}));
    let redacted = plan_answer(&json!({"a": text_result(PROSE), "b": text_result(OTHER_PROSE)}));
    deliver_plan(&meta, &[("a", &a), ("b", OTHER_PROSE)], &answer, &redacted).await;
    carol_holds(&firewall, "a", &a);
    carol_holds(&firewall, "b", OTHER_PROSE);

    assert!(
        refused(&firewall, "bob", OTHER_PROSE),
        "control: bob holds no copy"
    );
    assert!(
        !refused(&firewall, "alice", OTHER_PROSE),
        "alice still holds step B as delivered"
    );
    assert!(
        !refused(&firewall, "alice", PROSE),
        "alice still holds A's unredacted text"
    );
    assert!(
        refused(&firewall, "alice", SECRET),
        "the redacted text was never delivered to alice"
    );
}

/// No step's receipt holds another step's text: B's prose held by carol as
/// `alpha:a` is still a relay when alice sends it.
#[tokio::test]
async fn a_step_receipt_never_holds_another_steps_text() {
    let (meta, firewall) = relay_meta();
    let answer = plan_answer(&json!({"a": text_result(PROSE), "b": text_result(OTHER_PROSE)}));
    let changed =
        plan_answer(&json!({"a": text_result(PROSE), "b": text_result(OTHER_PROSE), "n": 1}));
    deliver_plan(
        &meta,
        &[("a", PROSE), ("b", OTHER_PROSE)],
        &answer,
        &changed,
    )
    .await;
    carol_holds(&firewall, "a", PROSE);
    carol_holds(&firewall, "a", OTHER_PROSE);

    assert!(
        !refused(&firewall, "alice", PROSE),
        "control: A's own text is excused"
    );
    assert!(
        refused(&firewall, "alice", OTHER_PROSE),
        "alice holds B's text from alpha:b, never from alpha:a"
    );
}

/// A plan with one staged receipt is still a plan: its answer carries text the
/// engine wrote, which is never attributed to the step's backend.
#[tokio::test]
async fn a_one_step_plan_never_attributes_engine_text_to_the_backend() {
    let (meta, firewall) = relay_meta();
    let answer = plan_answer(&json!({"a": text_result(PROSE), "b": ENGINE}));
    deliver_plan(&meta, &[("a", PROSE)], &answer, &answer).await;
    carol_holds(&firewall, "a", PROSE);
    carol_holds(&firewall, "a", ENGINE);

    assert!(
        !refused(&firewall, "alice", PROSE),
        "control: the step's text is excused"
    );
    assert!(
        refused(&firewall, "alice", ENGINE),
        "the engine's text is not alpha:a's"
    );
}

/// `n` distinct words of filler, so no two fillers share a k-gram.
fn filler(tag: &str, n: usize) -> String {
    (0..n)
        .map(|i| format!("{tag}{i:05}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A large plan: B's unchanged step sits in the middle of an answer far over
/// the receipt cap, behind steps whose text alone fills it. B keeps its
/// receipt after a change in step A.
#[tokio::test]
async fn a_large_plan_keeps_a_middle_steps_receipt() {
    let (meta, firewall) = relay_meta();
    let (head, tail) = (filler("head", 1200), filler("tail", 1200));
    let a = format!("{PROSE} {SECRET}");
    let steps = |a: &str| json!({"1": text_result(&head), "2": text_result(a), "3": text_result(OTHER_PROSE), "4": text_result(&tail)});
    let (answer, redacted) = (plan_answer(&steps(&a)), plan_answer(&steps(PROSE)));
    let staged = [
        ("h", head.as_str()),
        ("a", &a),
        ("b", OTHER_PROSE),
        ("t", &tail),
    ];
    deliver_plan(&meta, &staged, &answer, &redacted).await;
    carol_holds(&firewall, "b", OTHER_PROSE);

    assert!(
        refused(&firewall, "bob", OTHER_PROSE),
        "control: bob holds no copy"
    );
    assert!(
        !refused(&firewall, "alice", OTHER_PROSE),
        "B was delivered unchanged"
    );
}

/// A capped receipt has a seam between its head and its tail: text spanning
/// the cut was never produced contiguously by the source and grants no
/// excuse. A single-target receipt, committed as staged.
#[tokio::test]
async fn a_capped_receipt_records_nothing_across_its_cut() {
    let (meta, firewall) = relay_meta();
    let (head, middle, tail) = (
        filler("left", 600),
        filler("mid", 600),
        filler("right", 600),
    );
    let text = format!("{head} {middle} {tail}");
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(
                RelayKey::new("alice", true),
                ("alpha", "a"),
                &text_result(&text),
            );
        })
        .await;
    staged.commit(true);
    let cut = 3 * 1024;
    let across = format!(
        "{} {}",
        &text[cut - 150..cut],
        &text[text.len() - cut..][..150]
    );
    carol_holds(&firewall, "a", &across);
    carol_holds(&firewall, "a", &text[..cut]);

    assert!(
        !refused(&firewall, "alice", &text[200..cut]),
        "control: the head is excused"
    );
    assert!(
        refused(&firewall, "alice", &across),
        "nothing spans the cut"
    );
}

/// The stated residual: a k-gram in two steps, removed from A only, stays on
/// A's receipt, since the caller got it through B and A did produce it.
#[tokio::test]
async fn text_removed_from_one_step_but_delivered_by_another_stays_receipted() {
    let (meta, firewall) = relay_meta();
    let a = format!("{PROSE} {SECRET}");
    let b = format!("{OTHER_PROSE} {SECRET}");
    let answer = plan_answer(&json!({"a": text_result(&a), "b": text_result(&b)}));
    let redacted = plan_answer(&json!({"a": text_result(PROSE), "b": text_result(&b)}));
    deliver_plan(&meta, &[("a", &a), ("b", &b)], &answer, &redacted).await;
    carol_holds(&firewall, "a", SECRET);

    assert!(
        refused(&firewall, "bob", SECRET),
        "control: bob holds no copy"
    );
    assert!(
        !refused(&firewall, "alice", SECRET),
        "alice holds it from A and from B"
    );
}

/// A sensitive step stays sensitive after its plan is changed: carol relaying
/// alice's copy of it is still caught, though the answer lost the marker.
#[tokio::test]
async fn a_kept_plan_receipt_stays_sensitive() {
    let (meta, firewall) = relay_meta();
    let marked = |text: &str| {
        let mut v = text_result(text);
        v["_context_integrity"] = json!({"classification": {"data_classes": ["credentials"]}});
        v
    };
    let ((), staged) = meta
        .collecting_staged(async {
            plan_step(async {
                meta.stage_relay_receipt(
                    RelayKey::new("alice", true),
                    ("beta", "x"),
                    &marked(PROSE),
                );
            })
            .await;
            let answer = plan_answer(&json!({"x": marked(PROSE), "n": 1}));
            let delivered = plan_answer(&json!({"x": text_result(PROSE)}));
            meta.restage_if_changed(meta.relay_snapshot(&answer), Some(&delivered));
            meta.rebuild_receipt_from_final(
                Some(&delivered),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    staged.commit(true);
    let params = json!({"name": "send", "arguments": {"text": PROSE}});
    let carol = firewall.check_relay(
        RelayCaller::Keyed("carol"),
        "alpha",
        "send",
        &params,
        ("s", "carol"),
    );
    assert!(!carol.allowed, "alice's copy is still sensitive");
}

/// A step's text with quotes, backslashes and newlines, served through the
/// real `wrap_tool_success` envelope: unchanged, it keeps its receipt.
#[tokio::test]
async fn a_wrapped_plan_answer_keeps_escaped_step_text() {
    let (meta, firewall) = relay_meta();
    let b = format!("{OTHER_PROSE}\n\"quoted\" C:\\path\\to\\file {PROSE}");
    let wrap = |steps: &Value| {
        let response = crate::gateway::meta_mcp_helpers::wrap_tool_success(
            crate::protocol::RequestId::Number(1),
            steps,
            false,
        );
        serde_json::to_value(response.result.unwrap()).unwrap()
    };
    let a = format!("{PROSE} {SECRET}");
    let answer = wrap(&json!({"a": text_result(&a), "b": text_result(&b)}));
    let redacted = wrap(&json!({"a": text_result(PROSE), "b": text_result(&b)}));
    deliver_plan(&meta, &[("a", &a), ("b", &b)], &answer, &redacted).await;
    carol_holds(&firewall, "b", &b);

    assert!(refused(&firewall, "bob", &b), "control: bob holds no copy");
    assert!(
        !refused(&firewall, "alice", &b),
        "B was delivered unchanged"
    );
}

/// Over the bound a plan's receipts are kept against, they are dropped, as
/// before, and counted.
#[tokio::test]
async fn an_answer_over_the_bound_drops_the_plan_receipts() {
    let (meta, firewall) = relay_meta();
    let huge = "x ".repeat(600 * 1024);
    let answer = plan_answer(&json!({"a": text_result(PROSE), "pad": huge}));
    deliver_plan(&meta, &[("a", PROSE)], &answer, &answer).await;
    carol_holds(&firewall, "a", PROSE);

    assert!(
        refused(&firewall, "alice", PROSE),
        "dropped, so not excused"
    );
    assert_eq!(firewall.relay_plan_drops(), 1);
}

/// A plan receipt whose answer changed commits nothing until the final answer
/// has kept it: a route that never runs the final rebuild under-receipts.
#[tokio::test]
async fn a_changed_plan_receipt_never_commits_unkept() {
    let (meta, firewall) = relay_meta();
    let ((), staged) = meta
        .collecting_staged(async {
            plan_step(async {
                meta.stage_relay_receipt(
                    RelayKey::new("alice", true),
                    ("alpha", "a"),
                    &text_result(PROSE),
                );
            })
            .await;
            let answer = plan_answer(&json!({"a": text_result(PROSE)}));
            let changed = plan_answer(&json!({"a": text_result(PROSE), "n": 1}));
            meta.restage_if_changed(meta.relay_snapshot(&answer), Some(&changed));
        })
        .await;
    staged.commit(true);
    carol_holds(&firewall, "a", PROSE);
    assert!(
        refused(&firewall, "alice", PROSE),
        "never kept, never committed"
    );
}

/// The same through the other commit: what a dispatch collector records.
#[tokio::test]
async fn a_changed_plan_receipt_never_commits_unkept_from_a_dispatch() {
    let (meta, firewall) = relay_meta();
    crate::gateway::meta_mcp::invoke::relay::collecting(async {
        plan_step(async {
            meta.stage_relay_receipt(
                RelayKey::new("alice", true),
                ("alpha", "a"),
                &text_result(PROSE),
            );
        })
        .await;
        let answer = plan_answer(&json!({"a": text_result(PROSE)}));
        let changed = plan_answer(&json!({"a": text_result(PROSE), "n": 1}));
        meta.restage_if_changed(meta.relay_snapshot(&answer), Some(&changed));
        meta.commit_staged_relay(true);
    })
    .await;
    carol_holds(&firewall, "a", PROSE);
    assert!(
        refused(&firewall, "alice", PROSE),
        "never kept, never committed"
    );
}
