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

#[path = "relay_plan_budget_tests.rs"]
mod budget;

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
                plan_step(None, async {
                    meta.stage_relay_receipt(
                        RelayKey::new("alice", true),
                        ("alpha", tool),
                        &text_result(text),
                    );
                })
                .await;
            }
            let snapshot = meta.relay_snapshot(answer);
            meta.restage_if_changed(snapshot, Some(delivered), AnswerShape::Literal);
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
    // A is redacted, so its receipt goes through the k-gram path, not only
    // the whole-leaf one.
    let a = format!("{PROSE} {SECRET}");
    let answer = plan_answer(&json!({"a": text_result(&a), "b": text_result(OTHER_PROSE)}));
    let changed = plan_answer(&json!({"a": text_result(PROSE), "b": text_result(OTHER_PROSE)}));
    deliver_plan(&meta, &[("a", &a), ("b", OTHER_PROSE)], &answer, &changed).await;
    carol_holds(&firewall, "a", &a);
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
    // carol holds A as the source sent it, so a match is the same text in
    // the same context, never a winnowing edge.
    carol_holds(&firewall, "a", &a);

    assert!(
        refused(&firewall, "bob", SECRET),
        "control: bob holds no copy"
    );
    assert!(
        !refused(&firewall, "alice", SECRET),
        "alice holds it from A and from B"
    );
}

/// A sensitive step of a two-step plan stays sensitive after the plan's answer
/// is changed: carol relaying alice's copy of it is still caught, though the
/// answer lost the marker.
#[tokio::test]
async fn a_kept_plan_receipt_stays_sensitive() {
    let (meta, firewall) = super::classified_only_meta();
    let marked = |text: &str| {
        let mut v = text_result(text);
        v["_context_integrity"] = json!({"classification": {"data_classes": ["personal_data"]}});
        v
    };
    let ((), staged) = meta
        .collecting_staged(async {
            for (tool, value) in [("x", marked(PROSE)), ("y", text_result(OTHER_PROSE))] {
                plan_step(None, async {
                    meta.stage_relay_receipt(RelayKey::new("alice", true), ("beta", tool), &value);
                })
                .await;
            }
            let answer = plan_answer(&json!({"x": marked(PROSE), "y": text_result(OTHER_PROSE)}));
            let delivered =
                plan_answer(&json!({"x": text_result(PROSE), "y": text_result(OTHER_PROSE)}));
            meta.restage_if_changed(
                meta.relay_snapshot(&answer),
                Some(&delivered),
                AnswerShape::Literal,
            );
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
            plan_step(None, async {
                meta.stage_relay_receipt(
                    RelayKey::new("alice", true),
                    ("alpha", "a"),
                    &text_result(PROSE),
                );
            })
            .await;
            let answer = plan_answer(&json!({"a": text_result(PROSE)}));
            let changed = plan_answer(&json!({"a": text_result(PROSE), "n": 1}));
            meta.restage_if_changed(
                meta.relay_snapshot(&answer),
                Some(&changed),
                AnswerShape::Literal,
            );
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
        plan_step(None, async {
            meta.stage_relay_receipt(
                RelayKey::new("alice", true),
                ("alpha", "a"),
                &text_result(PROSE),
            );
        })
        .await;
        let answer = plan_answer(&json!({"a": text_result(PROSE)}));
        let changed = plan_answer(&json!({"a": text_result(PROSE), "n": 1}));
        meta.restage_if_changed(
            meta.relay_snapshot(&answer),
            Some(&changed),
            AnswerShape::Literal,
        );
        meta.commit_staged_relay(true);
    })
    .await;
    carol_holds(&firewall, "a", PROSE);
    assert!(
        refused(&firewall, "alice", PROSE),
        "never kept, never committed"
    );
}

/// A leaf removed from the middle of a step splits its run: the neighbours'
/// own text keeps every fingerprint the source's run had over it, so the
/// same-source reader relaying a neighbour is never refused, whichever window
/// minima the split moves. Several texts, since minima depend on the key.
#[tokio::test]
async fn removing_a_middle_leaf_keeps_its_neighbours_whole() {
    for round in 0..8 {
        let (meta, firewall) = relay_meta();
        let (left, gone, right) = (
            filler(&format!("l{round}x"), 40),
            filler(&format!("g{round}x"), 40),
            filler(&format!("r{round}x"), 40),
        );
        let step = |middle: &str| json!({"rows": [left.as_str(), middle, right.as_str()]});
        let (answer, redacted) = (
            plan_answer(&json!({"a": step(&gone), "b": text_result(OTHER_PROSE)})),
            plan_answer(&json!({"a": step("[removed]"), "b": text_result(OTHER_PROSE)})),
        );
        let ((), staged) = meta
            .collecting_staged(async {
                for (tool, value) in [("a", step(&gone)), ("b", text_result(OTHER_PROSE))] {
                    plan_step(None, async {
                        meta.stage_relay_receipt(
                            RelayKey::new("alice", true),
                            ("alpha", tool),
                            &value,
                        );
                    })
                    .await;
                }
                meta.restage_if_changed(
                    meta.relay_snapshot(&answer),
                    Some(&redacted),
                    AnswerShape::Literal,
                );
                meta.rebuild_receipt_from_final(
                    Some(&redacted),
                    GatewayStamps::Legacy,
                    AnswerShape::Literal,
                );
            })
            .await;
        staged.commit(true);
        firewall.record_delivery(RelayCaller::Keyed("carol"), "alpha", "a", &step(&gone));

        assert!(
            refused(&firewall, "bob", &left),
            "control: bob holds no copy"
        );
        assert!(
            !refused(&firewall, "alice", &left),
            "round {round}: left was delivered"
        );
        assert!(
            !refused(&firewall, "alice", &right),
            "round {round}: right was delivered"
        );
        assert!(
            refused(&firewall, "alice", &gone),
            "round {round}: the middle was removed"
        );
    }
}

/// Short-field data: step B is a row of fields each shorter than a k-gram, so
/// its receipt lives only in its run across leaves. A change in A keeps it.
#[tokio::test]
async fn a_short_field_step_keeps_its_receipt_through_its_run() {
    let (meta, firewall) = relay_meta();
    let row = json!({"city": "Tampere", "street": "Hameenkatu 14", "zip": "33100",
                     "owner": "Aino Virtanen", "phone": "+358 40 555 0101",
                     "note": "gate code 4471, dog on premises", "due": "2026-11-02"});
    let a = format!("{PROSE} {SECRET}");
    let answer = plan_answer(&json!({"a": text_result(&a), "b": row}));
    let redacted = plan_answer(&json!({"a": text_result(PROSE), "b": row}));
    let ((), staged) = meta
        .collecting_staged(async {
            for (tool, value) in [("a", text_result(&a)), ("b", row.clone())] {
                plan_step(None, async {
                    meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", tool), &value);
                })
                .await;
            }
            meta.restage_if_changed(
                meta.relay_snapshot(&answer),
                Some(&redacted),
                AnswerShape::Literal,
            );
            meta.rebuild_receipt_from_final(
                Some(&redacted),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    staged.commit(true);
    firewall.record_delivery(RelayCaller::Keyed("carol"), "alpha", "b", &row);
    let relayed = |who: &str| {
        let params = json!({"name": "send", "arguments": row.clone()});
        !firewall
            .check_relay(
                RelayCaller::Keyed(who),
                "alpha",
                "send",
                &params,
                ("s", who),
            )
            .allowed
    };

    assert!(relayed("bob"), "control: bob holds no copy of the row");
    assert!(!relayed("alice"), "the row was delivered unchanged");
}

/// MIK-7994: a plan step's receipt is staged once and only kept later,
/// never rebuilt, so the continuation the gateway wrote into the step
/// must not take the cap's budget there: the end of the backend's prompt the
/// plan delivers stays receipted, whether the receipt is kept to the plan's
/// answer or recorded as staged (`commit_with`, capped where it is recorded).
#[tokio::test]
async fn a_plan_steps_continuation_never_takes_its_receipts_budget() {
    use crate::gateway::meta_mcp::invoke::gateway_writes::{Layer, note};
    for kept in [true, false] {
        let (meta, firewall) = relay_meta();
        let prompt = crate::gateway::meta_mcp::invoke::receipt_test_support::distinct_prose(4800);
        let step = json!({
            "resultType": "input_required",
            "inputRequests": { "confirm": {
                "method": "elicitation/create",
                "params": { "message": prompt, "requestedSchema": { "type": "object" } }
            }},
            "requestState": "e".repeat(4000)
        });
        let answer = plan_answer(&json!({"a": step}));
        let ((), staged) = meta
            .collecting_staged(async {
                plan_step(None, async {
                    note(Layer::Value, &["requestState"], &step);
                    meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "a"), &step);
                })
                .await;
                if kept {
                    meta.rebuild_receipt_from_final(
                        Some(&answer),
                        GatewayStamps::Legacy,
                        AnswerShape::Literal,
                    );
                }
            })
            .await;
        staged.commit(true);
        carol_holds(&firewall, "a", &prompt);

        let head: String = prompt.chars().take(400).collect();
        let tail: String = prompt.chars().skip(prompt.chars().count() - 400).collect();
        for text in [&head, &tail] {
            assert!(
                refused(&firewall, "bob", text),
                "control: bob holds no copy, so carol's makes his relay a match"
            );
        }
        assert!(
            !refused(&firewall, "alice", &head),
            "control: alice holds the prompt's head (kept = {kept})"
        );
        assert!(
            !refused(&firewall, "alice", &tail),
            "the continuation pushed the prompt's tail out (kept = {kept})"
        );
    }
}

/// MIK-7992: a playbook's output mapping delivers one member of a step whose
/// other members the backend padded. Sorted, the delivered member sits in the
/// middle of the step's leaves, past the receipt's head budget, and the caller
/// still got it: it stays receipted.
#[tokio::test]
async fn a_mapped_member_past_the_padding_stays_receipted() {
    let (meta, firewall) = relay_meta();
    let step = json!({"a": filler("pad", 600), "body": PROSE, "z": filler("tail", 600)});
    let answer = plan_answer(&json!({"summary": PROSE}));
    let ((), staged) = meta
        .collecting_staged(async {
            plan_step(None, async {
                meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "a"), &step);
            })
            .await;
            meta.rebuild_receipt_from_final(
                Some(&answer),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    staged.commit(true);
    carol_holds(&firewall, "a", PROSE);

    assert!(
        refused(&firewall, "bob", PROSE),
        "control: bob holds no copy"
    );
    assert!(
        !refused(&firewall, "alice", PROSE),
        "the padding pushed the mapped member out of the step's receipt"
    );
}

/// MIK-7992: the padding is copies of a leaf the plan also delivers, once.
/// Each copy matches the delivered leaf verbatim, but only one copy was
/// delivered: the others must not take the budget of the mapped member, so
/// an answer under the receipt cap is receipted whole.
#[tokio::test]
async fn copies_of_a_delivered_leaf_do_not_crowd_out_a_mapped_member() {
    let (meta, firewall) = relay_meta();
    let copy = filler("rep", 30);
    let copies = vec![copy.as_str(); 15];
    let step = json!({"a": copies, "body": PROSE, "z": copies});
    let answer = plan_answer(&json!({"summary": PROSE, "x": copy}));
    let ((), staged) = meta
        .collecting_staged(async {
            plan_step(None, async {
                meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "a"), &step);
            })
            .await;
            meta.rebuild_receipt_from_final(
                Some(&answer),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    staged.commit(true);
    carol_holds(&firewall, "a", PROSE);

    assert!(
        refused(&firewall, "bob", PROSE),
        "control: bob holds no copy"
    );
    assert!(
        !refused(&firewall, "alice", PROSE),
        "undelivered copies pushed the mapped member out of the step's receipt"
    );
}

/// Stage `step` as one plan step of alice's and commit it against `answer`.
async fn deliver_step(
    meta: &std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>,
    step: &Value,
    answer: &Value,
) {
    let ((), staged) = meta
        .collecting_staged(async {
            plan_step(None, async {
                meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "a"), step);
            })
            .await;
            meta.rebuild_receipt_from_final(
                Some(answer),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    staged.commit(true);
}

/// MIK-7992: two short fields the plan delivers next to each other, where
/// the step holds the first one twice with padding between. The caller got
/// them adjacent, so the run across them stays receipted.
#[tokio::test]
async fn short_fields_delivered_adjacent_keep_their_run() {
    let (meta, firewall) = relay_meta();
    let (p, s) = (
        "row 01: late pears on the north slope, crate 17",
        "row 02: grafting dates logged by Aino, frost 3x",
    );
    assert!(
        p.len() < 48 && s.len() < 48,
        "premise: each field under a k-gram"
    );
    let step = json!({"a": p, "b": filler("pad", 60), "c": p, "d": s});
    let delivered = json!({"x": p, "y": s});
    deliver_step(&meta, &step, &plan_answer(&delivered)).await;
    firewall.record_delivery(RelayCaller::Keyed("carol"), "alpha", "a", &delivered);

    assert!(
        relays_row(&firewall, "bob", &delivered),
        "control: bob holds no copy of the row"
    );
    assert!(
        !relays_row(&firewall, "alice", &delivered),
        "the row was delivered adjacent"
    );
}

/// Whether `who` sending `row` as a tool's arguments is refused as a relay.
fn relays_row(firewall: &Firewall, who: &str, row: &Value) -> bool {
    let params = json!({"name": "send", "arguments": row});
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

/// MIK-7992: a step's two short fields delivered with another step's field
/// between them. The run across them is the step's own; its fingerprints
/// stay, as before the deferred cap.
#[tokio::test]
async fn interleaved_short_fields_keep_their_step_run() {
    let (meta, firewall) = relay_meta();
    let (p, s) = (
        "the vineyard gate opens at six for the pickers",
        "dog on premises, ring twice at the side porch!",
    );
    assert!(
        p.len() < 48 && s.len() < 48,
        "premise: each field under a k-gram"
    );
    let row = json!({"a": p, "b": s});
    let answer = plan_answer(&json!({"x": p, "y": OTHER_PROSE, "z": s}));
    deliver_step(&meta, &row, &answer).await;
    firewall.record_delivery(RelayCaller::Keyed("carol"), "alpha", "a", &row);

    assert!(
        relays_row(&firewall, "bob", &row),
        "control: bob holds no copy of the row"
    );
    assert!(
        !relays_row(&firewall, "alice", &row),
        "another step's field between them split the step's run"
    );
}

/// MIK-7992: many undelivered copies of a delivered leaf, sorted before a
/// member the plan delivers redacted. The copies must not crowd the
/// member's surviving text out of the receipt's retained fingerprints.
#[tokio::test]
async fn copies_do_not_crowd_out_a_redacted_members_survivors() {
    let (meta, firewall) = relay_meta();
    let copy = filler("rep", 25);
    let step = json!({"a": vec![copy.as_str(); 800], "body": format!("{PROSE} {SECRET}")});
    let answer = plan_answer(&json!({"a": copy, "body": PROSE}));
    deliver_step(&meta, &step, &answer).await;
    carol_holds(&firewall, "a", PROSE);

    assert!(
        refused(&firewall, "bob", PROSE),
        "control: bob holds no copy"
    );
    assert!(
        !refused(&firewall, "alice", PROSE),
        "repeated copies crowded the delivered text out of the receipt"
    );
}

/// MIK-7992: the step holds its first short field twice, and the plan
/// delivers each field once with another step's field between them. The
/// step's own run across the two fields stays, as before the deferred cap.
#[tokio::test]
async fn a_repeated_field_keeps_its_step_run_when_interleaved() {
    let (meta, firewall) = relay_meta();
    let (p, s) = (
        "the vineyard gate opens at six for the pickers",
        "dog on premises, ring twice at the side porch!",
    );
    assert!(
        p.len() < 48 && s.len() < 48,
        "premise: each field under a k-gram"
    );
    let step = json!({"a": p, "b": filler("pad", 60), "c": p, "d": s});
    let answer = plan_answer(&json!({"x": p, "y": OTHER_PROSE, "z": s}));
    deliver_step(&meta, &step, &answer).await;
    let row = json!({"c": p, "d": s});
    firewall.record_delivery(RelayCaller::Keyed("carol"), "alpha", "a", &row);

    assert!(
        relays_row(&firewall, "bob", &row),
        "control: bob holds no copy of the row"
    );
    assert!(
        !relays_row(&firewall, "alice", &row),
        "counting the repeated field split the step's run"
    );
}

/// MIK-7992: the plan delivers a step's two short fields in the other order.
/// The run the caller received is the delivered one, and it is receipted.
#[tokio::test]
async fn short_fields_delivered_reordered_keep_the_delivered_run() {
    let (meta, firewall) = relay_meta();
    let (p, s) = (
        "the vineyard gate opens at six for the pickers",
        "dog on premises, ring twice at the side porch!",
    );
    assert!(
        p.len() < 48 && s.len() < 48,
        "premise: each field under a k-gram"
    );
    let delivered = json!({"x": p, "y": s});
    deliver_step(&meta, &json!({"a": s, "b": p}), &plan_answer(&delivered)).await;
    firewall.record_delivery(RelayCaller::Keyed("carol"), "alpha", "a", &delivered);

    assert!(
        relays_row(&firewall, "bob", &delivered),
        "control: bob holds no copy of the row"
    );
    assert!(
        !relays_row(&firewall, "alice", &delivered),
        "the receipt kept the step's order, not the delivered one"
    );
}
