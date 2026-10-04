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
