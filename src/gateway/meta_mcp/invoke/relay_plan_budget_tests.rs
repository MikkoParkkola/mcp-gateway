// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7992: a plan's steps stage whole only up to a bound on the text their
//! delivery has staged; later steps are capped as they are staged, and past
//! a hard bound their receipts are dropped and counted.

use super::{AnswerShape, GatewayStamps, RelayKey, plan_step, relay_meta, text_result};

/// Three steps of about 600 KB each: the first two stage whole, the third
/// finds 1.2 MB already staged and is capped now, a cut counted at staging.
#[tokio::test]
async fn a_plan_stages_a_bounded_total_before_capping_its_steps() {
    let (meta, firewall) = relay_meta();
    let big = |tag: &str| {
        (0..75_000)
            .map(|i| format!("{tag}{i:06}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let steps = [big("a"), big("b"), big("c")];
    let ((), _staged) = meta
        .collecting_staged(async {
            for text in &steps {
                plan_step(async {
                    let who = RelayKey::new("alice", true);
                    meta.stage_relay_receipt(who, ("alpha", "read"), &text_result(text));
                })
                .await;
            }
        })
        .await;
    assert_eq!(
        firewall.relay_text_cuts(),
        1,
        "only the step past the bound"
    );
}

/// Past the plan bound a step's receipt is dropped, so a plan of many steps
/// holds a bounded total even when each step is capped; the plan is counted
/// once, however many steps it drops (`MIK-8094.DROPMETRIC.1`).
#[tokio::test]
async fn a_plan_past_its_staging_bound_drops_and_counts_receipts() {
    let (meta, firewall) = relay_meta();
    let empties = serde_json::json!({ "content": vec![""; 10_000] });
    let ((), staged) = meta
        .collecting_staged(async {
            for _ in 0..30 {
                plan_step(async {
                    let who = RelayKey::new("alice", true);
                    meta.stage_relay_receipt(who, ("alpha", "read"), &empties);
                })
                .await;
            }
        })
        .await;
    assert!(staged.receipts.len() < 29, "premise: several steps dropped");
    assert_eq!(firewall.relay_plan_drops(), 1, "one plan, counted once");
}

/// A plan dropped at staging whose answer is then over the bound its receipts
/// are kept against is still one plan, counted once (`MIK-8094.DROPMETRIC.2`).
#[tokio::test]
async fn a_plan_over_both_bounds_is_counted_once() {
    let (meta, firewall) = relay_meta();
    let empties = serde_json::json!({ "content": vec![""; 10_000] });
    let answer = text_result(&"x".repeat(2 * 1024 * 1024));
    let ((), staged) = meta
        .collecting_staged(async {
            for _ in 0..30 {
                plan_step(async {
                    let who = RelayKey::new("alice", true);
                    meta.stage_relay_receipt(who, ("alpha", "read"), &empties);
                })
                .await;
            }
            meta.rebuild_receipt_from_final(
                Some(&answer),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    assert!(
        staged.receipts.iter().all(|r| !r.in_plan),
        "premise: the answer bound dropped the plan's receipts"
    );
    assert_eq!(firewall.relay_plan_drops(), 1, "one plan, counted once");
}
