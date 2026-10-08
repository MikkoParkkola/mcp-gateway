// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7992: a plan's steps stage whole only up to a bound on the text their
//! delivery has staged; later steps are capped as they are staged, and past
//! a hard bound their receipts are dropped and counted.

use super::{RelayKey, plan_step, relay_meta, text_result};

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

/// Past the plan bound a step's receipt is dropped and counted, so a plan of
/// many steps holds a bounded total even when each step is capped.
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
    let drops = firewall.relay_plan_drops();
    assert!(drops > 0, "the bound was reached");
    let kept = u64::try_from(staged.receipts.len()).expect("fits");
    assert_eq!(kept + drops, 30, "each step is kept or counted");
}
