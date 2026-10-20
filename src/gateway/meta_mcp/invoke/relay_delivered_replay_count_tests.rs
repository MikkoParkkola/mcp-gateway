// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8408 G50 (final review round): `keep_replayed_receipts` counts each
//! replayed receipt it drops, once per receipt, whatever the delivery
//! shares between them. Pins the counting the per-delivery hoist must keep.

use serde_json::json;

use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

use super::super::{Kind, Receipt};
use super::keep_replayed_receipts;

fn observing() -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
    .keeping_every_kgram()
}

/// A receipt of `kind` for alpha's `text`, under plan label `step`.
fn receipt(fw: &Firewall, kind: Kind, text: &str, step: Option<u32>) -> Receipt {
    let digest = fw
        .receipt_digest("alpha", "read", &json!({ "text": text }), None)
        .expect("a sensitive delivery stages a digest: fixture");
    Receipt {
        key: "key-a".to_string(),
        keyed: true,
        server: "alpha".to_string(),
        tool: "read".to_string(),
        digest,
        in_plan: false,
        pending_retain: true,
        step,
        kind,
    }
}

const TEXTS: [&str; 3] = [
    "The orchard ledger for the north slope records seven rows of late pears.",
    "Minutes of the harbour committee: the dredging contract moves to spring.",
    "The ferry timetable keeps its Sunday gap until the pilot boat is mended.",
];

/// Three replayed receipts and one live one.
fn mixed(fw: &Firewall) -> Vec<Receipt> {
    let mut receipts: Vec<Receipt> = TEXTS
        .iter()
        .zip(0..)
        .map(|(text, step)| receipt(fw, Kind::Replayed, text, Some(step)))
        .collect();
    receipts.push(receipt(fw, Kind::Delivered, "a live delivery", None));
    receipts
}

/// G50: over the bound a receipt is kept against, every replayed receipt is
/// dropped and counted `over_bound` once each (3), the live receipt is left
/// alone, and nothing is counted `filtered`. Under the bound, against a
/// changed answer (no stored digest: not identical), receipts without
/// excuse sets are kept and nothing is counted. Mutants killed: skip the
/// `over_bound` count (0); count once per delivery (1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g50_each_dropped_replayed_receipt_is_counted_once() {
    let fw = observing();
    let over = json!({ "texts": TEXTS, "pad": "pad ".repeat(1_200 * 1024 / 4 + 1) });
    let mut receipts = mixed(&fw);
    let ((), over_bound) = crate::gateway::count_plan_replay_skipped("over_bound", async {
        keep_replayed_receipts(&fw, &mut receipts, &over);
    });
    assert_eq!(
        over_bound, 3,
        "each dropped replayed receipt is counted over_bound once"
    );
    assert!(
        receipts.len() == 1 && receipts[0].kind == Kind::Delivered,
        "only the live receipt survives an over-bound answer"
    );

    let under = json!({ "texts": TEXTS });
    let mut receipts = mixed(&fw);
    let ((), filtered) = crate::gateway::count_plan_replay_skipped("filtered", async {
        keep_replayed_receipts(&fw, &mut receipts, &under);
    });
    assert_eq!(filtered, 0, "a receipt with no excuse sets drops nothing");
    assert_eq!(receipts.len(), 4, "every receipt is kept under the bound");
    assert!(
        receipts
            .iter()
            .filter(|r| r.kind == Kind::Replayed)
            .all(|r| !r.pending_retain),
        "each replayed receipt was kept to the answer"
    );
    let ((), over_bound) = crate::gateway::count_plan_replay_skipped("over_bound", async {
        keep_replayed_receipts(&fw, &mut mixed(&fw), &under);
    });
    assert_eq!(over_bound, 0, "nothing is over the bound under it");
}
