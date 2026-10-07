// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7992 unit cases: a plan step's receipt is staged whole and capped
//! once it is kept to the plan's answer, or where it is recorded.

use serde_json::json;

use super::super::super::collusion::{CollusionDetector, RelayParams};
use super::super::{Delivered, DeliveryDigest, RECORD_CAP, RelayCaller};
use super::{PROSE, egress, observing};

/// MIK-7992: a plan step is staged whole and capped later exactly as a
/// delivery is capped now: the same head, seam and tail, char boundaries
/// included, and capped once.
#[test]
fn a_plan_step_digest_is_capped_later_as_a_delivery_is_now() {
    let half = RECORD_CAP / 2;
    let text = format!(
        "{}{}{}",
        "a".repeat(half - 1),
        "\u{1D11E}".repeat(RECORD_CAP),
        "z"
    );
    let leaves = ["short leaf", text.as_str(), "last leaf"];
    let (staged, cut) = DeliveryDigest::of_plan_step_leaves(&leaves, false);
    assert!(!cut && staged.is_deferred(), "staged whole, cap deferred");
    assert_eq!(staged.segment_texts().len(), 3, "every leaf whole");
    let (capped, cut) = staged.capped().expect("the cap is deferred");
    assert!(cut && !capped.is_deferred());
    let (now, _) = DeliveryDigest::of_leaves(&leaves, false);
    assert_eq!(capped.segment_texts(), now.segment_texts());
    assert!(capped.capped().is_none(), "a capped digest is capped once");
    let empty = vec![""; 1 << 16];
    let (many, _) = DeliveryDigest::of_plan_step_leaves(&empty, false);
    assert!(!many.is_deferred(), "each leaf costs a segment: capped now");
    let over = Delivered::of_leaves(empty);
    assert!(over.is_none(), "each delivered leaf costs a segment too");
}

/// MIK-7992: a plan step's digest recorded without being kept to its plan's
/// answer is capped where it is recorded: the cut is counted and the middle
/// of an over-cap text is not recorded, as for any other delivery.
#[test]
fn a_deferred_digest_is_capped_where_it_is_recorded() {
    let (fw, _dir) = observing(|_| {});
    let pad = |tag: &str| {
        (0..700)
            .map(|i| format!("{tag}{i:05}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let step = json!({"a": pad("head"), "body": PROSE, "z": pad("tail")});
    let digest = fw
        .plan_step_digest("alpha", "read", &step)
        .expect("relay detection is on");
    assert_eq!(fw.relay_text_cuts(), 0, "premise: staged whole");
    fw.record_digest(RelayCaller::Keyed("carol"), "alpha", "read", &digest);

    assert_eq!(fw.relay_text_cuts(), 1, "the cap applied at the sink");
    assert!(
        egress(&fw, RelayCaller::Keyed("bob")).findings.is_empty(),
        "the dropped middle was recorded"
    );
}

/// MIK-7992: a plan step kept to its answer can retain more fingerprints
/// than its text would record; the deferred cap bounds them too.
#[test]
fn a_capped_plan_step_retains_at_most_the_cap_of_fingerprints() {
    let detector = CollusionDetector::new(RelayParams::default());
    let text = (0..25_000)
        .map(|i| format!("w{i:06}"))
        .collect::<Vec<_>>()
        .join(" ");
    let answer = format!("{text} as delivered");
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&[&text], false);
    let delivered = Delivered::of_leaves(vec![answer.as_str()]).expect("under the bound");
    let kept = staged.retaining(&detector, &delivered);
    assert!(
        kept.retained_len() > RECORD_CAP,
        "premise: retention alone passes the cap"
    );
    let (capped, cut) = kept.capped().expect("the cap is deferred");
    assert!(cut, "the truncation counts as a cut");
    assert_eq!(capped.retained_len(), RECORD_CAP);
}

/// MIK-7992: repeats of a changed leaf retain the same fingerprints; once
/// each, so the count cap keeps a later leaf's.
#[test]
fn repeated_changed_leaves_do_not_crowd_out_a_later_leafs_fingerprints() {
    let detector = CollusionDetector::new(RelayParams::default());
    let words = |tag: &str, n: usize| (0..n).map(|i| format!("{tag}{i:05}")).collect::<Vec<_>>();
    let (copy, last) = (words("rep", 25).join(" "), PROSE.to_owned());
    let mut leaves = vec![copy.as_str(); 400];
    leaves.push(last.as_str());
    let (copy_sent, last_sent) = (format!("{copy} sent"), format!("{last} sent"));
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&leaves, false);
    let delivered = Delivered::of_leaves(vec![copy_sent.as_str(), last_sent.as_str()])
        .expect("under the bound");
    let (capped, _) = staged
        .retaining(&detector, &delivered)
        .capped()
        .expect("deferred");
    let kept: std::collections::HashSet<u64> = capped.fingerprints(&detector).into_iter().collect();
    assert!(
        detector
            .fingerprints(&last)
            .iter()
            .all(|fp| kept.contains(fp))
    );
}
