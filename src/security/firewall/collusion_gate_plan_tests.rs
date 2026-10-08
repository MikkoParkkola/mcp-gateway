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
        .receipt_digest("alpha", "read", &step, Some(&std::cell::Cell::new(0)))
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

/// MIK-7992 with MIK-7773: a step's split copy keeps its run-together
/// fingerprints when the answer puts another leaf after the first piece,
/// as only the step's own run still joins the pieces there.
#[test]
fn a_split_step_keeps_its_run_together_form_across_an_interleaved_leaf() {
    let detector = CollusionDetector::new(RelayParams::default());
    let (flat, pieces) = super::split_copy(60);
    let leaves: Vec<&str> = pieces.iter().map(String::as_str).collect();
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&leaves, false);
    let mut shown = vec![leaves[0], "a note another step put between them"];
    shown.extend(&leaves[1..]);
    let delivered = Delivered::of_leaves(shown).expect("bounded");
    let kept: std::collections::HashSet<u64> = staged
        .retaining(&detector, &delivered)
        .fingerprints(&detector)
        .into_iter()
        .collect();
    let flat_fps = detector.fingerprints(&flat);
    assert!(
        flat_fps.iter().all(|fp| kept.contains(fp)),
        "flat form kept"
    );
}

/// `MIK-7887.RECEIPT.2`: removing a middle leaf splits its run, and the
/// neighbours re-winnowed can select other minima. Every fingerprint of the
/// original run whose k-gram is still delivered, inside one leaf or across
/// adjacent kept short fields, is kept, and no other: none of the removed
/// text, none across a seam.
#[test]
fn a_split_run_keeps_exactly_its_original_delivered_fingerprints() {
    use std::collections::HashSet;

    use super::super::DeliveryDigest as D;
    let detector = CollusionDetector::new(RelayParams::default());
    let fields = |tag: &str| (0..12).map(|i| format!("{tag} f{i}")).collect::<Vec<_>>();
    let (mut moved, mut moved_together) = (false, false);
    let ofs = [D::of_leaves, D::of_plan_step_leaves];
    for round in 0..40 {
        let (left, right) = (fields(&format!("l{round}")), fields(&format!("r{round}")));
        let gone = format!("removed paragraph {round} ").repeat(8);
        let mut leaves: Vec<&str> = left.iter().map(String::as_str).collect();
        leaves.push(&gone);
        leaves.extend(right.iter().map(String::as_str));
        let (digest, _) = ofs[round % 2](&leaves, false);
        let original = digest.fingerprints(&detector);
        let mut shown: Vec<&str> = left.iter().map(String::as_str).collect();
        shown.extend(right.iter().map(String::as_str));
        let delivered = Delivered::of_leaves(shown.clone()).expect("bounded");
        let kept: HashSet<u64> = digest
            .retaining(&detector, &delivered)
            .fingerprints(&detector)
            .into_iter()
            .collect();
        // Each kept run in both forms, newline-joined and run together. A
        // deferred receipt keeps leaves in delivered order (MIK-7992), so its
        // run is the answer's: left beside right, as the caller received it.
        let mut forms = vec![
            left.join("\n"),
            left.concat(),
            right.join("\n"),
            right.concat(),
        ];
        if round % 2 == 1 {
            forms.extend([shown.join("\n"), shown.concat()]);
        }
        let allowed: HashSet<u64> = forms
            .iter()
            .flat_map(|run| detector.kgram_hashes(run))
            .collect();
        let alone: HashSet<u64> = forms
            .iter()
            .flat_map(|run| detector.fingerprints(run))
            .collect();
        // The run-together forms' k-grams that no newline form carries.
        let newline: HashSet<u64> = forms
            .iter()
            .step_by(2)
            .flat_map(|run| detector.kgram_hashes(run))
            .collect();
        let together: HashSet<u64> = forms
            .iter()
            .skip(1)
            .step_by(2)
            .flat_map(|run| detector.kgram_hashes(run))
            .filter(|k| !newline.contains(k))
            .collect();
        for fp in &original {
            assert_eq!(kept.contains(fp), allowed.contains(fp), "round {round}");
            moved |= allowed.contains(fp) && !alone.contains(fp);
            moved_together |= together.contains(fp) && !alone.contains(fp);
        }
        assert!(
            kept.iter().all(|fp| allowed.contains(fp)),
            "round {round}: kept text never delivered"
        );
    }
    assert!(moved, "premise: a split moved some minimum");
    assert!(
        moved_together,
        "premise: a split moved a run-together minimum"
    );
}

/// MIK-7992 with MIK-7773: kinds survive deferred retention and the cap, so
/// a kept step's key is never run together with its values.
#[test]
fn a_kept_and_capped_step_never_runs_a_value_into_its_key() {
    let detector = CollusionDetector::new(RelayParams::default());
    let words = |tag: &str| (0..20).map(|i| format!("{tag}{i:03}")).collect::<Vec<_>>();
    let (a, b, k) = (
        words("a").join(" "),
        words("b").join(" "),
        words("k").join(" "),
    );
    let parts = [a.as_str(), b.as_str(), k.as_str()];
    let (staged, _) = DeliveryDigest::of_plan_step_parts(&parts, 2, false);
    let delivered = Delivered::of_parts(parts.to_vec(), 2).expect("bounded");
    let (capped, _) = staged
        .retaining(&detector, &delivered)
        .capped()
        .expect("deferred");
    let allowed: std::collections::HashSet<u64> = [parts.join("\n"), format!("{a}{b}")]
        .iter()
        .flat_map(|t| detector.kgram_hashes(t))
        .collect();
    let joined = detector.fingerprints(&format!("{a}{b}{k}"));
    assert!(
        joined.iter().any(|fp| !allowed.contains(fp)),
        "premise: a value run into the key adds fingerprints"
    );
    let kept = capped.fingerprints(&detector);
    assert!(kept.iter().all(|fp| allowed.contains(fp)), "key kept apart");
}

/// MIK-7992: a deferred receipt kept to an answer that repeats one of its
/// leaves holds no more than it staged, so retention cannot grow a plan's
/// receipts past what its staging bound counted.
#[test]
fn a_kept_receipt_holds_no_more_than_its_step_staged() {
    let detector = CollusionDetector::new(RelayParams::default());
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&["", "the step's other leaf"], false);
    let before = staged.staged_len();
    let delivered = Delivered::of_leaves(vec![""; 20_000]).expect("bounded");
    let kept = staged.retaining(&detector, &delivered);
    assert!(
        kept.staged_len() <= before,
        "copies past the step's size kept"
    );
}
