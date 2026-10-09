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

/// `MIK-7887.RECEIPT.2`: removing a middle leaf splits its run. Every
/// fingerprint of the original run whose k-gram is still delivered, inside one
/// leaf or across adjacent kept short fields, is kept, and no other: none of
/// the removed text, none across a seam.
#[test]
fn a_split_run_keeps_exactly_its_original_delivered_fingerprints() {
    use std::collections::HashSet;

    use super::super::DeliveryDigest as D;
    let detector = CollusionDetector::new(RelayParams::default());
    let fields = |tag: &str| (0..12).map(|i| format!("{tag} f{i}")).collect::<Vec<_>>();
    let (mut kept_any, mut kept_together) = (false, false);
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
        // The answer's own values forms are delivered text too (`MIK-8209`
        // K3), so a k-gram the answer carries across left and right is
        // delivered whichever receipt shape kept the leaves.
        let forms = [
            left.join("\n"),
            left.concat(),
            right.join("\n"),
            right.concat(),
            shown.join("\n"),
            shown.concat(),
        ];
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
            // Context-free selection (MIK-8083): a delivered k-gram is a
            // fingerprint of its kept run as well.
            assert_eq!(allowed.contains(fp), alone.contains(fp), "round {round}");
            kept_any |= kept.contains(fp);
            kept_together |= together.contains(fp) && kept.contains(fp);
        }
        assert!(
            kept.iter().all(|fp| allowed.contains(fp)),
            "round {round}: kept text never delivered"
        );
    }
    assert!(kept_any, "premise: something delivered was kept");
    assert!(
        kept_together,
        "premise: a fingerprint only the run-together form carries was kept"
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

/// `MIK-8043.JOIN.4`: a rewritten wrapper of many short fields whose fields
/// together are over the bound is still read as its whole text, as before the
/// fields were read; no drop is counted while that reading fits.
#[test]
fn a_reading_over_the_bound_falls_back_to_the_whole_text() {
    let (fw, _dir) = observing(|_| {});
    let fields: Vec<serde_json::Value> = (0..40_000).map(|i| json!(format!("f{i:04}"))).collect();
    let answer = serde_json::Value::Array(fields.clone());
    let flat = json!(
        fields
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert!(
        fw.delivered_for_plan(&answer, None).is_none(),
        "premise: field by field is over the bound"
    );
    let drops = fw.relay_plan_drops();
    assert!(fw.delivered_preferring(&answer, &flat, None).is_some());
    assert_eq!(fw.relay_plan_drops(), drops, "no drop while the text fits");
}

/// `MIK-8209` K7: two steps each staged a shared `kind` and their own piece;
/// the answer repeats `kind`. Kept to its own span first, each step keeps its
/// own piece whole. Without labels K8 keeps it too: `chunk` is kept at most
/// once, as staged, so the earlier step's copy cannot spend the later
/// step's room (before K8 it did, and the piece was lost).
#[test]
fn a_repeated_leaf_from_another_step_never_crowds_out_a_steps_own_piece() {
    let detector = CollusionDetector::new(RelayParams::default());
    let (a, b) = ("piece of step zero", "piece of step one");
    let shown = vec!["chunk", a, "chunk", b];
    let labels = vec![Some(0), Some(0), Some(1), Some(1)];
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&["chunk", b], false);
    let unlabelled = Delivered::of_leaves(shown.clone()).expect("bounded");
    let kept = staged.retaining(&detector, &unlabelled);
    assert!(
        kept.whole_values().any(|v| v == b),
        "K8: an unlabelled copy crowded out the piece"
    );
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&["chunk", b], false);
    let labelled = Delivered::of_leaves(shown)
        .expect("bounded")
        .with_labels(labels);
    let kept = staged.retaining_for(&detector, &labelled, Some(1));
    assert!(kept.whole_values().any(|v| v == b), "own piece lost");
}

/// `MIK-8209` K7 keeps the MIK-7992 cap: a step's own long leaf after many
/// copies of its short staged leaf from another step stays whole, and the
/// kept receipt stages no more than before.
#[test]
fn own_span_first_keeps_the_staging_cap() {
    let detector = CollusionDetector::new(RelayParams::default());
    let long = "the long leaf this step delivered, well past one k-gram in length";
    let mut shown = vec!["x"; 50];
    let mut labels = vec![Some(0); 50];
    shown.extend(["x", long]);
    labels.extend([Some(1), Some(1)]);
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&["x", long], false);
    let before = staged.staged_len();
    let delivered = Delivered::of_leaves(shown)
        .expect("bounded")
        .with_labels(labels);
    let kept = staged.retaining_for(&detector, &delivered, Some(1));
    let whole: Vec<&str> = kept.whole_values().collect();
    assert!(whole.contains(&long), "own long leaf lost");
    assert!(kept.staged_len() <= before, "retention grew the receipt");
}

/// `MIK-8209` K7 with duplicates in the step's own span: the room is still
/// what the step staged, so the receipt never grows. (Copies inside one span
/// are still kept in answer order while room lasts, as MIK-7992 keeps them.)
#[test]
fn duplicates_in_a_steps_own_span_never_grow_its_receipt() {
    let detector = CollusionDetector::new(RelayParams::default());
    let long = "the long leaf this step delivered, well past one k-gram in length";
    let shown = vec!["x", "x", "x", long];
    let labels = vec![Some(1); 4];
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&["x", long], false);
    let before = staged.staged_len();
    let delivered = Delivered::of_leaves(shown)
        .expect("bounded")
        .with_labels(labels);
    let kept = staged.retaining_for(&detector, &delivered, Some(1));
    assert!(kept.staged_len() <= before, "retention grew the receipt");
}

/// `MIK-8251` DUP.1 (red, out of this PR): a step repeating a short leaf
/// within its own span still keeps its later long piece whole, so the seam
/// pass can own it. Today the extra copies spend the room first.
#[test]
#[ignore = "MIK-8251: copies within a step's own span spend its room first"]
fn a_repeated_leaf_in_a_steps_own_span_keeps_its_later_piece_whole() {
    let detector = CollusionDetector::new(RelayParams::default());
    let long = "the long leaf this step delivered, well past one k-gram in length";
    let (staged, _) = DeliveryDigest::of_plan_step_leaves(&["x", long], false);
    let delivered = Delivered::of_leaves(vec!["x", "x", "x", long])
        .expect("bounded")
        .with_labels(vec![Some(1); 4]);
    let kept = staged.retaining_for(&detector, &delivered, Some(1));
    assert!(
        kept.whole_values().any(|v| v == long),
        "own long piece lost"
    );
}

/// `MIK-8209` K3 keeps the delivered-set bound unchanged: the joins are
/// hashed, never charged to it, so a 600 KiB answer still keeps its plan
/// receipts.
#[test]
fn a_large_answer_keeps_its_receipts_under_the_unchanged_bound() {
    let leaf = "z".repeat(1_000);
    let answer = vec![leaf.as_str(); 600];
    assert!(Delivered::of_leaves(answer).is_some(), "the bound shrank");
}

/// `MIK-8209` Q2, gpt's input: three steps each staged `{part: p, x: "x"}`;
/// each step's span of the answer repeats `x` twenty times before `part`.
/// Each step must keep its own `part` whole (the seam pass owns it only then).
/// K8: a chain reaches it through late redaction (route row
/// `late_redaction_copies_keep_the_cross_step_join`).
#[test]
fn twenty_repeats_before_part_keep_each_steps_part_whole() {
    let detector = CollusionDetector::new(RelayParams::default());
    let parts = ["a".repeat(32), "b".repeat(32), "c".repeat(32)];
    let (mut shown, mut labels) = (Vec::new(), Vec::new());
    for (step, part) in parts.iter().enumerate() {
        let label = u32::try_from(step).ok();
        shown.extend(std::iter::repeat_n("x", 20));
        labels.extend(std::iter::repeat_n(label, 20));
        shown.push(part.as_str());
        labels.push(label);
    }
    for (step, part) in parts.iter().enumerate() {
        let (staged, _) = DeliveryDigest::of_plan_step_leaves(&[part.as_str(), "x"], false);
        let delivered = Delivered::of_leaves(shown.clone())
            .expect("bounded")
            .with_labels(labels.clone());
        let kept = staged.retaining_for(&detector, &delivered, u32::try_from(step).ok());
        assert!(
            kept.whole_values().any(|v| v == part),
            "step {step} lost its part"
        );
    }
}
