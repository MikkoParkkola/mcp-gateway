// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` PR 2b unit-level rows, run through the gate side so the view,
//! the budgets and the walks are reached as production reaches them. Test
//! plan: handoff/mutretro-8066-2b-testplan.md ("Unit rows").

use std::collections::HashSet;

use serde_json::{Value, json};

use super::big::{filler, firewall, step_of};
use crate::security::firewall::PlanStaging;
use crate::security::firewall::collusion::big::VIEW_BYTES;
use crate::security::firewall::collusion::{CollusionDetector, RelayParams};

/// `VIEW_BYTES` is a compile-time constant, never a configuration knob (lead
/// D8 condition 3): this line does not build if it stops being a `const`.
const _: usize = VIEW_BYTES;

/// Texts that stress the stream: multibyte characters, marks NFC composes
/// (`e` + U+0301), an unsafe control (U+202E), and whitespace runs.
fn corpus() -> Vec<String> {
    let base = filler(981, 4 * 1024);
    vec![
        base.clone(),
        format!("{base} añø ßü 漢字 {base}"),
        base.replace('e', "e\u{301}"),
        base.replace(' ', " \u{202e}"),
        base.replace(' ', "   \n\t  "),
    ]
}

/// `sampled_kgrams` (the streaming iterator, D2) equals `fingerprints` as a
/// set on the corpus, at the default rate and at one k-gram in one.
#[test]
fn sampled_kgrams_equal_fingerprints_at_both_rates() {
    for every in [false, true] {
        let mut detector = CollusionDetector::new(RelayParams::default());
        if every {
            detector.keep_every_kgram();
        }
        for text in corpus() {
            let expected: HashSet<u64> = detector.fingerprints(&text).into_iter().collect();
            assert!(!expected.is_empty(), "premise: the text has fingerprints");
            let streamed: HashSet<u64> = detector.sampled_kgrams(&text).into_iter().collect();
            assert_eq!(
                streamed, expected,
                "streaming sampled k-grams differ (every k-gram: {every})"
            );
        }
    }
}

/// An answer under the bound with leaves, an array and a nested key path, so
/// every join form is present.
fn joined_answer() -> Value {
    let texts = corpus();
    json!({"a": texts[0], "b": [texts[1], texts[2]], "c": {"d": texts[3], "e": texts[4]}})
}

/// The view of an answer equals the sampled subset of `Delivered::kgrams`
/// EXACTLY, across leaves and every join form, at both rates.
#[test]
fn the_view_equals_the_sampled_reference_at_both_rates() {
    let fw = firewall();
    let answer = joined_answer();
    let delivered = fw
        .delivered_for_plan(&answer, None)
        .expect("premise: the answer is under the bound");
    for every in [false, true] {
        let mut detector = CollusionDetector::new(RelayParams::default());
        if every {
            detector.keep_every_kgram();
        }
        let rate = detector.sample_rate();
        let reference: HashSet<u64> = delivered
            .kgrams(&detector)
            .iter()
            .copied()
            .filter(|h| h.is_multiple_of(rate))
            .collect();
        let view: HashSet<u64> = detector
            .view_of(&answer)
            .expect("the view was not built")
            .into_iter()
            .collect();
        assert_eq!(view, reference, "the view differs (every k-gram: {every})");
    }
}

/// A view of exactly A distinct hashes is admitted; A + 1 is refused.
#[test]
fn the_view_entry_cap_admits_a_and_refuses_a_plus_one() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let a = detector.view_entry_cap();
    assert!(
        detector.view_admits(a),
        "a view of exactly A entries was refused"
    );
    assert!(
        !detector.view_admits(a + 1),
        "a view of A + 1 entries was admitted"
    );
}

/// The measured charge of a maximum-size answer in each mode, and the
/// concurrency it leaves under `VIEW_BYTES` (lead D8 condition 2): a
/// <= 1 MiB answer of many short leaves (the multi-form worst case) and a
/// P3 answer near A entries.
#[test]
fn a_maximum_size_answer_is_charged_as_the_design_states() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let leaves: Vec<String> = (0..9_000u64)
        .map(|i| filler(990_000 + i, 48)[..48].to_owned())
        .collect();
    let leaves_answer = json!({ "items": leaves });
    let charge = detector.view_charge_of(&leaves_answer);
    assert!(
        (1 << 20..=6 << 20).contains(&charge),
        "a maximum-size <= 1 MiB answer charged {charge} B, outside the design's ~5 MiB"
    );
    assert!(
        VIEW_BYTES / charge >= 6,
        "VIEW_BYTES holds fewer than 6 maximum-size <= 1 MiB judgements ({charge} B each)"
    );
    let p3_answer = json!({"whole": filler(991, 3_900 * 1024)});
    let charge = detector.view_charge_of(&p3_answer);
    assert!(
        (6 << 20..=10 << 20).contains(&charge),
        "a maximum-size P3 view charged {charge} B, outside the design's ~8 MiB"
    );
    assert!(
        VIEW_BYTES / charge >= 3,
        "VIEW_BYTES holds fewer than 3 maximum-size P3 views ({charge} B each)"
    );
}

/// While a view is built, the reservation covers every live buffer at every
/// growth (both buffers during a reallocation) and at compaction, where the
/// charge is exact.
#[test]
fn a_view_build_never_runs_past_its_reservation() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let answer = json!({"whole": filler(1001, 1_500 * 1024)});
    let probes = detector.view_build_probe(&answer);
    assert!(
        !probes.is_empty() && probes.iter().all(|&(reserved, live)| reserved >= live),
        "a view build ran past its reservation: {probes:?}"
    );
    let &(reserved, live) = probes.last().expect("probes are not empty");
    assert_eq!(reserved, live, "the compacted view's charge is not exact");
}

/// Crafted answers past each preflight cap take the unread path without the
/// walks building a single reference list: too many nodes (an array of
/// numbers, so no text cap can decide it), too deep, and too much text.
#[test]
fn answers_past_the_walk_caps_are_unread_without_walking() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    // Numbers carry no text, so only the node cap can refuse this answer
    // (object keys would pass the text cap first).
    let many: Vec<Value> = (0..300_000).map(|i| json!(i)).collect();
    let mut deep = json!("leaf");
    for _ in 0..200 {
        deep = json!([deep]);
    }
    let long = json!({"whole": filler(1011, 5 * 1024 * 1024)});
    // Control: a readable answer is walked, so the counter can move.
    let before = detector.walk_refs_built();
    let _ = fw.delivered_for_plan(&json!({"a": "readable"}), None);
    assert!(
        detector.walk_refs_built() > before,
        "premise: a readable answer's walk was not counted"
    );
    for (name, answer) in [
        ("nodes", Value::Array(many)),
        ("depth", deep),
        ("text", long),
    ] {
        let built = detector.walk_refs_built();
        let delivered = fw.delivered_for_plan(&answer, None);
        assert!(
            delivered
                .as_ref()
                .is_some_and(super::super::Delivered::is_unread),
            "an answer past the {name} cap did not take the unread path"
        );
        assert_eq!(
            detector.walk_refs_built(),
            built,
            "an answer past the {name} cap was walked"
        );
    }
}

/// `keep_to` reserves its selection from `VIEW_BYTES` before collecting.
/// With room for the view but not the selection, the sketch is abandoned and
/// counted, the holder marked, and the step's evidence is still offered.
/// The budget is lowered once the view is built (a build is charged its
/// transient peak, a held view only its entries): what the view holds plus
/// 64 bytes, too little for any selection.
#[test]
fn a_selection_without_view_room_abandons_its_sketch_and_keeps_evidence() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (text, step) = step_of(1021, 100 * 1024);
    let answer = json!({"whole": text});
    let staged = PlanStaging::starting_at(1024 * 1024);
    staged.set_caller("alice");
    if let (Some(digest), Some(delivered)) = (
        fw.receipt_digest("alpha", "read", &step, Some(&staged)),
        fw.delivered_for_plan(&answer, Some(&staged)),
    ) {
        assert!(!delivered.is_unread(), "premise: the answer was read");
        detector.set_view_budget(detector.view_bytes() + 64);
        let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
        fw.record_digest(super::RelayCaller::Keyed("alice"), "alpha", "read", &kept);
    }
    assert_eq!(
        detector.selection_budget_refusals(),
        1,
        "a selection without view room was not refused and counted"
    );
}

/// The exact leaf hashes (D4) are charged to the plan's total, never its
/// baseline, so the capping switch is exactly 2a's (F3).
#[test]
fn leaf_hashes_are_charged_to_the_total_not_the_baseline() {
    let fw = firewall();
    let (_, step) = step_of(1031, 64 * 1024);
    let staged = PlanStaging::default();
    staged.set_caller("alice");
    fw.receipt_digest("alpha", "read", &step, Some(&staged))
        .expect("staged");
    assert!(
        staged.total() > staged.baseline(),
        "a step's leaf hashes were not charged to the plan total ({} / {})",
        staged.baseline(),
        staged.total()
    );
}

/// D8 condition 1: retention through the sampled view keeps exactly what
/// retention through the full unsampled set keeps, for plans whose steps the
/// answer delivers only in part (so the lookups decide what is kept). The
/// two sets differ on every unsampled k-gram, so a retention that ever looked
/// one up would keep something different.
#[test]
fn retention_through_the_view_keeps_what_the_full_set_keeps() {
    use super::super::Delivered;
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    for seed in 0..4u64 {
        let texts: Vec<String> = (0..4)
            .map(|i| filler(1100 + seed * 10 + i, 6 * 1024))
            .collect();
        let step = json!({ "content": texts[..3].to_vec() });
        let partial = texts[1][..3 * 1024].to_owned();
        let shown = [texts[0].clone(), partial, texts[3].clone()];
        let answer = Value::Array(shown.iter().cloned().map(Value::String).collect());
        let keep = |delivered: &Delivered<'_>| {
            let staged = PlanStaging::default();
            let digest = fw
                .receipt_digest("alpha", "read", &step, Some(&staged))
                .expect("staged");
            let kept = fw.cap_kept(fw.retain_delivered(digest, delivered, None));
            let mut fps = kept.fingerprints(detector);
            fps.sort_unstable();
            (fps, kept.staged_len(), kept.retained_len())
        };
        let by_view = fw
            .delivered_for_plan(&answer, None)
            .expect("under the bound");
        let leaves: Vec<&str> = shown.iter().map(String::as_str).collect();
        let by_set = Delivered::of_leaves(leaves).expect("under the bound");
        assert_eq!(
            keep(&by_view),
            keep(&by_set),
            "retention through the view differs from the full set (seed {seed})"
        );
    }
}

/// Each auxiliary reservation is charged before the build allocates: an
/// answer whose walk references do not fit takes the unread path and is
/// counted, and a long combining run shows in the build's first reservation.
#[test]
fn auxiliary_reservations_are_charged_first() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let many: Vec<Value> = (0..40_000).map(|i| json!(format!("leaf{i:05}"))).collect();
    let answer = Value::Array(many);
    detector.set_view_budget(40_000 * 32);
    let delivered = fw.delivered_for_plan(&answer, None);
    assert!(
        delivered
            .as_ref()
            .is_some_and(super::super::Delivered::is_unread),
        "an answer whose walk references do not fit was read"
    );
    assert_eq!(
        detector.view_budget_refusals(),
        1,
        "the refusal was not counted"
    );
    detector.set_view_budget(VIEW_BYTES);
    let marks = format!("a{}", "\u{301}".repeat(5_000));
    let probe = detector.view_build_probe(&json!({ "text": marks }));
    let &(reserved, _) = probe.first().expect("the build reserved");
    assert!(
        reserved >= 5_000 * 8,
        "a 5,000-mark combining run was not reserved ({reserved} B)"
    );
}

/// `MIK-8066` A2: `record_digest` takes the digest by reference, so "recorded
/// at most once" is a flag. A receipt past the per-delivery bound sketches
/// its truncated rest at record, one sketch per record; a second record of
/// the same digest adds no sketch (no evidence, no charge) and is counted.
/// The second call runs under `catch_unwind`, so the row holds in debug
/// builds (where it also asserts) and in release builds.
#[test]
fn a_second_record_of_one_digest_adds_nothing() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (_, step) = step_of(1051, 300 * 1024);
    let digest = fw
        .receipt_digest("alpha", "read", &step, None)
        .expect("a receipt");
    let caller = super::RelayCaller::Keyed("alice");
    fw.record_digest(caller, "alpha", "read", &digest);
    let once = detector.sketch_positions("alpha:read", "alice").len();
    assert_eq!(once, 1, "premise: the first record sketched its rest");
    let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fw.record_digest(caller, "alpha", "read", &digest);
    }));
    assert_eq!(
        again.is_err(),
        cfg!(debug_assertions),
        "a second record did not assert in a debug build"
    );
    assert_eq!(
        detector.sketch_positions("alpha:read", "alice").len(),
        once,
        "a second record of one digest added a sketch"
    );
    assert_eq!(
        detector.double_records(),
        1,
        "the second record was not counted"
    );
}

/// `MIK-8066` 2b seat H6 (gpt): the normalizer's combining buffer is sized
/// for runs that form across leaves (the run-together form joins them), not
/// only inside one string. 1,000 leaves that each start and end with 20
/// combining marks can meet in runs far past any one string's 20; the
/// build's first reservation covers the node charge plus every edge run.
#[test]
fn combining_runs_across_leaves_are_reserved() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let marks = "\u{301}".repeat(20);
    let leaves: Vec<Value> = (0..1_000)
        .map(|i| json!(format!("{marks}x{i}{marks}")))
        .collect();
    let probe = detector.view_build_probe(&Value::Array(leaves));
    let &(reserved, _) = probe.first().expect("the build reserved");
    let nodes = 1_001;
    let edge_marks = 1_000 * 40;
    assert!(
        reserved >= nodes * 64 + edge_marks * 8,
        "combining runs across leaves were not reserved ({reserved} B)"
    );
}
