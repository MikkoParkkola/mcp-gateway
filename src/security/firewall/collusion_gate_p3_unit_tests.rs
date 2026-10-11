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
/// walks building a single reference list: too many nodes (short keys), too
/// deep, and too much text.
#[test]
fn answers_past_the_walk_caps_are_unread_without_walking() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let many: serde_json::Map<String, Value> = (0..300_000)
        .map(|i| (format!("k{i}"), Value::Null))
        .collect();
    let mut deep = json!("leaf");
    for _ in 0..200 {
        deep = json!([deep]);
    }
    let long = json!({"whole": filler(1011, 5 * 1024 * 1024)});
    for (name, answer) in [
        ("nodes", Value::Object(many)),
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
#[test]
fn a_selection_without_view_room_abandons_its_sketch_and_keeps_evidence() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (text, step) = step_of(1021, 100 * 1024);
    let answer = json!({"whole": text});
    detector.set_view_budget(detector.view_charge_of(&answer) + 64);
    let staged = PlanStaging::starting_at(1024 * 1024);
    staged.set_caller("alice");
    if let (Some(digest), Some(delivered)) = (
        fw.receipt_digest("alpha", "read", &step, Some(&staged)),
        fw.delivered_for_plan(&answer, Some(&staged)),
    ) {
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
