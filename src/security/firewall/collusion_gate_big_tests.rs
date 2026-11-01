// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.BIG.3` and the EXCUSE.1 remainder: plan steps and answers past
//! the 1 MiB plan bound. A step staged once its plan holds the bound (P1),
//! a step over the bound (P2) and an answer over the bound (P3) keep no
//! sketch and no evidence today. Design r5.1 keeps exact and Bloom
//! fingerprint state for them in place of text.
//!
//! Production sampling (one k-gram in four); every relayed run is 2,000
//! chars of distinct k-grams (n = 1,953), so even at m = 16 a miss needs
//! fewer than 2 of 1,953 to survive (about 1e-12).

use std::fmt::Write;

use serde_json::{Value, json};

use super::{CollusionAction, CollusionConfig, RelayCaller};
use crate::security::firewall::{Firewall, FirewallConfig, ScanType};

/// Relay detection on, observing, with production sampling.
pub(super) fn firewall() -> Firewall {
    let config = FirewallConfig {
        collusion: CollusionConfig {
            action: CollusionAction::Observe,
            sources: vec!["alpha:*".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    Firewall::from_config(config, None)
}

/// Distinct filler prose of about `chars` characters.
pub(super) fn filler(seed: u64, chars: usize) -> String {
    let mut out = String::new();
    let mut i = seed;
    while out.len() < chars {
        i = i
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let _ = write!(out, "row{:x} ", i >> 40);
    }
    out
}

pub(super) fn deliver(fw: &Firewall, who: &str, text: &str) {
    let result = json!({"content": [{"type": "text", "text": text}]});
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", "read", &result);
}

pub(super) fn relays(fw: &Firewall, who: &str, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    fw.check_relay(
        RelayCaller::Keyed(who),
        "beta",
        "send",
        &params,
        ("direct:beta", who),
    )
    .findings
    .iter()
    .any(|f| f.scan_type == ScanType::CollusionRelay)
}

/// 2,000 chars of `text` from `at`.
pub(super) fn run(text: &str, at: usize) -> &str {
    &text[at..at + 2_000]
}

/// A 2,000-char run of `text` in `from..to`, picked under this run's key so
/// at least 4 of its sampled fingerprints survive thinning at m = 128: above
/// any record's rate here, so the run is evidence whatever the thinning.
pub(super) fn pick_run<'t>(
    detector: &crate::security::firewall::collusion::CollusionDetector,
    text: &'t str,
    from: usize,
    to: usize,
) -> &'t str {
    (from..to)
        .step_by(997)
        .map(|at| &text[at..at + 2_000])
        .find(|run| {
            detector
                .fingerprints(run)
                .iter()
                .filter(|&&fp| {
                    crate::security::firewall::collusion::CollusionDetector::thinning_keeps(fp, 128)
                })
                .count()
                >= 4
        })
        .expect("premise: a run whose fingerprints survive m = 128")
}

/// Alice's plan step `step`, staged with `staged` already held by her plan,
/// kept to `answer` and recorded, as a plan's delivery does. `false` when
/// the answer was over the bound and the receipt was dropped.
fn deliver_step(fw: &Firewall, step: &Value, staged: usize, answer: &Value) -> bool {
    let staged = crate::security::firewall::PlanStaging::starting_at(staged);
    staged.set_caller("alice");
    let Some(digest) = fw.receipt_digest("alpha", "read", step, Some(&staged)) else {
        return false;
    };
    let Some(delivered) = fw.delivered_for_plan(answer, Some(&staged)) else {
        return false;
    };
    let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
    fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &kept);
    true
}

/// `MIK-8066` T4b (P1): a 100 KiB step staged once its plan already holds
/// the 1 MiB bound, delivered whole by the answer. Its middle is evidence
/// against bob, and its holder alice is excused against carol's copy.
#[test]
fn a_step_staged_past_the_plan_bound_is_excused_and_evidence() {
    let fw = firewall();
    let text = filler(41, 100 * 1024);
    let relayed = run(&text, 40_000);
    let step = json!({"content": [{"type": "text", "text": text}]});
    let answer = json!({"whole": text});
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        deliver_step(&fw, &step, bound, &answer),
        "premise: the answer is under the bound"
    );
    assert!(
        relays(&fw, "bob", relayed),
        "the P1 step's middle was never receipted"
    );
    deliver(&fw, "carol", relayed);
    assert!(
        !relays(&fw, "alice", relayed),
        "the P1 step's holder was refused"
    );
}

/// `MIK-8066` T7 (guard): a P1 step the answer leaves out was never
/// received, so it is neither excused nor evidence.
#[test]
fn a_step_staged_past_the_plan_bound_and_omitted_is_neither() {
    let fw = firewall();
    let text = filler(43, 100 * 1024);
    let relayed = run(&text, 40_000);
    let step = json!({"content": [{"type": "text", "text": text}]});
    let answer = json!({"other": filler(44, 50 * 1024)});
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        deliver_step(&fw, &step, bound, &answer),
        "premise: under the bound"
    );
    assert!(!relays(&fw, "bob", relayed), "omitted text became evidence");
    deliver(&fw, "carol", relayed);
    assert!(relays(&fw, "alice", relayed), "omitted text was excused");
}

/// `MIK-8066` T4 (P2): one step over the bound (12 leaves of 100 KiB),
/// capped at staging; the answer delivers three of its leaves whole. The
/// middle of a delivered leaf is evidence, and alice is excused for it.
#[test]
fn a_step_over_the_plan_bound_is_excused_and_evidence_for_what_it_delivered() {
    let fw = firewall();
    let leaves: Vec<String> = (0..12).map(|i| filler(100 + i, 100 * 1024)).collect();
    let relayed = run(&leaves[4], 40_000).to_owned();
    let step = json!({ "parts": leaves });
    let answer = json!({"a": leaves[3], "b": leaves[4], "c": leaves[5]});
    assert!(
        deliver_step(&fw, &step, 0, &answer),
        "premise: the answer is under the bound"
    );
    assert!(
        relays(&fw, "bob", &relayed),
        "the P2 step's delivered middle was never receipted"
    );
    deliver(&fw, "carol", &relayed);
    assert!(
        !relays(&fw, "alice", &relayed),
        "the P2 step's holder was refused"
    );
}

/// `MIK-8066` T6 (P3): a 900 KiB step staged whole, delivered inside an
/// answer of 1.6 MiB. Today the over-bound answer drops every step receipt.
/// After BIG.3 the answer is read as a bounded fingerprint view: the step's
/// middle is evidence and its holder is excused.
#[test]
fn a_step_inside_an_answer_over_the_bound_is_excused_and_evidence() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let text = filler(51, 900 * 1024);
    // A fixed slice this deep can lose every fingerprint to keyed thinning.
    let relayed = pick_run(detector, &text, 300_000, 600_000);
    let step = json!({"content": [{"type": "text", "text": text}]});
    let answer = json!({"whole": text, "pad": filler(52, 700 * 1024)});
    assert!(
        deliver_step(&fw, &step, 0, &answer),
        "an answer over the bound dropped its step receipts"
    );
    assert!(
        relays(&fw, "bob", relayed),
        "the step's middle was never receipted"
    );
    deliver(&fw, "carol", relayed);
    assert!(
        !relays(&fw, "alice", relayed),
        "the step's holder was refused"
    );
}

/// `MIK-8066` T6, the join form (S3b): a step's labelled parts, each under
/// the 48-char k-gram, delivered inside an over-bound answer. Alice
/// forwarding the parts run together (the per-key-path join, MIK-8209) is
/// excused against carol's whole copy of that join.
#[test]
fn a_rejoined_step_inside_an_answer_over_the_bound_is_excused() {
    let fw = firewall();
    let parts: Vec<String> = (0..10)
        .map(|i| filler(60 + i, 40)[..40].to_owned())
        .collect();
    let items: Vec<Value> = parts
        .iter()
        .map(|p| json!({"kind": "chunk", "part": p}))
        .collect();
    let step = json!({ "items": items });
    let answer = json!({"items": items, "pad": filler(70, 1_200 * 1024)});
    let joined: String = parts.concat();
    assert!(
        deliver_step(&fw, &step, 0, &answer),
        "an answer over the bound dropped its step receipts"
    );
    deliver(&fw, "carol", &joined);
    assert!(
        relays(&fw, "bob", &joined),
        "control: bob without a copy is a relay"
    );
    assert!(
        !relays(&fw, "alice", &joined),
        "the re-joined parts were refused"
    );
}

pub(super) const SOURCE: &str = "alpha:read";

/// A plan step of `chars` of `seed` filler, as one content item.
pub(super) fn step_of(seed: u64, chars: usize) -> (String, Value) {
    let text = filler(seed, chars);
    let step = json!({"content": [{"type": "text", "text": text}]});
    (text, step)
}

/// `MIK-8066` T17 spot check (end to end, lead ruling): a 13 KiB P1 step
/// delivered whole stages every sampled fingerprint (m = 1), and its
/// middle's evidence fits `record_held_at`'s room (4,096 less the receipt's
/// fingerprints), so the record keeps it all: every middle window with at
/// least 2 sampled fingerprints is evidence against bob. A record that
/// thins against a smaller room (mutant "record room halved") drops some.
/// This is what sees `record_held_at` drift from the selector T17 calls.
#[test]
fn a_big_steps_staged_evidence_that_fits_the_room_is_recorded_whole() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (text, step) = step_of(701, 13 * 1024);
    let answer = json!({"whole": text});
    assert!(
        deliver_step(&fw, &step, super::super::DELIVERED_SET_CAP, &answer),
        "premise: under the bound"
    );
    let word = |i: usize| !text.as_bytes()[i].is_ascii_whitespace();
    let windows: Vec<&str> = (4 * 1024..9 * 1024)
        .step_by(7)
        .filter(|&at| word(at - 1) && word(at) && word(at + 59) && word(at + 60))
        .map(|at| &text[at..at + 60])
        .filter(|w| detector.fingerprints(w).len() >= 2)
        .collect();
    assert!(
        windows.len() >= 100,
        "premise: middle windows with 2+ sampled fingerprints ({})",
        windows.len()
    );
    let passed = windows.iter().filter(|w| !relays(&fw, "bob", w)).count();
    assert_eq!(
        passed,
        0,
        "{passed} of {} middle windows were never recorded",
        windows.len()
    );
}

/// `MIK-8066` T13 (F1): four same-source P1 steps of one plan, all staged
/// before any retention, reserve four distinct sketch positions for their
/// caller at staging. Peeking at the free positions without reserving
/// (mutant `f1_peek_without_reserve`) gives all four the same one.
#[test]
fn same_source_steps_of_one_plan_hold_distinct_positions() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let staged =
        crate::security::firewall::PlanStaging::starting_at(super::super::DELIVERED_SET_CAP);
    staged.set_caller("alice");
    // Held: a dropped receipt abandons its reservation.
    let held: Vec<_> = (0..4)
        .map(|seed| {
            let (text, step) = step_of(200 + seed, 100 * 1024);
            let digest = fw
                .receipt_digest("alpha", "read", &step, Some(&staged))
                .expect("staged");
            (text, digest)
        })
        .collect();
    let mut positions = detector.sketch_positions(SOURCE, "alice");
    positions.sort_unstable();
    assert_eq!(
        positions,
        vec![0, 1, 2, 3],
        "four distinct pending positions"
    );
    // Each step is kept to an answer of its text beside 800 KiB of foreign
    // text, so its sketch carries the foreign text's chance matches too.
    for (seed, (text, digest)) in (0u64..).zip(held) {
        let answer = json!({"whole": text, "foreign": filler(300 + seed, 800 * 1024)});
        let delivered = fw
            .delivered_for_plan(&answer, Some(&staged))
            .expect("premise: the answer is under the bound");
        let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
        fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &kept);
    }
    let mut live = detector.live_sketch_positions(SOURCE, "alice");
    live.sort_unstable();
    assert_eq!(
        live,
        vec![0, 1, 2, 3],
        "premise: all four sketches are live before measuring"
    );
    // B3': a stranger's sampled fingerprint is excused by the pair's live
    // sketches at under 3·P0. One-sided exact band: at a rate of 3·P0
    // (P0 = 0.0035), P(Bin(200,000, 0.0105) <= 1,886) = 9.6e-7. The design
    // rate is about P0 (some 656 expected).
    let sample = detector.sample_rate();
    let mut s = 0x8066_B163_0000_0013u64;
    let excused = (0..200_000)
        .filter(|_| {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            let h = z ^ (z >> 31);
            detector.sketch_holds(SOURCE, "alice", h - h % sample)
        })
        .count();
    assert!(
        excused > 0,
        "premise: the steps' sketches were published ({excused})"
    );
    assert!(
        excused <= 1_886,
        "{excused} of 200,000 strangers excused: the pair's rate reaches 3·P0"
    );
}

/// Alice's 64 KiB P1 step delivered whole inside 900 KiB of foreign text
/// (the answer stays under the bound). Returns the step's text.
fn deliver_step_beside_foreign_text(fw: &Firewall) -> String {
    let (text, step) = step_of(301, 64 * 1024);
    let answer = json!({"whole": text, "pad": filler(302, 900 * 1024)});
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        deliver_step(fw, &step, bound, &answer),
        "premise: under the bound"
    );
    text
}

/// `MIK-8066` T22 (H rule): the foreign text's Bloom false positives push the
/// step's selection past its own count n, and the headroom absorbs them: the
/// sketch is kept and its holder excused. Abandoning at n (no headroom)
/// would strip an honest holder.
#[test]
fn a_step_delivered_whole_beside_foreign_text_keeps_its_sketch() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let text = deliver_step_beside_foreign_text(&fw);
    let (selected, own) = detector
        .last_selection(SOURCE, "alice")
        .expect("a retention selection was recorded");
    assert!(
        selected > own,
        "premise: false positives passed n ({selected} <= {own})"
    );
    assert_eq!(detector.overfull_sketches(), 0, "the sketch was abandoned");
    assert!(
        !detector.sketch_positions(SOURCE, "alice").is_empty(),
        "no sketch kept"
    );
    let relayed = run(&text, 30_000);
    deliver(&fw, "carol", relayed);
    assert!(
        relays(&fw, "bob", relayed),
        "control: bob without a copy is a relay"
    );
    assert!(!relays(&fw, "alice", relayed), "the holder was refused");
}

/// `MIK-8066` T21: with no headroom the same selection passes n + H, so the
/// sketch is abandoned, counted and marked: the holder's refusal names lost
/// room, never a plain relay.
#[test]
fn an_overfull_selection_abandons_the_sketch() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    detector.zero_headroom();
    deliver_step_beside_foreign_text(&fw);
    let (selected, own) = detector
        .last_selection(SOURCE, "alice")
        .expect("a retention selection was recorded");
    assert!(
        selected > own,
        "premise: false positives passed n ({selected} <= {own})"
    );
    assert_eq!(
        detector.overfull_sketches(),
        1,
        "the overfull sketch was not abandoned"
    );
    assert!(
        detector.sketch_positions(SOURCE, "alice").is_empty(),
        "an overfull sketch was kept"
    );
    assert!(
        detector.excuse_lost(SOURCE, "alice"),
        "the lost excuse was not marked"
    );
}

/// The description of `who`'s relay refusal for `text`, if refused.
pub(super) fn refusal(fw: &Firewall, who: &str, text: &str) -> Option<String> {
    let params = json!({"name": "send", "arguments": {"text": text}});
    fw.check_relay(
        RelayCaller::Keyed(who),
        "beta",
        "send",
        &params,
        ("direct:beta", who),
    )
    .findings
    .into_iter()
    .find(|f| f.scan_type == ScanType::CollusionRelay)
    .map(|f| f.description)
}

/// A P2 step: 11 leaves of 100 KiB, over the bound on its own.
/// Distinct value leaves in each [`oversized_step`].
const STEP_LEAVES: u64 = 11;

fn oversized_step(seed: u64) -> Value {
    let leaves: Vec<String> = (0..STEP_LEAVES)
        .map(|i| filler(seed * 100 + i, 100 * 1024))
        .collect();
    json!({ "parts": leaves })
}

/// `MIK-8066` T12 (F3): two P2 steps whose attachments pass 1 MiB while
/// their capped receipts stay small. A later 100 KiB step is staged whole
/// and kept to its answer exactly as the release line keeps it: the same
/// staged length, retained count and fingerprints as a plan with no
/// attachments. Letting attachments drive the capping switch (mutant
/// `f3_shared_counter`) caps it.
#[test]
fn a_big_step_never_caps_a_later_small_step() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let staged = crate::security::firewall::PlanStaging::default();
    staged.set_caller("alice");
    for seed in [7, 8] {
        fw.receipt_digest("alpha", "read", &oversized_step(seed), Some(&staged))
            .expect("staged");
    }
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        staged.baseline() < bound && bound < staged.total(),
        "premise: attachments passed the bound, receipts did not ({} / {})",
        staged.baseline(),
        staged.total()
    );
    let (text, small) = step_of(9, 100 * 1024);
    let answer = json!({"whole": text});
    let keep = |plan: &crate::security::firewall::PlanStaging| {
        let digest = fw.receipt_digest("alpha", "read", &small, Some(plan))?;
        let deferred = digest.is_deferred();
        let delivered = fw.delivered_for_plan(&answer, Some(plan))?;
        let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
        Some((
            deferred,
            kept.staged_len(),
            kept.retained_len(),
            kept.fingerprints(detector),
        ))
    };
    let release_line = crate::security::firewall::PlanStaging::default();
    release_line.set_caller("bob");
    let expected = keep(&release_line).expect("premise: the release line keeps it");
    assert!(expected.0, "premise: the release line stages it whole");
    assert_eq!(
        keep(&staged),
        Some(expected),
        "a later small step was staged differently"
    );
}

/// A P1 step staged for alice, its reservation held by the returned
/// receipt; the store's bytes before staging.
fn stage_p1(fw: &Firewall, seed: u64) -> (crate::security::firewall::DeliveryDigest, usize) {
    let detector = fw.collusion_detector().expect("relay detection on");
    let before = detector.sketch_bytes_held();
    let staged =
        crate::security::firewall::PlanStaging::starting_at(super::super::DELIVERED_SET_CAP);
    staged.set_caller("alice");
    let digest = fw
        .receipt_digest("alpha", "read", &step_of(seed, 100 * 1024).1, Some(&staged))
        .expect("staged");
    assert!(
        detector.sketch_bytes_held() > before,
        "premise: the step reserved room at staging"
    );
    (digest, before)
}

/// `MIK-8066` T20a: a step dropped before retention (its plan went over a
/// bound, or the delivery was dropped) abandons its pending reservation.
#[test]
fn a_dropped_steps_reservation_is_released() {
    let fw = firewall();
    let (digest, before) = stage_p1(&fw, 401);
    drop(digest);
    let held = fw.collusion_detector().expect("on").sketch_bytes_held();
    assert_eq!(held, before, "a dropped step's reservation leaked");
}

/// `MIK-8066` T20b: a step kept to an answer that delivered nothing of it
/// (an answer with no k-gram at all, so not even a chance Bloom match: with
/// any foreign text, chance matches publish a small sketch inside the B3'
/// budget) publishes nothing, and its reservation is abandoned.
#[test]
fn an_omitted_steps_reservation_is_released() {
    let fw = firewall();
    let (digest, before) = stage_p1(&fw, 402);
    let answer = json!({"other": "ok"});
    let delivered = fw
        .delivered_for_plan(&answer, None)
        .expect("under the bound");
    let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
    fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &kept);
    drop(kept);
    let held = fw.collusion_detector().expect("on").sketch_bytes_held();
    assert_eq!(held, before, "an omitted step's reservation leaked");
}

/// `MIK-8066` T18 (F5): a step whose attachments find no room is skipped,
/// counted and marked, so its holder's refusal names lost room, not a relay.
#[test]
fn a_step_whose_attachments_never_fit_marks_its_excuse_lost() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    detector.install_sketch_caps(64, 64);
    let (text, step) = step_of(501, 100 * 1024);
    let answer = json!({"whole": text});
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        deliver_step(&fw, &step, bound, &answer),
        "premise: under the bound"
    );
    assert!(
        detector.excuse_lost(SOURCE, "alice"),
        "the skipped excuse was not marked"
    );
    let relayed = run(&text, 40_000);
    deliver(&fw, "carol", relayed);
    assert!(
        relays(&fw, "bob", relayed),
        "control: bob without a copy is a relay"
    );
    let why = refusal(&fw, "alice", relayed).expect("premise: alice is refused");
    assert!(
        why.contains("ran out of room"),
        "the refusal did not name lost room: {why}"
    );
}

/// `MIK-8066` T16 (F2): a 512 KiB P1 step stages its evidence thinned
/// (m >= 2: about 131k sampled fingerprints against the 32,768 budget). The
/// answer delivers only a 60-char extract, picked under this run's key,
/// mid-word at both ends, whose fingerprints no thinning at m >= 2 keeps, so
/// the staged evidence and the answer share nothing. Alice relaying it is
/// still excused, by the Bloom-selected sketch. Skipping the sketch when the
/// evidence intersection is empty (mutant `f2_skip_on_empty_evidence`)
/// refuses her.
#[test]
fn a_short_extract_of_a_big_step_the_sample_missed_is_still_excused() {
    use crate::security::firewall::collusion::CollusionDetector;
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (text, step) = step_of(601, 512 * 1024);
    let word = |i: usize| !text.as_bytes()[i].is_ascii_whitespace();
    let window = (10_000..400_000)
        .step_by(7)
        .filter(|&at| word(at - 1) && word(at) && word(at + 59) && word(at + 60))
        .map(|at| &text[at..at + 60])
        .find(|w| {
            let fps = detector.fingerprints(w);
            fps.len() >= 2
                && !fps
                    .iter()
                    .any(|&fp| CollusionDetector::thinning_keeps(fp, 2))
        })
        .expect("an extract no thinning at m >= 2 keeps")
        .to_owned();
    let answer = json!({"extract": window});
    let bound = super::super::DELIVERED_SET_CAP;
    assert!(
        deliver_step(&fw, &step, bound, &answer),
        "premise: under the bound"
    );
    // No exact record holds any of the extract's sampled fingerprints (not
    // even one, below the relay threshold): alice's excuse can only be the
    // sketch.
    assert!(
        !detector
            .fingerprints(&window)
            .iter()
            .any(|&fp| detector.tracks(fp)),
        "premise: the staged evidence holds none of the extract"
    );
    deliver(&fw, "carol", &window);
    assert!(
        relays(&fw, "bob", &window),
        "control: bob without a copy is a relay"
    );
    assert!(
        !relays(&fw, "alice", &window),
        "a delivered extract was refused"
    );
}

#[path = "collusion_gate_big_admit_tests.rs"]
mod admit;
