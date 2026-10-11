// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` PR 2b (P3) gate rows: a plan answer over the 1 MiB bound is
//! read as a bounded fingerprint view, and one that cannot be read fails
//! closed (D6). Test plan: handoff/mutretro-8066-2b-testplan.md.

use serde_json::{Value, json};

use super::RelayCaller;
use super::big::{SOURCE, deliver, filler, firewall, refusal, relays, step_of};
use crate::security::firewall::collusion::CollusionDetector;
use crate::security::firewall::{Firewall, PlanStaging};

/// `caller`'s plan of `steps` on one shared staging, kept to one `answer`
/// and recorded, as `keep_plan_receipts` does. `false` when the answer was
/// not read at all (today: over the bound, every receipt dropped).
fn deliver_plan_for(fw: &Firewall, caller: &str, steps: &[Value], answer: &Value) -> bool {
    let staged = PlanStaging::default();
    staged.set_caller(caller);
    let digests: Vec<_> = steps
        .iter()
        .filter_map(|step| fw.receipt_digest("alpha", "read", step, Some(&staged)))
        .collect();
    let Some(delivered) = fw.delivered_for_plan(answer, Some(&staged)) else {
        return false;
    };
    for digest in digests {
        let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
        fw.record_digest(RelayCaller::Keyed(caller), "alpha", "read", &kept);
    }
    true
}

fn deliver_plan(fw: &Firewall, steps: &[Value], answer: &Value) -> bool {
    deliver_plan_for(fw, "alice", steps, answer)
}

/// Deferred filler steps that bring a plan's staging past the 1 MiB bound,
/// so the next step is capped at staging (a P1 step).
fn to_the_bound(seed: u64) -> Vec<Value> {
    (0..11)
        .map(|i| step_of(seed * 100 + i, 100 * 1024).1)
        .collect()
}

/// A 2,000-char run of `text` in `from..to`, picked under this run's key so
/// at least 4 of its sampled fingerprints survive thinning at m = 128: above
/// any record's rate here, so the run is evidence whatever the thinning.
fn pick_run<'t>(detector: &CollusionDetector, text: &'t str, from: usize, to: usize) -> &'t str {
    (from..to)
        .step_by(997)
        .map(|at| &text[at..at + 2_000])
        .find(|run| {
            detector
                .fingerprints(run)
                .iter()
                .filter(|&&fp| CollusionDetector::thinning_keeps(fp, 128))
                .count()
                >= 4
        })
        .expect("premise: a run whose fingerprints survive m = 128")
}

/// `MIK-8066` T6b (P3 + P1): a P1 step (staged past the plan bound, a
/// `BigStep`) delivered whole inside a 1.5 MiB answer. Its middle is evidence
/// and its holder is excused: the view reaches `BigStep::keep_to`.
#[test]
fn a_big_step_inside_an_answer_over_the_bound_is_excused_and_evidence() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (text, step) = step_of(901, 100 * 1024);
    let mut steps = to_the_bound(9);
    steps.push(step);
    let answer = json!({"whole": text, "pad": filler(902, 1_400 * 1024)});
    let _ = deliver_plan(&fw, &steps, &answer);
    let relayed = pick_run(detector, &text, 30_000, 70_000);
    assert!(
        relays(&fw, "bob", relayed),
        "the P1 step's middle in an over-bound answer was never receipted"
    );
    deliver(&fw, "carol", relayed);
    assert!(
        !relays(&fw, "alice", relayed),
        "the P1 step's holder was refused"
    );
}

/// `MIK-8066` T6c (D3): a deferred step whose first 3 KiB the over-bound
/// answer omits. A run from the omitted head is not excused (the view keeps
/// no text receipt); a delivered middle run is. Red at the base only at the
/// positive half: today both are refused because every receipt is dropped.
#[test]
fn an_omitted_head_is_not_excused_and_a_delivered_middle_is() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (text, step) = step_of(911, 300 * 1024);
    let answer = json!({"part": &text[3_072..], "pad": filler(912, 1_300 * 1024)});
    let _ = deliver_plan(&fw, &[step], &answer);
    let head = &text[400..2_400];
    deliver(&fw, "carol", head);
    let why = refusal(&fw, "alice", head).expect("the omitted head was excused");
    assert!(
        !why.contains("ran out of room"),
        "the omitted head was refused for lost room, not as a relay: {why}"
    );
    let middle = pick_run(detector, &text, 60_000, 200_000);
    // Alice's view-retained record is the only holder yet, so bob is
    // refused only if the delivered middle became evidence (D3).
    assert!(
        relays(&fw, "bob", middle),
        "the delivered middle was not evidence"
    );
    deliver(&fw, "carol", middle);
    assert!(
        !relays(&fw, "alice", middle),
        "a delivered middle run was refused"
    );
}

/// `MIK-8066` T6d (D3 third rule): a P1 step whose attachments were refused
/// at staging (no `BigStep`, excuse marked lost), kept to an over-bound
/// answer that delivers its head and omits its tail. The delivered head is
/// excused through the view; the omitted tail stays refused for lost room.
#[test]
fn a_capped_step_without_attachments_keeps_only_its_delivered_head() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let (text, step) = step_of(921, 100 * 1024);
    let mut steps = to_the_bound(92);
    steps.push(step);
    // Tiny caps refuse the step's attachments at staging; the answer is then
    // read under the production caps, so retention uses the view.
    detector.install_sketch_caps(64, 64);
    let staged = PlanStaging::default();
    staged.set_caller("alice");
    let digests: Vec<_> = steps
        .iter()
        .filter_map(|s| fw.receipt_digest("alpha", "read", s, Some(&staged)))
        .collect();
    detector.install_sketch_caps(32 * 1024 * 1024, 8 * 1024 * 1024);
    let answer = json!({"head": &text[..50_000], "pad": filler(922, 1_200 * 1024)});
    if let Some(delivered) = fw.delivered_for_plan(&answer, Some(&staged)) {
        for digest in digests {
            let kept = fw.cap_kept(fw.retain_delivered(digest, &delivered, None));
            fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &kept);
        }
    }
    let tail = &text[90_000..92_000];
    deliver(&fw, "carol", tail);
    let why = refusal(&fw, "alice", tail).expect("the omitted tail was excused");
    assert!(
        why.contains("ran out of room"),
        "the omitted tail's refusal did not name lost room: {why}"
    );
    let head = &text[500..2_500];
    deliver(&fw, "carol", head);
    assert!(
        !relays(&fw, "alice", head),
        "the delivered head of a capped step was refused"
    );
}

/// What sends an answer down the unread path (D6).
#[derive(Clone, Copy)]
enum Unreadable {
    /// The answer's text is past the answer text cap.
    TextCap,
    /// The answer's view would pass the entry cap A.
    EntryCap,
    /// `VIEW_BYTES` has no room for the view.
    NoRoom,
}

/// `MIK-8066` T23 (D6): a plan of a deferred step and a P1 step whose
/// over-bound answer cannot be read. Each step's middle is still evidence
/// (bob refused); the caller is refused for lost room, never excused; the
/// P1 step's reservation is abandoned and no sketch published. Today the
/// receipts are dropped and bob passes: fail-open.
fn an_unread_answer_fails_closed(why: Unreadable) {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    match why {
        Unreadable::TextCap => detector.set_answer_text_cap(512 * 1024),
        Unreadable::EntryCap => detector.set_view_entry_cap(16),
        Unreadable::NoRoom => detector.set_view_budget(64),
    }
    let (small, small_step) = step_of(931, 300 * 1024);
    let (big, big_step) = step_of(932, 100 * 1024);
    let mut steps = vec![small_step];
    steps.extend(to_the_bound(93));
    steps.push(big_step);
    let answer = json!({"a": small, "b": big, "pad": filler(933, 700 * 1024)});
    let _ = deliver_plan(&fw, &steps, &answer);
    for (text, from, to) in [(&small, 60_000, 200_000), (&big, 30_000, 70_000)] {
        let middle = pick_run(detector, text, from, to);
        assert!(
            relays(&fw, "bob", middle),
            "an unread plan's step middle was not evidence (fail-open)"
        );
        deliver(&fw, "carol", middle);
        let refused = refusal(&fw, "alice", middle).expect("the unread plan's caller was excused");
        assert!(
            refused.contains("ran out of room"),
            "the unread plan's caller was not refused for lost room: {refused}"
        );
    }
    match why {
        Unreadable::TextCap | Unreadable::EntryCap => {
            assert_eq!(
                detector.unread_plans(),
                1,
                "the unread plan was not counted"
            );
        }
        Unreadable::NoRoom => {
            assert_eq!(
                detector.view_budget_refusals(),
                1,
                "the refused view was not counted"
            );
        }
    }
    assert!(
        detector.sketch_positions(SOURCE, "alice").is_empty(),
        "an unread P1 step kept or published its sketch position"
    );
}

#[test]
fn an_answer_past_the_text_cap_fails_closed() {
    an_unread_answer_fails_closed(Unreadable::TextCap);
}

#[test]
fn an_answer_past_the_entry_cap_fails_closed() {
    an_unread_answer_fails_closed(Unreadable::EntryCap);
}

#[test]
fn an_answer_with_no_view_room_fails_closed() {
    an_unread_answer_fails_closed(Unreadable::NoRoom);
}

/// `MIK-8066` T23c (guard): unread plans' holders never count toward
/// `Common`. Nine unread plans of distinct callers carry one text that one
/// real recipient (carol) also holds; it stays evidence against bob. A build
/// counting unread holders as callers makes it common, and bob passes.
#[test]
fn unread_holders_never_make_text_common() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    detector.set_answer_text_cap(512 * 1024);
    let (text, step) = step_of(941, 300 * 1024);
    let answer = json!({"a": text, "pad": filler(942, 900 * 1024)});
    for i in 0..9 {
        let _ = deliver_plan_for(
            &fw,
            &format!("caller{i}"),
            std::slice::from_ref(&step),
            &answer,
        );
    }
    let run = pick_run(detector, &text, 60_000, 200_000);
    deliver(&fw, "carol", run);
    assert!(
        relays(&fw, "bob", run),
        "unread holders made the text common: bob passed"
    );
}

/// `MIK-8066` T19 (D2/D8): `VIEW_BYTES` admits views while it has room. A
/// build is charged its transient peak (growth, pre-dedup), a held view only
/// its entries. The budget is two held views plus the largest build peak of
/// the first three, each measured independently: the third build fits in
/// exactly the room left, the fourth does not. Four over-bound answers read
/// at once give three views and one unread answer; the three holders are
/// excused, the fourth is refused for lost room.
#[test]
fn views_are_admitted_while_the_view_budget_has_room() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let plans: Vec<(String, Value, Value)> = (0..4u64)
        .map(|i| {
            let (text, step) = step_of(951 + i, 300 * 1024);
            let answer = json!({"a": text, "pad": filler(961 + i, 900 * 1024)});
            (text, step, answer)
        })
        .collect();
    let peak = (0..3)
        .map(|i| detector.view_build_peak(&plans[i].2))
        .max()
        .expect("three plans");
    let held = detector.view_charge_of(&plans[0].2) + detector.view_charge_of(&plans[1].2);
    assert!(held > 0 && peak > 0, "the fixture views were not charged");
    detector.set_view_budget(held + peak);
    let callers: Vec<String> = (0..4).map(|i| format!("holder{i}")).collect();
    let staged: Vec<PlanStaging> = callers
        .iter()
        .map(|c| {
            let s = PlanStaging::default();
            s.set_caller(c);
            s
        })
        .collect();
    let digests: Vec<_> = plans
        .iter()
        .zip(&staged)
        .map(|((_, step, _), s)| fw.receipt_digest("alpha", "read", step, Some(s)))
        .collect();
    // Every answer is read before any is retained: four views at once.
    let delivered: Vec<_> = plans
        .iter()
        .zip(&staged)
        .map(|((_, _, answer), s)| fw.delivered_for_plan(answer, Some(s)))
        .collect();
    for (i, d) in delivered.iter().enumerate().take(3) {
        assert!(
            d.as_ref().is_some_and(super::super::Delivered::is_view),
            "answer {i} was not admitted as a view"
        );
    }
    assert!(
        delivered[3]
            .as_ref()
            .is_some_and(super::super::Delivered::is_unread),
        "the 4th answer, past the view budget, did not take D6"
    );
    for (i, (digest, d)) in digests.into_iter().zip(&delivered).enumerate() {
        if let (Some(digest), Some(d)) = (digest, d) {
            let kept = fw.cap_kept(fw.retain_delivered(digest, d, None));
            fw.record_digest(RelayCaller::Keyed(&callers[i]), "alpha", "read", &kept);
        }
    }
    drop(delivered);
    for (i, (text, _, _)) in plans.iter().enumerate() {
        let run = pick_run(detector, text, 60_000, 200_000);
        deliver(&fw, "carol", run);
        let refused = refusal(&fw, &callers[i], run);
        if i < 3 {
            assert!(refused.is_none(), "admitted holder {i} was refused");
        } else {
            let why = refused.expect("the unread plan's holder was excused");
            assert!(
                why.contains("ran out of room"),
                "the unread plan's holder was not refused for lost room: {why}"
            );
        }
    }
}

/// `MIK-8066` T20c (D2): a view's charge is held only while it lives. It is
/// positive while the answer is being judged, and back to its pre-plan value
/// once the view drops: for a plan dropped unretained and for one whose
/// answer omits the step.
#[test]
fn a_view_returns_its_charge_when_it_drops() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let before = detector.view_bytes();
    let (_, step) = step_of(971, 300 * 1024);
    let answer = json!({"other": filler(972, 1_200 * 1024)});
    // (a) Read, then dropped before any retention.
    {
        let staged = PlanStaging::default();
        staged.set_caller("alice");
        let delivered = fw.delivered_for_plan(&answer, Some(&staged));
        assert!(
            delivered.is_some() && detector.view_bytes() > before,
            "a live view held no charge"
        );
    }
    assert_eq!(
        detector.view_bytes(),
        before,
        "a dropped plan's view leaked its charge"
    );
    // (b) Retained against an answer that omits the step.
    let _ = deliver_plan(&fw, std::slice::from_ref(&step), &answer);
    assert_eq!(
        detector.view_bytes(),
        before,
        "an omitted plan's view leaked its charge"
    );
}

/// `MIK-8066` `evidence_charge_survives_abandon` (D9): a P1 step whose sketch
/// is abandoned (no headroom, so its selection overflows) keeps its
/// evidence's charge through a second retention until it is recorded, after
/// which the charge is zero.
#[test]
fn a_step_evidence_charge_survives_an_abandoned_sketch_until_recorded() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    detector.zero_headroom();
    let (text, step) = step_of(1041, 100 * 1024);
    let mut steps = to_the_bound(104);
    steps.push(step);
    let answer = json!({"whole": text, "pad": filler(1042, 900 * 1024)});
    let staged = PlanStaging::default();
    staged.set_caller("alice");
    let digests: Vec<_> = steps
        .iter()
        .filter_map(|s| fw.receipt_digest("alpha", "read", s, Some(&staged)))
        .collect();
    let delivered = fw.delivered_for_plan(&answer, Some(&staged));
    let mut kept = Vec::new();
    if let Some(delivered) = &delivered {
        for digest in digests {
            // Retained twice, as the rewritten route can.
            let once = fw.retain_delivered(digest, delivered, None);
            kept.push(fw.retain_delivered(once, delivered, None));
        }
    }
    assert!(
        detector.evidence_charge_bytes() > 0,
        "an abandoned sketch's step evidence lost its charge before record"
    );
    for digest in kept {
        let capped = fw.cap_kept(digest);
        fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &capped);
    }
    assert_eq!(
        detector.evidence_charge_bytes(),
        0,
        "recorded evidence kept its charge"
    );
}

/// A deferred step of 40 short leaves (32 chars each, under the k-gram), kept
/// to an over-bound answer that delivers them, retained `times` times
/// through the view, then recorded for alice. Returns the run bob relays:
/// 30 of the leaves run together, text only the leaves' joined forms hold.
fn short_leaf_step_kept_through_a_view(fw: &Firewall, times: usize) -> String {
    let leaves: Vec<String> = (0..40u64).map(|i| filler(1100 + i, 32)).collect();
    let step = json!({ "parts": leaves });
    let staged = PlanStaging::default();
    staged.set_caller("alice");
    let digest = fw
        .receipt_digest("alpha", "read", &step, Some(&staged))
        .expect("staged");
    let answer = json!({ "parts": leaves, "pad": filler(1150, 1_200 * 1024) });
    let delivered = fw
        .delivered_for_plan(&answer, Some(&staged))
        .expect("relay detection on");
    assert!(
        delivered.is_view(),
        "premise: the answer was read as a view"
    );
    let mut kept = digest;
    for _ in 0..times {
        kept = fw.retain_delivered(kept, &delivered, None);
    }
    let kept = fw.cap_kept(kept);
    fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &kept);
    leaves[5..35].concat()
}

/// `MIK-8066` 2b seat C1 (gpt): view retention keeps every form the leaves
/// path fingerprints, so a step of leaves shorter than a k-gram is still
/// evidence for its run-together text: bob is refused, alice excused.
#[test]
fn a_short_leaf_step_kept_through_a_view_is_evidence_for_its_joined_text() {
    let fw = firewall();
    let run = short_leaf_step_kept_through_a_view(&fw, 1);
    // Before anyone else holds the text, only alice's record can make bob's
    // relay of it one.
    assert!(
        relays(&fw, "bob", &run),
        "a short-leaf step's joined text was no evidence on a view"
    );
    deliver(&fw, "carol", &run);
    assert!(!relays(&fw, "alice", &run), "the step's holder was refused");
}

/// `MIK-8066` 2b seat C2 (gpt, muse): the rewritten route retains a receipt
/// twice. A second view retention keeps the first one's cut, so the
/// evidence and the excuse survive: bob refused, alice excused.
#[test]
fn a_second_view_retention_keeps_the_first_ones_cut() {
    let fw = firewall();
    let run = short_leaf_step_kept_through_a_view(&fw, 2);
    assert!(
        relays(&fw, "bob", &run),
        "a second view retention erased the evidence"
    );
    deliver(&fw, "carol", &run);
    assert!(
        !relays(&fw, "alice", &run),
        "a second view retention erased the excuse"
    );
}

/// `MIK-8066` A4: every caller's unread evidence is held by one shared
/// unread principal, so five callers' unread plans of one text add one
/// unread holder to its fingerprints, not five. Each caller is still marked
/// lost on its own.
#[test]
fn unread_plans_of_many_callers_share_one_unread_holder() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    detector.set_answer_text_cap(512 * 1024);
    let (text, step) = step_of(1201, 300 * 1024);
    let answer = json!({"a": text, "pad": filler(1202, 900 * 1024)});
    let callers: Vec<String> = (0..5).map(|i| format!("caller{i}")).collect();
    for caller in &callers {
        let _ = deliver_plan_for(&fw, caller, std::slice::from_ref(&step), &answer);
        assert!(
            detector.excuse_lost(SOURCE, caller),
            "premise: {caller}'s unread plan did not mark it lost"
        );
    }
    let fp = detector
        .fingerprints(&text)
        .into_iter()
        .find(|&fp| detector.tracks(fp))
        .expect("premise: the unread evidence was recorded");
    assert_eq!(
        detector.unread_holders_of(fp),
        1,
        "unread evidence was held per caller"
    );
}

/// `MIK-8066` 2b delta seat D3a (gpt): an unread receipt holds, from
/// retention to record, only what its record keeps: its fingerprints to the
/// per-delivery bound and its cut thinned into the room left (4,096 in all),
/// never the whole staged step's fingerprints.
#[test]
fn an_unread_receipt_holds_only_what_its_record_keeps() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    detector.set_answer_text_cap(512 * 1024);
    let (text, step) = step_of(1251, 900 * 1024);
    let staged = PlanStaging::default();
    staged.set_caller("alice");
    let digest = fw
        .receipt_digest("alpha", "read", &step, Some(&staged))
        .expect("staged");
    let answer = json!({"a": text, "pad": filler(1252, 900 * 1024)});
    let delivered = fw
        .delivered_for_plan(&answer, Some(&staged))
        .expect("relay detection on");
    assert!(delivered.is_unread(), "premise: the answer was unread");
    let kept = fw.retain_delivered(digest, &delivered, None);
    let held = kept.unread_receipt_len().expect("premise: judged unread");
    assert!(
        held <= 4 * 1_024,
        "an unread receipt held {held} fingerprints until record"
    );
}
