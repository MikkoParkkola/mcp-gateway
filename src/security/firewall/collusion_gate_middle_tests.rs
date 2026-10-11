// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.CAP.2`: the middle of a cut delivery is evidence. A receipt
//! keeps the head and tail of a long delivery; a thinned sample of the rest
//! is recorded under the caller's own records, so a relay of the middle is
//! caught and the caller's own copy stays excused.
//!
//! These rows use production sampling (one k-gram in four kept): with every
//! k-gram kept, a cut receipt's head and tail alone pass the per-delivery
//! fingerprint bound and leave the middle no room. Each relayed run is
//! 1,000 chars of distinct k-grams (n = 953), so a miss needs fewer than 2
//! of 953 to survive: about 1e-117 at m = 1 and 2e-12 at m = 8 (B1′).

use std::fmt::Write;

use serde_json::json;

use super::{CollusionAction, CollusionConfig, RelayCaller};
use crate::security::firewall::collusion::CollusionDetector;
use crate::security::firewall::{Firewall, FirewallConfig, ScanType};

const SOURCE: &str = "alpha:read";

/// Relay detection on, observing, with production sampling.
fn firewall() -> Firewall {
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

/// Distinct filler prose of about `chars` characters: every 48-char window
/// differs, so a run of L chars has L - 47 distinct k-grams.
fn filler(seed: u64, chars: usize) -> String {
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

fn deliver(fw: &Firewall, who: &str, text: &str) {
    let result = json!({"content": [{"type": "text", "text": text}]});
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", "read", &result);
}

fn relays(fw: &Firewall, who: &str, text: &str) -> bool {
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

/// 1,000 chars of `text` from `at`, well inside its middle: past the head
/// and before the tail a receipt keeps (half of `RECORD_CAP` each).
fn middle_run(fw: &Firewall, text: &str, at: usize) -> String {
    let half = super::super::RECORD_CAP / 2;
    assert!(
        at > half && at + 1_000 < text.len() - half,
        "premise: inside the middle"
    );
    let run = text[at..at + 1_000].to_owned();
    let detector = fw.collusion_detector().expect("relay detection on");
    let mut kgrams = detector.kgram_hashes(&run);
    kgrams.sort_unstable();
    kgrams.dedup();
    assert_eq!(kgrams.len(), 953, "premise: distinct k-grams");
    run
}

/// `MIK-8066.CAP.2` M1: bob relays 1,000 chars from the middle of alice's
/// 12 KiB delivery. Its receipt was cut to head and tail; the whole middle
/// fits the room left (m = 1), so the run is evidence and bob is refused.
#[test]
fn the_middle_of_a_cut_delivery_is_evidence() {
    let fw = firewall();
    let text = filler(11, 12 * 1024);
    let run = middle_run(&fw, &text, 5_000);
    deliver(&fw, "alice", &text);
    assert_eq!(fw.relay_text_cuts(), 1, "premise: the receipt was cut");
    assert!(
        relays(&fw, "bob", &run),
        "the cut middle was never receipted"
    );
}

/// `MIK-8066.CAP.2` M2: alice relaying her own middle is not refused.
#[test]
fn a_holder_of_a_cut_delivery_relays_its_middle_unrefused() {
    let fw = firewall();
    let text = filler(11, 12 * 1024);
    let run = middle_run(&fw, &text, 5_000);
    deliver(&fw, "alice", &text);
    assert!(!relays(&fw, "alice", &run), "the holder was refused");
}

/// `MIK-8066.CAP.2` M3 (design r4 T2): carol and alice were delivered the
/// same 64 KiB text (m = 8 for both, the same sample). Alice's sketch is
/// then evicted for room. Her own sampled records still excuse her for
/// every match carol's records witness; bob is refused.
#[test]
fn an_evicted_sketch_leaves_the_holder_excused_for_its_sampled_middle() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let text = filler(13, 64 * 1024);
    let run = middle_run(&fw, &text, 30_000);
    deliver(&fw, "alice", &text);
    assert_eq!(
        detector.live_sketches(SOURCE, "alice"),
        1,
        "premise: sketched"
    );
    detector.cap_sketches_at_live_bytes();
    deliver(&fw, "carol", &text);
    assert_eq!(
        (
            detector.live_sketches(SOURCE, "alice"),
            detector.live_sketches(SOURCE, "carol")
        ),
        (0, 1),
        "premise: carol's sketch evicted alice's"
    );
    assert!(
        !relays(&fw, "alice", &run),
        "the holder was refused after eviction"
    );
    assert!(
        relays(&fw, "bob", &run),
        "the cut middle was never receipted"
    );
}

/// `MIK-8066.CAP.2` M4: a delivery whose sketch is refused for room still
/// records its middle sample: bob is refused, and alice is not.
#[test]
fn a_refused_sketch_still_records_the_middle_sample() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    detector.install_sketch_caps(64, 64);
    let text = filler(11, 12 * 1024);
    let run = middle_run(&fw, &text, 5_000);
    deliver(&fw, "alice", &text);
    assert_eq!(
        detector.sketches_refused(),
        1,
        "premise: the sketch was refused"
    );
    assert_eq!(
        detector.live_sketches(SOURCE, "alice"),
        0,
        "premise: no sketch"
    );
    assert!(
        relays(&fw, "bob", &run),
        "a refused sketch dropped the middle"
    );
    assert!(!relays(&fw, "alice", &run), "the holder was refused");
}

/// `MIK-8066.CAP.2` M6: a 64 KiB cut middle is thinned (m = 8) to the room
/// the receipt left: the delivery tracks at most the per-delivery bound and
/// truncates nothing.
#[test]
fn a_middle_sample_never_truncates_leaf_evidence() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    deliver(&fw, "alice", &filler(13, 64 * 1024));
    assert_eq!(
        detector.source_truncated(),
        0,
        "the sample truncated evidence"
    );
    let tracked = detector.tracked_fingerprints();
    assert!(
        tracked <= 4 * 1_024,
        "{tracked} fingerprints for one delivery"
    );
}

/// `MIK-8066.CAP.2` M7 (test plan A1), a guard on plan-path recording: a
/// plan step kept to its answer records the fingerprints the answer
/// delivered as retained ones (`DeliveryDigest::capped`, MIK-7992), and for
/// a short relay the middle sample cannot reliably catch, they are its only
/// witness.
///
/// The window is picked BEFORE the cap, from the digest retention kept, so
/// a mutant of `capped()` or of recording cannot change the pick: under
/// this process's key, the first 60-char window of the early middle, mid-word
/// at both ends, that has at least 2 fingerprints, all retained, and none the
/// middle sample keeps at any rate of 2 or more. Then:
/// - working code: recording keeps the head, the tail, then retained
///   fingerprints in text order up to the per-delivery bound (about 3 KiB to
///   13 KiB of a 64 KiB step), so the window is tracked and bob is refused;
/// - `capped()` dropping retained (mutant a8): the sample, at m = 8, keeps
///   none of the window, so bob is not refused, and the row fails at its own
///   assertion.
///
/// A window qualifies with about 8% probability and about 650 mid-word
/// starts are tried.
/// Residual: a partial loss of retained fingerprints that spares this window
/// is not detected here.
#[test]
fn a_kept_plan_steps_short_relay_is_caught_by_its_retained_fingerprints() {
    const PER_DELIVERY: usize = 4 * 1_024;
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let text = filler(17, 64 * 1024);
    let step = json!({"content": [{"type": "text", "text": text}]});
    let digest = fw
        .receipt_digest(
            "alpha",
            "read",
            &step,
            Some(&crate::security::firewall::PlanStaging::new()),
        )
        .expect("relay detection is on");
    let answer = json!({"whole": text});
    let delivered = fw
        .delivered_for_plan(&answer, None)
        .expect("under the bound");
    let retained = fw.retain_delivered(digest, &delivered, None);
    let held: std::collections::HashSet<u64> =
        retained.fingerprints(detector).into_iter().collect();
    // Recording keeps the head and tail (about RECORD_CAP / 4 sampled
    // fingerprints), then retained ones in text order up to the per-delivery
    // bound (`MAX_SOURCE_FINGERPRINTS`, 4,096): text up to about
    // half + 4 * (4,096 - RECORD_CAP / 4). Search three quarters of that.
    let cap = super::super::RECORD_CAP;
    let half = cap / 2;
    let cutoff = half + 3 * (PER_DELIVERY - cap / 4);
    let word = |i: usize| !text.as_bytes()[i].is_ascii_whitespace();
    let window = (half + 64..cutoff)
        .step_by(7)
        // Mid-word at both ends: a k-gram the egress forms across the
        // window's edge (a space or another field) is then in no step text.
        .filter(|&at| word(at - 1) && word(at) && word(at + 59) && word(at + 60))
        .map(|at| &text[at..at + 60])
        .find(|w| {
            let fps = detector.fingerprints(w);
            fps.len() >= 2
                && fps.iter().all(|fp| held.contains(fp))
                && !fps
                    .iter()
                    .any(|&fp| CollusionDetector::thinning_keeps(fp, 2))
        })
        .expect("a retained window no sample at m >= 2 keeps");
    let kept = fw.cap_kept(retained);
    fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &kept);
    assert!(
        relays(&fw, "bob", window),
        "a kept step's retained fingerprints were lost"
    );
    assert!(!relays(&fw, "alice", window), "the holder was refused");
}
