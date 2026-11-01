// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Overflow keeps its source (ADR-029, amended, item 5): a sensitive record
//! past a caller's cap is held as `(source, inferred)`, so a reload that
//! changes the lists or the flows is applied to it, and a caller whose
//! overflow no longer fits is unattributed and fails closed.
//!
//! Every row drives the detector directly. Text `T` is one fingerprint (48
//! normalised characters, every k-gram kept). Carol's cap is filled from 64
//! `fill:*` sources, covered in every view by a flow to the egress, so the
//! kept records never refuse; the overflow sources are `ov:*`, which no flow
//! covers.

use std::time::Instant;

use super::holders::{MAX_RECORDS_PER_CALLER, OVERFLOW_PAIRS_PER_CALLER};
use super::{CollusionDetector, RelayAction, RelayParams};
use crate::config_reload::Generation;
use crate::security::firewall::CollusionAction::Block;
use crate::security::firewall::collusion_live_rig::{Rig, config, flow, one_fp};

const EGRESS: &str = "alpha:send";

/// The rig for a row: `block`, `sources` plus the flow that covers `fill:*`.
fn rig(sources: &[&str]) -> Rig {
    let rig = Rig::new(config(Block, sources, vec![flow("fill:*", EGRESS)]));
    let detector = rig.firewall.collusion_detector().expect("block runs one");
    for i in [0, 1, 2] {
        assert_eq!(detector.fingerprints(&one_fp(i)).len(), 1, "one_fp({i})");
    }
    rig
}

fn detector(rig: &Rig) -> &CollusionDetector {
    rig.firewall.collusion_detector().expect("block runs one")
}

/// Record `text` for `caller` from `source`, list-match, no marker.
fn record(rig: &Rig, g: &Generation, (source, caller): (&str, &str), text: &str, at: Instant) {
    detector(rig).record_delivery_under(g.collusion_view(), (source, false), caller, text, at);
}

/// Fill `caller`'s cap for `text` from `MAX_RECORDS_PER_CALLER` `fill:*`
/// sources.
fn fill_cap(rig: &Rig, g: &Generation, caller: &str, text: &str, at: Instant) {
    for i in 0..MAX_RECORDS_PER_CALLER {
        record(rig, g, (&format!("fill:{i}"), caller), text, at);
    }
}

/// What bob sending `text` through the egress is reported as, under `g`.
fn bob(rig: &Rig, g: &Generation, text: &str, at: Instant) -> Option<&'static str> {
    detector(rig)
        .check_egress_under(g.collusion_view(), "bob", EGRESS, text, at)
        .map(|f| f.reason.label())
}

fn pairs(rig: &Rig, text: &str, caller: &str) -> Vec<(String, bool)> {
    detector(rig)
        .overflow_pairs_of(text, caller)
        .into_iter()
        .map(|(source, inferred)| (source.to_string(), inferred))
        .collect()
}

/// P8.8a: an overflow pair whose source stops being sensitive stops
/// refusing. RED on base at the pairs assertion (no pairs are kept) and at
/// G1 (an overflow refuses whatever the lists say).
#[test]
fn p8_8a_an_overflow_pair_follows_its_sources_listing() {
    let (rig, t, now) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
    let g0 = rig.generation();
    fill_cap(&rig, &g0, "carol", &t, now);
    record(&rig, &g0, ("ov:1", "carol"), &t, now);
    assert_eq!(pairs(&rig, &t, "carol"), [("ov:1".to_string(), false)]);
    assert_eq!(bob(&rig, &g0, &t, now), Some("capacity"), "control: G0");
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".to_string()]);
    assert_eq!(bob(&rig, &rig.generation(), &t, now), None, "P8.8a: G1");
}

/// P8.8b: a source removed and added back is judged each time by the lists
/// in force. RED on base at the pairs assertion and at G1.
#[test]
fn p8_8b_a_pair_is_rejudged_through_a_remove_and_re_add() {
    let (rig, t, now) = (rig(&["fill:*", "ov:2"]), one_fp(0), Instant::now());
    let g0 = rig.generation();
    fill_cap(&rig, &g0, "carol", &t, now);
    record(&rig, &g0, ("ov:2", "carol"), &t, now);
    assert_eq!(pairs(&rig, &t, "carol"), [("ov:2".to_string(), false)]);
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".to_string()]);
    assert_eq!(bob(&rig, &rig.generation(), &t, now), None, "G1 allowed");
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".into(), "ov:2".into()]);
    assert_eq!(
        bob(&rig, &rig.generation(), &t, now),
        Some("capacity"),
        "G2"
    );
    rig.reload(|c| {
        c.security
            .firewall
            .collusion
            .allowed_flows
            .push(flow("ov:2", EGRESS))
    });
    assert_eq!(bob(&rig, &rig.generation(), &t, now), None, "G3 allowed");
    rig.reload(|c| c.security.firewall.collusion.allowed_flows = vec![flow("fill:*", EGRESS)]);
    assert_eq!(
        bob(&rig, &rig.generation(), &t, now),
        Some("capacity"),
        "G4"
    );
}

/// P8.8b': a plain copy past the cap is dropped and stays dropped, even if
/// a reload later lists its source (a stated detection limit). GREEN pin on
/// base.
#[test]
fn p8_8b_prime_a_dropped_plain_copy_stays_dropped() {
    let (rig, t, now) = (rig(&["fill:*"]), one_fp(0), Instant::now());
    let g0 = rig.generation();
    fill_cap(&rig, &g0, "carol", &t, now);
    let before = detector(&rig).capped();
    record(&rig, &g0, ("plain2", "carol"), &t, now);
    assert_eq!(detector(&rig).capped(), before + 1, "one drop, one count");
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".into(), "plain2".into()]);
    assert_eq!(bob(&rig, &rig.generation(), &t, now), None, "P8.8b'");
    assert!(pairs(&rig, &t, "carol").is_empty());
}

/// P8.8c: a caller whose overflow outgrew the pair bound is unattributed and
/// refuses even when every source is flowed; one source short of the bound,
/// the same flows allow it. RED on base at the control "allowed".
#[test]
fn p8_8c_a_saturated_caller_is_unattributed() {
    let bound = u64::try_from(OVERFLOW_PAIRS_PER_CALLER).expect("small");
    let run = |sources: u64| {
        let (rig, t, now) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
        let g0 = rig.generation();
        fill_cap(&rig, &g0, "carol", &t, now);
        for i in 0..sources {
            record(&rig, &g0, (&format!("ov:{i}"), "carol"), &t, now);
        }
        rig.reload(|c| {
            c.security.firewall.collusion.sources = vec!["fill:*".to_string()];
            c.security
                .firewall
                .collusion
                .allowed_flows
                .push(flow("ov:*", EGRESS));
        });
        let verdict = bob(&rig, &rig.generation(), &t, now);
        (verdict, detector(&rig).overflow_unattributed(&t, "carol"))
    };
    assert_eq!(
        run(bound).0,
        None,
        "control: exactly the bound is attributed"
    );
    let (verdict, unattributed) = run(bound + 1);
    assert!(unattributed, "P8.8c: not marked unattributed");
    assert_eq!(verdict, Some("capacity"), "P8.8c: refused");
}

/// P8.8g: the sender's own copy from a pair's source does not excuse the
/// pair. GREEN pin on base.
#[test]
fn p8_8g_a_senders_copy_does_not_excuse_a_sourced_pair() {
    let (rig, t, now) = (rig(&["fill:*", "ov:1"]), one_fp(0), Instant::now());
    let g0 = rig.generation();
    fill_cap(&rig, &g0, "carol", &t, now);
    record(&rig, &g0, ("ov:1", "carol"), &t, now);
    record(&rig, &g0, ("ov:1", "dave"), &t, now);
    let found = detector(&rig).check_egress_under(g0.collusion_view(), "dave", EGRESS, &t, now);
    assert_eq!(found.map(|f| f.reason.label()), Some("capacity"));
}

use std::time::Duration;

/// `at` plus `secs`.
fn plus(at: Instant, secs: u64) -> Instant {
    at + Duration::from_secs(secs)
}

/// Saturate carol's overflow for `text`: `OVERFLOW_PAIRS_PER_CALLER + 1` pairs.
fn saturate(rig: &Rig, g: &Generation, text: &str, at: Instant) {
    fill_cap(rig, g, "carol", text, at);
    for i in 0..=OVERFLOW_PAIRS_PER_CALLER {
        record(rig, g, (&format!("ov:{i}"), "carol"), text, at);
    }
}

/// P8.8e: the unattributed marker expires on `window_secs`, and a later
/// delivery from an already-held pair refreshes that pair, not the marker.
/// RED on base at the last assertion: the overflow slot is extended by any
/// later delivery.
#[test]
fn p8_8e_the_unattributed_marker_expires_on_its_own_window() {
    let (rig, t, t0) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
    let g0 = rig.generation();
    saturate(&rig, &g0, &t, t0);
    record(&rig, &g0, ("ov:3", "carol"), &t, plus(t0, 300));
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".to_string()]);
    let g1 = rig.generation();
    assert_eq!(bob(&rig, &g1, &t, plus(t0, 300)), Some("capacity"));
    assert_eq!(bob(&rig, &g1, &t, plus(t0, 601)), None, "P8.8e: refreshed");
}

/// P8.8f: new unattributed evidence does refresh the marker. GREEN pin on
/// base.
#[test]
fn p8_8f_new_unattributed_evidence_refreshes_the_marker() {
    let (rig, t, t0) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
    let g0 = rig.generation();
    saturate(&rig, &g0, &t, t0);
    let fresh = format!("ov:{}", OVERFLOW_PAIRS_PER_CALLER + 5);
    record(&rig, &g0, (&fresh, "carol"), &t, plus(t0, 300));
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".to_string()]);
    let g1 = rig.generation();
    assert_eq!(bob(&rig, &g1, &t, plus(t0, 601)), Some("capacity"));
    assert_eq!(bob(&rig, &g1, &t, plus(t0, 901)), None);
}

/// A detector of its own (so a test can set its budget), `block`, every
/// k-gram kept, one match enough.
fn standalone() -> CollusionDetector {
    let mut detector = CollusionDetector::new(RelayParams {
        action: RelayAction::Block,
        min_matches: 1,
        ..RelayParams::default()
    });
    detector.keep_every_kgram();
    detector
}

/// The overflow bytes one first pair from a new source adds.
fn first_pair_charge() -> usize {
    let (rig, t, now) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
    let g = rig.generation();
    let d = standalone();
    for i in 0..MAX_RECORDS_PER_CALLER {
        d.record_delivery_under(
            g.collusion_view(),
            (&format!("fill:{i}"), false),
            "x",
            &t,
            now,
        );
    }
    let before = d.overflow_bytes().1;
    d.record_delivery_under(g.collusion_view(), ("ov:00", false), "x", &t, now);
    d.overflow_bytes().1 - before
}

/// P8.8d: a full total budget fails closed for the newcomer and keeps what
/// it already holds. Budget `k` first-pair charges; callers `c0..ck`, each
/// with its own text and its own source `ov:0i`. RED on base at "allowed":
/// every overflow refuses.
#[test]
fn p8_8d_a_full_total_budget_fails_closed_for_the_newcomer() {
    const K: u64 = 3;
    let charge = first_pair_charge();
    let (rig, now) = (rig(&["fill:*", "ov:*"]), Instant::now());
    let g0 = rig.generation();
    let mut d = standalone();
    d.set_overflow_bytes_total(usize::try_from(K).expect("small") * charge);
    for i in 0..=K {
        let (caller, text) = (format!("c{i}"), one_fp(i + 1));
        for j in 0..MAX_RECORDS_PER_CALLER {
            let src = format!("fill:{j}");
            d.record_delivery_under(g0.collusion_view(), (&src, false), &caller, &text, now);
        }
        let src = format!("ov:0{i}");
        d.record_delivery_under(g0.collusion_view(), (&src, false), &caller, &text, now);
    }
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".to_string()]);
    let g1 = rig.generation();
    let view = g1.collusion_view();
    let first = d.check_egress_under(view, "bob", EGRESS, &one_fp(1), now);
    assert!(
        first.is_none(),
        "P8.8d: the first caller's pair was lost or refuses"
    );
    assert_eq!(
        d.overflow_pairs_of(&one_fp(1), "c0"),
        [("ov:00".into(), false)]
    );
    let newcomer = d.check_egress_under(view, "bob", EGRESS, &one_fp(K + 1), now);
    assert_eq!(newcomer.map(|f| f.reason.label()), Some("capacity"));
    assert!(d.overflow_unattributed(&one_fp(K + 1), &format!("c{K}")));
}

/// O5.1: overflow bytes bind before the pair count, and a saturated caller
/// is unattributed. The name length is chosen so the per-caller byte bound
/// holds fewer pairs than the pair-count bound. RED on base at the pairs
/// assertion (no pairs are kept).
#[test]
fn o5_1_the_byte_bound_marks_saturation_before_the_pair_count() {
    use super::holders::OVERFLOW_BYTES_PER_CALLER;
    let (rig, t, now) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
    let g = rig.generation();
    fill_cap(&rig, &g, "carol", &t, now);
    let name = |i: usize| format!("ov:{i:0>200}");
    let before = detector(&rig).overflow_bytes().1;
    record(&rig, &g, (&name(1), "carol"), &t, now);
    let charge = (detector(&rig).overflow_bytes().1 - before).max(1);
    let fit = (OVERFLOW_BYTES_PER_CALLER / charge).min(2 * OVERFLOW_PAIRS_PER_CALLER);
    for i in 2..=fit {
        record(&rig, &g, (&name(i), "carol"), &t, now);
    }
    assert_eq!(pairs(&rig, &t, "carol").len(), fit, "O5.1: pairs kept");
    assert!(fit < OVERFLOW_PAIRS_PER_CALLER, "premise: bytes bind first");
    assert!(!detector(&rig).overflow_unattributed(&t, "carol"));
    record(&rig, &g, (&name(fit + 1), "carol"), &t, now);
    assert!(detector(&rig).overflow_unattributed(&t, "carol"), "O5.1");
    assert!(detector(&rig).overflow_bytes().0 <= OVERFLOW_BYTES_PER_CALLER);
}

/// O5.3: the last reference frees an interned source. RED on base at the
/// first assertion: the stub interns nothing.
#[test]
fn o5_3_the_last_reference_frees_the_interned_source() {
    let (rig, t, now) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
    let g = rig.generation();
    let before = detector(&rig).interned_sources_for_test();
    record(&rig, &g, ("ov:z", "carol"), &t, now);
    assert_eq!(detector(&rig).interned_sources_for_test(), before + 1);
    let _ = bob(&rig, &rig.generation(), &t, plus(now, 601));
    assert_eq!(detector(&rig).interned_sources_for_test(), before, "O5.3");
}

/// O5.2a: retention at the cap uses the lists of the generation the record is
/// made under. Lists change before recording; under cap pressure the source
/// listed now overflows as a pair and the one no longer listed is dropped.
/// RED on base at the pairs assertion.
#[test]
fn o5_2a_retention_uses_the_recording_generations_lists() {
    let (rig, t, now) = (rig(&["fill:*", "src:s"]), one_fp(0), Instant::now());
    rig.reload(|c| {
        c.security.firewall.collusion.sources = vec!["fill:*".to_string(), "src:p".to_string()];
    });
    let g1 = rig.generation();
    fill_cap(&rig, &g1, "carol", &t, now);
    record(&rig, &g1, ("src:s", "carol"), &t, now);
    record(&rig, &g1, ("src:p", "carol"), &t, now);
    assert_eq!(pairs(&rig, &t, "carol"), [("src:p".to_string(), false)]);
}
