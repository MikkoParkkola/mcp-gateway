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

use super::holders::{MAX_RECORDS_PER_CALLER, OVERFLOW_BYTES_TOTAL, OVERFLOW_PAIRS_PER_CALLER};
use super::{CollusionDetector, RelayParams};
use crate::config_reload::Generation;
use crate::security::firewall::CollusionAction::Block;
#[cfg(feature = "metrics")]
use crate::security::firewall::collusion_live_rig::bound_count;
use crate::security::firewall::collusion_live_rig::{Rig, config, flow, one_fp, two_fp};

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
    assert_eq!(
        pairs(&rig, &t, "carol"),
        [("ov:1".to_string(), false)],
        "P8.8a: carol's overflow pair for T is not (ov:1, non-inferred)"
    );
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
    assert_eq!(
        pairs(&rig, &t, "carol"),
        [("ov:2".to_string(), false)],
        "P8.8b: carol's overflow pair for T is not (ov:2, non-inferred)"
    );
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
            .push(flow("ov:2", EGRESS));
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
    assert!(
        pairs(&rig, &t, "carol").is_empty(),
        "P8.8b': a dropped plain copy was kept as an overflow pair"
    );
}

/// P8.8c: a caller whose overflow outgrew the pair bound is unattributed and
/// refuses even when every source is flowed; one source short of the bound,
/// the same flows allow it. RED on base at the control's `unattributed`
/// assertion: today every overflow is unattributed.
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
    // One source short of saturation the pairs are all kept, so the caller is
    // attributed and the flows decide: on base every overflow is unattributed
    // and refuses, which is what this row's control pins.
    let (verdict, unattributed) = run(bound);
    assert!(
        !unattributed,
        "P8.8c control: exactly the bound is held attributed, not unattributed"
    );
    assert_eq!(
        verdict, None,
        "P8.8c control: exactly the bound is allowed by its flows"
    );
    let (verdict, unattributed) = run(bound + 1);
    assert!(
        unattributed,
        "P8.8c: past the bound is not marked unattributed"
    );
    assert_eq!(
        verdict,
        Some("capacity"),
        "P8.8c: past the bound is not refused"
    );
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
    assert_eq!(
        found.map(|f| f.reason.label()),
        Some("capacity"),
        "P8.8g: the sender's own copy from the pair's source changed the refusal"
    );
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
    assert_eq!(
        bob(&rig, &g1, &t, plus(t0, 300)),
        Some("capacity"),
        "P8.8e: at t0+300 bob is not refused as capacity"
    );
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
    assert_eq!(
        bob(&rig, &g1, &t, plus(t0, 601)),
        Some("capacity"),
        "P8.8f: at t0+601 bob is not refused as capacity"
    );
    assert_eq!(
        bob(&rig, &g1, &t, plus(t0, 901)),
        None,
        "P8.8f: at t0+901 bob is still refused"
    );
}

/// A detector of its own (so a test can set its budget), `block`, every
/// k-gram kept, one match enough.
fn standalone() -> CollusionDetector {
    let mut detector = CollusionDetector::new(RelayParams {
        min_matches: 1,
        ..RelayParams::default()
    });
    detector.keep_every_kgram();
    detector
}

/// Fill `caller`'s cap for `text` on a standalone detector from `g`'s view.
fn fill_standalone(d: &CollusionDetector, g: &Generation, caller: &str, text: &str, at: Instant) {
    for j in 0..MAX_RECORDS_PER_CALLER {
        let src = format!("fill:{j}");
        d.record_delivery_under(g.collusion_view(), (&src, false), caller, text, at);
    }
}

/// The overflow bytes a first pair from a new source adds (`c_new`: pair
/// storage plus the newly interned string), and a second fingerprint's pair
/// from the same source adds (`c_fp`: the interned string is shared).
fn pair_charges() -> (usize, usize) {
    let (rig, now) = (rig(&["fill:*", "ov:*"]), Instant::now());
    let g = rig.generation();
    let d = standalone();
    let (first, second) = (one_fp(900), one_fp(901));
    fill_standalone(&d, &g, "x", &first, now);
    fill_standalone(&d, &g, "x", &second, now);
    let before = d.overflow_bytes().1;
    d.record_delivery_under(g.collusion_view(), ("ov:00", false), "x", &first, now);
    let mid = d.overflow_bytes().1;
    d.record_delivery_under(g.collusion_view(), ("ov:00", false), "x", &second, now);
    (mid - before, d.overflow_bytes().1 - mid)
}

/// The budget run: a total of `K` first-pair charges, callers `c0..` each
/// with its own text (`text_of`) and its own source, each filling its cap and
/// overflowing once. `per_caller` is what one caller's overflow charges; the
/// first caller the budget cannot hold is `K * c_new / per_caller` (`K` when
/// nothing is charged yet). The first caller's pair is kept and plain (not
/// evicted) and the newcomer fails closed.
fn run_budget(text_of: fn(u64) -> String, per_caller: impl Fn(usize, usize) -> usize) {
    const K: usize = 3;
    let (c_new, c_fp) = pair_charges();
    let per = per_caller(c_new, c_fp);
    let newcomer = (K * c_new).checked_div(per).unwrap_or(K);
    assert!(
        K * c_new <= OVERFLOW_BYTES_TOTAL,
        "premise: under the default total"
    );
    let (rig, now) = (rig(&["fill:*", "ov:*"]), Instant::now());
    let g0 = rig.generation();
    let mut d = standalone();
    d.set_overflow_bytes_total(K * c_new);
    for i in 0..=newcomer {
        let (caller, text) = (format!("c{i}"), text_of(i as u64 + 1));
        fill_standalone(&d, &g0, &caller, &text, now);
        let src = format!("ov:0{i}");
        d.record_delivery_under(g0.collusion_view(), (&src, false), &caller, &text, now);
    }
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["fill:*".to_string()]);
    let g1 = rig.generation();
    let first = d.check_egress_under(g1.collusion_view(), "bob", EGRESS, &text_of(1), now);
    assert!(
        first.is_none(),
        "P8.8d: the first caller's pair was lost or refuses"
    );
    let newcomer_text = text_of(newcomer as u64 + 1);
    let found = d.check_egress_under(g1.collusion_view(), "bob", EGRESS, &newcomer_text, now);
    assert_eq!(
        found.map(|f| f.reason.label()),
        Some("capacity"),
        "newcomer c{newcomer}"
    );
    assert!(
        d.overflow_unattributed(&newcomer_text, &format!("c{newcomer}")),
        "P8.8d: the newcomer is not marked unattributed"
    );
}

/// P8.8d, one fingerprint per text: a full total budget fails closed for the
/// newcomer (caller `K`) and keeps what it already holds. RED on base at the
/// first caller "allowed": every overflow refuses.
#[test]
fn p8_8d_a_full_total_budget_fails_closed_for_the_newcomer() {
    run_budget(one_fp, |c_new, _| c_new);
}

/// P8.8d, two fingerprints per text: the second fingerprint's pair shares the
/// interned source, so a caller charges `c_new + c_fp` and the newcomer lands
/// at `K * c_new / (c_new + c_fp)`, earlier than in the one-fingerprint run.
/// RED on base as above.
#[test]
fn p8_8d_two_fingerprints_charge_the_shared_string_once() {
    run_budget(two_fp, |c_new, c_fp| c_new + c_fp);
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
    assert!(
        !detector(&rig).overflow_unattributed(&t, "carol"),
        "O5.1: the caller is unattributed before the byte bound trips"
    );
    record(&rig, &g, (&name(fit + 1), "carol"), &t, now);
    assert!(detector(&rig).overflow_unattributed(&t, "carol"), "O5.1");
    assert!(
        detector(&rig).overflow_bytes().0 <= OVERFLOW_BYTES_PER_CALLER,
        "O5.1: the per-caller overflow bytes exceed the bound"
    );
}

/// O5.3: the last reference frees an interned source. RED on base at the
/// first assertion: the stub interns nothing.
#[test]
fn o5_3_the_last_reference_frees_the_interned_source() {
    let (rig, t, now) = (rig(&["fill:*", "ov:*"]), one_fp(0), Instant::now());
    let g = rig.generation();
    let before = detector(&rig).interned_sources_for_test();
    record(&rig, &g, ("ov:z", "carol"), &t, now);
    assert_eq!(
        detector(&rig).interned_sources_for_test(),
        before + 1,
        "O5.3: the interned source count did not rise by one"
    );
    let _ = bob(&rig, &rig.generation(), &t, plus(now, 601));
    assert_eq!(detector(&rig).interned_sources_for_test(), before, "O5.3");
}

/// Retention at the cap uses the lists of the generation the record is made
/// under: lists change before recording; under cap pressure the source listed
/// now overflows and the one no longer listed is dropped. Returns what the
/// detector counted for the two records (`fingerprints` each).
fn retention_under_the_recording_lists(text: &str) -> (Rig, u64) {
    let (rig, now) = (rig(&["fill:*", "src:s"]), Instant::now());
    rig.reload(|c| {
        c.security.firewall.collusion.sources = vec!["fill:*".to_string(), "src:p".to_string()];
    });
    let g1 = rig.generation();
    fill_cap(&rig, &g1, "carol", text, now);
    let before = detector(&rig).capped();
    #[cfg(feature = "metrics")]
    let (dropped, overflowed) = (
        bound_count("record_dropped"),
        bound_count("record_overflow"),
    );
    record(&rig, &g1, ("src:s", "carol"), text, now);
    record(&rig, &g1, ("src:p", "carol"), text, now);
    let counted = detector(&rig).capped() - before;
    #[cfg(feature = "metrics")]
    {
        assert!(
            bound_count("record_dropped") > dropped,
            "O5.2a: the dropped record was not counted as record_dropped"
        );
        assert!(
            bound_count("record_overflow") > overflowed,
            "O5.2a: the overflowed record was not counted as record_overflow"
        );
    }
    (rig, counted)
}

/// O5.2a, one fingerprint: the listed source overflows as a pair, the other
/// is dropped; two records are counted. RED on base at the pairs assertion.
#[test]
fn o5_2a_retention_uses_the_recording_generations_lists() {
    let text = one_fp(0);
    let (rig, counted) = retention_under_the_recording_lists(&text);
    assert_eq!(
        pairs(&rig, &text, "carol"),
        [("src:p".to_string(), false)],
        "O5.2a: carol's overflow pair is not (src:p, non-inferred)"
    );
    // `capped` is the exact per-detector total of drops and overflows
    // together; the dropped count is visible separately as the metric's
    // `bound` label (asserted above).
    assert_eq!(counted, 2, "one drop and one overflow, one fingerprint");
}

/// O5.2a, two fingerprints: the counters move once per fingerprint, so four
/// records are counted, not two. RED on base at the pairs assertion for the
/// first fingerprint.
#[test]
fn o5_2a_counts_per_fingerprint_not_per_delivery() {
    let text = two_fp(0);
    let (rig, counted) = retention_under_the_recording_lists(&text);
    assert_eq!(
        pairs(&rig, &text, "carol"),
        [("src:p".to_string(), false)],
        "O5.2a (two fingerprints): carol's overflow pair is not (src:p, non-inferred)"
    );
    // `capped` is the exact per-detector total of drops and overflows: one
    // of each per fingerprint; the metric's `bound` label separates them.
    assert_eq!(
        counted, 4,
        "one drop and one overflow, two fingerprints each"
    );
}

/// Retention priority is decided when a copy is recorded (ADR-029,
/// amended, item 3): carol's cap holds copies sensitive under the view they
/// were recorded under (`src:*` listed). A reload unlists `src:*`; a
/// newcomer sensitive under its own view (`new:*` listed) does not fit. The
/// held copies keep their record-time priority, so the newcomer overflows
/// as a pair instead of replacing one of them as plain. RED on base: the
/// held copies are re-judged under the newcomer's view, so one is replaced.
#[test]
fn a_reload_that_unlists_a_source_cannot_make_held_sensitive_evidence_evictable() {
    let (rig, t, now) = (rig(&["src:*"]), one_fp(0), Instant::now());
    let g0 = rig.generation();
    for i in 0..MAX_RECORDS_PER_CALLER {
        record(&rig, &g0, (&format!("src:{i}"), "carol"), &t, now);
    }
    rig.reload(|c| c.security.firewall.collusion.sources = vec!["new:*".to_string()]);
    let g1 = rig.generation();
    record(&rig, &g1, ("new:x", "carol"), &t, now);
    assert_eq!(
        pairs(&rig, &t, "carol"),
        [("new:x".to_string(), false)],
        "a held copy sensitive when recorded was replaced as plain under a later view"
    );
}
