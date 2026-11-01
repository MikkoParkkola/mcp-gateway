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

use super::CollusionDetector;
use super::holders::{MAX_RECORDS_PER_CALLER, OVERFLOW_PAIRS_PER_CALLER};
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
