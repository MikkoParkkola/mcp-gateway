// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SG5: the seam excuse (a holder forwarding a subset of the whole pieces it
//! was delivered is not a relay) is part of recording, so it works when the
//! detector was switched on by a reload. A child of the key-path rows, which
//! own the piece fixtures.

use super::super::super::CollusionAction::{Observe, Off};
use super::{TEXTS, flat, labelled_parts, pieces, text};
use crate::security::firewall::collusion_live_rig::{Rig, config};

/// The subset `pieces` without their middle piece, run together.
fn without_middle(pieces: &[String]) -> String {
    let middle = pieces.len() / 2;
    pieces
        .iter()
        .enumerate()
        .filter(|(k, _)| *k != middle)
        .map(|(_, piece)| piece.as_str())
        .collect()
}

/// Whether `who` forwarding `subset` is reported as a relay under `rig`'s
/// current generation.
fn reported(rig: &Rig, who: &str, subset: &str) -> bool {
    let verdict = rig.relays(who, ("alpha", "send"), subset, &rig.generation());
    !verdict.findings.is_empty()
}

/// SG5: under a startup `off` switched to `observe` by a reload, alice is
/// delivered the pieces and carol the exact join of a subset by the same
/// tool. Bob forwarding the subset is reported (positive control); alice,
/// who holds the whole pieces, is excused. RED on base at bob: nothing is
/// recorded under a startup `off`.
#[test]
fn sg5_the_seam_excuse_works_after_off_to_observe() {
    let rig = Rig::new(config(Off, &["alpha:*"], vec![]));
    rig.reload(|c| c.security.firewall.collusion.action = Observe);
    let g1 = rig.generation();
    for i in 0..TEXTS.min(5) {
        let (text, tool) = (text(i), format!("read{i}"));
        let pieces = pieces(&text);
        let subset = without_middle(&pieces);
        rig.deliver("alice", ("alpha", &tool), &labelled_parts(&pieces), &g1);
        rig.deliver("carol", ("alpha", &tool), &flat(&subset), &g1);
        assert!(
            reported(&rig, "bob", &subset),
            "SG5: text {i}: bob not reported"
        );
        assert!(
            !reported(&rig, "alice", &subset),
            "SG5: text {i}: alice reported"
        );
    }
}
