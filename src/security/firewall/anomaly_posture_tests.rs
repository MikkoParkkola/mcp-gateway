// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A full learned-pair map under each posture (design row 4).
//!
//! At the cap a new transition cannot be learned. A cold predecessor then
//! stays cold forever, so its successors are never scored: `standard` counts
//! the drop and passes the call, `hardened` refuses it unscored.

use std::sync::Arc;

use serde_json::json;

use super::{Firewall, FirewallConfig};
use crate::security::posture::SecurityPosture;
use crate::transition::TransitionTracker;

/// `MAX_LEARNED_PAIRS` in `anomaly.rs`; the fill below proves it is reached.
const CAP: usize = 100_000;

/// A firewall whose shared pair map is full and knows exactly one pair of
/// the predecessor `srv:a`, `srv:a -> srv:b`, which leaves `srv:a` cold.
fn capped(posture: SecurityPosture) -> Firewall {
    let tracker = Arc::new(TransitionTracker::new());
    assert!(tracker.record_pair("srv:a", "srv:b", CAP));
    let mut filler = 0_usize;
    while tracker.record_pair(&format!("fill:{filler}"), "fill:x", CAP) {
        filler += 1;
    }
    assert_eq!(filler, CAP - 1, "the map is exactly full");
    let config = FirewallConfig {
        anomaly_detection: true,
        anomaly_threshold: 0.7,
        anomaly_block_threshold: Some(1.0),
        ..FirewallConfig::default()
    };
    Firewall::from_config(config, Some(tracker)).with_posture(posture)
}

fn call(fw: &Firewall, tool: &str) -> bool {
    fw.check_request("s", "srv", tool, &json!({}), "caller", "caller")
        .allowed
}

#[test]
fn pair_cap_full_hardened_refuses() {
    let fw = capped(SecurityPosture::Hardened);
    assert!(call(&fw, "a"), "a first call has no transition to learn");
    assert!(!call(&fw, "c"), "srv:a -> srv:c cannot be learned: refused");
}

#[test]
fn pair_cap_full_hardened_admits_a_known_pair() {
    let fw = capped(SecurityPosture::Hardened);
    assert!(call(&fw, "a"));
    assert!(
        call(&fw, "b"),
        "srv:a -> srv:b is already learned: admitted"
    );
}

#[test]
fn pair_cap_full_standard_counts_and_passes() {
    let fw = capped(SecurityPosture::Standard);
    assert!(call(&fw, "a"));
    assert!(call(&fw, "c"), "standard never refuses at the cap");
    let dropped = fw.anomaly.as_ref().unwrap().pairs_dropped_count();
    assert_eq!(dropped, 1, "the unlearned transition is counted");
}
