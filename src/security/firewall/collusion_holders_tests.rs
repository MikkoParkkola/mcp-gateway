// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8123`: a fingerprint one caller received from many sources stays
//! judged. Text held by `common_principals` distinct callers stays `Common`
//! (boilerplate, never a finding); below that, every holder record stays
//! exact up to a per-caller cap, and a sensitive record the cap cannot keep
//! makes that caller's copy count conservatively instead of switching the
//! fingerprint off.

use std::time::Instant;

use super::{CollusionDetector, RelayAction, RelayParams};

const BOB: &str = "principal-bob";
const CAROL: &str = "principal-carol";
const EGRESS: &str = "backend:post_message";

fn detector() -> CollusionDetector {
    CollusionDetector::new(RelayParams {
        action: RelayAction::Observe,
        ..RelayParams::default()
    })
}

/// Non-periodic prose, long enough for many sampled fingerprints.
fn passage() -> String {
    (0..300)
        .map(|i| format!("w{:x}", (i * 2_654_435_761_u64) % 1_000_003))
        .collect::<Vec<_>>()
        .join(" ")
}

fn source(i: usize) -> String {
    format!("backend-{i}:read_doc")
}

/// `MIK-8123.SAT.2`: carol received a sensitive passage from nine sources;
/// bob, who has no copy, relaying it is a finding.
#[test]
fn nine_sensitive_sources_to_one_caller_stay_judged() {
    let d = detector();
    let now = Instant::now();
    let text = passage();
    for i in 0..9 {
        d.record_delivery_at(&source(i), CAROL, true, &text, now);
    }
    assert!(
        d.check_egress_at(CAROL, EGRESS, &text, now).is_none(),
        "control: carol's own copy is excused"
    );
    assert!(
        d.check_egress_at(BOB, EGRESS, &text, now).is_some(),
        "a passage held from nine sources stopped being judged"
    );
}

/// `MIK-8123.SAT.3` (control): text five callers hold is `Common`, as
/// before: a sixth relaying it is not a finding. Positive control: with four
/// holders, the same relay is one.
#[test]
fn text_five_callers_hold_stays_common() {
    let now = Instant::now();
    let text = passage();
    let held_by = |n: usize| {
        let d = detector();
        for i in 0..n {
            d.record_delivery_at(&source(i), &format!("caller-{i}"), true, &text, now);
        }
        d.check_egress_at(BOB, EGRESS, &text, now).is_some()
    };
    assert!(held_by(4), "control: four holders keep it judged");
    assert!(!held_by(5), "text five callers hold was refused");
}

/// `MIK-8123`: past the per-caller cap a plain record goes before a
/// sensitive one: carol's one sensitive copy, then many plain ones, still
/// witnesses bob's relay.
#[test]
fn plain_records_go_before_a_sensitive_one() {
    let d = detector();
    let now = Instant::now();
    let text = passage();
    d.record_delivery_at(&source(0), CAROL, true, &text, now);
    for i in 1..=80 {
        d.record_delivery_at(&source(i), CAROL, false, &text, now);
    }
    assert!(
        d.check_egress_at(BOB, EGRESS, &text, now).is_some(),
        "a sensitive copy was dropped for plain ones"
    );
}

/// `MIK-8123`: a sensitive record past the cap is never silently lost. Carol
/// got the passage first from a source no flow lets leave, then from many
/// sources whose flow allows the egress; bob relaying it through that flow
/// is still a finding.
#[test]
fn a_restriction_past_the_cap_still_holds() {
    let d = detector();
    let now = Instant::now();
    let text = passage();
    d.record_delivery_flows_at(&source(0), CAROL, (true, 0), &text, now);
    for i in 1..=80 {
        d.record_delivery_flows_at(&source(i), CAROL, (true, 1), &text, now);
    }
    assert!(
        d.check_egress_flows_at(BOB, (EGRESS, 1), &text, now)
            .is_some(),
        "a restriction past the cap was lost"
    );
}
