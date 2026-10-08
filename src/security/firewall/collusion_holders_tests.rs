// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8123`: a fingerprint one caller received from many sources stays
//! judged. Text held by `common_principals` distinct callers stays `Common`
//! (boilerplate, never a finding); below that, every holder record stays
//! exact up to a per-caller cap, and a sensitive record the cap cannot keep
//! makes that caller's copy count conservatively instead of switching the
//! fingerprint off.

use std::time::{Duration, Instant};

use super::{CollusionDetector, RelayAction, RelayParams};

const BOB: &str = "principal-bob";
const CAROL: &str = "principal-carol";
const DAVE: &str = "principal-dave";
/// A source no `allowed_flows` entry lets leave.
const RESTRICTED: &str = "vault:read_secret";
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

/// Carol received `text` as sensitive from 64 sources whose flow (entry 1)
/// lets it leave, at `at`, then from one more source no flow lets leave: one
/// record past her cap.
fn overflowed(d: &CollusionDetector, text: &str, at: Instant) {
    for i in 0..64 {
        d.record_delivery_flows_at(&source(i), CAROL, (true, 1), text, at);
    }
    d.record_delivery_flows_at(RESTRICTED, CAROL, (true, 0), text, at);
}

/// `MIK-8123`: a sensitive record past the cap is never silently lost: the
/// restriction it carried still holds. Bob relaying through a flow every
/// kept record allows is a finding.
#[test]
fn a_restriction_past_the_cap_still_holds() {
    let d = detector();
    let now = Instant::now();
    let text = passage();
    overflowed(&d, &text, now);
    assert!(
        d.check_egress_flows_at(BOB, (EGRESS, 1), &text, now)
            .is_some(),
        "a restriction past the cap was lost"
    );
}

/// `MIK-8123`: what a record past the cap carried has no source left, so no
/// exact copy excuses it: dave, who holds his own copy from the restricted
/// source, relaying it is still a finding.
#[test]
fn an_exact_copy_does_not_excuse_what_overflowed() {
    let d = detector();
    let now = Instant::now();
    let text = passage();
    overflowed(&d, &text, now);
    d.record_delivery_flows_at(RESTRICTED, DAVE, (false, 0), &text, now);
    assert!(
        d.check_egress_flows_at(DAVE, (EGRESS, 1), &text, now)
            .is_some(),
        "an exact copy excused what overflowed"
    );
}

/// `MIK-8123`: what overflowed is held as long as its own sensitive
/// delivery, never extended by later plain ones: inside the window bob's
/// relay is a finding, past it none, though carol kept receiving it plainly.
#[test]
fn what_overflowed_expires_with_its_own_delivery() {
    let d = detector();
    let t0 = Instant::now();
    let text = passage();
    overflowed(&d, &text, t0);
    for i in 100..110 {
        d.record_delivery_at(
            &source(i),
            CAROL,
            false,
            &text,
            t0 + Duration::from_secs(500),
        );
    }
    assert!(
        d.check_egress_flows_at(BOB, (EGRESS, 1), &text, t0 + Duration::from_secs(300))
            .is_some(),
        "control: inside the window it is a finding"
    );
    assert!(
        d.check_egress_flows_at(BOB, (EGRESS, 1), &text, t0 + Duration::from_secs(650))
            .is_none(),
        "plain deliveries extended what overflowed"
    );
}

/// `MIK-8123`: pool records are released when their fingerprint leaves the
/// window, so the pool never fills from expired text.
#[test]
fn pool_records_return_when_the_window_passes() {
    let d = detector();
    let now = Instant::now();
    let text = passage();
    for i in 0..20 {
        d.record_delivery_at(&source(i), CAROL, true, &text, now);
    }
    assert!(d.pool_in_use() > 0, "premise: records past the inline ones");
    let later = now + Duration::from_secs(700);
    assert!(d.check_egress_at(BOB, EGRESS, &text, later).is_none());
    assert_eq!(d.pool_in_use(), 0, "expired records kept their pool slots");
}

/// `MIK-8123`: with the pool full a sensitive record past the inline ones
/// becomes its caller's overflow, still evidence; the pool never grows.
#[test]
fn a_full_pool_keeps_sensitive_text_judged() {
    let mut d = detector();
    d.set_pool_capacity(0);
    let now = Instant::now();
    let text = passage();
    overflowed(&d, &text, now);
    assert_eq!(d.pool_in_use(), 0, "the pool grew past its capacity");
    assert!(d.capped() > 0, "records past the cap are counted");
    assert!(
        d.check_egress_flows_at(BOB, (EGRESS, 1), &text, now)
            .is_some(),
        "a full pool silenced sensitive text"
    );
}

/// `MIK-8123`: `Common` counts every caller seen, records kept or not:
/// with the pool full, five callers whose records did not all fit still
/// make the text common. Positive control: four callers keep it judged.
#[test]
fn callers_whose_records_were_dropped_still_count_toward_common() {
    let now = Instant::now();
    let text = passage();
    let with_callers = |n: usize| {
        let mut d = detector();
        d.set_pool_capacity(0);
        for i in 0..8 {
            d.record_delivery_at(&source(i), CAROL, true, &text, now);
        }
        for i in 1..n {
            d.record_delivery_at(&source(50 + i), &format!("caller-{i}"), false, &text, now);
        }
        d.check_egress_at(BOB, EGRESS, &text, now).is_some()
    };
    assert!(with_callers(4), "control: four callers keep it judged");
    assert!(!with_callers(5), "dropped records hid callers from common");
}

/// `MIK-8123`: the pool's memory bound. A holder record is at most 160
/// bytes on 64-bit targets, so the pool holds at most 10 MiB of records.
#[test]
fn the_pool_is_bounded_in_bytes() {
    let record = std::mem::size_of::<super::Holder>();
    assert!(record <= 160, "a holder record grew to {record} bytes");
    assert!(super::holders::EXTRA_RECORD_POOL * 160 <= 10 * 1024 * 1024);
}
