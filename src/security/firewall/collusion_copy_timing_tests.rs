// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Copies dated around an egress: a holder stamped after it excuses nothing,
//! and thinning or capping a pair's copies keeps the one held at the egress.

use super::*;

// A holder dated after the egress ──────────────────────────────────────
//
// Calls reach the lock out of time order, so a delivery stamped after an
// egress can be recorded before that egress is checked. Only copies held at
// the egress instant may excuse it or witness it.

/// B's copy from T is stamped after B's egress: it cannot excuse the egress.
#[test]
fn future_holder_does_not_excuse_earlier_egress() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now);
    d.record_delivery_at(T, B, false, &s, now + Duration::from_millis(1));
    assert!(
        d.check_egress_at(B, U, &s, now).is_some(),
        "a copy B got after sending cannot excuse the send"
    );
}

/// A's only sensitive copy is stamped after B's egress: no witness yet.
#[test]
fn future_sensitive_does_not_flag_earlier_egress() {
    let d = detector();
    let now = Instant::now();
    let later = now + Duration::from_millis(1);
    let s = secret();
    d.record_delivery_at(T, A, true, &s, later);
    assert!(
        d.check_egress_at(B, U, &s, now).is_none(),
        "A's later copy is not evidence for an earlier send"
    );
    // Positive control: the same text after A's delivery is a relay.
    assert!(d.check_egress_at(B, U, &s, later).is_some());
}

/// Merging keeps the earliest copy too: B held T before the egress and again
/// after it, so the egress stays excused.
#[test]
fn earlier_copy_still_excuses_after_a_future_redelivery() {
    let d = detector();
    let earlier = Instant::now();
    let now = earlier + Duration::from_secs(1);
    let s = secret();
    d.record_delivery_at(T, A, true, &s, earlier);
    d.record_delivery_at(T, B, false, &s, earlier);
    d.record_delivery_at(T, B, false, &s, now + Duration::from_millis(1));
    assert!(d.check_egress_at(B, U, &s, now).is_none());
    // Positive control: a principal that never got T is flagged.
    assert!(d.check_egress_at("principal-c", U, &s, now).is_some());
}

/// The witness ages on sensitive copies only: A's plain copy before the
/// egress does not date A's later sensitive copy back. Recorded latest first.
#[test]
fn earlier_plain_copy_does_not_backdate_a_future_sensitive_one() {
    let d = detector();
    let earlier = Instant::now();
    let now = earlier + Duration::from_secs(1);
    let later = now + Duration::from_millis(1);
    let s = secret();
    d.record_delivery_at(T, A, true, &s, later);
    d.record_delivery_at(T, A, false, &s, earlier);
    assert!(d.check_egress_at(B, U, &s, now).is_none());
    // Positive control: once A's sensitive copy exists, the same send flags.
    assert!(d.check_egress_at(B, U, &s, later).is_some());
}

/// Two sensitive copies straddle the egress, recorded latest first: the
/// earlier one is still evidence.
#[test]
fn earlier_sensitive_copy_survives_a_later_one_recorded_first() {
    let d = detector();
    let earlier = Instant::now();
    let now = earlier + Duration::from_secs(1);
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now + Duration::from_millis(1));
    d.record_delivery_at(T, A, true, &s, earlier);
    assert!(d.check_egress_at(B, U, &s, now).is_some());
}

/// B's copies from T are one from before the window and one
/// stamped after the egress, recorded latest first. Neither is held in the
/// window at the egress instant, so neither excuses it.
#[test]
fn stale_copy_and_future_redelivery_do_not_excuse() {
    let d = detector();
    let stale = Instant::now();
    let now = stale + RelayParams::default().window + Duration::from_secs(1);
    let s = secret();
    d.record_delivery_at(T, B, false, &s, now + Duration::from_millis(1));
    d.record_delivery_at(T, B, false, &s, stale);
    d.record_delivery_at(T, A, true, &s, now);
    assert!(
        d.check_egress_at(B, U, &s, now).is_some(),
        "a stale copy and a later one do not make a copy held in the window"
    );
    // Control: a copy inside the window, before the egress, still excuses.
    d.record_delivery_at(T, B, false, &s, now);
    assert!(d.check_egress_at(B, U, &s, now).is_none());
}

/// Thinning B's copies never drops the one held at the
/// egress. Copies at 0, 4, 8 and 12 minutes: at 11 minutes only the 8-minute
/// copy is in the window and before the egress, so it must survive.
#[test]
fn thinned_copies_keep_the_one_held_at_the_egress() {
    let d = detector();
    let start = Instant::now();
    let min = Duration::from_secs(60);
    let s = secret();
    for m in [0, 4, 8, 12] {
        d.record_delivery_at(T, B, false, &s, start + min * m);
    }
    let now = start + min * 11;
    d.record_delivery_at(T, A, true, &s, now);
    assert!(d.check_egress_at(B, U, &s, now).is_none());
}

/// Past the copy cap the oldest copy goes, not the newest.
/// Copies at 0, 6, 12 and 18 minutes: at 23 minutes only the 18-minute copy
/// is in the window.
#[test]
fn the_copy_cap_drops_the_oldest() {
    let d = detector();
    let start = Instant::now();
    let min = Duration::from_secs(60);
    let s = secret();
    for m in [0, 6, 12, 18] {
        d.record_delivery_at(T, B, false, &s, start + min * m);
    }
    let now = start + min * 23;
    d.record_delivery_at(T, A, true, &s, now);
    assert!(d.check_egress_at(B, U, &s, now).is_none());
}

/// A's sensitive copies from T are one from before the
/// window and one stamped after the egress. Neither is held at the egress
/// instant, so neither is a witness.
#[test]
fn stale_and_future_sensitive_copies_are_no_witness() {
    let d = detector();
    let stale = Instant::now();
    let now = stale + RelayParams::default().window + Duration::from_secs(1);
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now + Duration::from_millis(1));
    d.record_delivery_at(T, A, true, &s, stale);
    assert!(d.check_egress_at(B, U, &s, now).is_none());
    // Control: a sensitive copy inside the window, before the egress, is one.
    d.record_delivery_at(T, A, true, &s, now);
    assert!(d.check_egress_at(B, U, &s, now).is_some());
}

/// A pair that first got a plain copy and later a
/// sensitive one is a witness: the later sensitivity is kept.
#[test]
fn a_sensitive_copy_after_a_plain_one_is_a_witness() {
    let d = detector();
    let start = Instant::now();
    let s = secret();
    d.record_delivery_at(T, A, false, &s, start);
    d.record_delivery_at(T, A, true, &s, start + Duration::from_secs(1));
    let now = start + Duration::from_secs(2);
    assert!(d.check_egress_at(B, U, &s, now).is_some());
}
