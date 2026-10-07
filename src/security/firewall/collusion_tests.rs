// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Tests for the relay detector: design §8 rows 3-10, 14, 17, 18.
//!
//! Every test that asserts "no finding" carries a positive control on the same
//! text, so an inert detector cannot pass it.

use std::time::{Duration, Instant};

use std::collections::HashSet;

use super::{CollusionDetector, MAX_SOURCE_FINGERPRINTS, RelayAction, RelayParams, W, winnow};

const A: &str = "principal-a";
const B: &str = "principal-b";
const T: &str = "backend:read_doc";
const U: &str = "backend:post_message";

fn observe() -> RelayParams {
    RelayParams {
        action: RelayAction::Observe,
        ..RelayParams::default()
    }
}

fn detector() -> CollusionDetector {
    CollusionDetector::new(observe())
}

/// Non-periodic ASCII prose from a fixed-seed LCG: single-spaced, so
/// normalization never changes its length, and no k-gram repeats in practice.
fn text(seed: u64, words: usize) -> String {
    const SYLLABLES: [&str; 16] = [
        "ka", "lo", "mi", "nu", "pe", "ri", "so", "ta", "ve", "zu", "ba", "de", "fi", "go", "hu",
        "ja",
    ];
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    let mut out = String::new();
    for i in 0..words {
        if i > 0 {
            out.push(' ');
        }
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let len = 2 + usize::try_from(state >> 60).unwrap() % 3;
        for j in 0..len {
            let idx = usize::try_from((state >> (8 * j + 4)) & 0xF).unwrap();
            out.push_str(SYLLABLES[idx]);
        }
    }
    out
}

fn secret() -> String {
    text(7, 250)
}

/// First offset from 200 where a 63- and a 79-char slice neither start nor
/// end on a space, so normalization cannot shorten them.
fn solid_start(s: &str) -> usize {
    let b = s.as_bytes();
    (200..s.len() - 79)
        .find(|&i| b[i] != b' ' && b[i + 62] != b' ' && b[i + 78] != b' ')
        .unwrap()
}

fn shared(d: &CollusionDetector, a: &str, b: &str) -> usize {
    let fa = d.fingerprints(a);
    d.fingerprints(b).iter().filter(|f| fa.contains(f)).count()
}

// Row 3 ────────────────────────────────────────────────────────────────────

#[test]
fn prefixed_copy_detected() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now);
    let finding = d
        .check_egress_at(B, U, &format!("x{s}"), now)
        .expect("a one-char-shifted copy must match");
    assert_eq!(finding.sender, d.digest(B));
    assert_eq!(finding.receiver, d.digest(A));
    assert_eq!(finding.source, d.digest(T));
    assert_eq!(finding.tool, d.digest(U));
}

#[test]
fn embedded_excerpt_detected() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now);
    let payload = format!("{} {} {}", text(101, 600), &s[400..500], text(202, 600));
    assert!(d.check_egress_at(B, U, &payload, now).is_some());
}

/// Input sanitization strips control and zero-width characters before a
/// backend sees the arguments, so a copy interleaved with them is the same
/// copy and must match (sanitize bypass).
#[test]
fn copy_interleaved_with_stripped_characters_detected() {
    let now = Instant::now();
    let s = secret();
    for sep in ['\u{200B}', '\u{2028}', '\u{1}'] {
        let d = detector();
        d.record_delivery_at(T, A, true, &s, now);
        let evasive: String = s
            .chars()
            .enumerate()
            .flat_map(|(i, c)| std::iter::once(c).chain((i % 20 == 19).then_some(sep)))
            .collect();
        assert!(
            d.check_egress_at(B, U, &evasive, now).is_some(),
            "a copy interleaved with {sep:?} must match"
        );
    }
}

/// The winnowing guarantee itself: every 63-char span of a document shares a
/// fingerprint with it. A fixed stride or a global bottom-N sample leaves
/// spans with none.
#[test]
fn every_63_char_span_shares_a_fingerprint() {
    let d = detector();
    // Several times more k-grams than the 1,024-fingerprint source cap, so a
    // global bottom-1024 sample cannot reach every span.
    let s = text(7, 2_000);
    let all: HashSet<u64> = d.fingerprints(&s).into_iter().collect();
    assert!(!all.is_empty());
    for start in 0..=s.len() - 63 {
        let span = &s[start..start + 63];
        // Normalization trims edge spaces, which would shorten the span.
        if span.starts_with(' ') || span.ends_with(' ') {
            continue;
        }
        let span = d.fingerprints(span);
        assert!(
            span.iter().any(|f| all.contains(f)),
            "span at {start} shares no fingerprint"
        );
    }
}

/// The same guarantee on controlled hash values, independent of the key:
/// every window's minimum is kept. 1,100 low hashes then a high run: a global
/// bottom-N for any N up to 1,100 (so the 1,024 source cap included) drops
/// every high minimum, and a fixed stride skips positions.
#[test]
fn winnow_keeps_every_window_minimum() {
    let hashes: Vec<u64> = (0..1_100).chain((10_000..10_064).rev()).collect();
    let kept: HashSet<u64> = winnow(&hashes).into_iter().collect();
    for window in hashes.windows(W) {
        let min = window.iter().min().unwrap();
        assert!(kept.contains(min), "window minimum {min} dropped");
    }
    assert!(kept.iter().any(|&h| h >= 10_000));
}

// Row 4 ────────────────────────────────────────────────────────────────────

#[test]
fn same_source_self_copy_excused() {
    let now = Instant::now();
    let s = secret();

    let control = detector();
    control.record_delivery_at(T, A, true, &s, now);
    assert!(control.check_egress_at(B, U, &s, now).is_some());

    let d = detector();
    d.record_delivery_at(T, A, true, &s, now);
    d.record_delivery_at(T, B, false, &s, now);
    assert!(d.check_egress_at(B, U, &s, now).is_none());
}

// Row 5 ────────────────────────────────────────────────────────────────────

#[test]
fn shared_store_relay_not_excused() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now);
    d.record_delivery_at("memory:recall", B, false, &s, now);
    assert!(d.check_egress_at(B, U, &s, now).is_some());
}

// Row 6 ────────────────────────────────────────────────────────────────────

/// A holds it sensitive; `others` more principals hold it from other sources.
/// Deliveries are stamped `now`, so the caller checks egress at the same instant.
fn spread(others: usize, now: Instant) -> CollusionDetector {
    let d = detector();
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now);
    for i in 0..others {
        d.record_delivery_at(&format!("src-{i}"), &format!("p-{i}"), false, &s, now);
    }
    d
}

#[test]
fn common_content_skipped() {
    let now = Instant::now();
    let s = secret();
    // 4 distinct holders: below common_principals (5), still a relay.
    assert!(spread(3, now).check_egress_at(B, U, &s, now).is_some());
    // 5 distinct holders: Common, skipped.
    assert!(spread(4, now).check_egress_at(B, U, &s, now).is_none());
}

// Row 7 ────────────────────────────────────────────────────────────────────

#[test]
fn one_match_not_flagged() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    // k + w - 1 = 63 chars: 16 k-grams, one winnowing window, one fingerprint.
    let at = solid_start(&s);
    let excerpt = &s[at..at + 63];
    assert_eq!(d.fingerprints(excerpt).len(), 1, "premise: one fingerprint");
    assert_eq!(
        shared(&d, &s, excerpt),
        1,
        "premise: shared with the source"
    );
    d.record_delivery_at(T, A, true, &s, now);
    assert!(d.check_egress_at(B, U, excerpt, now).is_none());
    // Control: 79 chars hold two disjoint 16-hash windows, so two matches.
    assert!(d.check_egress_at(B, U, &s[at..at + 79], now).is_some());
}

#[test]
fn two_matches_flagged() {
    let d = detector();
    let now = Instant::now();
    // Space-free, so every prefix length keeps its length through
    // normalization and the count can be walked one char at a time.
    let s = secret().replace(' ', "");
    let at = 200;
    let end = (at + 64..=at + 79)
        .find(|&end| shared(&d, &s, &s[at..end]) == 2)
        .expect("premise: two shared fingerprints by 79 chars");
    d.record_delivery_at(T, A, true, &s, now);
    let finding = d
        .check_egress_at(B, U, &s[at..end], now)
        .expect("two matches meet the default min_matches");
    assert_eq!(finding.matches, 2);
}

// Row 8 ────────────────────────────────────────────────────────────────────

/// "Drop A != B" is an equivalent mutant: A's own (T, A) tuple is also A's
/// same-source excuse. Kept as a behavioural pin, not claimed as a kill.
#[test]
fn self_relay_not_flagged() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    d.record_delivery_at(T, A, true, &s, now);
    assert!(d.check_egress_at(A, U, &s, now).is_none());
    assert!(d.check_egress_at(B, U, &s, now).is_some());
}

/// An allowed flow: a copy whose source matched an `allowed_flows` entry the
/// egress also matched is no relay; another entry, or none, still is.
#[test]
fn allowed_flow_not_flagged() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    d.record_delivery_flows_at(T, A, (true, 0b01), &s, now);
    assert!(d.check_egress_flows_at(B, (U, 0b01), &s, now).is_none());
    assert!(d.check_egress_flows_at(B, (U, 0b11), &s, now).is_none());
    assert!(d.check_egress_flows_at(B, (U, 0b10), &s, now).is_some());
    assert!(d.check_egress_flows_at(B, (U, 0), &s, now).is_some());
}

// Row 9 ────────────────────────────────────────────────────────────────────

#[test]
fn relay_outside_window_not_flagged() {
    let t0 = Instant::now();
    let s = secret();
    let window = RelayParams::default().window;

    let inside = detector();
    inside.record_delivery_at(T, A, true, &s, t0);
    let before = t0 + window.checked_sub(Duration::from_secs(1)).unwrap();
    assert!(inside.check_egress_at(B, U, &s, before).is_some());

    // "Within the window" is inclusive.
    let edge = detector();
    edge.record_delivery_at(T, A, true, &s, t0);
    assert!(edge.check_egress_at(B, U, &s, t0 + window).is_some());

    let outside = detector();
    outside.record_delivery_at(T, A, true, &s, t0);
    let after = t0 + window + Duration::from_secs(1);
    assert!(outside.check_egress_at(B, U, &s, after).is_none());
}

/// A non-sensitive re-delivery refreshes the pair's time but not its
/// sensitivity: the sensitive receipt still ages out on schedule.
#[test]
fn stale_sensitivity_not_refreshed() {
    let t0 = Instant::now();
    let s = secret();
    let window = RelayParams::default().window;
    let d = detector();
    d.record_delivery_at(T, A, true, &s, t0);
    d.record_delivery_at(
        T,
        A,
        false,
        &s,
        t0 + window.checked_sub(Duration::from_secs(1)).unwrap(),
    );
    assert!(d.check_egress_at(B, U, &s, t0 + window).is_some());
    let late = t0 + window + Duration::from_secs(1);
    assert!(d.check_egress_at(B, U, &s, late).is_none());
}

/// Calls can reach the lock out of time order. An older delivery arriving
/// late must not pull back B's excuse or A's evidence.
#[test]
fn late_older_delivery_keeps_latest_times() {
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(300);
    let s = secret();
    let window = RelayParams::default().window;
    let between = t0 + window + Duration::from_secs(1);

    // B's excuse at t1, then a stale copy of it at t0: still excused.
    let excuse = detector();
    excuse.record_delivery_at(T, A, true, &s, t1);
    excuse.record_delivery_at(T, B, false, &s, t1);
    excuse.record_delivery_at(T, B, false, &s, t0);
    assert!(excuse.check_egress_at(B, U, &s, between).is_none());

    // A's evidence at t1, then a stale copy at t0: still a relay.
    let evidence = detector();
    evidence.record_delivery_at(T, A, true, &s, t1);
    evidence.record_delivery_at(T, A, true, &s, t0);
    assert!(evidence.check_egress_at(B, U, &s, between).is_some());
}

// Row 10 ───────────────────────────────────────────────────────────────────

#[test]
fn dedup_per_pair() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    for i in 0..20 {
        d.record_delivery_at(T, A, true, &s, now + Duration::from_millis(i));
    }
    // Appending duplicates would saturate every fingerprint at the 9th.
    assert!(
        d.check_egress_at(B, U, &s, now + Duration::from_secs(1))
            .is_some()
    );
    assert_eq!(d.saturated(), 0);
}

#[test]
fn cap_evicts_oldest_counted() {
    // The key is per process, so a probe detector fingerprints as `d` does.
    let probe = detector();
    let old = secret();
    let new = text(99, 250);
    let old_len = probe.fingerprints(&old).len();
    let new_len = probe.fingerprints(&new).len();
    assert!(
        old_len > 0 && new_len > 0,
        "premise: both texts fingerprint"
    );
    assert!(
        old_len <= 1_024 && new_len <= 1_024,
        "premise: no source truncation"
    );
    assert_eq!(shared(&probe, &old, &new), 0, "premise: disjoint texts");

    let d = CollusionDetector::new(RelayParams {
        max_fingerprints: new_len,
        ..observe()
    });
    let t0 = Instant::now();
    d.record_delivery_at(T, A, true, &old, t0);
    d.record_delivery_at("backend:other", A, true, &new, t0 + Duration::from_secs(1));
    let now = t0 + Duration::from_secs(2);
    // Old entries are all older than new ones, so each eviction takes an old
    // one: exactly `old_len` evictions whatever the two sizes, none of new.
    assert_eq!(d.tracked_fingerprints(), new_len);
    assert_eq!(d.evicted(), u64::try_from(old_len).unwrap());
    assert!(d.check_egress_at(B, U, &old, now).is_none());
    assert!(d.check_egress_at(B, U, &new, now).is_some());
}

// Row 14 ───────────────────────────────────────────────────────────────────

#[test]
fn finding_has_no_content() {
    let d = detector();
    let now = Instant::now();
    let s = secret();
    let args = format!("please forward: {s}");
    d.record_delivery_at(T, A, true, &s, now);
    let finding = d.check_egress_at(B, U, &args, now).expect("a relay");
    let rendered = format!("{finding:?}");
    for text in [s.as_str(), args.as_str()] {
        let chars: Vec<char> = text.chars().collect();
        for window in chars.windows(16) {
            let piece: String = window.iter().collect();
            assert!(!rendered.contains(&piece), "finding leaks content: {piece}");
        }
    }
}

#[test]
fn off_records_nothing() {
    let now = Instant::now();
    let s = secret();

    let on = detector();
    on.record_delivery_at(T, A, true, &s, now);
    assert!(on.tracked_fingerprints() > 0);
    assert!(on.check_egress_at(B, U, &s, now).is_some());

    let off = CollusionDetector::new(RelayParams::default());
    off.record_delivery_at(T, A, true, &s, now);
    assert_eq!(off.tracked_fingerprints(), 0);
    assert!(off.check_egress_at(B, U, &s, now).is_none());
}

// Row 17 ───────────────────────────────────────────────────────────────────

#[test]
fn excuse_holds_when_b_first() {
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_secs(1);
    let s = secret();

    let control = detector();
    control.record_delivery_at(T, A, true, &s, t1);
    assert!(control.check_egress_at(B, U, &s, t1).is_some());

    let d = detector();
    d.record_delivery_at(T, B, false, &s, t0);
    d.record_delivery_at(T, A, true, &s, t1);
    assert!(d.check_egress_at(B, U, &s, t1).is_none());
}

// Row 18 ───────────────────────────────────────────────────────────────────

/// Optional excuse for B first, then A's sensitive copy, then `fillers` more
/// (source, principal) tuples. `Common` is set out of reach so only the
/// tuple bound is in play.
fn crowded(with_excuse: bool, fillers: usize, now: Instant) -> CollusionDetector {
    let d = CollusionDetector::new(RelayParams {
        common_principals: 100,
        ..observe()
    });
    let s = secret();
    if with_excuse {
        d.record_delivery_at(T, B, false, &s, now);
    }
    d.record_delivery_at(T, A, true, &s, now);
    for i in 0..fillers {
        d.record_delivery_at(&format!("src-{i}"), &format!("p-{i}"), false, &s, now);
    }
    d
}

#[test]
fn saturated_fingerprint_never_flags() {
    let now = Instant::now();
    let s = secret();
    // Controls at 8 tuples: the excuse holds, and without it the relay flags.
    assert!(
        crowded(true, 6, now)
            .check_egress_at(B, U, &s, now)
            .is_none()
    );
    assert!(
        crowded(false, 7, now)
            .check_egress_at(B, U, &s, now)
            .is_some()
    );
    // A 9th tuple saturates: evicting the oldest would drop B's excuse.
    let d = crowded(true, 7, now);
    assert!(d.saturated() > 0);
    assert!(d.check_egress_at(B, U, &s, now).is_none());
    // Saturated never counts, even with no excuse to hide behind.
    let bare = crowded(false, 8, now);
    assert!(bare.saturated() > 0);
    assert!(bare.check_egress_at(B, U, &s, now).is_none());
}

// The primitive ────────────────────────────────────────────────────────────

#[test]
fn short_text_has_no_fingerprints() {
    let d = detector();
    assert!(d.fingerprints(&"x".repeat(47)).is_empty());
    assert!(!d.fingerprints(&secret()[..48]).is_empty());
    // k-grams count characters, not bytes: 48 two-byte chars are one k-gram.
    assert_eq!(d.fingerprints(&"\u{e9}".repeat(48)).len(), 1);
    assert!(d.fingerprints(&"\u{e9}".repeat(47)).is_empty());
}

#[test]
fn whitespace_and_nfc_normalized() {
    let d = detector();
    // Every syllable with an 'e' carries the accent, so nearly every k-gram
    // changes if normalization is skipped.
    let s = secret().replace('e', "\u{e9}");
    let spaced = s.replace(' ', "  \n ");
    let decomposed = s.replace('\u{e9}', "e\u{301}");
    assert!(!d.fingerprints(&s).is_empty());
    assert_eq!(d.fingerprints(&s), d.fingerprints(&spaced));
    assert_eq!(d.fingerprints(&s), d.fingerprints(&decomposed));
}

#[test]
fn source_fingerprints_capped() {
    let d = detector();
    let big = text(5, 24_000);
    let cap = MAX_SOURCE_FINGERPRINTS;
    assert!(
        d.fingerprints(&big).len() > cap,
        "premise: oversized result"
    );
    d.record_delivery_at(T, A, true, &big, Instant::now());
    assert_eq!(d.tracked_fingerprints(), cap);
    let first = d.fingerprints(&big);
    assert!(
        first[..cap].iter().all(|&fp| d.is_tracked(fp)),
        "keeps the first {cap}"
    );
    let dropped = d.fingerprints(&big).len() - cap;
    assert_eq!(d.source_truncated(), u64::try_from(dropped).unwrap());
}

// MIK-7696: a holder dated after the egress ───────────────────────────────
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

/// MIK-7881.RELAY.1: B's copies from T are one from before the window and one
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

/// MIK-7881.RELAY.1: thinning B's copies never drops the one held at the
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

/// MIK-7881.RELAY.1: past the copy cap the oldest copy goes, not the newest.
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

/// MIK-7881.RELAY.1: A's sensitive copies from T are one from before the
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

/// MIK-7881.RELAY.1: a pair that first got a plain copy and later a
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

/// `RELAY-SPLIT-FP.2` (MIK-7773): a receipt runs only values together, as
/// egress does, never a value into a long object key: an excuse may cover
/// only what an egress of the same pieces would read.
#[test]
fn a_split_receipt_never_runs_a_value_into_a_key() {
    use super::super::collusion_digest::{DeliveryDigest, delivery_parts};
    let d = detector();
    let flat = text(9, 40);
    let key = text(11, 20);
    assert!(
        key.chars().count() >= super::K,
        "premise: a key long enough to read"
    );
    let mut map = serde_json::Map::new();
    for (i, piece) in flat.as_bytes().chunks(20).enumerate() {
        let piece = String::from_utf8(piece.to_vec()).expect("ascii");
        map.insert(format!("p{i:03}"), serde_json::Value::String(piece));
    }
    map.insert(key, serde_json::Value::String("v".into()));
    let value = serde_json::Value::Object(map);
    let (leaves, values) = delivery_parts(&value);
    assert_eq!(values, leaves.len() - 1, "the key comes last");
    let (digest, _) = DeliveryDigest::of_parts(&leaves, values, false);
    let allowed: HashSet<u64> = [leaves.join("\n"), leaves[..values].concat()]
        .iter()
        .flat_map(|t| d.kgram_hashes(t))
        .collect();
    assert!(
        d.fingerprints(&leaves.concat())
            .iter()
            .any(|fp| !allowed.contains(fp)),
        "premise: running the key in adds fingerprints"
    );
    assert!(
        digest
            .fingerprints(&d)
            .iter()
            .all(|fp| allowed.contains(fp))
    );
}
