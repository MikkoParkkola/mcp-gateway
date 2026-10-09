// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8201`, `MIK-8206`: the reason a relay finding carries, and the
//! capacity bounds behind it (design §14.3 B2). Labels only: every row that
//! names a bound also checks the call is still refused or still excused.

use std::time::{Duration, Instant};

use super::sketch::{Markers, SketchStore};
use super::{CollusionDetector, RelayAction, RelayParams, RelayReason};

const BOB: &str = "principal-bob";
const CAROL: &str = "principal-carol";
/// A source no `allowed_flows` entry lets leave.
const RESTRICTED: &str = "vault:read_secret";
const EGRESS: &str = "backend:post_message";

fn detector() -> CollusionDetector {
    let mut d = CollusionDetector::new(RelayParams {
        action: RelayAction::Observe,
        ..RelayParams::default()
    });
    d.keep_every_kgram();
    d
}

/// `n` distinct words tagged `tag`, so two tags share no k-gram.
fn words(tag: &str, n: u64) -> String {
    (0..n)
        .map(|i| format!("{tag}{:x}", (i * 2_654_435_761) % 1_000_003))
        .collect::<Vec<_>>()
        .join(" ")
}

fn source(i: usize) -> String {
    format!("backend-{i}:read_doc")
}

/// The reason `who` sending `text` through flow 1 is reported for, if any.
fn reason(d: &CollusionDetector, who: &str, text: &str, now: Instant) -> Option<RelayReason> {
    d.check_egress_flows_at(who, (EGRESS, 1), text, now)
        .map(|f| f.reason)
}

/// `who` received `text` as sensitive from 64 sources whose flow lets it
/// leave, then from one no flow lets leave: one record past the cap.
fn overflow(d: &CollusionDetector, who: &str, text: &str, at: Instant) {
    for i in 0..64 {
        d.record_delivery_flows_at(&source(i), who, (true, 1), text, at);
    }
    d.record_delivery_flows_at(RESTRICTED, who, (true, 0), text, at);
}

/// A text over the per-delivery fingerprint cap, and its last 300 words:
/// what only the delivery's sketch holds.
fn big_and_tail() -> (String, String) {
    let big = words("t", 4_000);
    let tail = big.split(' ').skip(3_700).collect::<Vec<_>>().join(" ");
    (big, tail)
}

/// A plain match beside an overflow-witnessed one is a relay.
#[test]
fn a_plain_match_beside_an_overflow_is_a_relay() {
    let d = detector();
    let now = Instant::now();
    let (a, b) = (words("a", 60), words("b", 60));
    overflow(&d, CAROL, &a, now);
    d.record_delivery_flows_at(RESTRICTED, CAROL, (true, 0), &b, now);
    assert_eq!(
        reason(&d, BOB, &a, now),
        Some(RelayReason::OverflowWitness),
        "control: the overflow alone names capacity"
    );
    let both = format!("{a} {b}");
    assert_eq!(reason(&d, BOB, &both, now), Some(RelayReason::Relay));
}

/// A plain match beside an other-source one is a relay.
#[test]
fn a_plain_match_beside_an_other_source_copy_is_a_relay() {
    let d = detector();
    let now = Instant::now();
    let (a, b) = (words("a", 60), words("b", 60));
    d.record_delivery_at(&source(0), CAROL, true, &a, now);
    d.record_delivery_at(&source(0), CAROL, true, &b, now);
    d.record_delivery_at(&source(1), BOB, false, &a, now);
    assert_eq!(
        reason(&d, BOB, &a, now),
        Some(RelayReason::OtherSource),
        "control: the other-tool copy alone is named"
    );
    let both = format!("{a} {b}");
    assert_eq!(reason(&d, BOB, &both, now), Some(RelayReason::Relay));
}

/// `MIK-8206`: text past bob's per-delivery cap lives only in his sketch
/// from another tool; relaying it is named `OtherSource` while that sketch
/// is live, and a plain relay once it expires.
#[test]
fn an_over_cap_tail_from_another_tool_is_other_source_while_sketched() {
    let d = detector();
    let t0 = Instant::now();
    let (big, tail) = big_and_tail();
    d.record_delivery_at(&source(1), BOB, false, &big, t0);
    assert!(d.source_truncated() > 0, "premise: the delivery was cut");
    let live = t0 + Duration::from_secs(400);
    d.record_delivery_at(&source(0), CAROL, true, &tail, live);
    assert_eq!(reason(&d, BOB, &tail, live), Some(RelayReason::OtherSource));
    let expired = t0 + Duration::from_secs(650);
    assert_eq!(reason(&d, BOB, &tail, expired), Some(RelayReason::Relay));
}

/// A sketch refused for room leaves a marker: bob's own over-cap copy can no
/// longer excuse him, and the refusal says the detector ran out of room.
/// Control: with room, the same sketch excuses him.
#[test]
fn a_refused_sketch_is_named_as_lost() {
    let (big, tail) = big_and_tail();
    let now = Instant::now();
    let run = |cap: Option<usize>| {
        let d = detector();
        if let Some(cap) = cap {
            d.state.lock().sketches = SketchStore::with_caps(cap, cap);
        }
        d.record_delivery_at(&source(0), BOB, false, &big, now);
        d.record_delivery_at(&source(0), CAROL, true, &tail, now);
        reason(&d, BOB, &tail, now)
    };
    assert_eq!(run(None), None, "control: the sketch excuses bob");
    assert_eq!(run(Some(64)), Some(RelayReason::ExcuseLost));
}

/// `who` received `text` plainly from 64 sources, then from `source(64)`:
/// that record finds no room and is dropped.
fn dropped(d: &CollusionDetector, who: &str, text: &str, at: Instant) {
    for i in 0..65 {
        d.record_delivery_at(&source(i), who, false, text, at);
    }
}

/// Bob's exact copy from carol's source was dropped for room: named as lost.
#[test]
fn a_dropped_record_is_named_as_lost() {
    let d = detector();
    let now = Instant::now();
    let a = words("a", 60);
    dropped(&d, BOB, &a, now);
    assert!(d.capped() > 0, "premise: a record was dropped");
    d.record_delivery_at(&source(64), CAROL, true, &a, now);
    assert_eq!(reason(&d, BOB, &a, now), Some(RelayReason::ExcuseLost));
}

/// Bob's own sensitive copy overflowed his cap: named as lost.
#[test]
fn an_overflowed_holder_is_named_as_lost() {
    let d = detector();
    let now = Instant::now();
    let a = words("a", 60);
    overflow(&d, BOB, &a, now);
    d.record_delivery_flows_at(&source(70), CAROL, (true, 0), &a, now);
    assert_eq!(reason(&d, BOB, &a, now), Some(RelayReason::ExcuseLost));
}

/// A marker is source-level: one left by unrelated text labels a genuine
/// relay from that source `ExcuseLost`, and the relay is still reported.
#[test]
fn an_unrelated_marker_labels_a_relay_that_is_still_reported() {
    let d = detector();
    let now = Instant::now();
    let (a, c) = (words("a", 60), words("c", 60));
    dropped(&d, BOB, &c, now);
    d.record_delivery_at(&source(64), CAROL, true, &a, now);
    assert_eq!(reason(&d, BOB, &a, now), Some(RelayReason::ExcuseLost));
}

/// A marker never evicts a sketch: bob's same-source sketch, left before a
/// marker for that source, still excuses his over-cap copy.
#[test]
fn a_marker_leaves_the_same_source_sketch() {
    let d = detector();
    let now = Instant::now();
    let (big, tail) = big_and_tail();
    d.record_delivery_at(&source(64), BOB, false, &big, now);
    dropped(&d, BOB, &words("c", 60), now);
    d.record_delivery_at(&source(64), CAROL, true, &tail, now);
    assert_eq!(reason(&d, BOB, &tail, now), None, "the sketch was lost");
}

/// The marker map holds at most 65,536 markers, the oldest going first.
#[test]
fn the_marker_map_is_capped() {
    let now = Instant::now();
    let mut markers = Markers::default();
    for i in 0..=65_536_u64 {
        markers.mark((i, 0), now + Duration::from_secs(i));
    }
    assert!(!markers.holds((0, 0), now), "the oldest outlived the cap");
    assert!(markers.holds((1, 0), now), "more than the oldest went");
    assert!(markers.holds((65_536, 0), now), "the newest went");
}

/// A sketch that expires was not lost for room: it leaves no marker.
#[test]
fn an_expired_sketch_is_not_lost() {
    let now = Instant::now();
    let mut store = SketchStore::default();
    assert!(store.insert((1, 2), &[1, 2, 3], now));
    store.sweep(now + Duration::from_secs(700), Duration::from_secs(600));
    assert!(store.take_lost().is_empty(), "expiry counted as lost");
}

/// The value of `mcp_gateway_collusion_capacity_total{bound}`, 0 while absent.
/// Counters only grow, so a row reads "grew" and other rows cannot fail it.
#[cfg(feature = "metrics")]
fn bound_count(bound: &str) -> u64 {
    crate::metrics::install();
    let prefix = format!("mcp_gateway_collusion_capacity_total{{bound=\"{bound}\"}} ");
    crate::metrics::render()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0)
}

/// `MIK-8201.VIS.1`: `event` grows the `bound` series.
#[cfg(feature = "metrics")]
fn grows(bound: &str, event: impl FnOnce()) {
    let before = bound_count(bound);
    event();
    assert!(bound_count(bound) > before, "{bound} was not counted");
}

#[cfg(feature = "metrics")]
#[test]
fn every_capacity_bound_is_counted() {
    let now = Instant::now();
    let a = words("a", 60);
    grows("fingerprint_evicted", || {
        let mut d = CollusionDetector::new(RelayParams {
            action: RelayAction::Observe,
            max_fingerprints: 1,
            ..RelayParams::default()
        });
        d.keep_every_kgram();
        d.record_delivery_at(&source(0), CAROL, true, &a, now);
    });
    grows("receipt_truncated", || {
        detector().record_delivery_at(&source(0), CAROL, true, &big_and_tail().0, now);
    });
    grows("record_dropped", || dropped(&detector(), BOB, &a, now));
    grows("record_replaced", || {
        let d = detector();
        for i in 0..64 {
            d.record_delivery_at(&source(i), BOB, false, &a, now);
        }
        d.record_delivery_at(&source(64), BOB, true, &a, now);
    });
    grows("record_overflow", || overflow(&detector(), BOB, &a, now));
    grows("sketch_refused", || {
        assert!(SketchStore::default().reserve((1, 2), usize::MAX).is_none());
    });
    grows("sketch_evicted", || {
        let one = super::sketch::shape(3, 0).bytes();
        let mut store = SketchStore::with_caps(one, usize::MAX);
        assert!(store.insert((1, 2), &[1, 2, 3], now));
        assert!(store.insert((3, 4), &[4, 5, 6], now));
    });
    grows("marker_evicted", || {
        let mut markers = Markers::default();
        for i in 0..=65_536_u64 {
            markers.mark((i, 0), now);
        }
    });
}
