// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The latency sketch and its bounded slots (test plan rows 1-11).

use std::time::Duration;

use super::*;

fn ms(v: f64) -> Duration {
    Duration::from_secs_f64(v / 1_000.0)
}

/// The exact p95 of `samples` under the tracker's rank rule.
fn exact_p95(samples: &mut [f64]) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[usize::try_from(p95_rank(samples.len() as u64)).unwrap()]
}

/// Row 1: each edge starts its bin; just below it is the bin before.
#[test]
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "edges up to 1.25^62 ms are under u64 nanoseconds"
)]
fn bins_have_their_stated_edges() {
    assert_eq!(bin_of(ms(0.0)), 0);
    assert_eq!(bin_of(ms(0.999)), 0);
    assert_eq!(bin_of(ms(1.0)), 1);
    // A send time is whole nanoseconds: the first one at or above an edge
    // starts the next bin, the last one below it stays in this bin.
    for i in 1..62u8 {
        let edge_ns = RATIO.powi(i32::from(i)) * 1_000_000.0;
        let at = Duration::from_nanos(edge_ns.ceil() as u64);
        let below = Duration::from_nanos(edge_ns.ceil() as u64 - 1);
        assert_eq!(bin_of(at), i + 1, "edge {i}");
        assert_eq!(bin_of(below), i, "below edge {i}");
    }
    assert_eq!(bin_of(ms(RATIO.powi(62))), BINS - 1);
    assert_eq!(bin_of(Duration::from_secs(86_400)), BINS - 1);
}

/// Row 2: the p95 sample is the one at `floor(n * 0.95)`, clamped.
#[test]
fn p95_uses_the_trackers_rank() {
    for (n, rank) in [(1, 0), (19, 18), (20, 19), (21, 19), (100, 95)] {
        assert_eq!(p95_rank(n), rank, "n = {n}");
    }
    // 21 samples, 20 fast and one slow: the p95 is a fast one.
    let mut sketch = Sketch::default();
    for _ in 0..20 {
        sketch.add(bin_of(ms(10.0)));
    }
    sketch.add(bin_of(ms(10_000.0)));
    assert_eq!(sketch.p95_bin(), Some(bin_of(ms(10.0))));
}

/// Row 3 (LAT.4): two half-hour slots at a fixed clock, each p95 the rank
/// bin's midpoint exactly.
#[test]
fn lat4_fixed_clock_two_buckets() {
    let t0 = 1_800 * 1_000_000;
    let mut series = LatencySeries::default();
    for v in [10.0, 12.0, 14.0, 400.0] {
        series.add(t0 + 5, None, ms(v), End::Answered);
    }
    for v in [100.0, 110.0, 120.0, 130.0] {
        series.add(t0 + 1_800 + 5, None, ms(v), End::Answered);
    }
    // Two slots later both are closed.
    series.finalize(t0 + 3 * 1_800, None);
    let slots = series.half.slots();
    assert_eq!(slots.len(), 2, "{slots:?}");
    assert_eq!(slots[0].p95_ms, bin_ms(bin_of(ms(400.0))));
    assert_eq!(slots[1].p95_ms, bin_ms(bin_of(ms(130.0))));
    assert_eq!((slots[0].calls, slots[1].calls), (4, 4));
}

/// Row 4: on interior bins the reported p95 is within √1.25 of the exact one.
#[test]
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a test generator's uniform floats and small counts"
)]
fn interior_p95_within_root_ratio() {
    let bound = RATIO.sqrt();
    // A fixed LCG: deterministic, no new dependency.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        (state >> 11) as f64 / (1u64 << 53) as f64
    };
    for set in 0..1_000 {
        let n = 1 + (next() * 400.0) as usize;
        // 1.5 ms .. 1.25^60 ms: every sample, so every p95, is interior.
        let mut samples: Vec<f64> = (0..n)
            .map(|_| 1.5 * (RATIO.powi(60) / 1.5).powf(next()))
            .collect();
        let mut sketch = Sketch::default();
        for v in &samples {
            sketch.add(bin_of(ms(*v)));
        }
        let bin = sketch.p95_bin().unwrap();
        assert!((1..BINS - 1).contains(&bin), "set {set}: bin {bin}");
        let exact = exact_p95(&mut samples);
        let ratio = RATIO.powf(f64::from(bin) - 0.5) / exact;
        assert!(
            (1.0 / bound..=bound).contains(&ratio),
            "set {set}: ratio {ratio}"
        );
    }
}

/// Row 5: the open bins report their edges.
#[test]
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "1.25^62 ms fits a u64"
)]
fn open_bins_report_their_edge() {
    assert_eq!(bin_ms(0), 1);
    assert_eq!(bin_ms(BINS - 1), RATIO.powi(62).ceil() as u64);
}

/// Row 6: a merge sums bin by bin and keeps the vector sorted and dense.
#[test]
fn merge_sums_per_bin() {
    let (mut a, mut b) = (Sketch::default(), Sketch::default());
    for bin in [3, 3, 9] {
        a.add(bin);
    }
    for bin in [1, 3, 20] {
        b.add(bin);
    }
    a.merge(&b);
    assert_eq!(a.bins(), &[(1, 1), (3, 3), (9, 1), (20, 1)]);
}

/// Row 7: live slots follow the clock; an idle series keeps none.
#[test]
fn live_slots_are_wall_clock() {
    let t0 = 1_800 * 1_000_000;
    let mut series = LatencySeries::default();
    series.add(t0, None, ms(5.0), End::Answered);
    series.add(t0 + 1_800, None, ms(5.0), End::Answered);
    assert_eq!(series.half.live.len(), 2);
    series.finalize(t0 + 2 * 1_800, None);
    assert_eq!(series.half.live.len(), 1, "the older slot closed");
    series.finalize(t0 + 7 * 1_800, None);
    assert!(series.half.live.is_empty(), "idle: no stale live slot");
    assert_eq!(series.half.closed.len(), 2);
}

/// Row 8: the last-hour merge is the union's sketch, whose p95 differs from
/// either slot's.
#[test]
fn one_hour_merge_equals_union_sketch() {
    let t0 = 1_800 * 1_000_000;
    let mut series = LatencySeries::default();
    let first = [10.0; 19];
    let second = [1_000.0, 1_000.0];
    for v in first {
        series.add(t0, None, ms(v), End::Answered);
    }
    for v in second {
        series.add(t0 + 1_800, None, ms(v), End::Answered);
    }
    let (merged, _, _) = series.half.live_merged();
    let mut union = Sketch::default();
    for v in first.iter().chain(&second) {
        union.add(bin_of(ms(*v)));
    }
    assert_eq!(merged, union);
    assert_eq!(merged.p95_bin(), Some(bin_of(ms(1_000.0))));
    assert_ne!(series.half.live[0].sketch.p95_bin(), merged.p95_bin());
}

/// Row 9: closing keeps the outcome counts.
#[test]
fn closed_keeps_counts() {
    let t0 = 1_800 * 1_000_000;
    let mut series = LatencySeries::default();
    series.add(t0, None, ms(5.0), End::Answered);
    series.add(t0, None, ms(5.0), End::Failed);
    series.add(t0, None, ms(5.0), End::Cancelled);
    series.add(t0, None, ms(5.0), End::TimedOut);
    series.finalize(t0 + 3 * 1_800, None);
    let slot = series.half.slots()[0];
    assert_eq!(
        (slot.calls, slot.failed, slot.timed_out, slot.late),
        (4, 2, 1, 0)
    );
}

/// Row 10: a sample for a closed slot moves its counts, never its p95.
#[test]
fn late_sample_moves_counts_not_p95() {
    let t0 = 1_800 * 1_000_000;
    let mut series = LatencySeries::default();
    series.add(t0, None, ms(5.0), End::Answered);
    series.finalize(t0 + 3 * 1_800, None);
    let before = series.half.slots()[0];
    // The clock steps back into the closed slot.
    series.add(t0 + 10, None, ms(60_000.0), End::TimedOut);
    let after = series.half.slots()[0];
    assert_eq!(after.p95_ms, before.p95_ms);
    assert_eq!((after.calls, after.timed_out, after.late), (2, 1, 1));
    assert_eq!(
        series.half.live.len(),
        0,
        "no second slot for the same bucket"
    );
}

/// Row 11: today's sketch closes when the local day moves on.
#[test]
fn day_sketch_closes_at_the_next_day() {
    let t0 = 1_800 * 1_000_000;
    let mut series = LatencySeries::default();
    series.add(t0, Some(700_000), ms(50.0), End::Answered);
    assert_eq!(series.day.live.len(), 1);
    series.finalize(t0 + 86_400, Some(700_001));
    assert!(series.day.live.is_empty());
    assert_eq!(series.day.slots()[0].p95_ms, bin_ms(bin_of(ms(50.0))));
}
