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
/// bin's midpoint exactly. 400 ms is in bin 27, [1.25^26, 1.25^27) =
/// [330.87, 413.59) ms, midpoint 1.25^26.5 = 369.93, reported 370; 130 ms is
/// in bin 22, [108.42, 135.53) ms, midpoint 121.22, reported 121.
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
    assert_eq!(slots[0].p95_ms, 370);
    assert_eq!(slots[1].p95_ms, 121);
    assert_eq!((slots[0].calls, slots[1].calls), (4, 4));
}

/// Row 4a: the sketch's p95 bin is exactly the bin of the exact p95 sample,
/// on every set (which, with row 4b's midpoints, bounds the reported value).
#[test]
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a test generator's uniform floats and small counts"
)]
fn p95_bin_is_the_exact_samples_bin() {
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
        assert_eq!(bin, bin_of(ms(exact)), "set {set}: exact p95 {exact} ms");
    }
}

/// Row 4b: the value each bin reports, hand-computed as the round-half-up of
/// its geometric midpoint 1.25^(b - 0.5) ms: bin 10 [7.45, 9.31) -> 8.33 -> 8,
/// bin 22 -> 121.22 -> 121, bin 27 -> 369.93 -> 370, bin 40 -> 6728.92 -> 6729,
/// bin 62 -> 911939.02 -> 911939.
#[test]
fn interior_bins_report_their_midpoint() {
    for (bin, reported) in [(10, 8), (22, 121), (27, 370), (40, 6_729), (62, 911_939)] {
        assert_eq!(Sketch::from_bins(vec![(bin, 1)]).p95_ms(), Some(reported), "bin {bin}");
    }
}

/// Sub-10 ms p95s are whole milliseconds by design (a recorded LAT.4
/// deviation): bin 2, [1.25, 1.5625) ms, reports exactly 1 and bin 3,
/// [1.5625, 1.95) ms, exactly 2: there the 0.5 ms of rounding outweighs the
/// √1.25 bin width. A change to this rounding is a decision.
#[test]
fn sub_10ms_p95_is_whole_ms_rounded() {
    let one_and_a_half = Sketch::from_bins(vec![(bin_of(ms(1.5)), 1)]);
    assert_eq!(bin_of(ms(1.5)), 2);
    assert_eq!(one_and_a_half.p95_ms(), Some(1));
    assert_eq!(Sketch::from_bins(vec![(3, 1)]).p95_ms(), Some(2));
    assert_eq!(Sketch::from_bins(vec![(5, 1)]).p95_ms(), Some(3));
}

/// The stated bound: for the lowest and the highest sample of every interior
/// bin, the reported value is within a factor √1.25 of the sample, plus up to
/// 0.5 ms of rounding (an 11.6 ms sample reports 10 ms: 10 >= 11.6/√1.25 - 0.5).
#[test]
fn interior_p95_within_root_ratio_plus_rounding() {
    let root = RATIO.sqrt();
    for bin in 1..BINS - 1 {
        // The lowest whole-ns sample in the bin: its edge, rounded up to a ns.
        let low = (RATIO.powi(i32::from(bin) - 1) * 1e6).ceil() / 1e6;
        // 2 ns under the bin's upper edge, the highest sample it holds.
        let high = RATIO.powi(i32::from(bin)) - 2e-6;
        for sample in [low, high] {
            assert_eq!(bin_of(ms(sample)), bin, "sample {sample} ms");
            let reported = Sketch::from_bins(vec![(bin_of(ms(sample)), 1)])
                .p95_ms()
                .expect("one sample");
            #[expect(clippy::cast_precision_loss, reason = "at most 1.25^62 ms, exact in f64")]
            let reported = reported as f64;
            assert!(
                (sample / root - 0.5..=sample * root + 0.5).contains(&reported),
                "bin {bin}: sample {sample} ms reported {reported} ms"
            );
        }
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

/// Row 12b: a series busy in every slot keeps 96 half-hours and 30 days; the
/// next slot evicts the oldest.
#[test]
fn retention_holds_96_half_hours_and_30_days() {
    let t0 = 1_800 * 1_000_000;
    let mut series = LatencySeries::default();
    for slot in 0..97u64 {
        series.add(t0 + slot * 1_800, None, ms(5.0), End::Answered);
    }
    let held = series.half.slots();
    assert_eq!(held.len(), 96);
    assert_eq!(held[0].bucket, t0 / 1_800 + 1, "the first slot was evicted");
    for day in 0..31u64 {
        series.add(
            t0 + 97 * 1_800 + day * 86_400,
            Some(700_100 + day),
            ms(5.0),
            End::Answered,
        );
    }
    let days = series.day.slots();
    assert_eq!(days.len(), 30);
    assert_eq!(days[0].bucket, 700_101);
}

/// Review #11: a restored file is a system boundary. Bins past the last,
/// zero counts and duplicate bins in a live histogram, duplicate slots, and
/// more live slots than a ring keeps are dropped, summed or cut back.
#[test]
fn restore_reapplies_the_bounds() {
    let now = 1_800 * 1_000_000 / 1_800;
    let file: SeriesFile = serde_json::from_value(serde_json::json!({
        "half": {
            "live": [
                [now, 9, 0, 0, [[70, 5], [3, 2], [3, 1], [1, 0]]],
                [now, 1, 0, 0, [[2, 1]]],
                [now - 1, 1, 0, 0, [[4, 1]]],
                [now - 3, 1, 0, 0, [[5, 1]]],
            ],
            "closed": [[now - 9, 10, 1, 0, 0], [now - 9, 20, 1, 0, 0], [now - 8, 30]],
        },
    }))
    .expect("a file of the right shape");
    let series = LatencySeries::from_file(&file, now * 1_800, None);
    let live: Vec<(u64, Vec<(u8, u32)>)> = series
        .half
        .live
        .iter()
        .map(|l| (l.bucket, l.sketch.bins().to_vec()))
        .collect();
    assert_eq!(live, [(now - 1, vec![(4, 1)]), (now, vec![(3, 3)])], "{live:?}");
    let closed: Vec<(u64, u64)> = series.half.closed.iter().map(|c| (c.bucket, c.p95_ms)).collect();
    // The duplicate closed row and the two-field one are gone; the extra
    // live slot is closed, not lost.
    assert_eq!(closed, [(now - 9, 10), (now - 3, bin_ms(5))], "{closed:?}");
}

/// Review #12 (dedup is on the operator list; no visibility change here): the
/// sketch's p95 rank and the failsafe tracker's (`percentile_index`) agree.
/// The same whole-ms samples, each a factor 1.3 apart so every sample has a
/// bin of its own, go to both; the tracker's p95 sample is in the sketch's
/// p95 bin, so a rank one apart would show.
#[test]
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "whole, positive ms under 2 * 1.3^40, about 72 seconds"
)]
fn p95_rank_agrees_with_the_failsafe_tracker() {
    for n in [1_u32, 19, 20, 21, 40] {
        let tracker = crate::failsafe::HealthTracker::new("rank");
        let mut sketch = Sketch::default();
        for k in 0..n {
            let ms_whole = (2.0 * 1.3_f64.powi(i32::try_from(k).unwrap())).round();
            let sample = Duration::from_millis(ms_whole as u64);
            tracker.record_success(sample);
            sketch.add(bin_of(sample));
        }
        let tracker_p95 = tracker.metrics().latency_p95_ms.expect("samples recorded");
        assert_eq!(
            sketch.p95_bin(),
            Some(bin_of(Duration::from_millis(tracker_p95))),
            "n = {n}: tracker p95 {tracker_p95} ms"
        );
    }
}
