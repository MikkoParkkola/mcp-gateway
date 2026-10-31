// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-server backend latency for the web UI's history: a p95
//! per half-hour and per local day, beside each server's call counts.
//!
//! One sample per counted call: its summed backend send time, taken by the
//! send sites and recorded where the call is counted. Only the slots that
//! can still change keep a histogram (the two newest half-hours by the
//! clock, and today); a closed slot keeps its p95 and counts, so a series
//! is bounded by its slot count, never by how its latencies spread.

use std::collections::VecDeque;
use std::sync::LazyLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Histogram bins: bin 0 is under 1 ms, bin `i` in 1..=62 is
/// `[1.25^(i-1), 1.25^i)` ms, bin 63 is everything from `1.25^62` ms
/// (about 27 minutes) up.
pub(crate) const BINS: u8 = 64;
const RATIO: f64 = 1.25;

/// Calls a server needs in the Overview's window before it can be named
/// slowest. Under the p95 rank `floor(n * 0.95)`, n = 20 picks rank 19, the
/// slowest call itself, so one slow call would decide; 21 is the first n
/// whose p95 is not the last sample.
pub(crate) const SLOWEST_FLOOR: u64 = 21;

/// Half-hour slots that keep a histogram: the current one and the one
/// before, which the Overview's last-hour window merges.
pub(crate) const LIVE_HALF: u64 = 2;

/// The bin edges in nanoseconds: `EDGES_NS[i] = 1.25^i ms`, the lower edge
/// of bin `i + 1`. Compared with whole nanoseconds, which an `f64` holds
/// exactly below 2^53 (about 104 days), so a send on an edge never rounds
/// across it.
static EDGES_NS: LazyLock<[f64; 63]> = LazyLock::new(|| {
    let mut edges = [0.0; 63];
    for (i, edge) in edges.iter_mut().enumerate() {
        *edge = RATIO.powi(i32::try_from(i).unwrap_or(i32::MAX)) * 1_000_000.0;
    }
    edges
});

/// The bin a send of `elapsed` falls in.
#[expect(
    clippy::cast_precision_loss,
    reason = "exact below 2^53 ns; any longer send is in the top bin either way"
)]
pub(crate) fn bin_of(elapsed: Duration) -> u8 {
    let ns = elapsed.as_nanos() as f64;
    // Edges at or below `ns`: 0 under 1 ms, 63 at the top edge and above.
    u8::try_from(EDGES_NS.partition_point(|edge| *edge <= ns)).unwrap_or(BINS - 1)
}

/// The value a bin reports, in whole ms: the geometric midpoint of an
/// interior bin, rounded (within a factor of √1.25 of any sample in it, plus
/// up to 0.5 ms of rounding), the edge of the two open bins (no relative
/// bound).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "at most 1.25^62 ms, about 1.6 million"
)]
pub(crate) fn bin_ms(bin: u8) -> u64 {
    match bin {
        0 => 1,
        b if b >= BINS - 1 => (EDGES_NS[62] / 1_000_000.0).ceil() as u64,
        b => RATIO.powf(f64::from(b) - 0.5).round() as u64,
    }
}

/// The p95's 0-based rank among `n` samples: the failsafe tracker's rule
/// (`failsafe::health::percentile_index`), so a series p95 and the live p95
/// mean the same thing.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "a sample count; the rank is clamped to n - 1"
)]
fn p95_rank(n: u64) -> u64 {
    ((n as f64 * 0.95).floor() as u64).min(n.saturating_sub(1))
}

/// A sparse histogram: non-zero bins only, ascending.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Sketch(Vec<(u8, u32)>);

impl Sketch {
    /// Count one sample in `bin`.
    pub(crate) fn add(&mut self, bin: u8) {
        match self.0.binary_search_by_key(&bin, |(b, _)| *b) {
            Ok(i) => self.0[i].1 = self.0[i].1.saturating_add(1),
            Err(i) => self.0.insert(i, (bin, 1)),
        }
    }

    /// Add `other`'s counts, bin by bin.
    pub(crate) fn merge(&mut self, other: &Self) {
        for &(bin, count) in &other.0 {
            match self.0.binary_search_by_key(&bin, |(b, _)| *b) {
                Ok(i) => self.0[i].1 = self.0[i].1.saturating_add(count),
                Err(i) => self.0.insert(i, (bin, count)),
            }
        }
    }

    /// Samples held.
    pub(crate) fn total(&self) -> u64 {
        self.0.iter().map(|&(_, c)| u64::from(c)).sum()
    }

    /// The bin holding the p95 sample, when there is one.
    pub(crate) fn p95_bin(&self) -> Option<u8> {
        let n = self.total();
        if n == 0 {
            return None;
        }
        let rank = p95_rank(n);
        let mut seen = 0u64;
        self.0.iter().find_map(|&(bin, count)| {
            seen += u64::from(count);
            (seen > rank).then_some(bin)
        })
    }

    /// The p95 in ms, when there is one.
    pub(crate) fn p95_ms(&self) -> Option<u64> {
        self.p95_bin().map(bin_ms)
    }

    /// A sketch holding exactly `bins` (ascending, non-zero), for the size rows.
    #[cfg(test)]
    pub(crate) fn from_bins(bins: Vec<(u8, u32)>) -> Self {
        Self(bins)
    }

    /// The bins, ascending.
    #[cfg(test)]
    pub(crate) fn bins(&self) -> &[(u8, u32)] {
        &self.0
    }
}

/// How a call's backend send ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// The backend answered: a result, a tool's `isError`, or an answer the
    /// response firewall then refused.
    Answered,
    /// The send began and failed after it.
    Failed,
    /// The send ran into its timeout.
    TimedOut,
    /// The send was dropped before it finished; counted with `Failed`.
    Cancelled,
}

/// A slot that can still change: its histogram and its outcome counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Live {
    pub(crate) bucket: u64,
    pub(crate) sketch: Sketch,
    pub(crate) failed: u32,
    pub(crate) timed_out: u32,
}

/// A closed slot: its p95 over the samples it held when it closed, and its
/// counts. `late` samples arrived after it closed: they are in `calls` and
/// the outcome counts, never in `p95_ms`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Closed {
    pub(crate) bucket: u64,
    /// 0 when no sample reached the p95 (`calls == late`).
    pub(crate) p95_ms: u64,
    pub(crate) calls: u32,
    pub(crate) failed: u32,
    pub(crate) timed_out: u32,
    pub(crate) late: u32,
}

impl Live {
    fn note(&mut self, end: End) {
        match end {
            End::Answered => {}
            End::Failed | End::Cancelled => self.failed = self.failed.saturating_add(1),
            End::TimedOut => self.timed_out = self.timed_out.saturating_add(1),
        }
    }

    pub(super) fn close(&self) -> Closed {
        Closed {
            bucket: self.bucket,
            p95_ms: self.sketch.p95_ms().unwrap_or(0),
            calls: u32::try_from(self.sketch.total()).unwrap_or(u32::MAX),
            failed: self.failed,
            timed_out: self.timed_out,
            late: 0,
        }
    }
}

impl Closed {
    fn note_late(&mut self, end: End) {
        self.calls = self.calls.saturating_add(1);
        self.late = self.late.saturating_add(1);
        match end {
            End::Answered => {}
            End::Failed | End::Cancelled => self.failed = self.failed.saturating_add(1),
            End::TimedOut => self.timed_out = self.timed_out.saturating_add(1),
        }
    }
}

/// One granularity's slots: at most `LIVE` live slots, by the clock, and the
/// closed slots of a `W`-slot window, both oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LatRing<const W: u64, const LIVE: u64> {
    pub(crate) live: VecDeque<Live>,
    pub(crate) closed: VecDeque<Closed>,
}

impl<const W: u64, const LIVE: u64> LatRing<W, LIVE> {
    /// The first slot a window ending at `now` still holds.
    const fn first_held(now: u64) -> u64 {
        now.saturating_sub(W - 1)
    }

    /// Whether `bucket` is live at `now`: one of the newest `LIVE` slots by
    /// the clock, or newer (a clock that stepped back keeps it live).
    const fn is_live(bucket: u64, now: u64) -> bool {
        bucket + LIVE > now
    }

    /// Close the live slots `now` has passed and drop what the window no
    /// longer holds.
    pub(crate) fn finalize(&mut self, now: u64) {
        while let Some(i) = self.live.iter().position(|l| !Self::is_live(l.bucket, now)) {
            let Some(live) = self.live.remove(i) else {
                break;
            };
            let closed = live.close();
            let at = self.closed.partition_point(|c| c.bucket < closed.bucket);
            self.closed.insert(at, closed);
        }
        let first = Self::first_held(now);
        while self.closed.front().is_some_and(|c| c.bucket < first) {
            self.closed.pop_front();
        }
    }

    /// Record one sample in `bin`, ended `end`, for slot `bucket` at `now`.
    pub(crate) fn add(&mut self, bucket: u64, now: u64, bin: u8, end: End) {
        self.finalize(now);
        // A slot that already closed takes the sample as late, even when a
        // clock that stepped back makes it look live again.
        if let Ok(i) = self.closed.binary_search_by_key(&bucket, |c| c.bucket) {
            self.closed[i].note_late(end);
            return;
        }
        if Self::is_live(bucket, now) {
            let at = self.live.partition_point(|l| l.bucket < bucket);
            if self.live.get(at).is_none_or(|l| l.bucket != bucket) {
                self.live.insert(
                    at,
                    Live {
                        bucket,
                        ..Live::default()
                    },
                );
            }
            let live = &mut self.live[at];
            live.sketch.add(bin);
            live.note(end);
            return;
        }
        if bucket < Self::first_held(now) {
            return;
        }
        // Late for a slot that closed with no calls: its counts start here,
        // and it has no p95.
        let at = self.closed.partition_point(|c| c.bucket < bucket);
        self.closed.insert(
            at,
            Closed {
                bucket,
                ..Closed::default()
            },
        );
        self.closed[at].note_late(end);
    }

    #[cfg(test)]
    /// Every slot the window holds at `now`, oldest first, a live one shown
    /// as it would close now. Call [`Self::finalize`] first.
    pub(crate) fn slots(&self) -> Vec<Closed> {
        let mut slots: Vec<Closed> = self.closed.iter().copied().collect();
        slots.extend(self.live.iter().map(Live::close));
        slots.sort_by_key(|c| c.bucket);
        slots
    }

    #[cfg(test)]
    /// The merged histogram of the live slots, and their outcome counts.
    pub(crate) fn live_merged(&self) -> (Sketch, u32, u32) {
        let mut sketch = Sketch::default();
        let (mut failed, mut timed_out) = (0u32, 0u32);
        for live in &self.live {
            sketch.merge(&live.sketch);
            failed = failed.saturating_add(live.failed);
            timed_out = timed_out.saturating_add(live.timed_out);
        }
        (sketch, failed, timed_out)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.live.is_empty() && self.closed.is_empty()
    }
}

/// One label's latency: half-hours (two live) and local days (today live).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LatencySeries {
    pub(crate) half: LatRing<{ super::HALF_BUCKETS as u64 }, LIVE_HALF>,
    pub(crate) day: LatRing<{ super::DAYS as u64 }, 1>,
}

impl LatencySeries {
    /// Record one call's send time, finished at unix second `at`, on local
    /// day `day` when the zone could place it.
    pub(crate) fn add(&mut self, at: u64, day: Option<u64>, elapsed: Duration, end: End) {
        let bin = bin_of(elapsed);
        let now = at / super::HALF;
        self.half.add(now, now, bin, end);
        if let Some(day) = day {
            self.day.add(day, day, bin, end);
        }
    }

    /// Close what `at` (and `day`) have passed.
    pub(crate) fn finalize(&mut self, at: u64, day: Option<u64>) {
        self.half.finalize(at / super::HALF);
        if let Some(day) = day {
            self.day.finalize(day);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.half.is_empty() && self.day.is_empty()
    }
}

/// A closed slot on disk: `[bucket, p95_ms, calls, failed, timed_out]`,
/// plus `late` only when it is not 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ClosedRow(Vec<u64>);

/// A live slot on disk: `[bucket, calls, failed, timed_out, [[bin, count], ...]]`.
/// `calls` is the sketch's total, written for readers of the file; a
/// restore counts the sketch.
type LiveRow = (u64, u64, u32, u32, Sketch);

/// One ring on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RingFile {
    #[serde(default)]
    live: Vec<LiveRow>,
    #[serde(default)]
    closed: Vec<ClosedRow>,
}

/// One label's latency on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SeriesFile {
    #[serde(default)]
    half: RingFile,
    #[serde(default)]
    day: RingFile,
}

impl<const W: u64, const LIVE: u64> LatRing<W, LIVE> {
    fn to_file(&self) -> RingFile {
        RingFile {
            live: self
                .live
                .iter()
                .map(|l| {
                    (
                        l.bucket,
                        l.sketch.total(),
                        l.failed,
                        l.timed_out,
                        l.sketch.clone(),
                    )
                })
                .collect(),
            closed: self
                .closed
                .iter()
                .map(|c| {
                    let mut row = vec![
                        c.bucket,
                        c.p95_ms,
                        u64::from(c.calls),
                        u64::from(c.failed),
                        u64::from(c.timed_out),
                    ];
                    if c.late > 0 {
                        row.push(u64::from(c.late));
                    }
                    ClosedRow(row)
                })
                .collect(),
        }
    }

    /// The ring a file describes; a malformed row is dropped, never fatal,
    /// so a damaged latency field cannot cost the counts beside it.
    fn from_file(file: &RingFile) -> Self {
        let narrow = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        let mut ring = Self::default();
        for (bucket, _calls, failed, timed_out, sketch) in &file.live {
            ring.live.push_back(Live {
                bucket: *bucket,
                sketch: sketch.clone(),
                failed: *failed,
                timed_out: *timed_out,
            });
        }
        for ClosedRow(row) in &file.closed {
            let (bucket, p95_ms, calls, failed, timed_out, late) = match *row.as_slice() {
                [bucket, p95, calls, failed, timed_out] => {
                    (bucket, p95, calls, failed, timed_out, 0)
                }
                [bucket, p95, calls, failed, timed_out, late] => {
                    (bucket, p95, calls, failed, timed_out, late)
                }
                _ => continue,
            };
            ring.closed.push_back(Closed {
                bucket,
                p95_ms,
                calls: narrow(calls),
                failed: narrow(failed),
                timed_out: narrow(timed_out),
                late: narrow(late),
            });
        }
        ring.live.make_contiguous().sort_by_key(|l| l.bucket);
        ring.closed.make_contiguous().sort_by_key(|c| c.bucket);
        ring
    }
}

impl LatencySeries {
    pub(crate) fn to_file(&self) -> SeriesFile {
        SeriesFile {
            half: self.half.to_file(),
            day: self.day.to_file(),
        }
    }

    /// The series a file describes, closed and windowed to `at` and `day`.
    pub(crate) fn from_file(file: &SeriesFile, at: u64, day: Option<u64>) -> Self {
        let mut series = Self {
            half: LatRing::from_file(&file.half),
            day: LatRing::from_file(&file.day),
        };
        series.finalize(at, day);
        series
    }
}

#[cfg(test)]
#[path = "latency_tests.rs"]
mod tests;
