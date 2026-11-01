// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One read for many labels: each label's calls in the last 24 hours and in
//! the same hours of the day before, under one lock, so a list of hundreds
//! of tools costs one store read and every count comes from one snapshot.
//!
//! A count is `None` when calls in its period may be counted elsewhere or
//! are no longer held, so a number would read as exact while it could be
//! low. Coverage that began inside a period is not such a case: no call is
//! hidden there, the store did not exist yet.

use chrono::TimeZone;

use super::view::{Filter, Window, previous_buckets, window_slots};
use super::{CounterStore, HALF, Inner, Metric, Series};

/// One label's calls: `(last 24 hours, the same hours of the day before)`,
/// each `None` when it could be low.
/// Points in the half-hour series: the current bucket and the 11 before it.
pub(crate) const SERIES: usize = 12;

/// One label's calls over the windows [`CounterStore::window_sums`] reads,
/// each `None` where it could be low.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallWindows {
    /// The last 24 hours: the 48 half hours ending with the current one.
    pub day: Option<u64>,
    /// The same local wall-clock hours of the day before.
    pub prev_day: Option<u64>,
    /// The last two completed half hours: an exact hour ending at the start
    /// of the current one.
    pub hour: Option<u64>,
    /// The two completed half hours before those.
    pub prev_hour: Option<u64>,
    /// Calls per half hour, oldest first, starting at
    /// [`WindowSums::series_start`]; the last is the partial current one.
    pub series: [Option<u64>; SERIES],
}

impl CallWindows {
    /// Every window unknown: the label cannot be counted.
    pub(crate) const UNKNOWN: Self = Self {
        day: None,
        prev_day: None,
        hour: None,
        prev_hour: None,
        series: [None; SERIES],
    };

    /// The two 24-hour windows.
    pub(crate) fn days(&self) -> (Option<u64>, Option<u64>) {
        (self.day, self.prev_day)
    }
}

/// What [`CounterStore::window_sums`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowSums {
    /// When coverage began, unix seconds.
    pub since: u64,
    /// `(last 24 hours, the same hours of the day before)` per asked label,
    /// in the order asked.
    pub counts: Vec<CallWindows>,
    /// The unix start of every label's first series point.
    pub series_start: i64,
}

/// One caller x server pair's calls and blocks in the last 24 hours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PairRow {
    pub caller: String,
    pub server: String,
    pub calls: u64,
    pub blocks: u64,
}

/// What [`CounterStore::top_pairs`] read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TopPairs {
    /// The top pairs by calls, ties by caller then server.
    pub rows: Vec<PairRow>,
    /// Pairs with activity in the window that are not in `rows`.
    pub more_count: usize,
    /// Their calls.
    pub more_calls: u64,
    /// Calls in the window that the pair dimension's overflow holds.
    pub overflow_calls: u64,
}

impl CounterStore {
    /// The store's lock, taken by a reader. Counted in tests, per store.
    pub(super) fn read_lock(&self) -> parking_lot::MutexGuard<'_, Inner> {
        #[cfg(test)]
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.lock()
    }

    /// How many label windows a batch read walked.
    #[cfg(test)]
    pub(crate) fn window_walks_for_test(&self) -> usize {
        self.window_walks.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many times a reader took this store's lock.
    #[cfg(test)]
    pub(crate) fn reads_for_test(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The top `n` caller x server pairs by calls in the 24-hour window ending
    /// at `now` (the same buckets as [`Self::window_sums`]), under one lock.
    /// Only pairs with calls or blocks in the window rank or count toward
    /// `more`. The pair overflow is a series of its own, so its calls in the
    /// window are exact.
    pub(crate) fn top_pairs<Tz: TimeZone>(&self, now: u64, zone: &Tz, n: usize) -> TopPairs {
        let inner = self.read_lock();
        let keys: Vec<u64> = window_slots(Window::Day, now, inner.since, zone)
            .iter()
            .map(|slot| slot.key)
            .collect();
        let sum = |series: &Series, metric: Metric| -> u64 {
            keys.iter()
                .filter_map(|&b| series.half.get(b))
                .map(|counts| counts[metric.index()])
                .sum()
        };
        // Rank on borrowed labels; only the rows kept are cloned.
        let mut ranked: Vec<(&(String, String), u64, u64)> = inner
            .caller_server
            .labels
            .iter()
            .map(|(pair, series)| {
                (
                    pair,
                    sum(series, Metric::Calls),
                    sum(series, Metric::Blocks),
                )
            })
            .filter(|&(_, calls, blocks)| calls > 0 || blocks > 0)
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let rest = ranked.split_off(ranked.len().min(n));
        TopPairs {
            more_count: rest.len(),
            more_calls: rest.iter().map(|row| row.1).sum(),
            overflow_calls: sum(&inner.caller_server.overflow, Metric::Calls),
            rows: ranked
                .into_iter()
                .map(|((caller, server), calls, blocks)| PairRow {
                    caller: caller.clone(),
                    server: server.clone(),
                    calls,
                    blocks,
                })
                .collect(),
        }
    }

    /// Calls in the 24-hour window ending at unix second `now` (the 48
    /// half-hour buckets ending with the current one, which is partial), and
    /// in the buckets holding the same local wall-clock times on the previous
    /// date, plus the last completed hour, the hour before it and the last
    /// [`SERIES`] half hours, for each of `labels` (`Filter::Tool` or
    /// `Filter::Server`, raw names: the store normalizes them as it does when
    /// it records). One lock.
    pub(crate) fn window_sums<Tz: TimeZone>(
        &self,
        labels: &[Filter<'_>],
        now: u64,
        zone: &Tz,
    ) -> WindowSums {
        let inner = self.read_lock();
        let since = inner.since;
        let now_bucket = now / HALF;
        // The plan, shared by every label: the current buckets not before
        // coverage, and the previous date's buckets for the whole window.
        let current: Vec<u64> = window_slots(Window::Day, now, since, zone)
            .iter()
            .map(|slot| slot.key)
            .collect();
        let window = (now_bucket + 1).saturating_sub(48)..=now_bucket;
        let (previous, mapped) = previous_buckets(window.map(|b| b * HALF), zone);
        // Before coverage: skipped, still a number.
        let previous: Vec<u64> = previous
            .into_iter()
            .filter(|b| (b + 1) * HALF > since)
            .collect();
        // Labels the store does not hold are read from their dimension's
        // overflow alone, so one walk answers all of them.
        let mut unheld: Vec<(&Series, CallWindows)> = Vec::new();
        let counts = labels
            .iter()
            .map(|&label| {
                let Some(read) = Read::of(&inner, label) else {
                    return CallWindows::UNKNOWN;
                };
                let walk = || {
                    #[cfg(test)]
                    self.window_walks
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    read.windows(
                        &current,
                        mapped.then_some(previous.as_slice()),
                        now_bucket,
                        since,
                    )
                };
                if read.series.is_some() {
                    return walk();
                }
                if let Some((_, known)) =
                    unheld.iter().find(|(o, _)| std::ptr::eq(*o, read.overflow))
                {
                    return *known;
                }
                let answer = walk();
                unheld.push((read.overflow, answer));
                answer
            })
            .collect();
        WindowSums {
            since,
            counts,
            series_start: series_start(now_bucket),
        }
    }
}

/// The unix start of the first series point when the current bucket is
/// `now_bucket`; before the epoch (a clock near 0) it is negative.
fn series_start(now_bucket: u64) -> i64 {
    let back = i64::try_from(SERIES - 1).unwrap_or(0);
    let half = i64::try_from(HALF).unwrap_or(0);
    i64::try_from(now_bucket)
        .unwrap_or(i64::MAX)
        .saturating_sub(back)
        .saturating_mul(half)
}

/// One label's series as a batch read sees it.
struct Read<'a> {
    /// The label's own series; `None` for a label the store does not hold.
    series: Option<&'a Series>,
    /// Its dimension's overflow.
    overflow: &'a Series,
    /// The first bucket the label held, its admission bucket excluded:
    /// overflow calls earlier in that half hour may be its own.
    held_after: Option<u64>,
}

impl<'a> Read<'a> {
    /// `None` when the label cannot be counted at all: not held, and its
    /// dimension is full, so its calls go to the overflow.
    fn of(inner: &'a Inner, label: Filter<'_>) -> Option<Self> {
        match inner.find(label) {
            Ok((series, overflow)) => Some(Self {
                series: Some(series),
                overflow: overflow?,
                held_after: Some(series.admitted / HALF),
            }),
            Err((_, true)) => None,
            Err((overflow, false)) => Some(Self {
                series: None,
                overflow,
                held_after: None,
            }),
        }
    }

    /// The label's calls over the current buckets and over the previous
    /// date's (`None` when they could not be mapped), each `None` where it
    /// could be low.
    fn windows(
        &self,
        current: &[u64],
        previous: Option<&[u64]>,
        now_bucket: u64,
        since: u64,
    ) -> CallWindows {
        let day = |buckets: &[u64]| {
            self.holds_all(buckets, now_bucket)
                .then(|| self.sum(buckets))
                .flatten()
        };
        let series = self.points(now_bucket, since);
        // Pairs of points, so the hours and the series agree by construction.
        let pair = |a: usize| series[a].zip(series[a + 1]).map(|(x, y)| x + y);
        CallWindows {
            day: day(current),
            prev_day: previous.and_then(day),
            hour: pair(SERIES - 3),
            prev_hour: pair(SERIES - 5),
            series,
        }
    }

    /// The label's calls in each of the last [`SERIES`] buckets, the current
    /// one last. A bucket before the epoch or before coverage is 0: the
    /// store did not exist then, so no call is hidden.
    fn points(&self, now_bucket: u64, since: u64) -> [Option<u64>; SERIES] {
        let mut points = [Some(0); SERIES];
        for (back, point) in (0_u64..).zip(points.iter_mut().rev()) {
            if let Some(b) = now_bucket.checked_sub(back)
                && (b + 1) * HALF > since
            {
                *point = self
                    .holds_all(&[b], now_bucket)
                    .then(|| self.sum(&[b]))
                    .flatten();
            }
        }
        points
    }

    /// Whether the label held bucket `b`, after its admission bucket.
    fn held(&self, b: u64) -> bool {
        self.held_after.is_some_and(|first| b > first)
    }

    /// The label's calls over `buckets`, or `None` when the overflow has
    /// calls in a bucket the label did not hold.
    fn sum(&self, buckets: &[u64]) -> Option<u64> {
        let calls = Metric::Calls.index();
        let mut total = 0;
        for &b in buckets {
            if !self.held(b) && self.overflow.half.get(b).is_some_and(|c| c[calls] > 0) {
                return None;
            }
            if let Some(counts) = self.series.and_then(|s| s.half.get(b)) {
                total += counts[calls];
            }
        }
        Some(total)
    }

    /// Whether every one of `buckets` is still in the rings this read looks
    /// at: the label's own, and its overflow's, each judged at `now_bucket`
    /// by its own newest bucket.
    fn holds_all(&self, buckets: &[u64], now_bucket: u64) -> bool {
        let from = self
            .series
            .map_or(0, |s| s.half.window_start(now_bucket))
            .max(self.overflow.half.window_start(now_bucket));
        buckets.iter().all(|&b| b >= from)
    }
}
