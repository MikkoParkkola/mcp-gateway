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

/// What [`CounterStore::window_sums`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowSums {
    /// When coverage began, unix seconds.
    pub since: u64,
    /// `(last 24 hours, the same hours of the day before)` per asked label,
    /// in the order asked.
    pub counts: Vec<(Option<u64>, Option<u64>)>,
}

impl CounterStore {
    /// The store's lock, taken by a reader. Counted in tests, per store.
    pub(super) fn read_lock(&self) -> parking_lot::MutexGuard<'_, Inner> {
        #[cfg(test)]
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.lock()
    }

    /// How many times a reader took this store's lock.
    #[cfg(test)]
    pub(crate) fn reads_for_test(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Calls in the 24-hour window ending at unix second `now` (the 48
    /// half-hour buckets ending with the current one, which is partial), and
    /// in the buckets holding the same local wall-clock times on the previous
    /// date, for each of `labels` (`Filter::Tool` or `Filter::Server`, raw
    /// names: the store normalizes them as it does when it records). One lock.
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
        let counts = labels
            .iter()
            .map(|&label| {
                let Some(read) = Read::of(&inner, label) else {
                    return (None, None);
                };
                let current_known = read.holds_all(&current, now_bucket);
                let prev_known = mapped && read.holds_all(&previous, now_bucket);
                (
                    if current_known {
                        read.sum(&current)
                    } else {
                        None
                    },
                    if prev_known {
                        read.sum(&previous)
                    } else {
                        None
                    },
                )
            })
            .collect();
        WindowSums { since, counts }
    }
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
