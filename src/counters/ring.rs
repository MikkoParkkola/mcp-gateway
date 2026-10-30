// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bucket rings: sparse, oldest first, never wider than their window. The
//! rule is `HourBuckets`' (`cost_accounting/tally.rs`): the window ends at the
//! newest bucket seen or the one being added, whichever is later, so a clock
//! stepping back lands in its own bucket, in order, and never widens it.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::{DAYS, HALF, HALF_BUCKETS};

/// `(bucket, [calls, blocks, errors, firewall, cache hits])`, oldest first,
/// spanning at most `W` buckets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Ring<const W: u64>(VecDeque<(u64, [u64; 5])>);

impl<const W: u64> Ring<W> {
    fn newest(&self) -> Option<u64> {
        self.0.back().map(|(bucket, _)| *bucket)
    }

    /// The first bucket a window ending at `newest` still holds.
    const fn first_held(newest: u64) -> u64 {
        newest.saturating_sub(W - 1)
    }

    /// Add `counts` in `bucket`. Past the window: kept nowhere, because a
    /// bucket older than every held one goes to the front and the `expire`
    /// below drops it before this returns.
    pub(crate) fn add(&mut self, bucket: u64, counts: [u64; 5]) {
        let newest = self.newest().map_or(bucket, |n| n.max(bucket));
        let at_or_before = self.0.iter().rposition(|(b, _)| *b <= bucket);
        match at_or_before {
            Some(i) if self.0[i].0 == bucket => {
                for (total, add) in self.0[i].1.iter_mut().zip(counts) {
                    *total = total.saturating_add(add);
                }
            }
            Some(i) => self.0.insert(i + 1, (bucket, counts)),
            None => self.0.push_front((bucket, counts)),
        }
        self.expire(newest);
    }

    /// Drop buckets a window ending at `newest` no longer holds.
    pub(crate) fn expire(&mut self, newest: u64) {
        let newest = self.newest().map_or(newest, |n| n.max(newest));
        while self
            .0
            .front()
            .is_some_and(|(b, _)| *b < Self::first_held(newest))
        {
            self.0.pop_front();
        }
    }

    /// The counts in `bucket`, if held.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn get(&self, bucket: u64) -> Option<[u64; 5]> {
        self.0
            .binary_search_by_key(&bucket, |(b, _)| *b)
            .ok()
            .map(|i| self.0[i].1)
    }

    /// The first bucket this ring would still hold at `now_bucket`.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn window_start(&self, now_bucket: u64) -> u64 {
        Self::first_held(self.newest().map_or(now_bucket, |n| n.max(now_bucket)))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every bucket, oldest first.
    pub(crate) fn buckets(&self) -> impl Iterator<Item = (u64, [u64; 5])> + '_ {
        self.0.iter().copied()
    }
}

/// One label's history: half-hour buckets and local days.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Series {
    pub(crate) half: Ring<{ HALF_BUCKETS as u64 }>,
    pub(crate) day: Ring<{ DAYS as u64 }>,
    /// The unix second a label took its slot; 0 for the global and overflow
    /// series, and for a label held since before this was kept. A read
    /// compares the overflow's calls against it, never the ring, which drops
    /// its old buckets as it takes new ones.
    #[serde(default)]
    pub(crate) admitted: u64,
    /// Backend latency: kept on server, overflow and global
    /// series only, and saved apart from the counts (`snapshot::File`).
    #[serde(skip)]
    pub(crate) latency: super::latency::LatencySeries,
}

impl Series {
    /// A label's series, admitted at unix second `at`.
    pub(crate) fn admitted_at(at: u64) -> Self {
        Self {
            admitted: at,
            ..Self::default()
        }
    }

    /// Add `counts` at unix second `at`, on local day `day` when the zone
    /// could place it.
    pub(crate) fn add(&mut self, at: u64, day: Option<u64>, counts: [u64; 5]) {
        self.half.add(at / HALF, counts);
        if let Some(day) = day {
            self.day.add(day, counts);
        }
    }

    /// Whether nothing is left once both rings, and the latency, are aged
    /// to `at` and `day`.
    pub(crate) fn aged(&mut self, at: u64, day: Option<u64>) -> bool {
        self.half.expire(at / HALF);
        if let Some(day) = day {
            self.day.expire(day);
        }
        self.latency.finalize(at, day);
        self.half.is_empty() && self.day.is_empty() && self.latency.is_empty()
    }
}
