// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Per-pair delivery instants for the relay detector (moved from `collusion.rs`).

use std::time::{Duration, Instant};

/// Delivery instants kept per pair; see [`Copies`].
const MAX_COPIES: usize = 3;

/// When one pair received a fingerprint: up to [`MAX_COPIES`] delivery
/// instants, ascending. Calls reach the lock out of time order, so a copy
/// stamped after an egress can already be here when that egress is checked,
/// and the earliest and latest alone cannot say whether a copy was held in
/// the window at that instant (MIK-7881).
///
/// A copy whose neighbours are at most a window apart is dropped: a window
/// that contains it contains one of them, so no answer changes. Past the cap
/// the oldest is dropped; an egress checked more than about a window before
/// the pair's latest copy can then miss an older one, which turns an excuse
/// into a finding and can drop a witness.
#[derive(Clone, Copy)]
pub(super) struct Copies {
    at: [Instant; MAX_COPIES],
    len: usize,
}

impl Copies {
    pub(super) fn one(at: Instant) -> Self {
        Self {
            at: [at; MAX_COPIES],
            len: 1,
        }
    }

    fn all(&self) -> &[Instant] {
        &self.at[..self.len]
    }

    pub(super) fn latest(&self) -> Instant {
        self.at[self.len - 1]
    }

    pub(super) fn add(&mut self, other: &Self, window: Duration) {
        for &at in other.all() {
            let mut all = [at; MAX_COPIES + 1];
            all[..self.len].copy_from_slice(self.all());
            let mut n = self.len + 1;
            all[..n].sort_unstable();
            let mut i = 1;
            while i + 1 < n {
                if all[i + 1].saturating_duration_since(all[i - 1]) <= window {
                    all.copy_within(i + 1..n, i);
                    n -= 1;
                    i = (i - 1).max(1);
                } else {
                    i += 1;
                }
            }
            let oldest = n.saturating_sub(MAX_COPIES);
            self.len = n - oldest;
            self.at[..self.len].copy_from_slice(&all[oldest..n]);
        }
    }

    /// A copy delivered by `now` and within `window` of it.
    pub(super) fn held(&self, now: Instant, window: Duration) -> bool {
        self.all()
            .iter()
            .any(|&at| at <= now && now.saturating_duration_since(at) <= window)
    }
}
