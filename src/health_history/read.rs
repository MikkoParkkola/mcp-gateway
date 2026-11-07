// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reading the history: the tiles' spans, the half-hours, the strip's blocks
//! and restarts, and uptime as running over covered time.

use super::{BLOCK, Block, Half, HealthHistory, LATENCY_SLOTS, P95, Restart, Uptime};
use crate::gateway::health_metrics::ErrorKind;

/// The upper bound of latency slot `i` in ms, to the microsecond.
fn bound_ms(i: usize) -> f64 {
    let secs = crate::gateway::health_metrics::layers::LATENCY_BUCKETS[i];
    (secs * 1_000_000.0).round() / 1_000.0
}

impl HealthHistory {
    /// The p95 of added latency over the half-hours starting in `[from, to)`.
    pub(crate) fn p95(&self, from: u64, to: u64) -> P95 {
        let inner = self.0.lock();
        let mut counts = [0u64; LATENCY_SLOTS];
        for half in inner
            .halves
            .iter()
            .filter(|h| (from..to).contains(&h.start))
        {
            for (sum, n) in counts.iter_mut().zip(half.latency) {
                *sum += n;
            }
        }
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return P95::NoData;
        }
        // The rank of the 95th percentile, rounded up: ceil(0.95 * total).
        let rank = (total * 95).div_ceil(100);
        let mut seen = 0;
        for (i, n) in counts.iter().enumerate() {
            seen += n;
            if seen >= rank {
                return if i < LATENCY_SLOTS - 1 {
                    P95::Ms(bound_ms(i))
                } else {
                    P95::AboveMs(bound_ms(LATENCY_SLOTS - 2))
                };
            }
        }
        P95::NoData
    }

    /// Gateway errors (auth, request, internal; a backend's own errors are
    /// its health, not the gateway's) over the half-hours starting in
    /// `[from, to)`; `None` when none of them was observed.
    pub(crate) fn errors(&self, from: u64, to: u64) -> Option<u64> {
        let inner = self.0.lock();
        let mut found = None;
        for half in inner
            .halves
            .iter()
            .filter(|h| (from..to).contains(&h.start))
        {
            let gateway = half.errors[ErrorKind::Auth.index()]
                + half.errors[ErrorKind::Request.index()]
                + half.errors[ErrorKind::Internal.index()];
            found = Some(found.unwrap_or(0) + gateway);
        }
        found
    }

    /// The half-hour starting at `start`, if it was observed.
    pub(crate) fn half(&self, start: u64) -> Option<Half> {
        self.0
            .lock()
            .halves
            .iter()
            .find(|h| h.start == start)
            .cloned()
    }

    /// Every block kept, oldest first.
    pub(crate) fn blocks(&self) -> Vec<Block> {
        self.0.lock().blocks.iter().copied().collect()
    }

    /// The restarts that started in `[from, to)`, and whether details in that
    /// span were dropped by the cap (the block rollups still count them).
    pub(crate) fn restarts(&self, from: u64, to: u64) -> (Vec<Restart>, bool) {
        let inner = self.0.lock();
        let found = inner
            .restarts
            .iter()
            .filter(|r| (from..to).contains(&r.started_at))
            .copied()
            .collect();
        (found, inner.dropped_newest.is_some_and(|at| at >= from))
    }

    /// Uptime over the blocks overlapping `[from, to)`.
    pub(crate) fn uptime(&self, from: u64, to: u64) -> Uptime {
        let inner = self.0.lock();
        let (mut running, mut down) = (0, 0);
        for block in inner
            .blocks
            .iter()
            .filter(|b| b.start < to && b.start + BLOCK > from)
        {
            running += block.running_seconds;
            down += block.down_seconds;
        }
        let covered = running + down;
        let gap = inner.gaps.iter().any(|&(a, b)| a < to && b > from)
            || inner.gaps_dropped_to.is_some_and(|end| end > from);
        Uptime {
            running_seconds: running,
            down_seconds: down,
            covered_seconds: covered,
            #[allow(clippy::cast_precision_loss)] // Seconds in a week fit an f64 exactly.
            percent: (covered > 0).then(|| running as f64 / covered as f64 * 100.0),
            coverage_complete: !gap && from >= inner.observed_since,
        }
    }

    /// This run's history could not be saved yet.
    pub(crate) fn incomplete(&self) -> bool {
        self.0.lock().incomplete
    }
}
