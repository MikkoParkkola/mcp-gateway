// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Writing the history: a start that accounts for the gap before it, the
//! recorders, the running-time tick, the clean stop and the save.

use std::collections::VecDeque;

use parking_lot::Mutex;

use super::{
    BLOCK, BLOCKS_KEPT, Block, DowntimeSource, HALF, HALVES_KEPT, Half, HealthHistory, Inner,
    LATENCY_SLOTS, MAX_GAPS, MAX_RESTARTS, Restart, Restores, Started,
};
use crate::gateway::health_metrics::ErrorKind;

/// The latency slot a sample of `secs` falls in: the first bound it does not
/// exceed, or the overflow slot.
fn slot(secs: f64) -> usize {
    crate::gateway::health_metrics::layers::LATENCY_BUCKETS
        .iter()
        .position(|bound| secs <= *bound)
        .unwrap_or(LATENCY_SLOTS - 1)
}

impl Inner {
    fn fresh(now: u64, counters: Restores) -> Self {
        let (Restores::Counted(counters) | Restores::Restarted(counters)) = counters;
        Self {
            v: 1,
            observed_since: now,
            counters_seen: counters,
            started_at: now,
            last_tick: now,
            saved_at: now,
            clean_stop: None,
            halves: VecDeque::new(),
            blocks: VecDeque::new(),
            restarts: VecDeque::new(),
            dropped_newest: None,
            gaps: VecDeque::new(),
            gaps_dropped_to: None,
            incomplete: false,
        }
    }

    /// The half-hour holding `at`, created when first touched; `None` when it
    /// is older than every half-hour kept (a clock far behind).
    fn half_mut(&mut self, at: u64) -> Option<&mut Half> {
        let start = at - at % HALF;
        if !self.halves.iter().any(|h| h.start == start) {
            if self.halves.len() >= HALVES_KEPT
                && self.halves.front().is_some_and(|h| start < h.start)
            {
                return None;
            }
            let i = self
                .halves
                .iter()
                .position(|h| h.start > start)
                .unwrap_or(self.halves.len());
            self.halves.insert(
                i,
                Half {
                    start,
                    latency: [0; LATENCY_SLOTS],
                    errors: [0; 4],
                    memory_max: None,
                    sessions_max: None,
                },
            );
            while self.halves.len() > HALVES_KEPT {
                self.halves.pop_front();
            }
        }
        self.halves.iter_mut().find(|h| h.start == start)
    }

    /// The block holding `at`, created when first touched; `None` when it is
    /// older than every block kept.
    fn block_mut(&mut self, at: u64) -> Option<&mut Block> {
        let start = at - at % BLOCK;
        if !self.blocks.iter().any(|b| b.start == start) {
            if self.blocks.len() >= BLOCKS_KEPT
                && self.blocks.front().is_some_and(|b| start < b.start)
            {
                return None;
            }
            let i = self
                .blocks
                .iter()
                .position(|b| b.start > start)
                .unwrap_or(self.blocks.len());
            self.blocks.insert(
                i,
                Block {
                    start,
                    running_seconds: 0,
                    down_seconds: 0,
                    restarts: 0,
                    estimated: false,
                },
            );
            while self.blocks.len() > BLOCKS_KEPT {
                self.blocks.pop_front();
            }
        }
        self.blocks.iter_mut().find(|b| b.start == start)
    }

    /// Spread `[from, to)` over the blocks it crosses, adding to running or
    /// down time.
    fn spread(&mut self, from: u64, to: u64, down: bool, estimated: bool) {
        let mut at = from;
        while at < to {
            let end = (at - at % BLOCK + BLOCK).min(to);
            if let Some(block) = self.block_mut(at) {
                if down {
                    block.down_seconds += end - at;
                    block.estimated |= estimated;
                } else {
                    block.running_seconds += end - at;
                }
            }
            at = end;
        }
    }

    /// Accrue running time to `now` and mark the half-hours it covers.
    fn tick(&mut self, now: u64) {
        if now <= self.last_tick {
            return;
        }
        let from = self.last_tick;
        self.spread(from, now, false, false);
        // The half-hours [from, now) touches: one starting at `now` was not
        // reached.
        let mut half = from - from % HALF;
        while half < now {
            self.half_mut(half);
            half += HALF;
        }
        self.last_tick = now;
    }

    /// Keep the restart detail list within its cap, noting what was dropped.
    fn push_restart(&mut self, restart: Restart) {
        self.restarts.push_back(restart);
        while self.restarts.len() > MAX_RESTARTS {
            if let Some(old) = self.restarts.pop_front() {
                self.dropped_newest = Some(old.started_at);
            }
        }
    }

    /// Start a new run at `now` after this saved history.
    fn restart(&mut self, counters: Restores, now: u64) -> Started {
        let expected = self.counters_seen + 1;
        // counters.json counts every restore (this one included). Any other
        // count, or a count that started again, means a run this history did
        // not record: the gap is never claimed as known downtime.
        let (missed_run, count) = match counters {
            Restores::Counted(count) => (count != expected, count),
            // The count started again: whatever it says, a run went
            // unrecorded (an older binary wrote counters.json).
            Restores::Restarted(count) => (true, count),
        };
        let clean_stop = self.clean_stop.take();
        let mut restart = None;
        if missed_run {
            self.gaps.push_back((self.saved_at, now.max(self.saved_at)));
            while self.gaps.len() > MAX_GAPS {
                if let Some((_, end)) = self.gaps.pop_front() {
                    self.gaps_dropped_to = Some(self.gaps_dropped_to.map_or(end, |e| e.max(end)));
                }
            }
        } else {
            let (stopped_at, mut source) = match clean_stop {
                Some(at) => (at, DowntimeSource::Measured),
                None => (self.saved_at, DowntimeSource::Estimated),
            };
            // Never before the last second already counted as running (a
            // clock set backward during the last run).
            let stopped_at = stopped_at.max(self.last_tick);
            if now < stopped_at {
                // A clock set backward: no negative interval.
                source = DowntimeSource::Estimated;
            }
            let estimated = source == DowntimeSource::Estimated;
            self.spread(stopped_at, now, true, estimated);
            if let Some(block) = self.block_mut(now) {
                block.restarts += 1;
                block.estimated |= estimated;
            }
            let entry = Restart {
                stopped_at,
                started_at: now,
                downtime_source: source,
            };
            self.push_restart(entry);
            restart = Some(entry);
        }
        self.counters_seen = count;
        self.started_at = now;
        // A clock behind the last counted second accrues nothing until it
        // passes it: no second is counted twice.
        self.last_tick = now.max(self.last_tick);
        Started {
            fresh: false,
            set_aside: false,
            missed_run,
            restart,
        }
    }
}

impl HealthHistory {
    /// Start from `previous` (health.json's bytes, if any) with `counters`
    /// (counters.json's cumulative restore count, this start's included),
    /// at unix second `now`.
    pub(crate) fn start(previous: Option<&[u8]>, counters: Restores, now: u64) -> (Self, Started) {
        let none = Started {
            fresh: true,
            set_aside: false,
            missed_run: false,
            restart: None,
        };
        let (inner, started) = match previous.map(serde_json::from_slice::<Inner>) {
            None => (Inner::fresh(now, counters), none),
            Some(Err(_)) => (
                Inner::fresh(now, counters),
                Started {
                    set_aside: true,
                    ..none
                },
            ),
            Some(Ok(mut inner)) => {
                let started = inner.restart(counters, now);
                (inner, started)
            }
        };
        (Self(Mutex::new(inner)), started)
    }

    pub(crate) fn record_latency(&self, secs: f64, now: u64) {
        if let Some(half) = self.0.lock().half_mut(now) {
            half.latency[slot(secs)] += 1;
        }
    }

    pub(crate) fn record_error(&self, kind: ErrorKind, now: u64) {
        if let Some(half) = self.0.lock().half_mut(now) {
            half.errors[kind.index()] += 1;
        }
    }

    pub(crate) fn sample(&self, memory: Option<u64>, sessions: u64, now: u64) {
        let mut inner = self.0.lock();
        let Some(half) = inner.half_mut(now) else {
            return;
        };
        if let Some(bytes) = memory {
            half.memory_max = Some(half.memory_max.map_or(bytes, |m| m.max(bytes)));
        }
        half.sessions_max = Some(half.sessions_max.map_or(sessions, |m| m.max(sessions)));
    }

    pub(crate) fn tick(&self, now: u64) {
        self.0.lock().tick(now);
    }

    /// Mark whether this run's history is saved; the saver sets it.
    pub(crate) fn set_incomplete(&self, incomplete: bool) {
        self.0.lock().incomplete = incomplete;
    }

    /// A clean stop at `now`; the shutdown save follows.
    pub(crate) fn stop(&self, now: u64) {
        let mut inner = self.0.lock();
        inner.tick(now);
        inner.clean_stop = Some(inner.last_tick);
    }

    /// The bytes to save at `now`; `None` if they cannot be encoded, so a
    /// failed encoding never replaces a good file with an empty one.
    pub(crate) fn encode(&self, now: u64) -> Option<Vec<u8>> {
        let mut inner = self.0.lock();
        inner.tick(now);
        // The last second counted, which a backward clock leaves ahead of now.
        inner.saved_at = inner.last_tick;
        serde_json::to_vec(&*inner).ok()
    }
}
