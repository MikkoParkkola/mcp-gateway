// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reads of the latency series: per-slot p95s on the counters' window shape
//! (`GET /ui/api/metrics/series?metric=latency_p95`) and the last hour per
//! server for the Overview.

use chrono::TimeZone;
use serde::Serialize;

use super::latency::{Closed, LatRing, SLOWEST_FLOOR, Sketch};
use super::view::{Window, window_slots};
use super::{CounterStore, HALF, normalize};

/// One slot of a latency read. `v` is the p95 in ms over the samples the
/// slot held when it closed; absent when every sample arrived late.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct LatPoint {
    pub t: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<u64>,
    pub calls: u32,
    pub failed: u32,
    pub timed_out: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub late: u32,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip predicate takes a reference"
)]
const fn is_zero(v: &u32) -> bool {
    *v == 0
}

/// What a latency read returns, the counters' read shape with p95 points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LatencyView {
    pub points: Vec<LatPoint>,
    pub previous: Option<Vec<LatPoint>>,
    pub previous_complete: bool,
    pub folded: bool,
    pub since: u64,
}

/// One server's last hour, for the Overview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ServerLatency {
    pub name: String,
    pub p95_ms: u64,
    pub calls: u64,
}

/// The Overview's last-hour latency: every server with calls, slowest first,
/// and the slowest one with at least [`SLOWEST_FLOOR`] calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HourLatency {
    /// The two half-hour slots' bounds, unix seconds.
    pub from: u64,
    pub to: u64,
    pub servers: Vec<ServerLatency>,
    pub slowest: Option<ServerLatency>,
}

impl<const W: u64, const LIVE: u64> LatRing<W, LIVE> {
    /// Slot `bucket` as a closed slot: a live one as it would close now.
    fn get(&self, bucket: u64) -> Option<Closed> {
        if let Ok(i) = self.closed.binary_search_by_key(&bucket, |c| c.bucket) {
            return Some(self.closed[i]);
        }
        self.live
            .iter()
            .find(|l| l.bucket == bucket)
            .map(super::latency::Live::close)
    }

    /// The live slots from `first` on, merged: the clock decides, so a slot
    /// an idle series never finalized does not count.
    fn merged_from(&self, first: u64) -> Sketch {
        let mut sketch = Sketch::default();
        for live in self.live.iter().filter(|l| l.bucket >= first) {
            sketch.merge(&live.sketch);
        }
        sketch
    }
}

fn point(t: u64, slot: Closed) -> LatPoint {
    LatPoint {
        t,
        v: (slot.calls > slot.late).then_some(slot.p95_ms),
        calls: slot.calls,
        failed: slot.failed,
        timed_out: slot.timed_out,
        late: slot.late,
    }
}

impl CounterStore {
    /// The latency of `server` (all servers when `None`) over `window` at
    /// unix second `now`, days cut in `zone`; with the previous 24 hours
    /// when `compare` (24-hour window only).
    pub(crate) fn latency_series<Tz: TimeZone>(
        &self,
        server: Option<&str>,
        window: Window,
        compare: bool,
        now: u64,
        zone: &Tz,
    ) -> LatencyView {
        let inner = self.read_lock();
        let since = inner.since;
        let series = match server {
            None => &inner.global,
            Some(name) => match inner.server.labels.get(&normalize(name)) {
                Some(series) => series,
                // Not held: its calls may be in the overflow, so no points.
                None => {
                    return LatencyView {
                        points: Vec::new(),
                        previous: None,
                        previous_complete: true,
                        folded: true,
                        since,
                    };
                }
            },
        };
        let read = |slots: &[super::view::Slot]| -> Vec<LatPoint> {
            slots
                .iter()
                .filter_map(|slot| {
                    let found = match window {
                        Window::Day | Window::TwoDays => series.latency.half.get(slot.key),
                        Window::Month => series.latency.day.get(slot.key),
                    };
                    found.map(|c| point(slot.t, c))
                })
                .collect()
        };
        let slots = window_slots(window, now, since, zone);
        let mut view = LatencyView {
            points: read(&slots),
            previous: None,
            previous_complete: true,
            folded: false,
            since,
        };
        if compare && window == Window::Day {
            // The 24 hours before: 48 half-hour slots, read from the same ring.
            let now_bucket = now / HALF;
            let first = (now_bucket + 1).saturating_sub(96);
            let prev: Vec<super::view::Slot> = (first..first + 48)
                .map(|b| super::view::Slot {
                    t: b * HALF,
                    key: b,
                })
                .collect();
            view.previous_complete = first * HALF >= since;
            view.previous = Some(read(&prev));
        }
        view
    }

    /// Every server's latency over the current and the previous half-hour
    /// slot at unix second `now`.
    pub(crate) fn latency_hour(&self, now: u64) -> HourLatency {
        let inner = self.read_lock();
        let now_bucket = now / HALF;
        let first = now_bucket.saturating_sub(1);
        let mut servers: Vec<ServerLatency> = inner
            .server
            .labels
            .iter()
            .filter_map(|(name, series)| {
                let merged = series.latency.half.merged_from(first);
                Some(ServerLatency {
                    name: name.clone(),
                    p95_ms: merged.p95_ms()?,
                    calls: merged.total(),
                })
            })
            .collect();
        servers.sort_by(|a, b| b.p95_ms.cmp(&a.p95_ms).then_with(|| a.name.cmp(&b.name)));
        // Over every server, before any caller caps the rows.
        let slowest = servers.iter().find(|s| s.calls >= SLOWEST_FLOOR).cloned();
        HourLatency {
            from: first * HALF,
            to: (now_bucket + 1) * HALF,
            servers,
            slowest,
        }
    }
}

#[cfg(test)]
#[path = "latency_view_tests.rs"]
mod tests;
