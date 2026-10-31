// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reads of the latency series: per-slot p95s on the counters' window shape
//! (`GET /ui/api/metrics/series?metric=latency_p95`) and the last hour per
//! server for the Overview.

use chrono::TimeZone;
use serde::Serialize;

use super::latency::{Closed, LatRing, SLOWEST_FLOOR, Sketch};
use super::view::{Window, window_slots};
use super::{CounterStore, HALF, Series};

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
    /// The slots held from `first` on, closed and live.
    fn slots_from(&self, first: u64) -> impl Iterator<Item = u64> + '_ {
        self.closed
            .iter()
            .map(|c| c.bucket)
            .chain(self.live.iter().map(|l| l.bucket))
            .filter(move |&b| b >= first)
    }

    fn get(&self, bucket: u64) -> Option<Closed> {
        if let Ok(i) = self.closed.binary_search_by_key(&bucket, |c| c.bucket) {
            return Some(self.closed[i]);
        }
        self.live
            .iter()
            .find(|l| l.bucket == bucket)
            .map(super::latency::Live::close)
    }

    /// The live slots from `first` through `last`, merged: the clock decides,
    /// so a slot an idle series never finalized does not count, nor one a
    /// clock that stepped back left ahead of the window.
    fn merged_from(&self, first: u64, last: u64) -> Sketch {
        let mut sketch = Sketch::default();
        for live in self.live.iter().filter(|l| (first..=last).contains(&l.bucket)) {
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
        let mut since = inner.since;
        let mut slots = window_slots(window, now, since, zone);
        let held = |series: &Series, slot: &super::view::Slot| match window {
            Window::Day | Window::TwoDays => series.latency.half.get(slot.key),
            Window::Month => series.latency.day.get(slot.key),
        };
        // Where the previous period may start drawing, as U1's counts do.
        let mut previous_since = since;
        let empty = Series::default();
        let filter = server.map_or(super::view::Filter::All, super::view::Filter::Server);
        let series = match inner.find(filter) {
            // A server not held, with latency in the overflow in this window
            // (or a full dimension), may be among it: read folded, as counts.
            Err((overflow, full)) => {
                if full || slots.iter().any(|slot| held(overflow, slot).is_some()) {
                    return LatencyView {
                        points: Vec::new(),
                        previous: None,
                        previous_complete: true,
                        folded: true,
                        since,
                    };
                }
                &empty
            }
            Ok((series, overflow)) => {
                // Overflow latency from before the server took its slot may
                // be its own: it is covered from the slot it was admitted in.
                let first = slots
                    .iter()
                    .rposition(|slot| slot.t <= series.admitted)
                    .unwrap_or(0);
                if let Some(overflow) = overflow {
                    let admitted = series.admitted - series.admitted % HALF;
                    if overflow
                        .latency
                        .half
                        .slots_from((now / HALF + 1).saturating_sub(super::HALF_BUCKETS as u64))
                        .any(|bucket| bucket * HALF < admitted)
                    {
                        previous_since = previous_since.max(admitted);
                    }
                    if slots[..first].iter().any(|slot| held(overflow, slot).is_some()) {
                        since = since.max(slots[first].t);
                        slots.drain(..first);
                    }
                }
                series
            }
        };
        let read = |slots: &[super::view::Slot]| -> Vec<LatPoint> {
            slots
                .iter()
                .filter_map(|slot| held(series, slot).map(|c| point(slot.t, c)))
                .collect()
        };
        let mut view = LatencyView {
            points: read(&slots),
            previous: None,
            previous_complete: true,
            folded: false,
            since,
        };
        if compare && window == Window::Day {
            // The same local wall-clock times on the previous local date, as
            // U1's counts map them: a repeated hour gives both slots, a
            // skipped one none.
            let (buckets, mapped) = super::view::previous_buckets(slots.iter().map(|s| s.t), zone);
            let held_from = (now / HALF + 1).saturating_sub(super::HALF_BUCKETS as u64);
            let since = since.max(previous_since);
            let mut complete = mapped;
            let prev: Vec<super::view::Slot> = buckets
                .into_iter()
                .filter(|&bucket| {
                    let kept = bucket >= held_from && (bucket + 1) * HALF > since;
                    complete &= kept;
                    kept
                })
                .map(|bucket| super::view::Slot {
                    t: bucket * HALF,
                    key: bucket,
                })
                .collect();
            view.previous_complete = complete;
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
                let merged = series.latency.half.merged_from(first, now_bucket);
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
