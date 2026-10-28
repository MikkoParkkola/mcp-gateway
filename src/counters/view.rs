// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reading a series out of the store: windows, filters and the previous
//! period, which maps by local wall-clock time (ADR-017, ADR-026).

use chrono::{LocalResult, TimeZone};
use serde::Serialize;

use super::{CounterStore, Dim, HALF, Inner, Metric, Series, day, normalize};

/// How far back a series reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Window {
    /// 48 half-hour points.
    Day,
    /// 96 half-hour points.
    TwoDays,
    /// One point per local date, 30 dates.
    Month,
}

/// Which series to read. Only these combinations exist: anything else is
/// refused by the route, never answered with a broader aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filter<'a> {
    All,
    Server(&'a str),
    Tool(&'a str, &'a str),
    Caller(&'a str),
    CallerServer(&'a str, &'a str),
    /// A dimension's overflow count.
    Overflow(Dim),
}

/// One series read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Query<'a> {
    pub metric: Metric,
    pub window: Window,
    pub filter: Filter<'a>,
    /// Also read the previous period; [`Window::Day`] only.
    pub compare: bool,
}

#[cfg(test)]
impl<'a> Query<'a> {
    /// A read with no previous period.
    pub(crate) const fn new(metric: Metric, window: Window, filter: Filter<'a>) -> Self {
        Self {
            metric,
            window,
            filter,
            compare: false,
        }
    }
}

/// One point: the bucket's or day's start, in unix seconds, and its count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Point {
    pub t: u64,
    pub v: u64,
}

/// What a read returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeriesView {
    pub points: Vec<Point>,
    /// The previous period, when asked for.
    pub previous: Option<Vec<Point>>,
    /// False when part of the previous period lies outside what the store
    /// holds (before `since`, or past the 48-hour ring on a 25-hour day).
    pub previous_complete: bool,
    /// The asked label is not held and its dimension is full, or its
    /// dimension's overflow has calls in this window, so its calls may be in
    /// the overflow count: no points are returned for it.
    pub folded: bool,
    /// When coverage began. For a label admitted after its dimension's
    /// overflow had calls in this window, it is the label's own first bucket.
    pub since: u64,
}

impl Inner {
    /// The series `filter` names and, for a label, its dimension's overflow.
    /// `Err` when the label is not held: the overflow, and whether the
    /// dimension is full.
    pub(super) fn find(
        &self,
        filter: Filter<'_>,
    ) -> Result<(&Series, Option<&Series>), (&Series, bool)> {
        fn held<'s, K: std::hash::Hash + Eq>(
            dim: &'s super::Dimension<K>,
            key: &K,
        ) -> Result<(&'s Series, Option<&'s Series>), (&'s Series, bool)> {
            dim.labels
                .get(key)
                .map(|series| (series, Some(&dim.overflow)))
                .ok_or((&dim.overflow, dim.labels.len() >= dim.cap))
        }
        match filter {
            Filter::All => Ok((&self.global, None)),
            Filter::Server(s) => held(&self.server, &normalize(s)),
            Filter::Tool(s, t) => held(&self.tool, &(normalize(s), normalize(t))),
            Filter::Caller(c) => held(&self.caller, &normalize(c)),
            Filter::CallerServer(c, s) => held(&self.caller_server, &(normalize(c), normalize(s))),
            Filter::Overflow(Dim::Server) => Ok((&self.server.overflow, None)),
            Filter::Overflow(Dim::Tool) => Ok((&self.tool.overflow, None)),
            Filter::Overflow(Dim::Caller) => Ok((&self.caller.overflow, None)),
            Filter::Overflow(Dim::CallerServer) => Ok((&self.caller_server.overflow, None)),
        }
    }
}

/// One bucket of a window: its start in unix seconds, and its key in the
/// ring the window reads.
#[derive(Clone, Copy)]
pub(super) struct Slot {
    pub(super) t: u64,
    pub(super) key: u64,
}

/// The ring `window` reads, as one bucket's counts.
fn counts(series: &Series, window: Window, key: u64) -> Option<[u64; 5]> {
    match window {
        Window::Day | Window::TwoDays => series.half.get(key),
        Window::Month => series.day.get(key),
    }
}

/// The buckets `window` reads at unix second `now`, oldest first, none
/// before `since`.
pub(super) fn window_slots<Tz: TimeZone>(
    window: Window,
    now: u64,
    since: u64,
    zone: &Tz,
) -> Vec<Slot> {
    match window {
        Window::Day | Window::TwoDays => {
            let n = if window == Window::Day { 48 } else { 96 };
            let now_bucket = now / HALF;
            ((now_bucket + 1).saturating_sub(n)..=now_bucket)
                .filter(|b| (b + 1) * HALF > since)
                .map(|b| Slot {
                    t: b * HALF,
                    key: b,
                })
                .collect()
        }
        Window::Month => {
            // Today, then each day before it, walked back from its start.
            let mut days = vec![day::local_day(zone, now)];
            while days.len() < super::DAYS {
                let earliest = days[days.len() - 1];
                if earliest.start == 0 {
                    break;
                }
                days.push(day::local_day(zone, earliest.start - 1));
            }
            days.iter()
                .rev()
                .filter(|day| day.end > since)
                .map(|day| Slot {
                    t: day.start,
                    key: super::day_key(day.date),
                })
                .collect()
        }
    }
}

impl CounterStore {
    /// Read `query` at unix second `now`, days cut in `zone`.
    pub(crate) fn series<Tz: TimeZone>(
        &self,
        query: &Query<'_>,
        now: u64,
        zone: &Tz,
    ) -> SeriesView {
        let inner = self.read_lock();
        let mut since = inner.since;
        let mut slots = window_slots(query.window, now, since, zone);
        let overflowed =
            |overflow: &Series, slot: &Slot| counts(overflow, query.window, slot.key).is_some();
        let empty = Series::default();
        // Where the previous period may start drawing: rule (b) again, over
        // the 48-hour ring that period is read from.
        let mut previous_since = since;
        let series = match inner.find(query.filter) {
            // A label not held, with calls in its dimension's overflow in
            // this window, may be among them: zeros would read as exact.
            Err((overflow, full)) => {
                if full || slots.iter().any(|slot| overflowed(overflow, slot)) {
                    return SeriesView {
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
                // Overflow calls from before the label took its slot may be its
                // own: it is covered from the bucket it was admitted in.
                let first = slots
                    .iter()
                    .rposition(|slot| slot.t <= series.admitted)
                    .unwrap_or(0);
                if let Some(overflow) = overflow {
                    let admitted = series.admitted - series.admitted % HALF;
                    // Only the 48 hours the two periods are read from: a
                    // ring keeps older buckets until its next write.
                    let read_from = (now / HALF + 1).saturating_sub(super::HALF_BUCKETS as u64);
                    if overflow
                        .half
                        .buckets()
                        .any(|(b, _)| b >= read_from && b * HALF < admitted)
                    {
                        previous_since = previous_since.max(admitted);
                    }
                    if slots[..first].iter().any(|slot| overflowed(overflow, slot)) {
                        since = since.max(slots[first].t);
                        slots.drain(..first);
                    }
                }
                series
            }
        };
        let m = query.metric.index();
        let points: Vec<Point> = slots
            .into_iter()
            .map(|slot| Point {
                t: slot.t,
                v: counts(series, query.window, slot.key).map_or(0, |c| c[m]),
            })
            .collect();
        let mut view = SeriesView {
            points,
            previous: None,
            previous_complete: true,
            folded: false,
            since,
        };
        if query.compare && query.window == Window::Day {
            let (previous, complete) = previous_day(
                series,
                &view.points,
                now / HALF,
                since.max(previous_since),
                m,
                zone,
            );
            view.previous = Some(previous);
            view.previous_complete = complete;
        }
        view
    }
}

/// The previous period of `points`: for each point, the bucket holding the
/// same local wall-clock time on the previous local date. A wall time that
/// occurred twice there gives both buckets; one that did not exist gives
/// none. A bucket the ring no longer holds, or before `since`, is left out
/// and marks the period incomplete.
fn previous_day<Tz: TimeZone>(
    series: &Series,
    points: &[Point],
    now_bucket: u64,
    since: u64,
    m: usize,
    zone: &Tz,
) -> (Vec<Point>, bool) {
    let held_from = series.half.window_start(now_bucket);
    let (buckets, mapped) = previous_buckets(points.iter().map(|p| p.t), zone);
    let mut complete = mapped;
    let previous = buckets
        .into_iter()
        .filter(|&bucket| {
            let kept = bucket >= held_from && (bucket + 1) * HALF > since;
            complete &= kept;
            kept
        })
        .map(|bucket| Point {
            t: bucket * HALF,
            v: series.half.get(bucket).map_or(0, |c| c[m]),
        })
        .collect();
    (previous, complete)
}

/// The half-hour buckets holding, for each of `times` (unix seconds), the
/// same local wall-clock time on the previous local date: oldest first, each
/// once. A wall time that occurred twice there gives both buckets; one that
/// did not exist gives none. The flag is false when a time could not be
/// mapped at all (outside the zone's range), so its bucket is unknown.
pub(super) fn previous_buckets<Tz: TimeZone>(
    times: impl Iterator<Item = u64>,
    zone: &Tz,
) -> (Vec<u64>, bool) {
    let mut buckets: Vec<u64> = Vec::new();
    let mut mapped = true;
    for time in times {
        let Some(local) = i64::try_from(time)
            .ok()
            .and_then(|t| zone.timestamp_opt(t, 0).single())
            .map(|t| t.naive_local())
        else {
            mapped = false;
            continue;
        };
        let Some(wall) = local
            .date()
            .pred_opt()
            .map(|date| date.and_time(local.time()))
        else {
            mapped = false;
            continue;
        };
        let instants: Vec<_> = match zone.from_local_datetime(&wall) {
            LocalResult::Single(t) => vec![t],
            LocalResult::Ambiguous(a, b) => vec![a, b],
            LocalResult::None => vec![],
        };
        for instant in instants {
            let Ok(t) = u64::try_from(instant.timestamp()) else {
                mapped = false;
                continue;
            };
            buckets.push(t / HALF);
        }
    }
    // A repeated hour on either side maps two times to one bucket, and an
    // ambiguous wall time adds a later bucket before an earlier one.
    buckets.sort_unstable();
    buckets.dedup();
    (buckets, mapped)
}
