// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway host's local day (ADR-026).
//!
//! Every "day" the gateway counts runs from local midnight to local midnight
//! in the host's time zone, read from the system; there is no setting. A day
//! is not always 24 hours: it is 25 hours on the autumn DST change and 23 on
//! the spring one, and a zone may skip midnight itself. [`local_day`] dates an
//! instant and returns that day's exact bounds, so callers never divide by
//! 86 400.

use std::sync::OnceLock;

use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc};

/// One local calendar day and the UTC instants that bound it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalDay {
    /// The local calendar date.
    pub(crate) date: NaiveDate,
    /// Unix seconds of the day's first instant: local midnight, or the first
    /// valid local time after it where the zone skips midnight. 0 for the
    /// day holding the epoch in a zone ahead of UTC, so a walk back through
    /// `start - 1` stops there.
    pub(crate) start: u64,
    /// Unix seconds of the next date's first instant (exclusive), so
    /// consecutive days tile with no gap and no overlap.
    pub(crate) end: u64,
}

/// The local day `unix_secs` falls on in `zone`. An instant past
/// [`MAX_SECS`] counts as that one.
pub(crate) fn local_day<Z: TimeZone>(zone: &Z, unix_secs: u64) -> LocalDay {
    let secs = i64::try_from(unix_secs).map_or(MAX_SECS, |secs| secs.min(MAX_SECS));
    let date = local_date(zone, secs);
    LocalDay {
        date,
        start: first_instant(zone, date),
        end: date
            .succ_opt()
            .map_or(u64::MAX, |next| first_instant(zone, next)),
    }
}

/// 9999-12-31T23:59:59Z. Every offset keeps a date this late, or a few days
/// either side of it, inside chrono's range, so no conversion can overflow.
const MAX_SECS: i64 = 253_402_300_799;

/// The local date of `secs` in `zone`.
fn local_date<Z: TimeZone>(zone: &Z, secs: i64) -> NaiveDate {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map_or(NaiveDate::MAX, |utc| utc.with_timezone(zone).date_naive())
}

/// Unix seconds of the first instant whose local date is `date`. On a repeated
/// midnight that is the earlier one. Where the zone skips midnight, it is the
/// end of the gap, found to the second: UTC offsets stay within a day, so it
/// lies within two days of midnight read as UTC.
///
/// ponytail: a date the zone re-enters after rolling back across midnight
/// (America/St_Johns used 00:01 transitions until 2011) keeps only its first
/// stretch; split a day into several intervals if such dates ever matter.
fn first_instant<Z: TimeZone>(zone: &Z, date: NaiveDate) -> u64 {
    let midnight = date.and_time(NaiveTime::MIN);
    let secs = zone.from_local_datetime(&midnight).earliest().map_or_else(
        || {
            let guess = midnight.and_utc().timestamp();
            let (mut lo, mut hi) = (guess - 2 * 86_400, guess + 2 * 86_400);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if local_date(zone, mid) >= date {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            lo
        },
        |at| at.timestamp(),
    );
    u64::try_from(secs).unwrap_or(0)
}

/// The zone the system reports, read once. An unknown or unparseable name
/// falls back to UTC with one warning.
fn system_zone() -> chrono_tz::Tz {
    static ZONE: OnceLock<chrono_tz::Tz> = OnceLock::new();
    *ZONE.get_or_init(|| {
        let read = iana_time_zone::get_timezone();
        if let Ok(Ok(tz)) = read.as_deref().map(str::parse::<chrono_tz::Tz>) {
            tz
        } else {
            tracing::warn!(zone = ?read, "Cannot read the host's time zone; counting days in UTC");
            chrono_tz::Tz::UTC
        }
    })
}

/// The host's time zone.
#[cfg(not(test))]
pub(crate) fn host_zone() -> chrono_tz::Tz {
    system_zone()
}

/// The host's time zone: under `cfg(test)`, this thread's [`test_zone`]
/// override, else UTC, so a test's days never depend on where it runs.
#[cfg(test)]
pub(crate) fn host_zone() -> chrono_tz::Tz {
    TEST_ZONE
        .with(std::cell::Cell::get)
        .unwrap_or(chrono_tz::Tz::UTC)
}

/// The IANA name of [`host_zone`], such as `"Europe/Amsterdam"`; `"UTC"` on
/// the fallback.
pub(crate) fn host_zone_name() -> &'static str {
    host_zone().name()
}

#[cfg(test)]
thread_local! {
    static TEST_ZONE: std::cell::Cell<Option<chrono_tz::Tz>> = const { std::cell::Cell::new(None) };
}

/// Restores the zone this thread read before, when dropped. Not `Send`, so
/// it is dropped on the thread whose override it holds.
#[cfg(test)]
#[must_use]
pub(crate) struct ZoneGuard {
    previous: Option<chrono_tz::Tz>,
    _this_thread: std::marker::PhantomData<*const ()>,
}

#[cfg(test)]
impl Drop for ZoneGuard {
    fn drop(&mut self) {
        TEST_ZONE.with(|z| z.set(self.previous));
    }
}

/// This thread's [`host_zone`] reads `tz` until the guard drops.
#[cfg(test)]
pub(crate) fn test_zone(tz: chrono_tz::Tz) -> ZoneGuard {
    ZoneGuard {
        previous: TEST_ZONE.with(|z| z.replace(Some(tz))),
        _this_thread: std::marker::PhantomData,
    }
}

#[cfg(test)]
#[path = "local_day_tests.rs"]
mod tests;
