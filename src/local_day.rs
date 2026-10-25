// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway host's local day (ADR-026, MIK-8901).
//!
//! Every "day" the gateway counts runs from local midnight to local midnight
//! in the host's time zone, read from the system; there is no setting. A day
//! is not always 24 hours: it is 25 hours on the autumn DST change and 23 on
//! the spring one, and a zone may skip midnight itself. [`local_day`] dates an
//! instant and returns that day's exact bounds, so callers never divide by
//! 86 400.

use std::sync::OnceLock;

use chrono::{DateTime, NaiveDate, NaiveTime, TimeDelta, TimeZone, Utc};

/// One local calendar day and the UTC instants that bound it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the bounds' first reader is MIK-8854's counter store"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalDay {
    /// The local calendar date.
    pub(crate) date: NaiveDate,
    /// Unix seconds of the day's first instant: local midnight, or the first
    /// valid local time after it where the zone skips midnight.
    pub(crate) start: u64,
    /// Unix seconds of the next date's first instant (exclusive), so
    /// consecutive days tile with no gap and no overlap.
    pub(crate) end: u64,
}

/// The local day `unix_secs` falls on in `zone`.
pub(crate) fn local_day<Z: TimeZone>(zone: &Z, unix_secs: u64) -> LocalDay {
    let utc = i64::try_from(unix_secs)
        .ok()
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let date = utc.with_timezone(zone).date_naive();
    LocalDay {
        date,
        start: first_instant(zone, date),
        end: date
            .succ_opt()
            .map_or(u64::MAX, |next| first_instant(zone, next)),
    }
}

/// The longest run of local time a zone has ever skipped is one whole day
/// (Pacific/Apia, 2011-12-30), so a first valid minute lies within two days.
const MAX_GAP_MINUTES: i64 = 2 * 24 * 60;

/// Unix seconds of the first instant whose local date is `date`. On a repeated
/// midnight that is the earlier one; in a gap, the first valid minute after
/// it. Zone transitions fall on whole minutes.
fn first_instant<Z: TimeZone>(zone: &Z, date: NaiveDate) -> u64 {
    let midnight = date.and_time(NaiveTime::MIN);
    let secs = (0..=MAX_GAP_MINUTES)
        .find_map(|m| {
            let local = TimeDelta::try_minutes(m).and_then(|d| midnight.checked_add_signed(d))?;
            zone.from_local_datetime(&local).earliest()
        })
        .map_or_else(|| midnight.and_utc().timestamp(), |d| d.timestamp());
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

/// Restores the UTC test zone when dropped.
#[cfg(test)]
#[must_use]
pub(crate) struct ZoneGuard(());

#[cfg(test)]
impl Drop for ZoneGuard {
    fn drop(&mut self) {
        TEST_ZONE.with(|z| z.set(None));
    }
}

/// This thread's [`host_zone`] reads `tz` until the guard drops.
#[cfg(test)]
pub(crate) fn test_zone(tz: chrono_tz::Tz) -> ZoneGuard {
    TEST_ZONE.with(|z| z.set(Some(tz)));
    ZoneGuard(())
}

#[cfg(test)]
#[path = "local_day_tests.rs"]
mod tests;
