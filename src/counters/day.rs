// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The host-local day an instant falls on.
//!
//! Private stand-in for `crate::local_day`, which the host-local day change owns and lands
//! first (ADR-026). The signature is that API's, exactly, so U1 swaps this
//! file for one import at rebase and lands no second implementation. The
//! zone is a parameter, so a test names its zone instead of the host's.

use chrono::{NaiveDate, TimeZone};

/// One local day: its date, and where it starts and ends in UTC unix
/// seconds. `end` is exclusive and is the next day's `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalDay {
    pub date: NaiveDate,
    pub start: u64,
    pub end: u64,
}

/// The first instant of `date` in `zone`: midnight, or the first instant
/// after it when the zone skips midnight that day.
fn first_instant<Z: TimeZone>(zone: &Z, date: NaiveDate) -> u64 {
    let midnight = date.and_time(chrono::NaiveTime::MIN);
    (0..=12)
        .find_map(|quarter| {
            let local =
                midnight.checked_add_signed(chrono::TimeDelta::try_minutes(15 * quarter)?)?;
            zone.from_local_datetime(&local).earliest()
        })
        .and_then(|start| u64::try_from(start.timestamp()).ok())
        .unwrap_or_default()
}

/// The local day `unix_secs` falls on in `zone`. An instant chrono cannot
/// place (past year 262,000) is read as the epoch's day.
pub(crate) fn local_day<Z: TimeZone>(zone: &Z, unix_secs: u64) -> LocalDay {
    let date = i64::try_from(unix_secs)
        .ok()
        .and_then(|secs| zone.timestamp_opt(secs, 0).single())
        .map_or(NaiveDate::default(), |local| local.date_naive());
    let next = date.succ_opt().unwrap_or(date);
    LocalDay {
        date,
        start: first_instant(zone, date),
        end: first_instant(zone, next),
    }
}
