// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The local day an instant falls on, and when a local day starts.
//!
//! Private stand-in for the shared local-day function MIK-8901 owns (ADR-026):
//! U1 swaps these for it at rebase and lands no second implementation. The
//! zone is a parameter, `chrono::Local` in production, so a test names its
//! zone instead of depending on the host's.

use chrono::{Datelike, NaiveDate, TimeZone};

/// The local date of unix second `at` in `zone`, as days from the common
/// era, or `None` outside chrono's range.
pub(crate) fn day_key<Tz: TimeZone>(at: u64, zone: &Tz) -> Option<u64> {
    let secs = i64::try_from(at).ok()?;
    let local = zone.timestamp_opt(secs, 0).single()?;
    u64::try_from(local.date_naive().num_days_from_ce()).ok()
}

/// The date a [`day_key`] names.
pub(crate) fn date_of(key: u64) -> Option<NaiveDate> {
    NaiveDate::from_num_days_from_ce_opt(i32::try_from(key).ok()?)
}

/// The unix second local day `key` starts in `zone`: its midnight, or the
/// first instant after it when the zone skips midnight that day.
pub(crate) fn day_start<Tz: TimeZone>(key: u64, zone: &Tz) -> Option<u64> {
    let date = date_of(key)?;
    let midnight = date.and_hms_opt(0, 0, 0)?;
    let start = (0..=12).find_map(|quarter| {
        let local = midnight.checked_add_signed(chrono::TimeDelta::try_minutes(15 * quarter)?)?;
        zone.from_local_datetime(&local).earliest()
    })?;
    u64::try_from(start.timestamp()).ok()
}
