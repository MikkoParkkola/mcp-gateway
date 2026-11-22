// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `spend-history.json` rows: what a save writes and what a restore brings
//! back (refused files and the rest: `spend_history_save_rows_tests.rs`). Instants are fixed; the zone is UTC unless a
//! row sets its own.

use std::collections::HashSet;
use std::path::Path;

use chrono::NaiveDate;
use serde_json::Value;

use super::{FILE_NAME, MAX_KEYS, fingerprint, restore, save};
use crate::clock::test_clock::at_secs;
use crate::cost_accounting::CostTracker;
use crate::cost_accounting::spend_history_tests::spend;
use crate::cost_accounting::tally::Series;

pub(super) const HOUR: u64 = 3600;
pub(super) const DAY: u64 = 24 * HOUR;
/// 2026-11-21 12:00:00 UTC.
pub(super) const T0: u64 = 1_795_262_400;

fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// Save `tracker` into `dir` at `now`; the file as JSON.
pub(super) fn saved(tracker: &CostTracker, dir: &Path, now: u64) -> Value {
    assert!(save(tracker, dir, now), "the save wrote");
    let bytes = std::fs::read(dir.join(FILE_NAME)).expect("the file");
    serde_json::from_slice(&bytes).expect("JSON")
}

/// A new tracker restored from `dir` at `now`, `names` being the configured
/// API keys.
pub(super) fn restored(dir: &Path, names: &[&str], now: u64) -> CostTracker {
    let tracker = CostTracker::new();
    let _clock = at_secs(now);
    restore(&tracker, dir, &owned(names), Some(now));
    tracker
}

/// Micro-USD over a series' hours, and over its days.
pub(super) fn micro(series: &Series) -> (u64, u64) {
    let hours = series.hours.rows().iter().map(|r| r.2).sum();
    let days = series.days.rows().iter().map(|r| r.2).sum();
    (hours, days)
}

/// Micro-USD over a saved series' hours, and over its days.
pub(super) fn saved_micro(rows: &Value) -> (u64, u64) {
    let sum = |field: &str| {
        rows[field]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| row[2].as_u64().expect("micro"))
            .sum()
    };
    (sum("hours"), sum("days"))
}

pub(super) fn date_of(secs: u64) -> NaiveDate {
    crate::cost_accounting::tally::local_date(secs)
}

/// S1, S9: a restart brings back each key's hours and days, the keyless
/// series and the gateway's sum. Red before the file existed: a new tracker
/// read zero. Mutant: a saved hour replayed with its hour number as the time.
#[test]
fn a_restart_keeps_every_series_hours_and_days() {
    let dir = tempfile::tempdir().expect("dir");
    let before = CostTracker::new();
    // Three hours over two local dates for the key, one keyless call.
    for (at, n) in [(T0 - 26 * HOUR, 1), (T0 - HOUR, 2), (T0, 4)] {
        spend(&before, Some("k"), at, n);
    }
    spend(&before, None, T0, 8);
    saved(&before, dir.path(), T0);

    let after = restored(dir.path(), &["k"], T0 + 60);
    let (was, back) = (
        before.key_series("k").expect("the key"),
        after.key_series("k").expect("the key is back"),
    );
    assert_eq!(back.hours.rows(), was.hours.rows());
    assert_eq!(back.days.rows(), was.days.rows());
    assert_eq!(back.days.rows().len(), 2, "premise: two local dates");
    let (keyless, keyless_back) = (before.keyless_series(), after.keyless_series());
    assert_eq!(keyless_back.hours.rows(), keyless.hours.rows());
    assert_eq!(keyless_back.days.rows(), keyless.days.rows());
    let at = T0 + 60;
    let (total, total_back) = (before.gateway_series(at), after.gateway_series(at));
    assert_eq!(total_back.hours.rows(), total.hours.rows());
    assert_eq!(total_back.days.rows(), total.days.rows());
    // The windows the views read are back as well.
    let _clock = at_secs(T0 + 60);
    let report = after.key_snapshot("k").expect("a report");
    assert_eq!(report.window_24h.tokens, Some(6));
}

/// S4: one series in the file holds at most 721 hours and 30 local dates.
#[test]
fn a_saved_series_holds_at_most_721_hours_and_30_dates() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    for ago in (0..800).rev() {
        spend(&tracker, Some("k"), T0 - ago * HOUR, 1);
    }
    let file = saved(&tracker, dir.path(), T0);
    let row = &file["keys"][0];
    assert_eq!(row["hours"].as_array().expect("hours").len(), 721);
    assert_eq!(row["days"].as_array().expect("days").len(), 30);
}

/// S4: past 512 keys, the least 30-day spenders are summed into `overflow`.
/// That sum is never a key: a real key called `other` stays its own row,
/// and no key appears after a restore that nobody recorded. Mutants: the
/// fold dropped instead of summed; the overflow restored into the key map.
#[test]
fn keys_past_the_cap_fold_into_the_overflow_which_is_no_key() {
    assert_eq!(MAX_KEYS, 512, "premise");
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    // 513 keys spending 1..=513, so the two least (1 and 2) fold.
    let names: Vec<String> = (0..513).map(|i| format!("k{i:04}")).collect();
    for (name, n) in names.iter().zip(1..) {
        spend(&tracker, Some(name), T0, n);
    }
    spend(&tracker, Some("other"), T0, 1_000);
    let file = saved(&tracker, dir.path(), T0);

    let rows = file["keys"].as_array().expect("keys");
    assert_eq!(rows.len(), MAX_KEYS);
    let kept: HashSet<&str> = rows
        .iter()
        .map(|r| r["name"].as_str().expect("name"))
        .collect();
    assert!(
        !kept.contains("k0000") && !kept.contains("k0001"),
        "the least spend folds"
    );
    assert!(kept.contains("other"));
    assert_eq!(saved_micro(&file["overflow"]), (3, 3));

    let mut configured: Vec<&str> = names.iter().map(String::as_str).collect();
    configured.push("other");
    let back = restored(dir.path(), &configured, T0 + 60);
    assert_eq!(back.per_key.len(), MAX_KEYS, "only the saved rows are keys");
    assert!(
        back.per_key
            .iter()
            .all(|e| configured.contains(&e.key().as_str()))
    );
    assert_eq!(
        micro(&back.key_series("other").expect("other")),
        (1_000, 1_000)
    );
    assert_eq!(micro(&back.carried.lock()), (3, 3));
    assert_eq!(
        micro(&back.gateway_series(T0 + 60)),
        micro(&tracker.gateway_series(T0 + 60))
    );
}

/// S4, S16 (r7d): a 200-byte key keeps its full name in memory and in the
/// views; its row saves the display form and the fingerprint, and after a
/// restore the full name finds its history. Nothing answers to the display
/// form.
#[test]
fn a_long_name_is_found_by_its_full_name_before_and_after_a_restore() {
    let dir = tempfile::tempdir().expect("dir");
    let long = "n".repeat(200);
    let tracker = CostTracker::new();
    spend(&tracker, Some(&long), T0, 5);
    {
        let _clock = at_secs(T0);
        assert!(
            tracker.key_snapshot(&long).is_some(),
            "the view uses the full name"
        );
    }
    let file = saved(&tracker, dir.path(), T0);

    let row = &file["keys"][0];
    let display = row["name"].as_str().expect("name");
    assert_eq!(display, crate::counters::normalize(&long));
    assert!(display.len() <= 128 && display != long);
    assert_eq!(row["fp"], fingerprint(&long));
    let back = restored(dir.path(), &[&long], T0 + 60);
    assert_eq!(
        micro(&back.key_series(&long).expect("by full name")),
        (5, 5)
    );
    assert!(
        back.key_series(display).is_none(),
        "the display form is no key"
    );
}

/// r7d carry: a long name and a key named exactly its display form, both
/// configured, save two rows with one display name and two fingerprints,
/// and each comes back to its own key.
#[test]
fn a_key_named_like_another_keys_display_form_keeps_its_own_row() {
    let dir = tempfile::tempdir().expect("dir");
    let long = "L".repeat(200);
    let short = crate::counters::normalize(&long);
    let tracker = CostTracker::new();
    spend(&tracker, Some(&long), T0, 5);
    spend(&tracker, Some(&short), T0, 7);
    let file = saved(&tracker, dir.path(), T0);
    let rows = file["keys"].as_array().expect("keys");
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["name"] == short.as_str()));
    assert_ne!(rows[0]["fp"], rows[1]["fp"]);

    let back = restored(dir.path(), &[&long, &short], T0 + 60);
    assert_eq!(micro(&back.key_series(&long).expect("long")), (5, 5));
    assert_eq!(micro(&back.key_series(&short).expect("short")), (7, 7));
}

/// S24b: the next start's config drops the long key and adds one named its
/// display form. That key inherits nothing; the old spend is carried, so the
/// gateway's total is the saved one. Mutant: the restore matching by display
/// name.
#[test]
fn a_new_key_named_like_a_removed_keys_display_form_inherits_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let long = "L".repeat(200);
    let short = crate::counters::normalize(&long);
    let before = CostTracker::new();
    spend(&before, Some(&long), T0, 5);
    spend(&before, None, T0, 1);
    saved(&before, dir.path(), T0);

    let back = restored(dir.path(), &[&short], T0 + 60);
    assert!(
        back.key_series(&short).is_none(),
        "the new key has no history"
    );
    assert_eq!(micro(&back.carried.lock()), (5, 5));
    assert_eq!(
        micro(&back.gateway_series(T0 + 60)),
        micro(&before.gateway_series(T0 + 60))
    );
}

/// S25: across a reload, a key named like an old key's display form starts
/// its own series and leaves the old one as it was. Mutant: memory keyed by
/// the display form.
#[test]
fn a_reloaded_key_named_like_a_display_form_records_apart() {
    let long = "L".repeat(200);
    let short = crate::counters::normalize(&long);
    let tracker = CostTracker::new();
    spend(&tracker, Some(&long), T0, 5);
    spend(&tracker, Some(&short), T0 + 60, 7);
    assert_eq!(micro(&tracker.key_series(&short).expect("short")), (7, 7));
    assert_eq!(micro(&tracker.key_series(&long).expect("long")), (5, 5));
}

/// S27: a saved row no configured key claims is carried, and the next save
/// writes it in the overflow, never as a key row. Mutant: unmatched rows
/// dropped.
#[test]
fn a_removed_keys_row_is_carried_into_the_next_saves_overflow() {
    let (dir, next) = (
        tempfile::tempdir().expect("dir"),
        tempfile::tempdir().expect("dir"),
    );
    let before = CostTracker::new();
    spend(&before, Some("gone"), T0, 5);
    saved(&before, dir.path(), T0);

    let back = restored(dir.path(), &[], T0 + 60);
    assert_eq!(back.per_key.len(), 0);
    let file = saved(&back, next.path(), T0 + 60);
    assert_eq!(file["keys"].as_array().expect("keys").len(), 0);
    assert_eq!(saved_micro(&file["overflow"]), (5, 5));
}

/// S5: what aged out while the gateway was down stays out. Nothing comes
/// back from a file 40 days old; from a file 2 days old, only the hours and
/// the dates still inside their windows do.
#[test]
fn a_restore_drops_what_aged_out_while_the_gateway_was_down() {
    let dir = tempfile::tempdir().expect("dir");
    let old = CostTracker::new();
    spend(&old, Some("k"), T0 - 40 * DAY, 3);
    spend(&old, None, T0 - 40 * DAY, 3);
    saved(&old, dir.path(), T0 - 40 * DAY);
    let back = restored(dir.path(), &["k"], T0);
    assert_eq!(micro(&back.gateway_series(T0)), (0, 0));
    // grok seat 2: an idle key whose rows all aged out is not reborn empty.
    assert!(
        back.key_series("k").is_none(),
        "an aged-out key got an entry"
    );

    let dir = tempfile::tempdir().expect("dir");
    let recent = CostTracker::new();
    let saved_at = T0 - 2 * DAY;
    for ago in (0..800).rev() {
        spend(&recent, Some("k"), saved_at - ago * HOUR, 1);
    }
    let file = saved(&recent, dir.path(), saved_at);
    let back = restored(dir.path(), &["k"], T0);
    let series = back.key_series("k").expect("the key");
    let first_hour = T0 / HOUR - 720;
    let want_hours: Vec<u64> = file["keys"][0]["hours"]
        .as_array()
        .expect("hours")
        .iter()
        .map(|row| row[0].as_u64().expect("hour"))
        .filter(|hour| *hour >= first_hour)
        .collect();
    assert_eq!(
        want_hours.len(),
        721 - 48,
        "premise: two days of hours aged out"
    );
    let got_hours: Vec<u64> = series.hours.rows().iter().map(|r| r.0).collect();
    assert_eq!(got_hours, want_hours);
    let today = date_of(T0);
    let got_days: Vec<NaiveDate> = series.days.rows().iter().map(|r| r.0).collect();
    assert_eq!(
        got_days.len(),
        28,
        "the dates within 30 of today, from a save 2 days back"
    );
    assert!(got_days.iter().all(|d| (today - *d).num_days() < 30));
}

/// grok seat 2 (CRITICAL): a start whose clock reads before 1970 restores
/// nothing and saves nothing for the rest of its run, so the file on disk
/// waits for a start that can read it. Red before: the start skipped the
/// restore but left saving on, and its next save replaced the file.
#[test]
fn a_start_before_1970_neither_restores_nor_replaces_the_history() {
    let dir = tempfile::tempdir().expect("dir");
    let before = CostTracker::new();
    spend(&before, Some("k"), T0, 5);
    saved(&before, dir.path(), T0);
    let on_disk = std::fs::read(dir.path().join(FILE_NAME)).expect("the file");

    let dark = CostTracker::new();
    restore(&dark, dir.path(), &owned(&["k"]), None);
    assert!(dark.key_series("k").is_none(), "something was restored");
    spend(&dark, Some("k"), T0 + 60, 7);
    assert!(!save(&dark, dir.path(), T0 + 60), "the run saved");
    let after = std::fs::read(dir.path().join(FILE_NAME)).expect("the file");
    assert_eq!(after, on_disk, "the history on disk was replaced");
}

/// gpt delta 2 (CRITICAL), fixed at its cause (lead): a file written on a
/// clock that ran 40 days ahead, restored after the clock was put back. Its
/// spend is kept in the restore's own hour and date, with one warning that
/// gives the skew, so no slot is dated after the restore. The key then ages
/// like one that spent at the restore: a sweep 29 days on keeps it, and one
/// 31 days on drops it with its rows expired. Red before: the rows kept
/// their future dates, so a sweep 31 days on dropped a key still holding
/// spend inside its windows.
#[test]
fn rows_dated_ahead_restore_into_the_restore_hour_and_age_from_there() {
    let dir = tempfile::tempdir().expect("dir");
    let ahead = CostTracker::new();
    spend(&ahead, Some("k"), T0 + 40 * DAY, 3);
    saved(&ahead, dir.path(), T0 + 40 * DAY);
    let at_restore = || restored(dir.path(), &["k"], T0);
    let (back, logged) = crate::test_log_capture::capture_warnings(at_restore);
    let series = back.key_series("k").expect("the key restored");
    assert_eq!(series.hours.rows(), vec![(T0 / HOUR, 3, 3)]);
    assert_eq!(series.days.rows(), vec![(date_of(T0), 3, 3)]);
    assert_eq!(logged.matches(" WARN ").count(), 1, "one warning: {logged}");
    assert!(logged.contains("hours_ahead=960"), "the skew: {logged}");

    let kept_after_sweep_at = |at: u64| {
        back.next_key_sweep
            .store(0, std::sync::atomic::Ordering::Relaxed);
        spend(&back, Some("poke"), at, 1);
        back.key_series("k").is_some()
    };
    assert!(
        kept_after_sweep_at(T0 + 29 * DAY),
        "swept with its rows held"
    );
    assert!(
        !kept_after_sweep_at(T0 + 31 * DAY),
        "kept with its rows expired"
    );
}

/// Lead 2026-11-22: the clamp keeps every unit of spend. A file with rows
/// before, in and after the restore hour restores to the file's own totals,
/// over hours and over days, and nothing is dated after the restore. The
/// totals held before the clamp too; the two date checks were red.
#[test]
fn a_restore_that_clamps_rows_keeps_the_files_totals() {
    let dir = tempfile::tempdir().expect("dir");
    let written = CostTracker::new();
    // Before, in and after the restore hour, and three days on.
    let spent_at = [T0 - 2 * HOUR, T0, T0 + 5 * HOUR, T0 + 3 * DAY];
    for (at, n) in spent_at.into_iter().zip([1, 2, 4, 8]) {
        spend(&written, Some("k"), at, n);
    }
    let file = saved(&written, dir.path(), T0 + 3 * DAY);
    let series = restored(dir.path(), &["k"], T0)
        .key_series("k")
        .expect("the key");
    let kept = micro(&series);
    assert_eq!(kept, saved_micro(&file["keys"][0]), "the file's totals");
    assert_eq!(kept, (15, 15));
    let last_hour = series.hours.newest().expect("hours");
    let last_date = series.days.newest().expect("dates");
    assert_eq!(
        (last_hour, last_date),
        (T0 / HOUR, date_of(T0)),
        "dated ahead"
    );
}
