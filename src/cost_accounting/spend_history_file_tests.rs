// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `spend-history.json` rows: what a save writes, what a restore brings back,
//! and what a restore refuses. Instants are fixed; the zone is UTC unless a
//! row sets its own.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use chrono::NaiveDate;
use serde_json::{Value, json};

use super::{FILE_NAME, MAX_KEYS, fingerprint, restore, save, save_with};
use crate::clock::test_clock::at_secs;
use crate::cost_accounting::spend_history_tests::{date, local, spend};
use crate::cost_accounting::tally::Series;
use crate::cost_accounting::{CostTracker, KeyCost};

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;
/// 2026-11-21 12:00:00 UTC.
const T0: u64 = 1_795_262_400;

fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// Save `tracker` into `dir` at `now`; the file as JSON.
fn saved(tracker: &CostTracker, dir: &Path, now: u64) -> Value {
    assert!(save(tracker, dir, now), "the save wrote");
    let bytes = std::fs::read(dir.join(FILE_NAME)).expect("the file");
    serde_json::from_slice(&bytes).expect("JSON")
}

/// A new tracker restored from `dir` at `now`, `names` being the configured
/// API keys.
fn restored(dir: &Path, names: &[&str], now: u64) -> CostTracker {
    let tracker = CostTracker::new();
    let _clock = at_secs(now);
    restore(&tracker, dir, &owned(names), now);
    tracker
}

/// Micro-USD over a series' hours, and over its days.
fn micro(series: &Series) -> (u64, u64) {
    let hours = series.hours.rows().iter().map(|r| r.2).sum();
    let days = series.days.rows().iter().map(|r| r.2).sum();
    (hours, days)
}

/// Micro-USD over a saved series' hours, and over its days.
fn saved_micro(rows: &Value) -> (u64, u64) {
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

fn date_of(secs: u64) -> NaiveDate {
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
    let (total, total_back) = (before.gateway_series(), after.gateway_series());
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
        micro(&back.gateway_series()),
        micro(&tracker.gateway_series())
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
        micro(&back.gateway_series()),
        micro(&before.gateway_series())
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
    assert_eq!(micro(&back.gateway_series()), (0, 0));

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

/// A whole file holding one hour and one date in the keyless series and the
/// overflow, and `keys`: each case below breaks it in one place.
fn valid(keys: Value) -> Value {
    let rows = json!({"hours": [[T0 / HOUR, 1, 1]], "days": [["2026-11-21", 1, 1]]});
    json!({"keyless": rows.clone(), "keys": keys, "overflow": rows})
}

fn key_row(fp: &str) -> Value {
    json!({"fp": fp, "name": "k", "hours": [[T0 / HOUR, 1, 1]], "days": []})
}

/// S6, S26: a file the restore cannot trust starts the history empty with one
/// warning and is set aside; with no file there is no warning. Mutants: a
/// series past its row caps accepted; two rows with one fingerprint
/// accepted.
#[test]
fn a_bad_file_starts_empty_with_one_warning_and_is_set_aside() {
    let fp = fingerprint("k");
    let hours = |n: u64| {
        json!(
            (0..n)
                .map(|i| json!([T0 / HOUR - i, 1, 1]))
                .collect::<Vec<_>>()
        )
    };
    let days = |n: u64| {
        let today = date_of(T0);
        let rows: Vec<Value> = (0..n)
            .map(|i| json!([(today - chrono::Days::new(i)).to_string(), 1, 1]))
            .collect();
        json!(rows)
    };
    let with = |field: &str, rows: Value| {
        let mut file = valid(json!([]));
        file["keyless"][field] = rows;
        file.to_string().into_bytes()
    };
    let keys = |rows: Vec<Value>| valid(json!(rows)).to_string().into_bytes();
    let many: Vec<Value> = (0..=MAX_KEYS)
        .map(|i| key_row(&fingerprint(&format!("x{i}"))))
        .collect();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("an empty file", Vec::new()),
        ("not JSON", b"{not json".to_vec()),
        ("a missing field", br#"{"keys": []}"#.to_vec()),
        (
            "a date that does not parse",
            with("days", json!([["2026-13-01", 1, 1]])),
        ),
        (
            "an hour past the clock",
            with("hours", json!([[u64::MAX / 3600 + 1, 1, 1]])),
        ),
        (
            "a repeated hour",
            with("hours", json!([[T0 / HOUR, 1, 1], [T0 / HOUR, 1, 1]])),
        ),
        (
            "a repeated date",
            with("days", json!([["2026-11-21", 1, 1], ["2026-11-21", 1, 1]])),
        ),
        ("722 hours", with("hours", hours(722))),
        ("31 dates", with("days", days(31))),
        ("513 keys", keys(many)),
        (
            "one fingerprint twice",
            keys(vec![key_row(&fp), key_row(&fp)]),
        ),
        (
            "an upper-case fingerprint",
            keys(vec![key_row(&fp.to_uppercase())]),
        ),
        ("a short fingerprint", keys(vec![key_row(&fp[..31])])),
    ];
    for (what, bytes) in cases {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join(FILE_NAME), &bytes).expect("write");
        let (back, warnings) =
            crate::test_log_capture::capture_warnings(|| restored(dir.path(), &["k"], T0));
        assert_eq!(
            micro(&back.gateway_series()),
            (0, 0),
            "{what}: restored something"
        );
        assert_eq!(back.per_key.len(), 0, "{what}: restored a key");
        let warned = warnings.lines().filter(|l| l.contains("WARN")).count();
        assert_eq!(warned, 1, "{what}: {warnings}");
        assert!(
            !dir.path().join(FILE_NAME).exists(),
            "{what}: not set aside"
        );
        let aside = std::fs::read_dir(dir.path())
            .expect("dir")
            .filter_map(Result::ok)
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("spend-history.json.unreadable-")
            });
        assert!(aside, "{what}: the bytes are kept aside");
    }
    // Whole, the file the cases break restores without a warning.
    let dir = tempfile::tempdir().expect("dir");
    let whole = valid(json!([key_row(&fp)])).to_string();
    std::fs::write(dir.path().join(FILE_NAME), whole).expect("write");
    let (back, warnings) =
        crate::test_log_capture::capture_warnings(|| restored(dir.path(), &["k"], T0));
    assert!(warnings.is_empty(), "{warnings}");
    assert_eq!(micro(&back.key_series("k").expect("k")), (1, 0));

    let dir = tempfile::tempdir().expect("dir");
    let (back, warnings) =
        crate::test_log_capture::capture_warnings(|| restored(dir.path(), &["k"], T0));
    assert!(warnings.is_empty(), "no file: {warnings}");
    assert_eq!(back.per_key.len(), 0);
}

/// The string values held at any depth of `value`, in document order.
fn texts(value: &Value) -> Vec<&str> {
    match value {
        Value::String(text) => vec![text.as_str()],
        Value::Array(items) => items.iter().flat_map(texts).collect(),
        Value::Object(fields) => fields.values().flat_map(texts).collect(),
        _ => Vec::new(),
    }
}

/// S8: the file holds numbers, dates, fingerprints and key names only: no
/// session id, backend or tool name.
#[test]
fn the_file_holds_only_numbers_dates_fingerprints_and_key_names() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    {
        let _clock = at_secs(T0);
        tracker.record("a-session-id", Some("k"), "a-backend", "a-tool", 3, 1.0);
        tracker.record("", None, "a-backend", "a-tool", 3, 1.0);
    }
    let file = saved(&tracker, dir.path(), T0);
    let fp = fingerprint("k");
    for text in texts(&file) {
        let allowed =
            text == "k" || text == fp || NaiveDate::parse_from_str(text, "%Y-%m-%d").is_ok();
        assert!(allowed, "the file holds {text:?}");
    }
    let raw = std::fs::read_to_string(dir.path().join(FILE_NAME)).expect("file");
    for word in ["a-session-id", "a-backend", "a-tool"] {
        assert!(!raw.contains(word), "{word} in the file");
    }
}

/// S10: a save cut off between writing its scratch file and the rename
/// keeps the old file, byte for byte, and a restore still reads it. Mutant:
/// the file written in place.
#[test]
fn a_save_stopped_before_its_rename_leaves_the_previous_file() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    spend(&tracker, Some("k"), T0, 2);
    saved(&tracker, dir.path(), T0);
    let before = std::fs::read(dir.path().join(FILE_NAME)).expect("file");

    spend(&tracker, Some("k"), T0, 5);
    let stop = || Err(std::io::Error::other("stopped before the rename"));
    assert!(!save_with(&tracker, dir.path(), T0, &mut || {}, stop));
    assert_eq!(
        std::fs::read(dir.path().join(FILE_NAME)).expect("file"),
        before
    );
    let back = restored(dir.path(), &["k"], T0);
    assert_eq!(micro(&back.key_series("k").expect("k")), (2, 2));
    let left = std::fs::read_dir(dir.path()).expect("dir").count();
    assert_eq!(left, 1, "no scratch file is left");
}

/// S11: a restored key reports its windows again, while its per-tool
/// breakdown is empty: those sums live for one process (documented).
#[test]
fn after_a_restore_the_windows_return_and_the_tool_sums_start_at_zero() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    spend(&tracker, Some("k"), T0, 3);
    saved(&tracker, dir.path(), T0);
    let back = restored(dir.path(), &["k"], T0 + 60);
    let _clock = at_secs(T0 + 60);
    let report = back.key_snapshot("k").expect("report");
    assert_eq!(report.window_24h.tokens, Some(3));
    assert!(report.by_tool.is_empty(), "{:?}", report.by_tool);
}

/// A file of `keys` keys `k0000`… each holding 10 micro-USD in the hour of
/// T0, and `overflow` micro-USD in the overflow.
fn file_with(keys: usize, overflow: u64) -> (Value, Vec<String>) {
    let names: Vec<String> = (0..keys).map(|i| format!("k{i:04}")).collect();
    let row = |n: &String| {
        let (hours, days) = (
            json!([[T0 / HOUR, 10, 10]]),
            json!([["2026-11-21", 10, 10]]),
        );
        json!({"fp": fingerprint(n), "name": n, "hours": hours, "days": days})
    };
    let rows: Vec<Value> = names.iter().map(row).collect();
    let spill = json!({
        "hours": [[T0 / HOUR, overflow, overflow]],
        "days": [["2026-11-21", overflow, overflow]],
    });
    let empty = json!({"hours": [], "days": []});
    let file = json!({"keyless": empty, "keys": rows, "overflow": spill});
    (file, names)
}

fn restore_file(file: &Value, names: &[String]) -> (tempfile::TempDir, CostTracker) {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join(FILE_NAME), file.to_string()).expect("write");
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let back = restored(dir.path(), &refs, T0);
    (dir, back)
}

/// S12 (a): with fewer keys than the cap, the overflow a restore carried in
/// is still in the next save. Mutant: an overflow built only from this
/// run's keys past the cap.
#[test]
fn a_restored_overflow_survives_a_save_below_the_cap() {
    let (file, names) = file_with(2, 7);
    let (dir, back) = restore_file(&file, &names);
    let again = saved(&back, dir.path(), T0 + 60);
    assert_eq!(saved_micro(&again["overflow"]), (7, 7));
}

/// S12 (b), S13: a full file with an overflow is restored, then two more keys
/// push the map past the cap. Each save writes the carried amount plus that
/// save's own fold, and saving again does not count the fold a second time.
/// Mutants: the carried amount left out; a save feeding its own overflow
/// back into what it carries.
#[test]
fn every_save_writes_the_carried_overflow_plus_its_own_fold() {
    let (file, names) = file_with(MAX_KEYS, 7);
    let (dir, back) = restore_file(&file, &names);
    // Two keys with the least spend: this run's fold.
    spend(&back, Some("new-a"), T0 + 60, 1);
    spend(&back, Some("new-b"), T0 + 60, 1);
    let first = saved(&back, dir.path(), T0 + 120);
    assert_eq!(first["keys"].as_array().expect("keys").len(), MAX_KEYS);
    assert_eq!(saved_micro(&first["overflow"]), (9, 9));
    let second = saved(&back, dir.path(), T0 + 180);
    assert_eq!(
        saved_micro(&second["overflow"]),
        (9, 9),
        "the fold counted twice"
    );
}

/// S19: a save ages every copy to one cutoff. `old` spent from 1,420 to 700
/// hours ago, an hour at a time; `top` did the same with the most spend, so
/// it keeps a row; `now` spent this hour. Past the cap, `old` and `now` fold.
/// No saved row reaches past the cutoff's windows, so the overflow stays
/// within 721 hours and the file restores. Mutant: the copies saved without
/// the one cutoff (`top`'s row then holds hours outside the window).
#[test]
fn one_cutoff_ages_every_copy_before_the_fold() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    for ago in (700..=1_420).rev() {
        spend(&tracker, Some("old"), T0 - ago * HOUR, 1);
        spend(&tracker, Some("top"), T0 - ago * HOUR, 1_000);
    }
    spend(&tracker, Some("now"), T0, 1);
    let rest: Vec<String> = (0..MAX_KEYS - 1).map(|i| format!("k{i:04}")).collect();
    for name in &rest {
        spend(&tracker, Some(name), T0, 100);
    }
    let file = saved(&tracker, dir.path(), T0);

    let first_hour = T0 / HOUR - 720;
    let today = date_of(T0);
    let as_date = |row: &Value| {
        let text = row[0].as_str().expect("a date");
        text.parse::<NaiveDate>().expect("ISO")
    };
    let mut series: Vec<&Value> = file["keys"].as_array().expect("keys").iter().collect();
    series.extend([&file["keyless"], &file["overflow"]]);
    for rows in series {
        let hours = rows["hours"].as_array().expect("hours");
        assert!(hours.len() <= 721);
        let inside = |r: &Value| r[0].as_u64().expect("hour") >= first_hour;
        assert!(hours.iter().all(inside), "{rows}");
        let dates = rows["days"].as_array().expect("days");
        assert!(
            dates.iter().all(|r| (today - as_date(r)).num_days() < 30),
            "{rows}"
        );
    }
    let keys = file["keys"].as_array().expect("keys");
    let names: HashSet<&str> = keys
        .iter()
        .map(|r| r["name"].as_str().expect("name"))
        .collect();
    assert!(names.contains("top") && !names.contains("old") && !names.contains("now"));
    // `old`'s 21 hours inside the window and `now`'s one.
    assert_eq!(saved_micro(&file["overflow"]).0, 22);

    let mut configured: Vec<&str> = rest.iter().map(String::as_str).collect();
    configured.extend(["old", "top", "now"]);
    let (back, warnings) =
        crate::test_log_capture::capture_warnings(|| restored(dir.path(), &configured, T0));
    assert!(warnings.is_empty(), "{warnings}");
    assert_eq!(micro(&back.carried.lock()).0, 22);
}

/// S14: records that land while a save is copying never split it. The save
/// pauses once every key is copied. During the pause: a kept key and a
/// folded key spend again, a keyless call lands, a key is made, and a sweep
/// takes an idle key whose name then spends again. Each saved series is what
/// it held when copied; no name is both a row and folded; the next save
/// counts every call once. Mutants: the total stored as a series of its
/// own; the live series ranked instead of the copies; the key map walked
/// twice.
#[test]
fn a_save_keeps_one_split_while_records_land_mid_save() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    // 514 keys spending 10, 20, … so the two least (k0000, k0001) fold,
    // and an idle key whose spend is long gone.
    let names: Vec<String> = (0..514).map(|i| format!("k{i:04}")).collect();
    for (name, n) in names.iter().zip((1..).map(|i: u64| i * 10)) {
        spend(&tracker, Some(name), T0, n);
    }
    spend(&tracker, Some("idle"), T0 - 40 * DAY, 1_000);
    spend(&tracker, None, T0, 3);
    let keys_at_start = tracker.per_key.len();

    let (paused_tx, paused_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (live, folder) = (&tracker, dir.path());
    let first = std::thread::scope(|scope| {
        // The receiver moves in: a `Receiver` cannot be shared by reference.
        let saver = scope.spawn(move || {
            let mut copies = 0;
            let mut pause = || {
                copies += 1;
                if copies == keys_at_start {
                    paused_tx.send(()).expect("the test waits");
                    go_rx.recv().expect("the test resumes the save");
                }
            };
            save_with(live, folder, T0, &mut pause, || Ok(()))
        });
        paused_rx.recv().expect("the save paused");
        tracker
            .next_key_sweep
            .store(0, std::sync::atomic::Ordering::Relaxed);
        // Kept and already copied; this record also runs the sweep.
        spend(&tracker, Some("k0513"), T0, 5);
        assert!(
            tracker.key_series("idle").is_none(),
            "premise: `idle` was swept"
        );
        spend(&tracker, Some("k0000"), T0, 7); // folded, already copied
        spend(&tracker, None, T0, 11); // keyless, copied after the pause
        spend(&tracker, Some("fresh"), T0, 13); // a key made mid-save
        spend(&tracker, Some("idle"), T0, 17); // the swept name again
        go_tx.send(()).expect("the save waits");
        assert!(
            saver.join().expect("the save does not panic"),
            "the save wrote"
        );
        let bytes = std::fs::read(dir.path().join(FILE_NAME)).expect("file");
        serde_json::from_slice::<Value>(&bytes).expect("JSON")
    });

    let rows = first["keys"].as_array().expect("keys");
    assert_eq!(rows.len(), MAX_KEYS);
    let named: Vec<&str> = rows
        .iter()
        .map(|r| r["name"].as_str().expect("name"))
        .collect();
    let unique: HashSet<&str> = named.iter().copied().collect();
    assert_eq!(unique.len(), named.len(), "a name appears once");
    for gone in ["k0000", "k0001", "idle", "fresh"] {
        assert!(!unique.contains(gone), "{gone} is a row");
    }
    // Each row is what its key held when copied: k0513 without the 5.
    let row_of = |name: &str| rows.iter().find(|r| r["name"] == name).expect("a row");
    assert_eq!(saved_micro(row_of("k0513")), (5_140, 5_140));
    assert_eq!(saved_micro(row_of("k0002")), (30, 30));
    // The fold is k0000 and k0001 as copied; `idle`'s spend had aged out.
    assert_eq!(saved_micro(&first["overflow"]), (30, 30));
    assert_eq!(saved_micro(&first["keyless"]), (14, 14));

    // The next save counts every record once: the 514 keys, the records made
    // during the pause, and the keyless calls.
    let second = saved(&tracker, dir.path(), T0 + 60);
    let mut total = saved_micro(&second["keyless"]).0 + saved_micro(&second["overflow"]).0;
    for row in second["keys"].as_array().expect("keys") {
        total += saved_micro(row).0;
    }
    let keys: u64 = (1..=514).map(|i| i * 10).sum();
    assert_eq!(total, keys + 5 + 7 + 3 + 11 + 13 + 17);
}

/// S15 (the history half): the Chatham key the sweep keeps on April 30th's
/// last local second saves its April 1st total, and a restore at that
/// instant brings it back.
#[test]
fn a_day_the_sweep_kept_is_saved_and_restored() {
    let tz = chrono_tz::Pacific::Chatham;
    let _zone = crate::local_day::test_zone(tz);
    let april_1 = date(2026, 4, 1);
    let spent = local(tz, april_1, (0, 1));
    let last = local(tz, date(2026, 5, 1), (0, 0)) - 1;
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    spend(&tracker, Some("k"), spent, 4);
    let file = saved(&tracker, dir.path(), last);
    assert_eq!(file["keys"][0]["days"], json!([["2026-04-01", 4, 4]]));
    let back = restored(dir.path(), &["k"], last);
    let days = back.key_series("k").expect("k").days.rows();
    assert_eq!(days, vec![(april_1, 4, 4)]);
}

/// S4: at its bounds (512 keys with 200-byte names, every series full with
/// the largest numbers) the file stays within the size its row shapes
/// allow, and restores. The PR states the measured size.
#[test]
fn a_full_file_stays_within_its_stated_size_and_restores() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    let fill = |series: &mut Series| {
        for hour in T0 / HOUR - 720..=T0 / HOUR {
            series.hours.add_slot(hour, hour, u64::MAX, u64::MAX);
        }
        for back in (0..30).rev() {
            let day = date_of(T0) - chrono::Days::new(back);
            series.days.add_slot(day, day, u64::MAX, u64::MAX);
        }
    };
    let names: Vec<String> = (0..MAX_KEYS)
        .map(|i| format!("{i:04}{}", "n".repeat(196)))
        .collect();
    {
        let _clock = at_secs(T0);
        for name in &names {
            let key = Arc::new(KeyCost::new(name));
            fill(&mut key.spend.lock().0);
            tracker.per_key.insert(name.clone(), key);
        }
    }
    fill(&mut tracker.keyless.lock());
    fill(&mut tracker.carried.lock());
    saved(&tracker, dir.path(), T0);
    let bytes = std::fs::metadata(dir.path().join(FILE_NAME))
        .expect("file")
        .len();
    // An hour row is at most `[hour,MAX,MAX],` (51 bytes), a date row
    // `["YYYY-MM-DD",MAX,MAX],` (57); a key adds its fingerprint, its name
    // (128 bytes at most) and the field names (about 64).
    let series = 721 * 51 + 30 * 57;
    let bound = (MAX_KEYS + 2) * series + MAX_KEYS * (32 + 128 + 64) + 256;
    eprintln!("spend-history.json at its bounds: {bytes} bytes (bound {bound})");
    assert!(
        bytes <= u64::try_from(bound).expect("fits"),
        "{bytes} > {bound}"
    );

    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let (back, warnings) =
        crate::test_log_capture::capture_warnings(|| restored(dir.path(), &refs, T0));
    assert!(warnings.is_empty(), "{warnings}");
    assert_eq!(back.per_key.len(), MAX_KEYS);
}
