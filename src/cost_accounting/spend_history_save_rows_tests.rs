// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! More `spend-history.json` rows, split from `spend_history_file_tests.rs`
//! for the file-size ceiling: refused files, the file's contents, crash
//! safety, the unchanged-state skip, the carried overflow, the save cutoff,
//! records during a save, and the file at its bounds.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::NaiveDate;
use serde_json::{Value, json};

use super::{FILE_NAME, MAX_KEYS, fingerprint, save_with};
use crate::clock::test_clock::at_secs;
use crate::cost_accounting::spend_history_tests::{date, local, spend};
use crate::cost_accounting::tally::Series;
use crate::cost_accounting::{CostTracker, KeyCost};

use super::file_tests::{DAY, HOUR, T0, date_of, micro, restored, saved, saved_micro};

/// A whole file holding one hour and one date in the keyless series and the
/// overflow, and `keys`: each case below breaks it in one place.
fn valid(keys: &Value) -> Value {
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
        let mut file = valid(&json!([]));
        file["keyless"][field] = rows;
        file.to_string().into_bytes()
    };
    let keys = |rows: Vec<Value>| valid(&json!(rows)).to_string().into_bytes();
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
            micro(&back.gateway_series(T0)),
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
    let whole = valid(&json!([key_row(&fp)])).to_string();
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

/// The file's identity on disk: its modification time and its inode (each
/// write renames a new file into place, so a write moves it).
#[cfg(unix)]
fn stamp(path: &std::path::Path) -> (std::time::SystemTime, u64) {
    let meta = std::fs::metadata(path).expect("the file");
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    (meta.modified().expect("an mtime"), inode)
}

/// Lead 2026-11-21: a save of an unchanged state writes nothing, so an idle
/// gateway rewrites and syncs nothing; a changed state writes once; a file
/// removed meanwhile is written again, and so is one widened to 0644 while
/// nothing changed, which comes back 0600. Red before the skip: the second
/// save renames a new file into place. Unix only: elsewhere every save
/// writes.
#[cfg(unix)]
#[test]
fn an_unchanged_state_writes_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join(FILE_NAME);
    let tracker = CostTracker::new();
    spend(&tracker, Some("k"), T0, 2);
    saved(&tracker, dir.path(), T0);
    let first = stamp(&path);

    saved(&tracker, dir.path(), T0 + 60);
    assert_eq!(stamp(&path), first, "an unchanged state was written again");

    spend(&tracker, Some("k"), T0 + 60, 5);
    let file = saved(&tracker, dir.path(), T0 + 60);
    assert_ne!(stamp(&path), first, "a changed state was not written");
    assert_eq!(saved_micro(&file["keys"][0]), (7, 7));

    std::fs::remove_file(&path).expect("remove");
    let again = saved(&tracker, dir.path(), T0 + 120);
    assert_eq!(
        saved_micro(&again["keys"][0]),
        (7, 7),
        "a removed file stays gone"
    );

    let kept = stamp(&path);
    let wide = std::fs::Permissions::from_mode(0o644);
    std::fs::set_permissions(&path, wide).expect("chmod");
    saved(&tracker, dir.path(), T0 + 180);
    let bits = std::fs::metadata(&path).expect("file").permissions().mode() & 0o777;
    assert_eq!(bits, 0o600, "a widened file was left as it was");
    assert_ne!(
        stamp(&path).1,
        kept.1,
        "a widened file was not written again"
    );
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
    let listed: Vec<&str> = rows
        .iter()
        .map(|r| r["name"].as_str().expect("name"))
        .collect();
    let unique: HashSet<&str> = listed.iter().copied().collect();
    assert_eq!(unique.len(), listed.len(), "a name appears once");
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
        bytes <= u64::try_from(bound).expect("fits") && bytes <= super::MAX_FILE_BYTES,
        "{bytes} > {bound}"
    );
    // The measured size, pinned so a passing run states it: 512 key rows of
    // 38,679 bytes plus the two other series and the frame (worked out from
    // the row shapes; a failure prints the real count).
    assert_eq!(bytes, 19_881_195, "spend-history.json at its bounds");

    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let (back, warnings) =
        crate::test_log_capture::capture_warnings(|| restored(dir.path(), &refs, T0));
    assert!(warnings.is_empty(), "{warnings}");
    assert_eq!(back.per_key.len(), MAX_KEYS);
}

/// gpt seat 1 (CRITICAL): a restored file may hold the largest numbers. Two
/// adjacent hours sum to more than a u64 holds; the window a view reads
/// saturates at the largest value instead of wrapping or panicking. Red
/// before: the window's sum overflowed. The second hour's micro-USD is 1, so
/// a wrapped sum reads 0 (two maxima would wrap to one less than the max and
/// pass the USD check; gpt delta 2).
#[test]
fn restored_maximum_values_saturate_the_window_a_view_reads() {
    let full = |hour: u64, micro: u64| json!([hour, u64::MAX, micro]);
    let hours = json!([full(T0 / HOUR - 1, u64::MAX), full(T0 / HOUR, 1)]);
    let row = json!({"fp": fingerprint("k"), "name": "k", "hours": hours, "days": []});
    let empty = json!({"hours": [], "days": []});
    let file = json!({"keyless": empty, "keys": [row], "overflow": empty});
    let (_dir, back) = restore_file(&file, &["k".to_owned()]);
    let _clock = at_secs(T0);
    let window = back.key_snapshot("k").expect("the key").window_24h;
    assert_eq!(window.tokens, Some(u64::MAX));
    // Saturated micro-USD is about 1.8e13 USD; a wrapped sum would be tiny.
    let usd = window.cost_usd.expect("a dated window");
    assert!(usd.is_finite() && usd > 1.8e13, "{window:?}");
}

/// gpt seat 1 (HIGH): a file past the read cap is refused by its length,
/// before it is read: set aside, with one warning that says why. Red before:
/// the restore read the whole file and refused it only as bad JSON.
#[test]
fn a_file_past_the_read_cap_is_refused_unread() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join(FILE_NAME);
    let file = std::fs::File::create(&path).expect("create");
    file.set_len(super::MAX_FILE_BYTES + 1)
        .expect("a sparse file");
    drop(file);
    let (back, warnings) =
        crate::test_log_capture::capture_warnings(|| restored(dir.path(), &["k"], T0));
    assert_eq!(back.per_key.len(), 0);
    let warned = warnings.lines().filter(|l| l.contains("WARN")).count();
    assert_eq!(warned, 1, "{warnings}");
    assert!(warnings.contains("larger than"), "{warnings}");
    assert!(!path.exists(), "the file is set aside");
}

/// Lead 2026-11-22, the "never save over an unloaded file" class: a FIFO at
/// the path is no history file. The restore refuses it without opening it
/// (an open would wait for a writer and hang the start), sets it aside with
/// one warning, and so the run's saves write a new file beside the kept one.
/// Red before: the open blocked, past the 120 s hang guard (flaky-under-load
/// family).
#[cfg(unix)]
#[test]
fn a_fifo_at_the_history_path_is_set_aside_without_a_hang() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join(FILE_NAME);
    let made = std::process::Command::new("mkfifo").arg(&path).status();
    assert!(
        made.is_ok_and(|s| s.success()),
        "premise: a FIFO at the path"
    );
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let folder = dir.path().to_path_buf();
    std::thread::spawn(move || {
        let restoring = || restored(&folder, &["k"], T0).per_key.len();
        let outcome = crate::test_log_capture::capture_warnings(restoring);
        done_tx.send(outcome).ok();
    });
    let (keys, logged) = done_rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect("the restore returns instead of waiting on the FIFO");
    assert_eq!(keys, 0, "a key was restored from a FIFO");
    assert_eq!(logged.matches("WARN").count(), 1, "one warning: {logged}");
    assert!(logged.contains("not a regular file"), "{logged}");
    assert!(!path.exists(), "the FIFO is set aside");
}

/// Lead 2026-11-22 (save and age measure from now): one key spent while the
/// clock ran 40 days ahead; the clock then stepped back and another key spent
/// at the corrected time. The save keeps the second key's row: its cut is
/// the save instant, not the newest slot any copy holds. Red with the cut at
/// the newest slot: the second key's hour and date were aged out of the file.
#[test]
fn a_save_after_the_clock_stepped_back_keeps_every_other_keys_rows() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    spend(&tracker, Some("ran-ahead"), T0 + 40 * DAY, 5);
    spend(&tracker, Some("current"), T0, 2);
    let file = saved(&tracker, dir.path(), T0 + 60);
    let row_of = |name: &str| {
        file["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .find(|row| row["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no row for {name}: {file}"))
    };
    assert_eq!(saved_micro(&row_of("current")), (2, 2), "{file}");
    // The spend dated ahead is kept, counted in the save's own hour and date.
    let ahead = row_of("ran-ahead");
    assert_eq!(saved_micro(&ahead), (5, 5), "{file}");
    assert_eq!(ahead["hours"][0][0], json!(T0 / HOUR), "{file}");
    let save_date = json!(date_of(T0).to_string());
    assert_eq!(ahead["days"][0][0], save_date, "{file}");
}

/// Lead 2026-11-22: past [`MAX_KEYS`], the fold sums every folded key into the
/// overflow. One folded key spent while the clock ran 40 days ahead, another
/// at the corrected time; the overflow keeps both keys' spend, and no slot of
/// it is dated after the save. Red with the slot dated ahead kept as it was:
/// summing it in aged the other folded key's rows out of the overflow.
#[test]
fn the_fold_keeps_every_folded_keys_spend_when_one_ran_ahead() {
    let dir = tempfile::tempdir().expect("dir");
    let tracker = CostTracker::new();
    // The key dated ahead spends first: a record may run the idle sweep at its
    // own instant, and one 40 days on would sweep every key spent at T0. After
    // it, the sweep is not due again before T0 + 40 days.
    spend(&tracker, Some("small-ran-ahead"), T0 + 40 * DAY, 1);
    for i in 0..MAX_KEYS {
        spend(&tracker, Some(&format!("big{i:04}")), T0, 100);
    }
    spend(&tracker, Some("small-current"), T0, 2);
    assert_eq!(tracker.per_key.len(), MAX_KEYS + 2, "premise: no key swept");
    let file = saved(&tracker, dir.path(), T0 + 60);
    let overflow = &file["overflow"];
    assert_eq!(saved_micro(overflow), (3, 3), "{overflow}");
    let hours = overflow["hours"].as_array().expect("hours");
    let not_after_save = |row: &Value| row[0].as_u64() <= Some(T0 / HOUR);
    assert!(hours.iter().all(not_after_save), "{overflow}");
    // ISO dates order as text.
    let save_day = date_of(T0).to_string();
    // A date that is not text fails: `None <= Some(..)` would pass it.
    let on_or_before = |row: &Value| row[0].as_str().is_some_and(|d| d <= save_day.as_str());
    let dates = overflow["days"].as_array().expect("dates");
    assert!(dates.iter().all(on_or_before), "{overflow}");
}
