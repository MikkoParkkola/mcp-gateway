// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Resident memory read from `statm`, and the start-time gauge.

use std::path::Path;
use std::time::Instant;

use chrono::{TimeZone, Utc};

use super::process::{START_TIME, exposition_from, record_start_time, resident_bytes};
use crate::gateway::router::ProcessStart;

#[test]
fn resident_bytes_is_the_second_field_times_the_page_size() {
    assert_eq!(resident_bytes("100 25 3 0 0 7 0", 4096), Some(25 * 4096));
}

#[test]
fn resident_bytes_refuses_a_line_it_cannot_read() {
    for bad in ["", "100", "100 x", "100 -1", "1 18446744073709551615"] {
        assert_eq!(resident_bytes(bad, 4096), None, "{bad:?}");
    }
}

#[test]
fn a_good_read_carries_help_type_and_sample() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("statm");
    std::fs::write(&path, "100 25 3 0 0 7 0\n").expect("statm");

    let text = exposition_from(&path, 4096);

    assert!(text.starts_with("# HELP process_resident_memory_bytes Resident set size. Linux only"));
    assert!(text.contains("# TYPE process_resident_memory_bytes gauge\n"));
    assert!(text.ends_with(&format!("process_resident_memory_bytes {}\n", 25 * 4096)));
}

#[test]
fn a_failed_read_after_a_good_one_appends_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("statm");
    std::fs::write(&path, "100 25 3\n").expect("statm");
    assert!(!exposition_from(&path, 4096).is_empty());

    std::fs::remove_file(&path).expect("removed");

    assert_eq!(exposition_from(&path, 4096), "");
    assert_eq!(exposition_from(Path::new("/nonexistent/statm"), 4096), "");
}

#[cfg(target_os = "linux")]
#[test]
fn the_live_sample_is_positive_on_linux() {
    let text = super::process::resident_memory_exposition();
    let bytes: u64 = text
        .lines()
        .last()
        .and_then(|l| l.strip_prefix("process_resident_memory_bytes "))
        .and_then(|v| v.parse().ok())
        .expect("a sample line");
    assert!(bytes > 0);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn the_sample_is_absent_off_linux() {
    assert_eq!(super::process::resident_memory_exposition(), "");
}

#[test]
fn the_start_gauge_equals_the_process_start_wall_time() {
    let wall = Utc.with_ymd_and_hms(2026, 10, 29, 6, 0, 0).unwrap();
    let start = ProcessStart::at(Some(wall), Instant::now());
    let recorder = crate::metrics::builder().build_recorder();
    let handle = recorder.handle();

    telemetry_metrics::with_local_recorder(&recorder, || record_start_time(start.wall()));

    let rendered = handle.render();
    let value: f64 = rendered
        .lines()
        .find_map(|l| l.strip_prefix(START_TIME)?.strip_prefix(' ')?.parse().ok())
        .expect("a start-time sample");
    #[allow(clippy::cast_precision_loss)] // Unix seconds are far below 2^53
    let expected = wall.timestamp() as f64;
    assert_eq!(value, expected);
}

#[test]
fn no_start_time_is_set_when_the_clock_could_not_be_read() {
    let recorder = crate::metrics::builder().build_recorder();
    let handle = recorder.handle();

    telemetry_metrics::with_local_recorder(&recorder, || record_start_time(None));

    assert!(!handle.render().contains(START_TIME));
}
