// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio telemetry window keeps the temp dirs a test registered, as an
//! audit log does: the dir outlives the test's share and goes with the sink.

use super::*;
use crate::protocol_revision_telemetry::window;
use crate::test_dir_keep::{before_first_fs_call, expect_unkept, kept_tempdir};

fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// A file only the original dir holds: gone if the dir was removed and
/// recreated, whatever the recreated dir then contains.
fn plant_marker(root: &Path) -> std::path::PathBuf {
    let marker = root.join("marker");
    std::fs::write(&marker, b"kept").expect("plant the marker");
    marker
}

/// T1. A stdio window in a kept dir keeps it: with the test's share dropped,
/// a persist lands in the original dir with its delta, and the dir goes with
/// the sink.
/// Mutant: the hook missing in `DurableTelemetrySink::open`.
#[test]
fn a_stdio_window_in_a_kept_dir_keeps_it_past_the_tests_share() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let mut sink = DurableTelemetrySink::open(&root).expect("durable sink");
    let marker = plant_marker(&root);
    drop(dir);
    let mut registry = Registry::new();
    registry.observe_request(Some("2025-11-25"), "codex", Transport::Stdio);
    sink.persist_registry(&registry)
        .expect("a persist after the test's share drops");
    assert!(marker.exists(), "the dir was removed and recreated");
    assert_eq!(window::load(&root).expect("the window").stdio.total, 1);
    drop(sink);
    assert!(!root.exists(), "the dir did not go with the sink");
}

/// T3d. A stdio window in a plain temp dir is recorded once, with the kind,
/// its data dir and this test.
/// Mutants: the report removed; the kind const changed.
#[test]
fn a_stdio_window_in_a_plain_temp_dir_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let unkept = expect_unkept();
    let sink = DurableTelemetrySink::open(dir.path()).expect("durable sink");
    assert_eq!(
        unkept.recorded(),
        vec![("telemetry window", dir.path().to_path_buf(), this_test())]
    );
    drop(sink);
}

/// T4d (control). A stdio window in a kept dir records nothing.
/// Mutant: the condition inverted.
#[test]
fn a_stdio_window_in_a_kept_dir_records_nothing() {
    let dir = kept_tempdir();
    let unkept = expect_unkept();
    let sink = DurableTelemetrySink::open(dir.path()).expect("durable sink");
    assert_eq!(unkept.recorded(), vec![]);
    drop(sink);
}

/// T5d. The stdio window holds its dir before its first filesystem call:
/// the test's only share drops at that point, before the telemetry subdir
/// exists, and the dir still lives while the sink does.
/// Mutant: the lookup moved after `create_dir_all`.
#[test]
fn a_stdio_window_holds_its_dir_before_its_first_filesystem_call() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let subdir = root.join(DURABLE_TELEMETRY_DIR);
    before_first_fs_call(move || {
        assert!(!subdir.exists(), "the hook ran after the sink wrote");
        drop(dir);
    });
    let sink = DurableTelemetrySink::open(&root).expect("durable sink");
    assert!(root.exists(), "the dir is alive while the sink lives");
    drop(sink);
    assert!(!root.exists(), "the dir was not held through the open");
}
