// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable-window internals: parent-directory sync retry and the private temp file.

use super::*;
use crate::protocol_revision_telemetry::window;

#[test]
fn committed_window_is_not_counted_twice_after_parent_sync_failure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut sink = DurableTelemetrySink::open(directory.path()).expect("durable sink");
    let mut registry = Registry::new();
    registry.observe_request(Some("2025-11-25"), "codex", Transport::Stdio);

    let error = sink
        .persist_with_parent_sync(StdioCounts::of(&registry), 1, |_| {
            Err(io::Error::other("injected parent sync failure"))
        })
        .expect_err("parent sync must fail after the rename");
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(sink.parent_sync_pending);
    assert_eq!(window::load(directory.path()).unwrap().stdio.total, 1);

    sink.persist_with_parent_sync(StdioCounts::of(&registry), 2, |_| Ok(()))
        .expect("retry pending parent sync");
    assert!(!sink.parent_sync_pending);
    assert_eq!(window::load(directory.path()).unwrap().stdio.total, 1);
}

#[cfg(windows)]
#[test]
fn window_file_is_owner_only_in_an_open_directory_and_over_a_stale_temp() {
    // WT-ASSERT 1718-W5: the window is created private, and a stale temp
    // planted with an open DACL does not carry it into the window file.
    use crate::private_fs::test_support::{assert_owner_only, everyone_full_dir};

    let dir = everyone_full_dir("1718-W5");
    let path = dir.path().join("window.json");
    std::fs::write(path.with_extension("json.tmp"), "stale").unwrap();

    write_json_atomic(&path, &window::WindowV2::empty(1)).unwrap();

    // Relies on `create_file_private(.., Share::Exclusive)`: owner-only from creation, not repaired after.
    assert_owner_only("1718-W5", &path, false);
}

#[test]
fn the_stdio_window_survives_a_process_restart() {
    // Moved from tests/mik_7218_acs.rs (mcp728_u1_2): two stdio sink
    // lifetimes over one data directory add up, and the shadow is kept.
    let data_dir = tempfile::tempdir().expect("temporary data directory");
    let mut first_sink = DurableTelemetrySink::open(data_dir.path()).expect("create the window");
    let mut first_process = Registry::new();
    for _ in 0..60 {
        first_process.observe_request(Some("2025-11-25"), "claude", Transport::Stdio);
    }
    first_process.shadow_tools_list(crate::protocol_revision_telemetry::ListFilters::default());
    first_sink
        .persist_registry(&first_process)
        .expect("persist the first process");
    let first = window::load(data_dir.path()).expect("load the first process's window");
    assert_eq!(first.stdio.total, 60);
    assert_eq!(first.tools_list_shadow.values().sum::<u64>(), 1);

    drop(first_sink);
    let mut restarted = DurableTelemetrySink::open(data_dir.path()).expect("reopen the window");
    let mut second_process = Registry::new();
    for _ in 0..40 {
        second_process.observe_request(Some("2025-06-18"), "codex", Transport::Stdio);
    }
    restarted
        .persist_registry(&second_process)
        .expect("persist after the restart");
    let window = window::load(data_dir.path()).expect("load after the restart");
    assert_eq!(window.stdio.total, 100);
    assert_eq!(window.stdio.by_revision.get("2025-11-25"), Some(&60));
    assert_eq!(window.stdio.by_revision.get("2025-06-18"), Some(&40));
    assert_eq!(
        durable_window_path(data_dir.path()).file_name().unwrap(),
        "window.json"
    );
}
