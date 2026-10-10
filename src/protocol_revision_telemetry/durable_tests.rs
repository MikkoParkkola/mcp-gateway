// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable-window internals: parent-directory sync retry and the private temp file.

use super::*;
use crate::protocol_revision_telemetry::Transport;

#[test]
fn committed_window_is_not_counted_twice_after_parent_sync_failure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut sink = DurableTelemetrySink::open(directory.path()).expect("durable sink");
    let mut registry = Registry::new();
    registry.observe_request(Some("2025-11-25"), "codex", Transport::Stdio);

    let error = sink
        .persist_with_parent_sync(registry.snapshot(), registry.shadow_snapshot(), 1, |_| {
            Err(io::Error::other("injected parent sync failure"))
        })
        .expect_err("parent sync must fail after the rename");
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(sink.parent_sync_pending);
    assert_eq!(
        load_durable_window(directory.path())
            .unwrap()
            .snapshot
            .total,
        1
    );

    sink.persist_with_parent_sync(registry.snapshot(), registry.shadow_snapshot(), 2, |_| {
        Ok(())
    })
    .expect("retry pending parent sync");
    assert!(!sink.parent_sync_pending);
    assert_eq!(
        load_durable_window(directory.path())
            .unwrap()
            .snapshot
            .total,
        1
    );
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

    write_window_atomic(&path, &DurableWindow::empty(1)).unwrap();

    // Relies on `create_file_private(.., Share::Exclusive)`: owner-only from creation, not repaired after.
    assert_owner_only("1718-W5", &path, false);
}
