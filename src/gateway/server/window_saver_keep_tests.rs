// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An HTTP telemetry window keeps the temp dirs a test registered, and a
//! detached open keeps the ones captured when its thread was spawned.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{CountsFn, Sink, SinkState, Writers, checkpoint_detached, open_detached};
use crate::protocol_revision_telemetry::DURABLE_TELEMETRY_DIR;
use crate::protocol_revision_telemetry::window::{
    self, HttpSegmentSink, Kept, SegmentCounts, WriterIdentity,
};
use crate::test_dir_keep::{
    before_first_fs_call, expect_unkept, kept_dirs_for, kept_tempdir, kept_tempdir_in,
};

/// Every wait in these rows is bounded; a timeout fails the row.
const BOUND: Duration = Duration::from_secs(30);

fn identity() -> WriterIdentity {
    WriterIdentity {
        listen: "127.0.0.1:0".to_owned(),
        exe: "keep-tests".to_owned(),
        process_started_at_ms: 1,
    }
}

fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// A file only the original dir holds: gone if the dir was removed and
/// recreated.
fn plant_marker(root: &Path) -> PathBuf {
    let marker = root.join("marker");
    std::fs::write(&marker, b"kept").expect("plant the marker");
    marker
}

/// Valid counts for `total` HTTP requests, built the way a gateway builds
/// them (a sink refuses counters that do not add up).
fn counts(total: u64) -> SegmentCounts {
    let mut registry = crate::protocol_revision_telemetry::Registry::new();
    for _ in 0..total {
        registry.observe_request(
            Some("2025-11-25"),
            "codex",
            crate::protocol_revision_telemetry::Transport::Http,
        );
    }
    SegmentCounts {
        snapshot: registry.snapshot(),
        ..SegmentCounts::empty()
    }
}

fn unopened() -> Sink {
    Arc::new(Mutex::new(SinkState::Unopened))
}

/// T1h. An HTTP window in a kept dir keeps it: with the test's share
/// dropped, a checkpoint lands in the original dir with its counts, and the
/// dir goes with the sink.
/// Mutant: the hook missing in `HttpSegmentSink::open_with`.
#[test]
fn an_http_window_in_a_kept_dir_keeps_it_past_the_tests_share() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let mut sink = HttpSegmentSink::open(&root, identity(), 1).expect("http sink");
    let marker = plant_marker(&root);
    drop(dir);
    sink.checkpoint(&counts(3), 2)
        .expect("a checkpoint after the test's share drops");
    assert!(marker.exists(), "the dir was removed and recreated");
    let window = window::load(&root).expect("the window");
    assert_eq!(window.http_segments[0].snapshot.total, 3);
    drop(sink);
    assert!(!root.exists(), "the dir did not go with the sink");
}

/// T3h. An HTTP window in a plain temp dir is recorded once, with the kind,
/// its data dir and this test.
/// Mutants: the report removed; the kind const changed.
#[test]
fn an_http_window_in_a_plain_temp_dir_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let unkept = expect_unkept();
    let sink = HttpSegmentSink::open(dir.path(), identity(), 1).expect("http sink");
    assert_eq!(
        unkept.recorded(),
        vec![("telemetry window", dir.path().to_path_buf(), this_test())]
    );
    drop(sink);
}

/// T4h (control). An HTTP window in a kept dir records nothing.
/// Mutant: the condition inverted.
#[test]
fn an_http_window_in_a_kept_dir_records_nothing() {
    let dir = kept_tempdir();
    let unkept = expect_unkept();
    let sink = HttpSegmentSink::open(dir.path(), identity(), 1).expect("http sink");
    assert_eq!(unkept.recorded(), vec![]);
    drop(sink);
}

/// T5h. The HTTP window holds its dir before its first filesystem call: the
/// test's only share drops there, before the telemetry subdir exists.
/// Mutant: the lookup moved after `create_dir_all`.
#[test]
fn an_http_window_holds_its_dir_before_its_first_filesystem_call() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let subdir = root.join(DURABLE_TELEMETRY_DIR);
    before_first_fs_call(move || {
        assert!(!subdir.exists(), "the hook ran after the sink wrote");
        drop(dir);
    });
    let sink = HttpSegmentSink::open(&root, identity(), 1).expect("http sink");
    assert!(root.exists(), "the dir is alive while the sink lives");
    drop(sink);
    assert!(!root.exists(), "the dir was not held through the open");
}

/// T2. A detached open that runs after the test dropped its share still
/// lands in the original dir: the dirs were taken when the thread was
/// spawned. The thread is held before any of its work runs.
/// Mutant: `open_detached` takes `kept_at_spawn` inside the thread.
#[tokio::test]
async fn a_late_detached_open_lands_in_the_kept_dir() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let writers = Arc::new(Writers::default());
    let sink = unopened();
    let identity = identity();
    let held = writers.hold_next_work();
    let opened = open_detached(&writers, &sink, &root, &identity, crate::clock::unix_millis);
    held.entered
        .recv_timeout(BOUND)
        .expect("the open thread started");
    let marker = plant_marker(&root);
    drop(dir);
    held.release();
    let opened = tokio::time::timeout(BOUND, opened)
        .await
        .expect("the open resolved in time")
        .expect("the open reported");
    assert!(opened, "the late open failed");
    tokio::time::timeout(BOUND, writers.idle())
        .await
        .expect("every writer ended in time");
    assert!(marker.exists(), "the late open recreated the dir");
    assert_eq!(
        window::load(&root).expect("the window").http_segments.len(),
        1
    );
    drop(sink);
    assert!(!root.exists(), "the dir did not go with the sink");
}

/// T2c. A checkpoint's retry-open that runs after the test dropped its share
/// lands in the original dir, with its counts.
/// Mutant: `checkpoint_detached` takes `kept_at_spawn` inside the thread.
#[tokio::test]
async fn a_late_checkpoint_retry_open_lands_in_the_kept_dir() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let writers = Arc::new(Writers::default());
    let sink = unopened();
    let three: CountsFn = Arc::new(|_| counts(3));
    let held = writers.hold_next_work();
    checkpoint_detached(
        &writers,
        &sink,
        &root,
        &identity(),
        &three,
        crate::clock::unix_millis,
    );
    held.entered
        .recv_timeout(BOUND)
        .expect("the checkpoint thread started");
    let marker = plant_marker(&root);
    drop(dir);
    held.release();
    tokio::time::timeout(BOUND, writers.idle())
        .await
        .expect("every writer ended in time");
    assert!(marker.exists(), "the late open recreated the dir");
    let window = window::load(&root).expect("the window");
    assert_eq!(window.http_segments.len(), 1);
    assert_eq!(window.http_segments[0].snapshot.total, 3);
    drop(sink);
    assert!(!root.exists(), "the dir did not go with the sink");
}

/// T6. A dir passed only in the spawn-time list is kept, and its open is
/// not reported: the registry does not know the dir at all.
/// Mutant: `open_with` drops the spawn-time list.
#[test]
fn a_spawn_time_list_keeps_a_dir_the_registry_does_not_know() {
    let dir = Arc::new(tempfile::tempdir().expect("a temp dir"));
    let root = dir.path().to_owned();
    assert!(
        kept_dirs_for(&root).is_empty(),
        "the dir must be unregistered"
    );
    let unkept = expect_unkept();
    let kept: Kept = vec![Arc::clone(&dir)];
    let mut sink = HttpSegmentSink::open_with(&root, identity(), 1, kept).expect("http sink");
    assert_eq!(unkept.recorded(), vec![]);
    let marker = plant_marker(&root);
    drop(dir);
    sink.checkpoint(&counts(3), 2)
        .expect("a checkpoint after the row's share drops");
    assert!(marker.exists(), "the dir was removed and recreated");
    drop(sink);
    assert!(!root.exists(), "the dir did not go with the sink");
}

/// T7. An open keeps both its spawn-time list and a dir the registry knows:
/// an unregistered parent passed at spawn, a registered child found at open.
/// Mutant: either list alone instead of both.
#[test]
fn an_open_keeps_its_spawn_time_list_and_a_registered_dir() {
    let parent = Arc::new(tempfile::tempdir().expect("a temp dir"));
    let child = kept_tempdir_in(parent.path());
    let (parent_root, child_root) = (parent.path().to_owned(), child.path().to_owned());
    let kept: Kept = vec![Arc::clone(&parent)];
    let mut sink = HttpSegmentSink::open_with(&child_root, identity(), 1, kept).expect("http sink");
    let marker = plant_marker(&child_root);
    drop(child);
    drop(parent);
    sink.checkpoint(&counts(3), 2)
        .expect("a checkpoint after both shares drop");
    assert!(marker.exists(), "a dir was removed and recreated");
    drop(sink);
    assert!(!parent_root.exists(), "the dirs did not go with the sink");
}
