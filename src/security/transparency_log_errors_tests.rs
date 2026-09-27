// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R6: an I/O error the log returns names its operation and the path that
//! failed, and keeps its kind. One fault per independent boundary, forced by
//! a directory where a file must be, or a removed parent (never chmod: CI
//! runs as root).

use super::rotation_tests::{append, cfg, log_path, rotate_n};
use super::segments::{list_segments, sealed_path};
use super::*;

#[track_caller]
fn assert_names(e: &io::Error, op: &str, path: &std::path::Path) {
    let text = e.to_string();
    assert!(text.contains(op), "no operation `{op}` in: {text}");
    assert!(
        text.contains(&path.display().to_string()),
        "no path {} in: {text}",
        path.display()
    );
}

/// Opening the active file.
#[test]
fn open_names_the_active_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    std::fs::create_dir(&path).unwrap();
    let e = TransparencyLogger::open(cfg(&path, 2, false))
        .err()
        .expect("a directory");
    assert_names(&e, "open", &path);
}

/// Renaming the active file to its sealed name during rotation.
#[test]
fn rotation_rename_names_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    std::fs::create_dir(sealed_path(&path, 0)).unwrap();
    let e = (0..1_000)
        .find_map(|i| {
            l.log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
                .err()
        })
        .expect("rotation must fail onto a directory");
    assert_names(&e, "rename", &path);
}

/// Removing an expired segment.
#[test]
fn retention_remove_names_the_segment() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    rotate_n(&l, &path, 1);
    let oldest = list_segments(&path).unwrap()[0].path.clone();
    let text = std::fs::read(&oldest).unwrap();
    std::fs::remove_file(&oldest).unwrap();
    std::fs::create_dir(&oldest).unwrap();
    std::fs::write(oldest.join("x"), text).unwrap();
    let e = (0..1_000)
        .find_map(|i| {
            l.log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
                .err()
        })
        .expect("retention must fail on a directory");
    assert_names(&e, "", &oldest);
}

/// Reading a sealed segment during recovery.
#[test]
fn recovery_read_names_the_segment() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    std::fs::remove_file(&path).unwrap();
    let seg = list_segments(&path).unwrap()[0].path.clone();
    std::fs::remove_file(&seg).unwrap();
    std::fs::create_dir(&seg).unwrap();
    let e = TransparencyLogger::open(cfg(&path, 12, false))
        .err()
        .expect("unreadable");
    assert_names(&e, "read", &seg);
}

/// End to end: the log's directory removed under a live writer; the kind
/// stays `NotFound` and the text names the operation and the path.
#[test]
fn a_removed_directory_is_named_and_keeps_its_kind() {
    let outer = tempfile::tempdir().unwrap();
    let dir = outer.path().join("logdir");
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("transparency.jsonl");
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    append(&l, 0);
    std::fs::remove_dir_all(&dir).unwrap();
    let e = l
        .log_invocation("s", "c", "srv", "t", "a", "b")
        .expect_err("the directory is gone");
    assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
    assert!(e.to_string().contains("audit log:"), "{e}");
    assert!(e.to_string().contains(&dir.display().to_string()), "{e}");
}

/// Writing a line (a plain fault through the write seam, not ENOSPC).
#[test]
fn write_names_the_active_file() {
    use super::rotation::WriteFault;
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    l.arm_write_fault(Some(WriteFault::WriteError));
    let e = l
        .log_invocation("s", "c", "srv", "t", "a", "b")
        .expect_err("the write fault fires");
    assert_eq!(l.write_faults_fired(), 1, "the write hook never fired");
    assert_eq!(e.kind(), io::ErrorKind::Other, "{e}");
    assert_names(&e, "write", &path);
}

/// Syncing a synced append.
#[test]
fn sync_names_the_active_file() {
    use super::rotation::WriteFault;
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    l.arm_write_fault(Some(WriteFault::SyncError));
    let e = l
        .append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
        .expect_err("the sync fault fires");
    assert_eq!(l.write_faults_fired(), 1, "the sync hook never fired");
    assert_eq!(e.kind(), io::ErrorKind::Other, "{e}");
    assert_names(&e, "sync", &path);
}

/// Listing the segments: the log's parent is a regular file.
#[test]
fn listing_names_the_parent() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain-file");
    std::fs::write(&plain, b"x").unwrap();
    let path = plain.join("transparency.jsonl");
    let e = verify_log(&path).expect_err("a file is not a directory");
    assert_names(&e, "list", &plain);
}
