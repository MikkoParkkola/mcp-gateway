// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A log opened inside a registered temp dir (`crate::test_dir_keep`) keeps
//! that dir, and every registered dir containing it, from before its first
//! filesystem call until its last handle drops. A log in an unregistered temp
//! dir is named instead (MIK-8986 part 2, PR 1).

use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::Duration;

use super::keep_dir_tests::note;
use super::{TransparencyLogConfig, TransparencyLogger};
use crate::test_dir_keep::{
    AUDIT_LOG, Unkept, expect_unkept, kept_tempdir, kept_tempdir_in, outside_temp,
};

fn config(path: &str) -> Arc<TransparencyLogConfig> {
    Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_owned(),
        ..TransparencyLogConfig::default()
    })
}

fn open(path: &Path) -> Arc<TransparencyLogger> {
    Arc::new(TransparencyLogger::open(config(&path.to_string_lossy())).expect("the log opens"))
}

/// This row's own test name, as libtest names its thread.
fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// R1. The test's own share drops first; a late append still lands, and the
/// dir goes with the log's last handle.
/// Mutant: the hook removed from `open_resolving`.
#[test]
fn a_log_in_a_kept_tempdir_keeps_it_with_no_call() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let log = open(&root.join("audit.jsonl"));
    drop(dir);
    note(&log);
    assert!(root.join("audit.jsonl").is_file(), "the late append landed");
    drop(log);
    assert!(!root.exists(), "the dir outlived the log's last handle");
}

/// R2. A home-relative config path is looked up by where it resolves: the
/// raw string `~/audit.jsonl` lies in no registered dir.
/// Mutant: the lookup made on `config.path` instead of the resolved path.
#[test]
fn a_home_relative_config_path_is_kept_by_its_resolved_dir() {
    let home = kept_tempdir();
    let root = home.path().to_owned();
    let log = Arc::new(
        TransparencyLogger::open_resolving(
            config("~/audit.jsonl"),
            Duration::ZERO,
            Some(home.path()),
        )
        .expect("the log opens"),
    );
    assert_eq!(log.path, root.join("audit.jsonl"), "it resolved under home");
    drop(home);
    note(&log);
    drop(log);
    assert!(!root.exists(), "the resolved dir was not kept");
}

/// R3. The dir is held before the first filesystem call: the checkpoint
/// drops the caller's last share after the lookup and before
/// `create_dir_all`, and the open still lives in the original dir.
/// Mutant: the lookup moved after `create_dir_all` (or to just before
/// return): the dir is gone at the lookup, `create_dir_all` recreates it
/// unkept, and it outlives the log.
#[test]
fn the_dir_is_held_before_the_first_filesystem_call() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let path = root.join("nested").join("audit.jsonl");
    crate::test_dir_keep::before_first_fs_call(move || drop(dir));
    let log = open(&path);
    assert!(root.exists(), "the dir is alive while the log lives");
    note(&log);
    drop(log);
    assert!(!root.exists(), "the dir was not held through the open");
}

/// R4. A log in a plain temp dir is recorded once, with its path and the
/// test it is attributed to.
/// Mutant: the report removed, doubled or misattributed.
#[test]
fn an_unkept_temp_dir_log_is_recorded_once_with_its_test() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("audit.jsonl");
    let unkept = expect_unkept();
    let log = open(&path);
    assert_eq!(unkept.recorded(), vec![(AUDIT_LOG, path, this_test())]);
    drop(log);
}

/// R7. A log in a kept dir inside another kept dir keeps both: with both
/// test shares dropped, a late append lands and both dirs go with the log.
/// Mutant: only the first, or only the deepest, match kept.
#[test]
fn a_nested_kept_dir_keeps_both() {
    let outer = kept_tempdir();
    let inner = kept_tempdir_in(outer.path());
    let (outer_root, inner_root) = (outer.path().to_owned(), inner.path().to_owned());
    let log = open(&inner_root.join("audit.jsonl"));
    drop(inner);
    drop(outer);
    note(&log);
    assert!(
        inner_root.join("audit.jsonl").is_file(),
        "the late append landed"
    );
    drop(log);
    assert!(!inner_root.exists(), "the inner dir outlived the log");
    assert!(!outer_root.exists(), "the outer dir outlived the log");
}

/// Env var that turns this test binary into R10's child.
const KEPT_CHILD: &str = "MCP_TLOG_KEPT_DIR_CHILD";

/// R10 child side: opens a log at the path it is given under
/// `expect_unkept`, and exits 0 when nothing was recorded, 5 when the open
/// was recorded as unkept. A no-op in a normal run.
#[test]
fn kept_dir_child_process() {
    let Ok(path) = std::env::var(KEPT_CHILD) else {
        return;
    };
    let unkept = expect_unkept();
    let log = open(Path::new(&path));
    let code = if unkept.recorded().is_empty() { 0 } else { 5 };
    drop(log);
    std::process::exit(code);
}

/// R10. A child process keeps no `Arc` of its parent's dir, but a dir the
/// parent names in `MCP_GATEWAY_TEST_KEPT_DIRS` is not reported; without
/// the variable the same open is.
/// Mutant: a real open that never consults the variable.
#[test]
fn a_child_process_honours_its_parents_kept_dirs() {
    let dir = kept_tempdir();
    let path = dir.path().join("audit.jsonl");
    let run = |kept: Option<&Path>| {
        let mut child =
            std::process::Command::new(std::env::current_exe().expect("this test binary"));
        child
            .args([
                "--exact",
                "security::transparency_log::kept_dir_tests::kept_dir_child_process",
                "--test-threads=1",
            ])
            .env(KEPT_CHILD, &path)
            .env_remove("MCP_GATEWAY_TEST_KEPT_DIRS");
        if let Some(kept) = kept {
            child.env(
                "MCP_GATEWAY_TEST_KEPT_DIRS",
                std::env::join_paths([kept]).expect("a joinable path"),
            );
        }
        child.status().expect("the child runs").code()
    };
    assert_eq!(
        run(Some(dir.path())),
        Some(0),
        "a parent-kept dir is not reported"
    );
    assert_eq!(run(None), Some(5), "an undeclared dir is reported");
}

/// R11 (control). A log in a kept dir records nothing.
/// Mutant: the check inverted.
#[test]
fn a_kept_log_records_nothing() {
    let dir = kept_tempdir();
    let unkept = expect_unkept();
    let log = open(&dir.path().join("audit.jsonl"));
    assert_eq!(unkept.recorded(), Vec::<Unkept>::new());
    drop(log);
}

/// R13 (control). A refused second open releases every share it took:
/// with the test's share and the first log gone, the dir is gone too.
/// Mutant: a failed open leaking its kept shares.
#[test]
fn a_refused_open_releases_what_it_took() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let path = root.join("audit.jsonl");
    let first = open(&path);
    let refused =
        TransparencyLogger::open_with_wait(config(&path.to_string_lossy()), Duration::ZERO)
            .err()
            .expect("a second writer is refused");
    assert!(super::lease::is_lease_held(&refused), "{refused}");
    let weak: Weak<tempfile::TempDir> = Arc::downgrade(&dir);
    drop(dir);
    drop(first);
    assert!(
        weak.upgrade().is_none(),
        "a share of the dir outlived every owner"
    );
    assert!(!root.exists(), "the dir outlived every owner");
}

/// R15. A log opened through a symlinked alias of a kept dir keeps the real
/// dir: the lookup compares normal forms, not the path as written.
/// Mutant: the lookup on the raw path.
#[cfg(unix)]
#[test]
fn a_log_opened_through_an_alias_keeps_the_real_dir() {
    let dir = kept_tempdir();
    let root = dir.path().to_owned();
    let links = outside_temp();
    let alias = links.path().join("alias");
    std::os::unix::fs::symlink(&root, &alias).expect("a symlink");
    let log = open(&alias.join("audit.jsonl"));
    drop(dir);
    note(&log);
    assert!(root.join("audit.jsonl").is_file(), "the late append landed");
    drop(log);
    assert!(
        !root.exists(),
        "the real dir was not kept through its alias"
    );
}

/// R16 (control). A real log opened outside the temp dir is never recorded,
/// whichever side of the report the filter sits on.
/// Mutant: the outside-temp filter removed from the open path.
#[test]
fn a_real_log_outside_the_temp_dir_records_nothing() {
    let dir = outside_temp();
    let unkept = expect_unkept();
    let log = open(&dir.path().join("audit.jsonl"));
    assert_eq!(unkept.recorded(), Vec::<Unkept>::new());
    drop(log);
}

/// R17. A log opened on a worker thread is attributed to the test that
/// spawned the worker (`test_late_write::writing_for`), not to the worker.
/// Mutant: the worker's own thread name used.
#[test]
fn a_worker_open_is_attributed_to_its_spawning_test() {
    let parent = this_test();
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("audit.jsonl");
    let spawner = parent.clone();
    let worker_path = path.clone();
    let recorded = std::thread::Builder::new()
        .name("kept-dir-worker".to_owned())
        .spawn(move || {
            crate::test_late_write::writing_for(Some(spawner));
            let unkept = expect_unkept();
            let log = open(&worker_path);
            let recorded = unkept.recorded();
            drop(log);
            recorded
        })
        .expect("a worker")
        .join()
        .expect("the worker does not panic");
    assert_eq!(recorded, vec![(AUDIT_LOG, path, parent)]);
}
