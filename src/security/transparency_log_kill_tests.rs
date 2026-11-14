// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Crash rows under a real kill: the scenario runs in a child process that
//! aborts at a named boundary, and the parent reopens what it left.

use std::path::{Path, PathBuf};

use super::identity_tests::{beta_records, beta_shape, chain_file, identified};
use super::kill::{self, At};
use super::rotation_tests::{append, cfg, lines, rotate_n, verify};
use super::segments::{list_segments, read_hwm, sealed_path, sibling};
use super::*;

/// The boundary the child is killed at, by name.
const KILL_AT: &str = "MCP_GW_TEST_AUDIT_KILL_AT";
/// The directory the child's log lives in.
const KILL_DIR: &str = "MCP_GW_TEST_AUDIT_KILL_DIR";
/// Written by the child on reaching the boundary, before it aborts.
const MARKER: &str = "killed";
/// The open-record field naming what survived of a lost predecessor.
const PREDECESSOR: &str = "predecessor_missing";

/// The log a kill row's child writes in `dir`.
pub(super) fn kill_log(dir: &Path) -> PathBuf {
    dir.join("transparency.jsonl")
}

/// Run [`child`] killed at `at` over the log in `dir`, and assert it got
/// there by dying: a child that ran no row, or never reached the boundary,
/// leaves no marker, and one that reached it but did not abort exits
/// cleanly. Only success is refused, since an abort's status differs per
/// platform.
pub(super) fn killed_at(at: At, dir: &Path) {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "security::transparency_log::kill_tests::child",
            "--ignored",
            "--nocapture",
        ])
        .env(KILL_AT, format!("{at:?}"))
        .env(KILL_DIR, dir)
        .output()
        .unwrap();
    // An abort never exits cleanly: a zero exit means the child did not
    // die at the boundary, whatever it reached.
    assert!(
        !out.status.success(),
        "the child exited cleanly instead of aborting at {at:?}"
    );
    assert!(
        dir.join(MARKER).exists(),
        "the child never reached {at:?}:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "run by the kill rows, in a child that aborts"]
fn child() {
    let (Ok(at), Some(dir)) = (std::env::var(KILL_AT), std::env::var_os(KILL_DIR)) else {
        return;
    };
    let at = match at.as_str() {
        "LoggerBuilt" => At::LoggerBuilt,
        "BeforeIdentified" => At::BeforeIdentified,
        other => panic!("unknown boundary {other}"),
    };
    let dir = PathBuf::from(dir);
    kill::arm(at, dir.join(MARKER));
    let path = kill_log(&dir);
    let logger = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    kill::point(At::LoggerBuilt);
    drop(logger);
}

#[test]
#[allow(non_snake_case)]
fn crash_S2() {
    // GIVEN: a child killed just after its logger was built (id minted and
    // recorded), its lease released only by its death
    let dir = crate::test_dir_keep::kept_tempdir();
    killed_at(At::LoggerBuilt, dir.path());
    let path = kill_log(dir.path());
    let id = lines(&path)[0]["log_id"].as_str().unwrap().to_string();

    // WHEN: the log is reopened twice
    for _ in 0..2 {
        let again =
            TransparencyLogger::open(cfg(&path, 12, false)).expect("the lease went with the child");
        // THEN: the same id
        assert_eq!(again.log_id().as_str(), id);
    }

    // THEN: never a second identified record
    let found = identified(&path);
    assert_eq!(
        found.len(),
        1,
        "never a second identified record: {found:?}"
    );
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
}

#[test]
fn a_kill_before_the_identified_record_is_finished_on_reopen() {
    // GIVEN: a child killed after the genesis open record, before the
    // identified record that names its id
    let dir = crate::test_dir_keep::kept_tempdir();
    killed_at(At::BeforeIdentified, dir.path());
    let path = kill_log(dir.path());
    let left = lines(&path);
    assert_eq!(
        left.len(),
        1,
        "the kill landed after the open record: {left:?}"
    );
    let id = left[0]["log_id"].as_str().unwrap().to_string();

    // WHEN: the log is reopened twice
    for _ in 0..2 {
        let again =
            TransparencyLogger::open(cfg(&path, 12, false)).expect("the lease went with the child");
        // THEN: the open record's id
        assert_eq!(again.log_id().as_str(), id);
    }

    // THEN: exactly one identified record naming it, and verify passes
    let found = identified(&path);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
}

#[test]
fn a_restart_after_the_active_file_was_deleted_names_the_surviving_mark() {
    // GIVEN: a log with records, its writer gone, its active file deleted
    // and its mark kept
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = kill_log(dir.path());
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&first, 0);
    append(&first, 1);
    drop(first);
    let mark = read_hwm(&path, b"", "test").unwrap();
    std::fs::remove_file(&path).unwrap();

    // WHEN: a new process opens it (killed once its logger is built)
    killed_at(At::LoggerBuilt, dir.path());

    // THEN: as the child left it, the new genesis's open record already
    // names the mark that survived, and no previous id (the mark holds none)
    let head = lines(&path);
    let marker = &head[0][PREDECESSOR];
    assert!(marker.is_object(), "no predecessor evidence: {head:?}");
    assert!(marker.get("previous_log_id").is_none(), "{marker}");
    let hw = &marker["previous_high_water"];
    assert_eq!(hw["counter"].as_u64(), Some(mark.counter));
    assert_eq!(hw["entry_hash"].as_str(), Some(mark.entry_hash.as_str()));

    // THEN: its id holds across two reopens
    let id = head[0]["log_id"].as_str().unwrap().to_string();
    for _ in 0..2 {
        let again =
            TransparencyLogger::open(cfg(&path, 12, false)).expect("the lease went with the child");
        assert_eq!(again.log_id().as_str(), id);
    }

    // THEN: verify fails on the deletion and reports the evidence unverified
    deleted_and_unverified(&path, mark.counter);
}

/// Verify fails naming the deleted active segment, and reports the
/// predecessor evidence by the mark's `counter` once, as unverified: the
/// chain check stops at the deletion before it reaches that record.
fn deleted_and_unverified(path: &Path, counter: u64) {
    let r = verify(path, false);
    let msg = r.error_message.unwrap_or_default();
    assert!(msg.contains("the active segment was deleted"), "{msg}");
    let named = format!("counter {counter}");
    let warned: Vec<&String> = r.warnings.iter().filter(|w| w.contains(&named)).collect();
    assert_eq!(warned.len(), 1, "{:?}", r.warnings);
    assert!(warned[0].contains("unverified"), "{warned:?}");
}

#[test]
fn a_kill_before_the_upgrade_records_its_id_is_finished_on_reopen() {
    // GIVEN: a beta log (no id anywhere), and a child that opens it under
    // this version and is killed before the identified record
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = kill_log(dir.path());
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&first, 0);
    drop(first);
    beta_shape(&path);
    killed_at(At::BeforeIdentified, dir.path());
    assert!(
        identified(&path).is_empty(),
        "the kill landed before the record"
    );

    // WHEN: the log is reopened twice
    let id = TransparencyLogger::open(cfg(&path, 12, false))
        .expect("the lease went with the child")
        .log_id();
    let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();

    // THEN: one identified record, and the id it names holds across reopens
    assert_eq!(again.log_id(), id);
    let found = identified(&path);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
}

#[test]
fn a_kill_after_a_replacing_genesis_keeps_its_predecessor_evidence() {
    // GIVEN: a log with records, its writer gone, its active file deleted
    // and its mark kept; a new process killed after the new genesis's open
    // record, before its identified record
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = kill_log(dir.path());
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&first, 0);
    drop(first);
    let mark = read_hwm(&path, b"", "test").unwrap();
    std::fs::remove_file(&path).unwrap();
    killed_at(At::BeforeIdentified, dir.path());
    let left = lines(&path);
    assert!(identified(&path).is_empty(), "killed first: {left:?}");
    let hw = &left[0][PREDECESSOR]["previous_high_water"];
    assert_eq!(hw["counter"].as_u64(), Some(mark.counter), "{left:?}");
    assert_eq!(hw["entry_hash"].as_str(), Some(mark.entry_hash.as_str()));
    let id = left[0]["log_id"].as_str().unwrap().to_string();

    // WHEN: the log is reopened twice
    for _ in 0..2 {
        let again =
            TransparencyLogger::open(cfg(&path, 12, false)).expect("the lease went with the child");
        // THEN: the genesis's id holds
        assert_eq!(again.log_id().as_str(), id);
    }

    // THEN: the open record still names the surviving mark, and exactly one
    // identified record names the open record's id
    let head = lines(&path);
    let hw = &head[0][PREDECESSOR]["previous_high_water"];
    assert_eq!(hw["counter"].as_u64(), Some(mark.counter), "{head:?}");
    assert_eq!(hw["entry_hash"].as_str(), Some(mark.entry_hash.as_str()));
    let found = identified(&path);
    assert_eq!(found.len(), 1, "one identified: {head:?}");
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));

    // THEN: verify fails on the deletion and reports the evidence unverified
    deleted_and_unverified(&path, mark.counter);
}

#[test]
fn a_rotated_log_whose_files_vanished_finishes_its_new_genesis_on_reopen() {
    // GIVEN: a rotated log whose writer is gone, its active file and sealed
    // segments deleted and its mark (naming a segment past 0) kept; a new
    // process killed after the new genesis's open record, before its
    // identified record
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = kill_log(dir.path());
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&first, &path, 1);
    append(&first, 0);
    drop(first);
    let mark = read_hwm(&path, b"", "test").unwrap();
    assert!(mark.segment_seq > 0, "the fixture rotated: {mark:?}");
    for seg in list_segments(&path).unwrap() {
        std::fs::remove_file(&seg.path).unwrap();
    }
    std::fs::remove_file(&path).unwrap();
    killed_at(At::BeforeIdentified, dir.path());
    let left = lines(&path);
    assert!(identified(&path).is_empty(), "killed first: {left:?}");
    assert_eq!(left[0]["segment_seq"].as_u64(), Some(mark.segment_seq));
    let hw = &left[0][PREDECESSOR]["previous_high_water"];
    assert_eq!(hw["counter"].as_u64(), Some(mark.counter), "{left:?}");
    assert_eq!(hw["entry_hash"].as_str(), Some(mark.entry_hash.as_str()));
    let id = left[0]["log_id"].as_str().unwrap().to_string();

    // WHEN: the log is reopened twice
    for _ in 0..2 {
        let again =
            TransparencyLogger::open(cfg(&path, 12, false)).expect("the lease went with the child");
        // THEN: the genesis's id holds
        assert_eq!(again.log_id().as_str(), id);
    }

    // THEN: exactly one identified record, naming that id
    let found = identified(&path);
    assert_eq!(found.len(), 1, "{:?}", lines(&path));
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
}

#[test]
fn an_upgraded_rotated_beta_log_killed_before_its_id_record_stays_unidentified() {
    // GIVEN: a rotated beta log (no id on any segment) whose active file and
    // mark were deleted; a child opens it under this version, mints an id
    // onto the open record that continues the sealed segment, and is killed
    // before the identified record
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = kill_log(dir.path());
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&first, &path, 1);
    drop(first);
    let sealed = sealed_path(&path, 0);
    chain_file(&sealed, beta_records(&sealed));
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(sibling(&path, "hwm")).unwrap();
    killed_at(At::BeforeIdentified, dir.path());
    let left = lines(&path);
    assert!(left[0].get("prev_segment_seq").is_some(), "{left:?}");
    let id = left[0]["log_id"].as_str().unwrap().to_string();

    // WHEN: the log is reopened twice
    for _ in 0..2 {
        let again =
            TransparencyLogger::open(cfg(&path, 12, false)).expect("the lease went with the child");
        // THEN: the minted id holds
        assert_eq!(again.log_id().as_str(), id);
    }

    // THEN: the accepted exception: no identified record is ever added, as
    // the repair keys on an open record linking to no sealed segment
    assert!(identified(&path).is_empty(), "{:?}", lines(&path));
}
