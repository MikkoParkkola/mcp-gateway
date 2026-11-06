// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Crash rows under a real kill: the scenario runs in a child process that
//! aborts at a named boundary, and the parent reopens what it left.

use std::path::{Path, PathBuf};

use super::identity_tests::identified;
use super::kill::{self, At};
use super::rotation_tests::{cfg, lines, verify};
use super::*;

/// The boundary the child is killed at, by name.
const KILL_AT: &str = "MCP_GW_TEST_AUDIT_KILL_AT";
/// The directory the child's log lives in.
const KILL_DIR: &str = "MCP_GW_TEST_AUDIT_KILL_DIR";
/// Written by the child on reaching the boundary, before it aborts.
const MARKER: &str = "killed";

/// The log a kill row's child writes in `dir`.
pub(super) fn kill_log(dir: &Path) -> PathBuf {
    dir.join("transparency.jsonl")
}

/// Run [`child`] killed at `at` over the log in `dir`, and assert it got
/// there: a child that ran no row, or never reached the boundary, leaves no
/// marker. Its exit status is not the check (an abort reads differently per
/// platform, and the drop-instead-of-abort mutant exits cleanly).
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
