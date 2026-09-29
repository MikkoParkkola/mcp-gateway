// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1718: on Windows the journal is created owner-only, and an existing one is
//! judged like the reader judges it (Integrity: others may read, not change)
//! before anything is appended.

use super::append_line;
use crate::private_fs::test_support::{
    assert_owner_only, everyone_full_dir, fixture_fail, plant_file_with,
};

const EVERYONE_READ: &str = "(A;;FR;;;WD)";
const EVERYONE_WRITE: &str = "(A;;FW;;;WD)";

#[test]
fn a_new_journal_is_owner_only_in_an_open_directory() {
    let row = "1718-W6";
    let dir = everyone_full_dir(row);
    let journal = dir.path().join("grants.yaml.journal");

    append_line(&journal, b"one\n").unwrap();

    // Relies on `create_file_private(.., Share::Exclusive)`: owner-only from creation, not repaired after.
    assert_owner_only(row, &journal, false);
    assert_eq!(std::fs::read(&journal).unwrap(), b"one\n");
}

#[test]
fn an_existing_journal_others_can_write_is_refused_on_append() {
    let row = "1718-W6a";
    let dir = tempfile::tempdir().unwrap();
    let journal = dir.path().join("j");
    std::fs::write(&journal, "old\n").unwrap();
    plant_file_with(row, &journal, EVERYONE_WRITE);

    let appended = append_line(&journal, b"new\n");

    assert!(
        appended.is_err(),
        "WT-ASSERT {row}: appending to a journal Everyone can write must be refused"
    );
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        b"old\n",
        "WT-ASSERT {row}"
    );
}

#[test]
fn an_existing_journal_others_can_only_read_is_appended_to() {
    let row = "1718-W6b";
    let dir = tempfile::tempdir().unwrap();
    let journal = dir.path().join("j");
    std::fs::write(&journal, "old\n").unwrap();
    plant_file_with(row, &journal, EVERYONE_READ);

    let appended = append_line(&journal, b"new\n");

    assert!(appended.is_ok(), "WT-ASSERT {row}: {appended:?}");
    assert_eq!(
        std::fs::read(&journal).unwrap(),
        b"old\nnew\n",
        "WT-ASSERT {row}"
    );
}

#[test]
fn a_journal_that_is_a_symlink_is_refused_and_its_target_untouched() {
    let row = "1718-W6c";
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, "elsewhere\n").unwrap();
    plant_file_with(row, &target, "");
    let journal = dir.path().join("j");
    std::os::windows::fs::symlink_file(&target, &journal)
        .unwrap_or_else(|e| fixture_fail(row, &format!("creating the symlink failed: {e}")));

    let appended = append_line(&journal, b"new\n");

    assert!(
        appended.is_err(),
        "WT-ASSERT {row}: a planted link must be refused"
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"elsewhere\n",
        "WT-ASSERT {row}"
    );
}

#[test]
fn a_journal_that_is_a_directory_is_refused() {
    let row = "1718-W6d";
    let dir = tempfile::tempdir().unwrap();
    let journal = dir.path().join("j");
    std::fs::create_dir(&journal).unwrap_or_else(|e| fixture_fail(row, &e.to_string()));

    let appended = append_line(&journal, b"new\n");

    assert!(
        appended.is_err(),
        "WT-ASSERT {row}: a directory is not a journal"
    );
}

#[test]
fn a_journal_that_is_a_junction_is_refused_and_its_target_untouched() {
    let row = "1718-W6e";
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap_or_else(|e| fixture_fail(row, &e.to_string()));
    let journal = dir.path().join("j");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&journal)
        .arg(&target)
        .status();
    if !made.is_ok_and(|s| s.success()) {
        fixture_fail(row, "mklink /J failed");
    }

    let appended = append_line(&journal, b"new\n");

    assert!(
        appended.is_err(),
        "WT-ASSERT {row}: a junction is not a journal"
    );
    assert_eq!(
        std::fs::read_dir(&target).unwrap().count(),
        0,
        "WT-ASSERT {row}: nothing may be written through the junction"
    );
}
