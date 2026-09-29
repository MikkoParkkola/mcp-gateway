// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1718: on Windows the guarded reader judges the opened handle's DACL by the
//! file's class. Secrecy files must be owner-only; Integrity files may be read
//! by others, never changed. Descriptors are planted with PowerShell, not with
//! `win_acl`, so planting and judging are not the same code.

use super::{GuardedRead, SecretFile, read_guarded_file};
use crate::private_fs::test_support::{
    fixture_fail, plant_file_with, plant_sddl, read_sddl, user_sid,
};
use std::path::PathBuf;

const EVERYONE_READ: &str = "(A;;FR;;;WD)";
const EVERYONE_WRITE: &str = "(A;;FW;;;WD)";
const EVERYONE_FULL: &str = "(A;;FA;;;WD)";

/// A file holding `text`, planted with the user's full control plus `extra`.
/// Under the working directory, not TEMP: the runner's TEMP is an 8.3 path
/// (`RUNNER~1`), and `~` is outside the set that gets a runnable repair.
fn planted(row: &str, extra: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = std::env::current_dir()
        .and_then(tempfile::tempdir_in)
        .unwrap_or_else(|e| fixture_fail(row, &e.to_string()));
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "value")
        .unwrap_or_else(|e| fixture_fail(row, &format!("writing the fixture failed: {e}")));
    plant_file_with(row, &path, extra);
    (dir, path)
}

fn refusal(row: &str, read: Result<String, GuardedRead>) -> String {
    match read {
        Err(GuardedRead::Refused(text)) => text,
        other => panic!("WT-ASSERT {row}: expected a refusal, got {other:?}"),
    }
}

#[test]
fn secrecy_file_readable_by_everyone_is_refused_with_file_rules_and_repair() {
    let row = "1718-R1";
    let (_dir, path) = planted(row, EVERYONE_READ);

    let text = refusal(row, read_guarded_file(&path, SecretFile::Config));

    for wanted in [
        path.display().to_string().as_str(),
        "config file",
        "ForeignSid(\"S-1-1-0\")",
        "To repair it",
    ] {
        assert!(
            text.contains(wanted),
            "WT-ASSERT {row}: {wanted:?} missing: {text}"
        );
    }
    assert!(
        !text.contains("(A;;FR;;;WD)"),
        "WT-ASSERT {row}: a secret's repair must not grant Everyone read: {text}"
    );
}

#[test]
fn secrecy_file_owner_only_is_read() {
    let row = "1718-R2";
    let (_dir, path) = planted(row, "");

    let read = read_guarded_file(&path, SecretFile::Config);

    assert_eq!(
        read.ok().as_deref(),
        Some("value"),
        "WT-ASSERT {row}: owner-only Secrecy file must be read"
    );
}

#[test]
fn every_broken_rule_is_named_not_just_the_first() {
    let row = "1718-R3";
    let user = user_sid();
    let dir = tempfile::tempdir().unwrap_or_else(|e| fixture_fail(row, &e.to_string()));
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "value").unwrap_or_else(|e| fixture_fail(row, &e.to_string()));
    let sddl = format!("O:{user}D:(A;;FA;;;{user}){EVERYONE_READ}");
    plant_sddl(row, &path, &sddl, &sddl);

    let text = refusal(row, read_guarded_file(&path, SecretFile::TlsKey));

    for wanted in ["ForeignSid", "NotProtected"] {
        assert!(
            text.contains(wanted),
            "WT-ASSERT {row}: {wanted:?} missing: {text}\nread back by path: {}\n\
             by handle: {:?}",
            read_sddl(row, &path),
            std::fs::File::open(&path).and_then(|f| crate::win_acl::inspect(&f)),
        );
    }
}

#[test]
fn integrity_file_writable_by_everyone_is_refused_with_the_integrity_repair() {
    for (row, extra) in [("1718-R4w", EVERYONE_WRITE), ("1718-R4f", EVERYONE_FULL)] {
        let (_dir, path) = planted(row, extra);

        let text = refusal(row, read_guarded_file(&path, SecretFile::IdentityGrants));

        for wanted in [
            "identity grants file",
            "ForeignSid",
            "To repair it",
            "(A;;FR;;;WD)",
        ] {
            assert!(
                text.contains(wanted),
                "WT-ASSERT {row}: {wanted:?} missing: {text}"
            );
        }
    }
}

#[test]
fn integrity_file_readable_by_everyone_is_read() {
    let row = "1718-R5";
    for what in [
        SecretFile::TlsCert,
        SecretFile::TlsCrl,
        SecretFile::ControlPlaneCollection,
    ] {
        let (_dir, path) = planted(row, EVERYONE_READ);

        let read = read_guarded_file(&path, what);

        assert_eq!(
            read.ok().as_deref(),
            Some("value"),
            "WT-ASSERT {row}: {what:?} readable by Everyone must be read"
        );
    }
}

#[test]
fn directory_target_is_refused_as_a_file_to_replace() {
    let row = "1718-R6";
    let dir = tempfile::tempdir().unwrap_or_else(|e| fixture_fail(row, &e.to_string()));

    let text = refusal(row, read_guarded_file(dir.path(), SecretFile::Config));

    assert!(text.contains("replace the file"), "WT-ASSERT {row}: {text}");
}

#[test]
fn symlink_to_a_good_file_is_read_like_on_unix() {
    let row = "1718-R7";
    let (dir, target) = planted(row, "");
    let link = dir.path().join("link.txt");
    std::os::windows::fs::symlink_file(&target, &link)
        .unwrap_or_else(|e| fixture_fail(row, &format!("creating the symlink failed: {e}")));

    let read = read_guarded_file(&link, SecretFile::Config);

    assert_eq!(
        read.ok().as_deref(),
        Some("value"),
        "WT-ASSERT {row}: a link to an owner-only file is judged on its target and read"
    );
}

#[test]
fn symlink_to_a_bad_file_is_judged_on_the_target() {
    let row = "1718-R8";
    let (dir, target) = planted(row, EVERYONE_READ);
    let link = dir.path().join("link.txt");
    std::os::windows::fs::symlink_file(&target, &link)
        .unwrap_or_else(|e| fixture_fail(row, &format!("creating the symlink failed: {e}")));

    let text = refusal(row, read_guarded_file(&link, SecretFile::Config));

    assert!(text.contains("ForeignSid"), "WT-ASSERT {row}: {text}");
}
