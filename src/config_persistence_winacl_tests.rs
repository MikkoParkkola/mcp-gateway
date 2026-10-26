// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! On Windows an `Inherit` save over an existing file keeps that
//! file's access list, so an owner-only file in a folder other accounts can
//! read stays owner-only. A new file still takes the folder's list. Each
//! folder here hands Everyone full access to its children, so a scratch that
//! takes the folder's list is caught at once.

use std::path::Path;

use super::{FileMode, Symlink, write_atomic};
use crate::private_fs::test_support::{
    assert_owner_only, everyone_full_dir, icacls, parse_sddl, plant_any, plant_file_with,
    plant_owner_only, read_sddl,
};

fn save(path: &Path) {
    write_atomic(path, b"new", FileMode::Inherit, Symlink::Replace)
        .unwrap_or_else(|e| panic!("save of {} failed: {e}", path.display()));
}

/// A1: an owner-only file stays owner-only.
#[test]
fn an_owner_only_file_stays_owner_only_after_a_save() {
    let row = "WINACL-A1";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("caps.yaml");
    std::fs::write(&path, b"old").unwrap();
    plant_owner_only(row, &path);
    save(&path);
    assert_owner_only(row, &path, false);
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
}

/// A2: a custom protected list (the user, plus read for BUILTIN\Users) is
/// kept as it was, entries in order, not replaced by the folder's.
#[test]
fn a_custom_access_list_is_kept_after_a_save() {
    let row = "WINACL-A2";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("ledger.json");
    std::fs::write(&path, b"old").unwrap();
    plant_file_with(row, &path, "(A;;FR;;;BU)");
    let before = parse_sddl(&read_sddl(row, &path));
    save(&path);
    assert_eq!(
        parse_sddl(&read_sddl(row, &path)),
        before,
        "{row}: list changed"
    );
}

/// A3: an ordinary inherited list is unchanged by a save.
#[test]
fn an_inherited_access_list_is_unchanged_by_a_save() {
    let row = "WINACL-A3";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("stamp");
    std::fs::write(&path, b"old").unwrap();
    let before = parse_sddl(&read_sddl(row, &path));
    save(&path);
    assert_eq!(
        parse_sddl(&read_sddl(row, &path)),
        before,
        "{row}: list changed"
    );
}

/// A4: a new file takes the folder's list, as a plain create would.
#[test]
fn a_new_file_takes_the_folders_access_list() {
    let row = "WINACL-A4";
    let dir = everyone_full_dir(row);
    let sibling = dir.path().join("sibling");
    std::fs::write(&sibling, b"x").unwrap();
    let path = dir.path().join("new.yaml");
    save(&path);
    let want = parse_sddl(&read_sddl(row, &sibling));
    assert_eq!(
        parse_sddl(&read_sddl(row, &path)),
        want,
        "{row}: not the folder's list"
    );
}

/// A refused save: the error names `code`, the old file is byte-identical,
/// and the folder holds exactly what it held before (no scratch left).
fn assert_refused(row: &str, path: &Path, code: &str) {
    let dir = path.parent().unwrap();
    let listing = |d: &Path| {
        let mut names: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let before = listing(dir);
    let err = write_atomic(path, b"new", FileMode::Inherit, Symlink::Replace)
        .expect_err(&format!("{row}: the save was not refused"));
    assert!(
        err.to_string().contains(code),
        "{row}: wanted {code}, got {err}"
    );
    assert_eq!(
        std::fs::read(path).unwrap(),
        b"old",
        "{row}: old file changed"
    );
    assert_eq!(
        listing(dir),
        before,
        "{row}: the folder changed (scratch left?)"
    );
}

/// A6: a file carrying an integrity label is refused: the label cannot be
/// copied, and dropping it could widen access.
#[test]
fn a_labeled_file_is_refused() {
    let row = "WINACL-A6";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("caps.yaml");
    std::fs::write(&path, b"old").unwrap();
    plant_owner_only(row, &path);
    icacls(row, &path, &["/setintegritylevel", "Low"]);
    assert_refused(row, &path, "security-label");
}

/// A7: an unlabeled file in a folder that hands a Low label to new files is
/// refused: the scratch would carry a label the file does not.
#[test]
fn a_scratch_that_inherits_a_low_label_is_refused() {
    let row = "WINACL-A7";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("caps.yaml");
    std::fs::write(&path, b"old").unwrap();
    plant_owner_only(row, &path);
    icacls(row, dir.path(), &["/setintegritylevel", "(OI)(CI)Low"]);
    assert_refused(row, &path, "security-label");
}

/// The owner a file created now in `dir` gets under this process's token:
/// the user, or BUILTIN\Administrators for an elevated administrator.
fn fresh_owner(row: &str, dir: &Path) -> String {
    let probe = dir.join("owner-probe");
    std::fs::write(&probe, b"x").unwrap();
    let owner = parse_sddl(&read_sddl(row, &probe)).owner;
    std::fs::remove_file(&probe).unwrap();
    owner
}

/// A9: a file whose owner differs from the owner a new file gets here is
/// refused, and the message names the owner found and the owner expected.
/// The rule is relative to this token, never a fixed list of owners.
#[test]
fn a_file_with_another_owner_is_refused_naming_both_owners() {
    let row = "WINACL-A9";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, b"old").unwrap();
    let user = crate::private_fs::test_support::user_sid();
    let expected = fresh_owner(row, dir.path());
    let other = if expected == "S-1-5-32-544" {
        user.clone()
    } else {
        "S-1-5-32-544".to_owned()
    };
    plant_any(row, &path, &format!("O:{other}D:P(A;;FA;;;{user})"));
    let err = write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace)
        .expect_err("WINACL-A9: the save was not refused");
    let text = err.to_string();
    assert!(text.contains("foreign-owner"), "{row}: {text}");
    assert!(
        text.contains(&other) && text.contains(&expected),
        "{row}: {text}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
}

/// A9b: a file owned by the owner a new file gets here (BUILTIN\Administrators
/// for an elevated service) saves normally and keeps its list.
#[test]
fn a_file_with_the_owner_new_files_get_saves_normally() {
    let row = "WINACL-A9b";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, b"old").unwrap();
    let user = crate::private_fs::test_support::user_sid();
    let expected = fresh_owner(row, dir.path());
    plant_any(row, &path, &format!("O:{expected}D:P(A;;FA;;;{user})"));
    let before = parse_sddl(&read_sddl(row, &path));
    save(&path);
    assert_eq!(
        parse_sddl(&read_sddl(row, &path)),
        before,
        "{row}: list changed"
    );
}

/// A10: a file moved in from another folder keeps that folder's inherited
/// entries; the copy cannot match, so the save is refused and says why.
#[test]
fn a_file_moved_in_from_another_folder_is_refused() {
    let row = "WINACL-A10";
    let from = everyone_full_dir(row);
    let to = tempfile::tempdir().unwrap();
    icacls(row, to.path(), &["/grant", "*S-1-5-32-545:(OI)(CI)R"]);
    let old = from.path().join("cursor.json");
    std::fs::write(&old, b"old").unwrap();
    let path = to.path().join("cursor.json");
    std::fs::rename(&old, &path).unwrap();
    assert_refused(row, &path, "acl-mismatch");
}

/// A12: on a volume that keeps no access lists the save falls back to a
/// default create, with no check (the seam answers for FAT/exFAT).
#[test]
fn a_volume_without_access_lists_saves_with_a_default_create() {
    use super::windows::test_seams::VOLUME;
    let row = "WINACL-A12";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("caps.yaml");
    std::fs::write(&path, b"old").unwrap();
    plant_owner_only(row, &path);
    VOLUME.with(|v| v.set(Some(false)));
    let result = write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace);
    VOLUME.with(|v| v.set(None));
    result.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    // The default create took the folder's list, which grants Everyone.
    let got = parse_sddl(&read_sddl(row, &path));
    assert!(
        got.aces.iter().any(|ace| ace.3 == "S-1-1-0"),
        "{row}: the default create did not run: {got:?}"
    );
}

/// A13: when the check finds the copy differs, the save is refused before
/// any byte is written: old file unchanged, no scratch left.
#[test]
fn a_copy_that_differs_is_refused_with_nothing_written() {
    use super::windows::test_seams::FORCE_MISMATCH;
    let row = "WINACL-A13";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("caps.yaml");
    std::fs::write(&path, b"old").unwrap();
    plant_owner_only(row, &path);
    FORCE_MISMATCH.with(|f| f.set(true));
    let listing = |d: &Path| {
        let mut n: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        n.sort();
        n
    };
    let before = listing(dir.path());
    let result = write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace);
    FORCE_MISMATCH.with(|f| f.set(false));
    let err = result.expect_err("WINACL-A13: the save was not refused");
    assert!(err.to_string().contains("acl-mismatch"), "{row}: {err}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"old",
        "{row}: old file changed"
    );
    assert_eq!(listing(dir.path()), before, "{row}: scratch left");
}

/// The comparison: order matters, a NULL list and an empty list differ, and
/// a differing protection bit is a difference.
#[test]
fn the_comparison_reads_order_null_and_protection() {
    use super::windows::first_difference;
    use crate::win_acl::{Ace, Inspection, Sid};
    let user = Sid::from_parts(5, &[21, 1, 2, 3, 1001]);
    let users = Sid::from_parts(5, &[32, 545]);
    let allow = Ace::Allowed {
        flags: 0,
        mask: 0x1F_01FF,
        sid: users.clone(),
    };
    let deny = Ace::Denied {
        flags: 0,
        mask: 0x1F_01FF,
        sid: users,
    };
    let list = |aces: Option<Vec<Ace>>, protected| Inspection {
        owner: Some(user.clone()),
        dacl: aces,
        protected,
    };
    let a = list(Some(vec![deny.clone(), allow.clone()]), true);
    assert!(first_difference(&a, &a.clone()).is_none());
    let reversed = list(Some(vec![allow, deny]), true);
    assert!(first_difference(&a, &reversed).is_some(), "order ignored");
    let null = list(None, true);
    let empty = list(Some(Vec::new()), true);
    assert!(
        first_difference(&null, &empty).is_some(),
        "NULL equals empty"
    );
    assert!(
        first_difference(&empty, &null).is_some(),
        "empty equals NULL"
    );
    let unprotected = list(a.dacl.clone(), false);
    assert!(
        first_difference(&a, &unprotected).is_some(),
        "protection ignored"
    );
}

/// A8: a trust-label or access-filter entry (or any access-enforcing SACL
/// entry) refuses the copy. A live fixture is impossible on CI runners: only
/// a protected process can set a trust label. So the refusal is pinned over
/// a synthetic inspection, and the query bits in `win_acl`'s own tests.
#[test]
fn an_access_enforcing_sacl_entry_refuses_the_copy() {
    use super::windows::source_refusal;
    use crate::win_acl::{Ace, Inspection, Sid};
    let plain = Inspection {
        owner: Some(Sid::from_parts(5, &[18])),
        dacl: Some(Vec::new()),
        protected: true,
    };
    assert_eq!(source_refusal(&plain, 0), None);
    assert_eq!(
        source_refusal(&plain, 1).map(|r| r.0),
        Some("security-label")
    );
    let other = Inspection {
        dacl: Some(vec![Ace::Other { ace_type: 9 }]),
        ..plain
    };
    assert_eq!(
        source_refusal(&other, 0).map(|r| r.0),
        Some("undecodable-ace")
    );
}
