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

/// A9: a file owned by another principal (Administrators) is refused, and the
/// message names the owner found and the owner expected.
#[test]
fn a_file_owned_by_administrators_is_refused_naming_both_owners() {
    let row = "WINACL-A9";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, b"old").unwrap();
    let user = crate::private_fs::test_support::user_sid();
    plant_any(row, &path, &format!("O:BAD:P(A;;FA;;;{user})"));
    let err = write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace)
        .expect_err("WINACL-A9: the save was not refused");
    let text = err.to_string();
    assert!(text.contains("foreign-owner"), "{row}: {text}");
    assert!(
        text.contains("S-1-5-32-544") && text.contains(&user),
        "{row}: {text}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
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
