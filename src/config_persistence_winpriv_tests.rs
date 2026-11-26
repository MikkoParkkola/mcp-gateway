// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WRITER.5: on Windows a `Private` save keeps the file's owner or refuses
//! `foreign-owner` before any scratch exists, as on unix. The private copy is
//! always owned by the account the gateway runs as, so a file another account
//! owns is refused rather than handed over. Owners other than the token's
//! own are planted with the restore privilege, which CI's elevated runner has.

use std::path::Path;

use super::winacl_tests::assert_refused_as;
use super::{FileMode, Symlink, write_atomic};
use crate::private_fs::test_support::{
    OwnerPlant, everyone_full_dir, parse_sddl, plant_any, plant_owner, plant_owner_only, read_sddl,
    user_sid,
};

/// NT AUTHORITY\SYSTEM: an owner this token may not assign without a privilege.
const SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators: the owner an elevated token gives new files.
const ADMINISTRATORS: &str = "S-1-5-32-544";

/// `oauth.json` in a fresh folder, holding "old" and owned by `owner` (set
/// `how`), behind a protected list that grants the user `list` (SDDL rights;
/// empty for none).
fn planted(
    row: &str,
    owner: &str,
    how: OwnerPlant,
    list: &str,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = everyone_full_dir(row);
    let path = dir.path().join("oauth.json");
    std::fs::write(&path, b"old").unwrap();
    let user = user_sid();
    let dacl = if list.is_empty() {
        String::new()
    } else {
        format!("(A;;{list};;;{user})")
    };
    plant_any(row, &path, &format!("O:{user}D:P{dacl}"));
    plant_owner(row, &path, owner, how);
    (dir, path)
}

/// The owner of the file at `path`.
fn owner_of(row: &str, path: &Path) -> String {
    parse_sddl(&read_sddl(row, path)).owner
}

/// W1: a file owned by NT AUTHORITY\SYSTEM is refused `foreign-owner`,
/// naming that owner and the gateway's account; its owner stays SYSTEM.
#[test]
fn w1_a_private_save_over_a_file_another_account_owns_is_refused() {
    let row = "WINPRIV-W1";
    let (_dir, path) = planted(row, SYSTEM, OwnerPlant::WithRestorePrivilege, "FA");
    assert_eq!(owner_of(row, &path), SYSTEM, "{row}: owner not planted");
    let text = assert_refused_as(row, &path, FileMode::Private, "foreign-owner");
    assert!(
        text.contains(SYSTEM) && text.contains(&user_sid()),
        "{row}: {text}"
    );
    assert_eq!(owner_of(row, &path), SYSTEM, "{row}: owner changed");
}

/// W2: a file the user owns saves, and the user stays its owner.
#[test]
fn w2_a_private_save_over_the_users_own_file_keeps_its_owner() {
    let row = "WINPRIV-W2";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("oauth.json");
    std::fs::write(&path, b"old").unwrap();
    plant_owner_only(row, &path);
    write_atomic(&path, b"new", FileMode::Private, Symlink::Replace)
        .unwrap_or_else(|e| panic!("{row}: the save failed: {e}"));
    assert_eq!(std::fs::read(&path).unwrap(), b"new", "{row}: not saved");
    assert_eq!(owner_of(row, &path), user_sid(), "{row}: owner changed");
}

/// W3: where the volume keeps no access lists (FAT, exFAT; answered by the
/// seam) there is no owner to keep, so the SYSTEM-owned file saves.
#[test]
fn w3_a_volume_without_access_lists_has_no_owner_to_keep() {
    let row = "WINPRIV-W3";
    let (_dir, path) = planted(row, SYSTEM, OwnerPlant::WithRestorePrivilege, "FA");
    super::windows::test_seams::VOLUME.with(|answer| answer.set(Some(false)));
    let saved = write_atomic(&path, b"new", FileMode::Private, Symlink::Replace);
    super::windows::test_seams::VOLUME.with(|answer| answer.set(None));
    saved.unwrap_or_else(|e| panic!("{row}: the save failed: {e}"));
    assert_eq!(std::fs::read(&path).unwrap(), b"new", "{row}: not saved");
}

/// W4: an elevated token gives new files BUILTIN\Administrators as owner,
/// but the private copy belongs to the user: a `Private` save over an
/// Administrators-owned file is refused rather than change its owner.
#[test]
fn w4_a_private_save_over_an_administrators_owned_file_is_refused() {
    let row = "WINPRIV-W4";
    let dir = everyone_full_dir(row);
    let probe = dir.path().join("probe");
    std::fs::write(&probe, b"x").unwrap();
    assert_eq!(
        owner_of(row, &probe),
        ADMINISTRATORS,
        "{row}: needs an elevated runner, where new files belong to BUILTIN\\Administrators"
    );
    std::fs::remove_file(&probe).unwrap();
    let (_dir, path) = planted(row, ADMINISTRATORS, OwnerPlant::AsToken, "FA");
    assert_eq!(
        owner_of(row, &path),
        ADMINISTRATORS,
        "{row}: owner not planted"
    );
    let text = assert_refused_as(row, &path, FileMode::Private, "foreign-owner");
    assert!(text.contains(ADMINISTRATORS), "{row}: {text}");
}

/// W5: a SYSTEM-owned file whose protected list grants this token nothing
/// (so not even `READ_CONTROL`) is refused `descriptor-unreadable`: the
/// writer never hands itself a file it cannot inspect.
#[test]
fn w5_a_private_save_over_a_file_whose_owner_cannot_be_read_is_refused() {
    let row = "WINPRIV-W5";
    let (_dir, path) = planted(row, SYSTEM, OwnerPlant::WithRestorePrivilege, "");
    assert!(
        std::fs::File::open(&path).is_err(),
        "{row}: the planted file is still readable by this token"
    );
    assert_refused_as(row, &path, FileMode::Private, "descriptor-unreadable");
}

/// W6: a metadata error other than "not found" (forced by the seam) ends a
/// `Private` save with that error before any scratch, so the owner check
/// cannot be skipped.
#[test]
fn w6_a_metadata_error_ends_a_private_save_before_any_scratch() {
    let row = "WINPRIV-W6";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("oauth.json");
    std::fs::write(&path, b"old").unwrap();
    super::windows::test_seams::METADATA_ERROR.with(|forced| forced.set(Some(5)));
    let result = write_atomic(&path, b"new", FileMode::Private, Symlink::Replace);
    super::windows::test_seams::METADATA_ERROR.with(|forced| forced.set(None));
    let err = result.expect_err("WINPRIV-W6: the save went ahead");
    assert_eq!(err.raw_os_error(), Some(5), "{row}: {err}");
    assert_eq!(std::fs::read(&path).unwrap(), b"old", "{row}: file changed");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "{row}: scratch left"
    );
}
