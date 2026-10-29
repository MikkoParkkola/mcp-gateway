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
    OwnerPlant, assert_owner_only, everyone_full_dir, icacls, parse_sddl, plant_any,
    plant_file_with, plant_owner, plant_owner_only, read_sddl,
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

/// A9: a file whose owner this token may not assign (NT AUTHORITY\SYSTEM,
/// planted with the restore privilege from another process) is refused,
/// naming that owner and the account the gateway runs as, and is unchanged.
#[test]
fn a_file_with_another_owner_is_refused_naming_both_owners() {
    let row = "WINACL-A9";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, b"old").unwrap();
    let user = crate::private_fs::test_support::user_sid();
    plant_any(row, &path, &format!("O:{user}D:P(A;;FA;;;{user})"));
    let planted = plant_owner(row, &path, SYSTEM, OwnerPlant::WithRestorePrivilege);
    assert_eq!(
        parse_sddl(&planted).owner,
        SYSTEM,
        "{row}: owner not planted"
    );
    let err = write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace)
        .expect_err("WINACL-A9: the save was not refused");
    let text = err.to_string();
    assert!(text.contains("foreign-owner"), "{row}: {text}");
    assert!(
        text.contains(SYSTEM) && text.contains(&user),
        "{row}: {text}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "{row}: a scratch was left behind"
    );
}

/// NT AUTHORITY\SYSTEM: an owner no test or gateway token may assign
/// without a privilege.
const SYSTEM: &str = "S-1-5-18";

/// A9c: a file owned by the token's own user saves and keeps that owner,
/// whatever owner a new file would get here (BUILTIN\Administrators on an
/// elevated token, as on CI).
#[test]
fn a_file_the_user_owns_keeps_its_owner_after_a_save() {
    let row = "WINACL-A9c";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, b"old").unwrap();
    plant_owner_only(row, &path);
    let before = parse_sddl(&read_sddl(row, &path));
    save(&path);
    let after = parse_sddl(&read_sddl(row, &path));
    assert_eq!(after.owner, before.owner, "{row}: owner changed");
    assert_eq!(after, before, "{row}: list changed");
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
}

/// A9d: the same for a file whose list is inherited (the default-create
/// path): the user owner is kept and the folder's inherited entries apply.
#[test]
fn a_user_owned_file_with_an_inherited_list_keeps_its_owner() {
    let row = "WINACL-A9d";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("stamp");
    std::fs::write(&path, b"old").unwrap();
    let user = crate::private_fs::test_support::user_sid();
    plant_owner(row, &path, &user, OwnerPlant::AsToken);
    let before = parse_sddl(&read_sddl(row, &path));
    assert_eq!(before.owner, user, "{row}: owner not planted");
    assert!(!before.protected, "{row}: the list is not inherited");
    save(&path);
    let after = parse_sddl(&read_sddl(row, &path));
    assert_eq!(after.owner, user, "{row}: owner changed");
    assert_eq!(after, before, "{row}: list changed");
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
}

/// A9e: a file with an inherited list whose owner this token may not assign
/// is refused on the default-create path too, and is unchanged.
#[test]
fn an_inherited_list_file_with_another_owner_is_refused() {
    let row = "WINACL-A9e";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("stamp");
    std::fs::write(&path, b"old").unwrap();
    let planted = parse_sddl(&plant_owner(
        row,
        &path,
        SYSTEM,
        OwnerPlant::WithRestorePrivilege,
    ));
    assert_eq!(planted.owner, SYSTEM, "{row}: owner not planted");
    assert!(!planted.protected, "{row}: the list is not inherited");
    let err = write_atomic(&path, b"new", FileMode::Inherit, Symlink::Replace)
        .expect_err("WINACL-A9e: the save was not refused");
    let text = err.to_string();
    assert!(
        text.contains("foreign-owner") && text.contains(SYSTEM),
        "{row}: {text}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "{row}: a scratch was left behind"
    );
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

/// B1: a backup of an owner-only file is owner-only; a plain copy would take
/// the folder's list.
#[test]
fn a_backup_of_an_owner_only_file_is_owner_only() {
    let row = "WINACL-B1";
    let dir = everyone_full_dir(row);
    let src = dir.path().join("gateway.yaml");
    std::fs::write(&src, b"admin: secret").unwrap();
    plant_owner_only(row, &src);
    let dst = dir.path().join("gateway.yaml.bak");
    super::copy_keeping_access(&src, &dst).unwrap();
    assert_owner_only(row, &dst, false);
    assert_eq!(std::fs::read(&dst).unwrap(), b"admin: secret");
}

/// A7b: the Low-label folder case for a file whose list is inherited (the
/// default-create path): the scratch's inherited label is refused too.
#[test]
fn a_low_label_on_the_default_create_path_is_refused() {
    let row = "WINACL-A7b";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("cursor.json");
    std::fs::write(&path, b"old").unwrap();
    icacls(row, dir.path(), &["/setintegritylevel", "(OI)(CI)Low"]);
    assert_refused(row, &path, "security-label");
}

/// B4: a backup made through a symbolic link copies the linked file's list,
/// not the link's.
#[test]
fn a_backup_through_a_link_keeps_the_linked_files_list() {
    let row = "WINACL-B4";
    let dir = everyone_full_dir(row);
    let real = dir.path().join("gateway.yaml");
    std::fs::write(&real, b"admin: secret").unwrap();
    plant_owner_only(row, &real);
    let link = dir.path().join("link.yaml");
    std::os::windows::fs::symlink_file(&real, &link)
        .unwrap_or_else(|e| panic!("WT-FIXTURE {row}: symlink: {e}"));
    let dst = dir.path().join("gateway.yaml.bak");
    super::copy_keeping_access(&link, &dst).unwrap();
    assert_owner_only(row, &dst, false);
    assert_eq!(std::fs::read(&dst).unwrap(), b"admin: secret");
}

/// Table rows for the crate's private-create helpers: each result, made in a
/// folder that hands Everyone full access, is owner-only.
#[test]
fn the_private_create_helpers_make_owner_only_results() {
    let dir = everyone_full_dir("WINACL-T");
    let new = dir.path().join("new-private");
    drop(super::super::create_new_private(&new).unwrap());
    assert_owner_only("WINACL-T1 create_new_private", &new, false);

    let replaced = dir.path().join("replaced-private");
    std::fs::write(&replaced, b"stale").unwrap();
    drop(super::super::create_private_replacing(&replaced).unwrap());
    assert_owner_only("WINACL-T2 create_private_replacing", &replaced, false);

    let sub = dir.path().join("private-dir");
    crate::private_fs::create_dir_private(&sub).unwrap();
    assert_owner_only("WINACL-T3 create_dir_private", &sub, true);
}

/// Table rows for the cross-process lock sidecars: every `fs_lock`
/// constructor leaves an owner-only sidecar, one row each so a constructor
/// that regresses fails on its own. The folder is a plain temporary one,
/// since the lock refuses a folder that hands Everyone write access.
mod lock_sidecars {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use crate::fs_lock::{Attempt, ExclusiveFileLock};
    use crate::private_fs::test_support::assert_owner_only;

    const POLL: Duration = Duration::from_millis(10);

    /// Take the lock at a fresh sidecar with `take`, release it, and check
    /// the sidecar is owner-only.
    fn row(row: &str, take: impl FnOnce(&Path)) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.lock");
        take(&path);
        assert_owner_only(row, &path, false);
    }

    #[test]
    fn try_acquire_makes_an_owner_only_sidecar() {
        row("WINACL-T4 fs_lock try_acquire", |path| {
            drop(ExclusiveFileLock::try_acquire(path).unwrap());
        });
    }

    #[test]
    fn acquire_makes_an_owner_only_sidecar() {
        row("WINACL-T5 fs_lock acquire", |path| {
            drop(ExclusiveFileLock::acquire(path).unwrap());
        });
    }

    #[test]
    fn acquire_until_makes_an_owner_only_sidecar() {
        row("WINACL-T6 fs_lock acquire_until", |path| {
            let deadline = Instant::now() + Duration::from_secs(10);
            drop(ExclusiveFileLock::acquire_until(path, POLL, deadline).unwrap());
        });
    }

    #[test]
    fn try_lease_makes_an_owner_only_sidecar() {
        row(
            "WINACL-T7 fs_lock try_lease",
            |path| match ExclusiveFileLock::try_lease(path).unwrap() {
                Attempt::Taken(lock) => drop(lock),
                Attempt::Held => panic!("WINACL-T7: a fresh sidecar read as held"),
                Attempt::Refused(error) => panic!("WINACL-T7: {error}"),
            },
        );
    }

    #[test]
    fn lease_makes_an_owner_only_sidecar() {
        row("WINACL-T8 fs_lock lease", |path| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            drop(
                runtime
                    .block_on(ExclusiveFileLock::lease(path, POLL, deadline))
                    .unwrap(),
            );
        });
    }
}
