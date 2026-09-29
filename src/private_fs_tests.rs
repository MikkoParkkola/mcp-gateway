// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Handle-level rows of the Windows owner-only test plan. Each decisive
//! assertion starts `WT-ASSERT <row>`; each fixture failure `WT-FIXTURE <row>`.

use super::test_support::{assert_owner_only, icacls, plant_sddl, user_sid};
use super::*;
use std::io::Write as _;

fn judge_path(path: &Path) -> Result<(), PrivacyRefusal> {
    let file = open_file_read(path).expect("fixture file opens");
    judge_file(&file)
}

fn private_file_in(dir: &Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut f = create_file_private(&path, Share::Exclusive).expect("create");
    f.write_all(b"{}").expect("write");
    path
}

// W-T1 (handle level): what `private_fs` creates is owner-only, read back by
// PowerShell, not by `win_acl`.
#[test]
fn wt1_created_objects_carry_only_the_user_ace() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("store");
    create_dir_private(&dir).unwrap();
    let file = private_file_in(&dir, "record.json");
    assert_owner_only("W-T1/dir", &dir, true);
    assert_owner_only("W-T1/file", &file, false);
}

// W-T1b: private at the instant of creation. Files are read from the live,
// unshared handle; directories by path.
#[test]
fn wt1b_objects_are_private_at_the_instant_of_creation() {
    use std::sync::Mutex;
    static SEEN: Mutex<Vec<(String, Option<crate::win_acl::Inspection>)>> = Mutex::new(Vec::new());
    fn record(path: &Path, file: Option<&File>) {
        let inspection = file.map(|f| crate::win_acl::inspect(f).expect("inspect live handle"));
        SEEN.lock()
            .unwrap()
            .push((path.display().to_string(), inspection));
    }
    let root = tempfile::tempdir().unwrap();
    crate::win_acl::AFTER_CREATE.with(|h| h.set(Some(record)));
    let dir = root.path().join("store");
    create_dir_private(&dir).unwrap();
    let dir_sddl = super::test_support::read_sddl("W-T1b", &dir);
    let _file = private_file_in(&dir, "record.json");
    crate::win_acl::AFTER_CREATE.with(|h| h.set(None));
    let seen = std::mem::take(&mut *SEEN.lock().unwrap());
    assert_eq!(
        seen.len(),
        2,
        "WT-FIXTURE W-T1b: the creation hook fired {} times",
        seen.len()
    );
    let parsed = super::test_support::parse_sddl(&dir_sddl);
    assert!(
        parsed.protected && parsed.aces.len() == 1,
        "WT-ASSERT W-T1b/dir: at creation the directory carried {dir_sddl}"
    );
    let file_view = seen[1].1.as_ref().expect("file hook carries its handle");
    let user = crate::win_acl::current_user_sid().unwrap();
    assert!(
        file_view.owner.as_ref() == Some(&user)
            && file_view.protected
            && matches!(file_view.dacl.as_deref(), Some([crate::win_acl::Ace::Allowed { sid, .. }]) if *sid == user),
        "WT-ASSERT W-T1b/file: at creation the file carried {file_view:?}"
    );
}

// W-T2: a foreign allow ACE on a store directory.
#[test]
fn wt2_foreign_ace_on_store_dir_refuses() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("store");
    create_dir_private(&dir).unwrap();
    icacls("W-T2", &dir, &["/grant", "*S-1-1-0:R"]);
    let handle = open_dir(&dir).unwrap();
    assert_eq!(
        judge_dir(&handle, &dir),
        Err(PrivacyRefusal::ForeignSid("S-1-1-0".into())),
        "WT-ASSERT W-T2"
    );
}

// W-T3: an inheriting directory, under a parent that grants only the user, so
// inheritance adds no foreign SID and only P5 can fail.
#[test]
fn wt3_inherited_ace_on_store_dir_refuses() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    let user = user_sid();
    plant_sddl(
        "W-T3",
        &parent,
        &format!("O:{user}D:P(A;OICI;FA;;;{user})"),
        &format!("O:{user}D:P(A;OICI;FA;;;{user})"),
    );
    let dir = parent.join("store");
    create_dir_private(&dir).unwrap();
    icacls("W-T3", &dir, &["/inheritance:e"]);
    let handle = open_dir(&dir).unwrap();
    assert_eq!(
        judge_dir(&handle, &dir),
        Err(PrivacyRefusal::NotProtected),
        "WT-ASSERT W-T3"
    );
}

/// Plant `sddl` on a fresh file and return the judge's verdict. The literal is
/// read back first, so a plant Windows altered fails as a fixture error.
fn judged_after_plant(row: &str, sddl: &str, back: &str) -> Result<(), PrivacyRefusal> {
    let root = tempfile::tempdir().unwrap();
    let file = private_file_in(root.path(), "record.json");
    plant_sddl(row, &file, sddl, back);
    judge_path(&file)
}

// W-T8: a protected NULL DACL. Also fails P3; the reason must be NullDacl.
#[test]
fn wt8_null_dacl_refuses() {
    let user = user_sid();
    let sddl = format!("O:{user}D:PNO_ACCESS_CONTROL");
    let got = judged_after_plant("W-T8", &sddl, &sddl);
    assert_eq!(got, Err(PrivacyRefusal::NullDacl), "WT-ASSERT W-T8");
}

// W-T8b: only P3 fails (protected, one user ACE, owner = user, read only).
#[test]
fn wt8b_read_only_ace_refuses() {
    let user = user_sid();
    let sddl = format!("O:{user}D:P(A;;FR;;;{user})");
    let got = judged_after_plant("W-T8b", &sddl, &sddl);
    assert_eq!(got, Err(PrivacyRefusal::NoReadWrite), "WT-ASSERT W-T8b");
}

// W-T8c: an inherit-only grant applies to children only, so it does not
// satisfy P3 on the object itself.
#[test]
fn wt8c_inherit_only_grant_refuses() {
    let user = user_sid();
    let sddl = format!("O:{user}D:P(A;IO;FA;;;{user})(A;;FR;;;{user})");
    let got = judged_after_plant("W-T8c", &sddl, &sddl);
    assert_eq!(got, Err(PrivacyRefusal::NoReadWrite), "WT-ASSERT W-T8c");
}

// W-T8d: a deny naming the user that takes away write data fails P3. Only
// FILE_WRITE_DATA is denied, so the fixture's own read open still works.
#[test]
fn wt8d_user_deny_refuses() {
    let user = user_sid();
    let sddl = format!("O:{user}D:P(D;;0x2;;;{user})(A;;FA;;;{user})");
    let root = tempfile::tempdir().unwrap();
    let file = private_file_in(root.path(), "record.json");
    // The read-back spells 0x2 as an alias, so require only that a deny for
    // the user survived the plant.
    let back = super::test_support::plant_any("W-T8d", &file, &sddl);
    if !back.contains("(D;;") || !back.contains(&user) {
        super::test_support::fixture_fail("W-T8d", &format!("planted {sddl}, read back {back}"));
    }
    assert_eq!(
        judge_path(&file),
        Err(PrivacyRefusal::NoReadWrite),
        "WT-ASSERT W-T8d: {back}"
    );
}

// W-T8e: a deny that applies to children only takes nothing away (accept
// side of P3). A generic grant cannot be planted: Windows maps GENERIC_*
// rights to specific ones when it stores the ACE.
#[test]
fn wt8e_inherit_only_deny_accepted() {
    let user = user_sid();
    let sddl = format!("O:{user}D:P(D;IO;FA;;;{user})(A;;FA;;;{user})");
    let root = tempfile::tempdir().unwrap();
    let file = private_file_in(root.path(), "record.json");
    let back = super::test_support::plant_any("W-T8e", &file, &sddl);
    // The row only proves something if Windows kept the inherit-only deny.
    if !back.contains("(D;IO;") {
        super::test_support::fixture_fail("W-T8e", &format!("planted {sddl}, read back {back}"));
    }
    assert_eq!(judge_path(&file), Ok(()), "WT-ASSERT W-T8e: {back}");
}

// W-T11: only P4 fails (owner BUILTIN\Administrators).
#[test]
fn wt11_foreign_owner_refuses() {
    let user = user_sid();
    let sddl = format!("O:BAD:P(A;;FA;;;{user})");
    let got = judged_after_plant("W-T11", &sddl, &sddl);
    assert_eq!(
        got,
        Err(PrivacyRefusal::ForeignOwner("S-1-5-32-544".into())),
        "WT-ASSERT W-T11"
    );
}

// W-T13: only P5 fails (one user ACE, owner = user, not protected, nothing to
// inherit because the source directory inherits nothing).
#[test]
fn wt13_moved_in_unprotected_file_refuses() {
    let user = user_sid();
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    plant_sddl(
        "W-T13",
        &source,
        &format!("O:{user}D:P(A;;FA;;;{user})"),
        &format!("O:{user}D:P(A;;FA;;;{user})"),
    );
    let store = root.path().join("store");
    create_dir_private(&store).unwrap();
    let file = private_file_in(&source, "record.json");
    let sddl = format!("O:{user}D:(A;;FA;;;{user})");
    plant_sddl("W-T13", &file, &sddl, &sddl);
    let moved = store.join("record.json");
    std::fs::rename(&file, &moved).unwrap();
    assert_eq!(
        judge_path(&moved),
        Err(PrivacyRefusal::NotProtected),
        "WT-ASSERT W-T13"
    );
}

// W-T19: a conditional (callback) ACE beside the user's; every other rule holds.
#[test]
fn wt19_other_ace_type_refuses() {
    let user = user_sid();
    let sddl = format!("O:{user}D:P(A;;FA;;;{user})(XA;;FR;;;WD;(Member_of {{SID(BA)}}))");
    let root = tempfile::tempdir().unwrap();
    let file = private_file_in(root.path(), "record.json");
    // `Set-Acl` normalises the condition text, so only the type is re-checked.
    let back = super::test_support::plant_any("W-T19", &file, &sddl);
    if !back.contains("(XA;") {
        super::test_support::fixture_fail("W-T19", &format!("no callback ACE after plant: {back}"));
    }
    assert!(
        matches!(judge_path(&file), Err(PrivacyRefusal::OtherAceType(_))),
        "WT-ASSERT W-T19"
    );
}

// W-T21: a deny ACE for a group the runner is not in is accepted.
#[test]
fn wt21_foreign_deny_ace_is_accepted() {
    let groups = std::process::Command::new("whoami")
        .arg("/groups")
        .output()
        .unwrap();
    if String::from_utf8_lossy(&groups.stdout).contains("S-1-5-32-546") {
        super::test_support::fixture_fail("W-T21", "runner token contains Guests");
    }
    let user = user_sid();
    let sddl = format!("O:{user}D:P(D;;FA;;;S-1-5-32-546)(A;;FA;;;{user})");
    let got = judged_after_plant("W-T21", &sddl, &sddl);
    assert_eq!(got, Ok(()), "WT-ASSERT W-T21");
}

// W-T16a: a held store directory, alone, blocks its own rename (probe E6: 32);
// released, the same rename succeeds.
#[test]
fn wt16a_held_directory_blocks_its_own_rename() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("store");
    create_dir_private(&dir).unwrap();
    let held = open_dir(&dir).unwrap();
    let before = crate::win_acl::file_identity(&held).unwrap();
    let moved = root.path().join("moved");
    let err = std::fs::rename(&dir, &moved).err();
    assert_eq!(
        err.as_ref().and_then(std::io::Error::raw_os_error),
        Some(32),
        "WT-ASSERT W-T16a: rename of a held store directory gave {err:?}"
    );
    assert_eq!(
        crate::win_acl::file_identity(&held).unwrap(),
        before,
        "WT-ASSERT W-T16a: identity"
    );
    drop(held);
    std::fs::rename(&dir, &moved).unwrap_or_else(|e| {
        super::test_support::fixture_fail("W-T16a", &format!("control rename failed: {e}"))
    });
}

// W-T22b: a real flush needs write access, so it fails on a read-only handle;
// a no-op flush would not.
#[test]
fn wt22b_sync_file_really_flushes() {
    let root = tempfile::tempdir().unwrap();
    let path = private_file_in(root.path(), "record.json");
    let read_only = open_file_read(&path).unwrap();
    assert!(
        sync_file(&read_only).is_err(),
        "WT-ASSERT W-T22b: flush succeeded read-only"
    );
}

// W-T23: a directory at a record name opens (backup semantics) and is refused
// as NotRegular, not as a raw open error.
#[test]
fn wt23_directory_at_record_name_refuses() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("record.json");
    create_dir_private(&dir).unwrap();
    let opened = open_file_read(&dir);
    assert!(
        opened.is_ok(),
        "WT-ASSERT W-T23: directory did not open: {opened:?}"
    );
    assert_eq!(
        judge_file(&opened.unwrap()),
        Err(PrivacyRefusal::NotRegular),
        "WT-ASSERT W-T23"
    );
}

// W-T25: creation refuses an existing name and leaves the object untouched.
#[test]
fn wt25_create_refuses_an_existing_name() {
    let root = tempfile::tempdir().unwrap();
    let path = private_file_in(root.path(), "record.json");
    let id_before = crate::win_acl::file_identity(&File::open(&path).unwrap()).unwrap();
    let again = create_file_private(&path, Share::Exclusive);
    assert_eq!(
        again.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::AlreadyExists),
        "WT-ASSERT W-T25"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"{}",
        "WT-ASSERT W-T25: content changed"
    );
    let id_after = crate::win_acl::file_identity(&File::open(&path).unwrap()).unwrap();
    assert_eq!(id_before, id_after, "WT-ASSERT W-T25: identity changed");
    let dir = root.path().join("dir");
    std::fs::create_dir(&dir).unwrap();
    assert_eq!(
        create_dir_private(&dir).err().map(|e| e.kind()),
        Some(std::io::ErrorKind::AlreadyExists),
        "WT-ASSERT W-T25: directory"
    );
}

/// Rows that need the privileged CI step (a mapped drive, FAT32/exFAT volumes).
/// Run with `--ignored win_privileged::`.
mod win_privileged {
    use super::*;

    fn root_from(var: &str, row: &str) -> std::path::PathBuf {
        std::env::var(var).map_or_else(
            |_| super::super::test_support::fixture_fail(row, &format!("{var} unset")),
            std::path::PathBuf::from,
        )
    }

    // W-T12: a network drive letter is not local.
    #[test]
    #[ignore = "needs the privileged CI step"]
    fn wt12_mapped_network_drive_refuses() {
        let root = root_from("MGW_NET_ROOT", "W-T12");
        let handle = open_dir(&root).unwrap();
        assert!(
            !crate::win_acl::volume_is_local(&handle).unwrap(),
            "WT-ASSERT W-T12"
        );
        assert_eq!(
            judge_dir(&handle, &root),
            Err(PrivacyRefusal::NotLocal),
            "WT-ASSERT W-T12/judge"
        );
    }

    // W-T15: volumes that keep no ACLs are refused.
    #[test]
    #[ignore = "needs the privileged CI step"]
    fn wt15_fat32_volume_refuses() {
        let root = root_from("MGW_FAT32_ROOT", "W-T15/fat32");
        let handle = open_dir(&root).unwrap();
        assert!(
            !crate::win_acl::volume_is_local(&handle).unwrap(),
            "WT-ASSERT W-T15/fat32"
        );
        assert_eq!(
            judge_dir(&handle, &root),
            Err(PrivacyRefusal::NotLocal),
            "WT-ASSERT W-T15/fat32/judge"
        );
    }

    #[test]
    #[ignore = "needs the privileged CI step"]
    fn wt15_exfat_volume_refuses() {
        let root = root_from("MGW_EXFAT_ROOT", "W-T15/exfat");
        let handle = open_dir(&root).unwrap();
        assert!(
            !crate::win_acl::volume_is_local(&handle).unwrap(),
            "WT-ASSERT W-T15/exfat"
        );
        assert_eq!(
            judge_dir(&handle, &root),
            Err(PrivacyRefusal::NotLocal),
            "WT-ASSERT W-T15/exfat/judge"
        );
    }

    // W-T15c: the shared private create refuses a volume that drops ACLs and
    // leaves no file behind, so no caller can write a secret there.
    #[test]
    #[ignore = "needs the privileged CI step"]
    fn wt15c_private_create_refuses_volumes_without_acls() {
        for (var, row) in [
            ("MGW_FAT32_ROOT", "W-T15c/fat32"),
            ("MGW_EXFAT_ROOT", "W-T15c/exfat"),
        ] {
            let path = root_from(var, row).join("mgw-private-create.key");
            let Err(err) = crate::config_persistence::create_new_private(&path) else {
                panic!("WT-ASSERT {row}: created on a volume without ACLs");
            };
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "WT-ASSERT {row}: {err}"
            );
            assert!(!path.exists(), "WT-ASSERT {row}: refused file left behind");
        }
    }
}

// W-T15d/e: a create the volume check refuses leaves no file behind. The
// check's answer is forced (the hook runs at the refusal, before cleanup), so
// these run unprivileged on NTFS; the real FAT and exFAT volumes are W-T15c.
fn refuse_create(path: &Path, share: Share, hook: fn(&Path)) -> io::Error {
    crate::win_acl::NO_ACLS.with(|forced| forced.set(Some(hook)));
    let result = create_file_private(path, share);
    crate::win_acl::NO_ACLS.with(|forced| forced.set(None));
    let err = result.expect_err("WT-ASSERT W-T15d: created on a volume without ACLs");
    assert_eq!(
        err.kind(),
        io::ErrorKind::PermissionDenied,
        "WT-ASSERT W-T15d: {err}"
    );
    err
}

fn gone(path: &Path) -> bool {
    matches!(std::fs::metadata(path), Err(e) if e.kind() == io::ErrorKind::NotFound)
}

fn open_shared(path: &Path, share: u32) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(share)
        .open(path)
}

thread_local! {
    static HELD: std::cell::RefCell<Option<File>> = const { std::cell::RefCell::new(None) };
}

// W-T15d: an unshared create is deleted through its own handle, which no
// other opener can join, even one that shares everything.
#[test]
fn wt15d_refused_private_create_leaves_no_file() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("refused.key");
    let err = refuse_create(&path, Share::Exclusive, |path| {
        let joined =
            open_shared(path, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).map(drop);
        assert_eq!(
            joined.as_ref().err().and_then(io::Error::raw_os_error),
            Some(32),
            "WT-ASSERT W-T15d: another opener joined the refused handle"
        );
    });
    assert!(
        !err.to_string().contains("could not be removed"),
        "WT-ASSERT W-T15d: {err}"
    );
    assert!(gone(&path), "WT-ASSERT W-T15d: refused file left behind");
}

// W-T15f: between the release of the creating handle and the delete, nobody
// can open the refused file. Fails if the exclusive cleanup reverts to
// `drop(file); remove_file(path)`, whose window a full-sharing opener joins.
#[test]
fn wt15f_refused_exclusive_file_cannot_be_joined_before_its_delete() {
    fn join(path: &Path) {
        let joined =
            open_shared(path, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).map(drop);
        assert_eq!(
            joined.as_ref().err().and_then(io::Error::raw_os_error),
            Some(32),
            "WT-ASSERT W-T15f: another opener joined the refused file before its delete"
        );
    }
    /// Clears the hook even when an assertion inside it panics, so it never
    /// leaks into the next test on this thread.
    struct Installed;
    impl Drop for Installed {
        fn drop(&mut self) {
            crate::win_acl::BEFORE_DELETE.with(|hook| hook.set(None));
        }
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("refused.key");
    crate::win_acl::BEFORE_DELETE.with(|hook| hook.set(Some(join)));
    let installed = Installed;
    let err = refuse_create(&path, Share::Exclusive, |_| {});
    drop(installed);
    assert!(
        !err.to_string().contains("could not be removed"),
        "WT-ASSERT W-T15f: {err}"
    );
    assert!(gone(&path), "WT-ASSERT W-T15f: refused file left behind");
}

// W-T15e: a sidecar create is deleted by a DELETE reopen; a reader holding it
// without delete sharing makes that fail, and the failure is reported.
#[test]
fn wt15e_refused_sidecar_is_removed_or_reported() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("refused.lock");
    refuse_create(&path, Share::LockSidecar, |_| {});
    assert!(gone(&path), "WT-ASSERT W-T15e: refused sidecar left behind");
    let err = refuse_create(&path, Share::LockSidecar, |path| {
        let held = open_shared(path, FILE_SHARE_READ | FILE_SHARE_WRITE)
            .expect("WT-FIXTURE W-T15e: a sharing reader opens");
        HELD.with(|slot| *slot.borrow_mut() = Some(held));
    });
    HELD.with(|slot| drop(slot.borrow_mut().take()));
    assert!(
        err.to_string()
            .contains("the empty file could not be removed"),
        "WT-ASSERT W-T15e: a failed removal was not reported: {err}"
    );
}

// #2305: a device handle is refused as not regular, for both classes and by
// the store judge, before any attribute or DACL is read.
#[test]
fn device_handle_refuses_as_not_regular() {
    let nul = File::open("NUL").expect("WT-FIXTURE #2305: NUL opens");
    for what in [
        crate::config::Protects::Secrecy,
        crate::config::Protects::Integrity,
    ] {
        assert_eq!(
            file_refusals_for(&nul, what),
            vec![PrivacyRefusal::NotRegular],
            "WT-ASSERT #2305/{what:?}"
        );
    }
    assert_eq!(
        judge_file(&nul),
        Err(PrivacyRefusal::NotRegular),
        "WT-ASSERT #2305/judge"
    );
}

// W-T6: a symlink at a record name is judged as a reparse point on the handle
// the no-follow open returns. Skips (with a marker) where symlink creation
// needs a privilege the runner lacks; junctions cover the rule in W-T5.
#[test]
fn wt6_symlink_record_refuses() {
    let root = tempfile::tempdir().unwrap();
    let target = private_file_in(root.path(), "target.json");
    let link = root.path().join("record.json");
    if std::os::windows::fs::symlink_file(&target, &link).is_err() {
        println!("WT-SKIP W-T6: symlink creation is not permitted here");
        return;
    }
    let handle = open_file_read(&link).expect("a no-follow open of a symlink succeeds");
    assert_eq!(
        judge_file(&handle),
        Err(PrivacyRefusal::ReparsePoint),
        "WT-ASSERT W-T6"
    );
}

// W-T27: a store path past MAX_PATH works through each Win32 call, as it does
// through `std::fs`. Each call runs on its own std-made fixture, so a failure
// names every call that refused.
#[test]
fn wt27_long_path_reaches_every_win32_call() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("d".repeat(150)).join("e".repeat(150));
    std::fs::create_dir_all(&base).expect("WT-FIXTURE W-T27: std creates long parents");
    std::fs::write(base.join("staged.json"), b"{}").expect("WT-FIXTURE W-T27: std writes");
    let moved = base.join("moved.json");
    let failed: Vec<String> = [
        (
            "CreateDirectoryW",
            create_dir_private(&base.join("store")).err(),
        ),
        (
            "CreateFileW",
            create_file_private(&base.join("record.json"), Share::Exclusive).err(),
        ),
        (
            "MoveFileExW",
            replace(base.join("staged.json"), &moved).err(),
        ),
    ]
    .into_iter()
    .filter_map(|(call, error)| error.map(|e| format!("{call}: {e}")))
    .collect();
    assert!(failed.is_empty(), "WT-ASSERT W-T27: {failed:?}");
    assert_eq!(std::fs::read(&moved).unwrap(), b"{}", "WT-ASSERT W-T27");
}
