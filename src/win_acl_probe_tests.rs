// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Throwaway probes E1-E6 (design §4). Each prints `PROBE <id> ...` lines and
//! asserts nothing about the outcome it measures; run with `--nocapture`.

use super::*;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::windows::fs::OpenOptionsExt as _;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
};

fn dir_handle(path: &Path, access: u32, share: u32) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[test]
fn e1_directory_flush() {
    let dir = tempfile::tempdir().unwrap();
    for (label, access) in [
        ("rw", GENERIC_READ | GENERIC_WRITE),
        ("w", GENERIC_WRITE),
        ("r", GENERIC_READ),
    ] {
        let r = dir_handle(dir.path(), access, FILE_SHARE_READ | FILE_SHARE_WRITE)
            .and_then(|h| h.sync_all());
        println!("PROBE E1 access={label} sync_all={r:?}");
    }
}

#[test]
fn e2_replace_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let user = current_user_sid().unwrap();
    let dest = dir.path().join("dest.json");
    std::fs::write(&dest, b"old").unwrap();
    let tmp = dir.path().join("tmp.json");
    let mut f = create_file_private(&tmp, &user, Share::Exclusive).unwrap();
    f.write_all(b"new").unwrap();
    f.sync_all().unwrap();
    drop(f);
    let reader = File::open(&dest).unwrap();
    println!("PROBE E2b replace_over_open_reader={:?}", replace(&tmp, &dest));
    drop(reader);
    println!("PROBE E2 replace_after_reader_closed={:?}", replace(&tmp, &dest));
    println!("PROBE E2 dest_contents={:?}", std::fs::read(&dest));
    std::fs::write(&tmp, b"std").unwrap();
    let reader = File::open(&dest).unwrap();
    println!("PROBE E2 std_rename_over_open_reader={:?}", std::fs::rename(&tmp, &dest));
    drop(reader);
}

#[test]
fn e3_owner_on_creation() {
    let dir = tempfile::tempdir().unwrap();
    let user = current_user_sid().unwrap();
    println!("PROBE E3 user={}", user.to_sddl());
    let std_file = dir.path().join("std.txt");
    std::fs::write(&std_file, b"x").unwrap();
    let h = OpenOptions::new().access_mode(READ_CONTROL).open(&std_file).unwrap();
    let i = inspect(&h).unwrap();
    println!(
        "PROBE E3 std_default owner={:?} protected={} aces={:?}",
        i.owner.as_ref().map(Sid::to_sddl),
        i.protected,
        i.dacl.as_ref().map(Vec::len)
    );
    let ours = dir.path().join("ours.txt");
    let f = create_file_private(&ours, &user, Share::Exclusive);
    println!("PROBE E3 create_file_private={:?}", f.as_ref().map(|_| ()));
    if let Ok(f) = f {
        let i = inspect(&f).unwrap();
        println!(
            "PROBE E3 private owner={:?} protected={} dacl={:?}",
            i.owner.as_ref().map(Sid::to_sddl),
            i.protected,
            i.dacl
        );
    }
    let d = dir.path().join("dir");
    println!("PROBE E3 create_dir_private={:?}", create_dir_private(&d, &user));
    let h = dir_handle(&d, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE);
    if let Ok(h) = h {
        let i = inspect(&h).unwrap();
        println!("PROBE E3 dir owner_is_user={} protected={} dacl={:?}", i.owner == Some(user.clone()), i.protected, i.dacl);
    }
}

#[test]
fn e4_try_lock() {
    let dir = tempfile::tempdir().unwrap();
    let user = current_user_sid().unwrap();
    let p = dir.path().join(".lock");
    let a = create_file_private(&p, &user, Share::LockSidecar).unwrap();
    println!("PROBE E4 first_try_lock={:?}", a.try_lock());
    let b = OpenOptions::new()
        .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&p);
    println!("PROBE E4 second_open={:?}", b.as_ref().map(|_| ()));
    if let Ok(b) = b {
        println!("PROBE E4 second_try_lock={:?}", b.try_lock());
        drop(a);
        println!("PROBE E4 after_first_dropped={:?}", b.try_lock());
    }
}

/// Needs `MGW_NET_ROOT` (a directory on a `net use` drive); the CI step sets it.
#[test]
#[ignore = "needs a mapped network drive"]
fn e5_network_drive() {
    let root = std::env::var("MGW_NET_ROOT").unwrap();
    let h = dir_handle(Path::new(&root), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE);
    match h {
        Ok(h) => println!(
            "PROBE E5 final_path={:?} volume_is_local={:?}",
            final_path(&h),
            volume_is_local(&h)
        ),
        Err(e) => println!("PROBE E5 open={e:?}"),
    }
    let local = tempfile::tempdir().unwrap();
    let h = dir_handle(local.path(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE).unwrap();
    println!("PROBE E5 local volume_is_local={:?}", volume_is_local(&h));
}

#[test]
fn e6_held_directory_pins_path() {
    for (label, access) in [
        ("list", READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY),
        ("meta_only", READ_CONTROL | FILE_READ_ATTRIBUTES),
    ] {
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join("a");
        let b = a.join("b");
        let store = b.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let held = dir_handle(&store, access, FILE_SHARE_READ | FILE_SHARE_WRITE).unwrap();
        println!("PROBE E6 {label} rename_store={:?}", std::fs::rename(&store, b.join("s2")));
        println!("PROBE E6 {label} rename_parent={:?}", std::fs::rename(&b, a.join("b2")));
        println!("PROBE E6 {label} rename_grandparent={:?}", std::fs::rename(&a, root.path().join("a2")));
        println!("PROBE E6 {label} identity={:?}", file_identity(&held));
        drop(held);
    }
}
