// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows: every lock constructor (`acquire`, `try_lease`, `lease`,
//! `acquire_until`) creates its sidecar owner-only, replaces an existing one
//! another account could open only when nothing holds it, refuses one it
//! cannot replace at the caller's deadline, and refuses a lock directory
//! another account could plant a sidecar in. `try_acquire` is not one of
//! them and is covered by its own rows.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{Attempt, ExclusiveFileLock};
use crate::private_fs::test_support::{assert_owner_only, plant_any, plant_sddl, user_sid};

const CONSTRUCTORS: [&str; 4] = ["acquire", "try_lease", "lease", "acquire_until"];

/// Take the lock through `how`; a refused or held lock is an error here
/// (`try_lease` maps `Held` to `WouldBlock`, `Refused` to its error).
fn take(how: &str, path: &Path) -> io::Result<ExclusiveFileLock> {
    let wait = Duration::from_millis(300);
    match how {
        "acquire" => ExclusiveFileLock::acquire(path),
        "try_lease" => match ExclusiveFileLock::try_lease(path)? {
            Attempt::Taken(lock) => Ok(lock),
            Attempt::Held => Err(io::ErrorKind::WouldBlock.into()),
            Attempt::Refused(error) => Err(error),
        },
        "lease" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime");
            let deadline = tokio::time::Instant::now() + wait;
            runtime.block_on(ExclusiveFileLock::lease(
                path,
                Duration::from_millis(10),
                deadline,
            ))
        }
        "acquire_until" => {
            ExclusiveFileLock::acquire_until(path, Duration::from_millis(10), Instant::now() + wait)
        }
        other => unreachable!("{other}"),
    }
}

/// A sidecar file Everyone may open: what an older build left behind when
/// its directory's ACL was inherited, or what another account planted.
fn plant_open_sidecar(row: &str, path: &Path) {
    std::fs::write(path, b"").expect("plant");
    let user = user_sid();
    let planted = plant_any(row, path, &format!("O:{user}D:(A;;FA;;;WD)"));
    assert!(
        planted.contains("S-1-1-0"),
        "{row}: Everyone planted: {planted}"
    );
}

/// A holder the way an older build opened the sidecar: std `OpenOptions`
/// (read, write and delete sharing), locked.
fn legacy_holder(path: &Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("legacy open");
    file.try_lock().expect("legacy lock");
    file
}

#[test]
fn every_constructor_creates_an_owner_only_sidecar() {
    for how in CONSTRUCTORS {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(".store.lock");
        drop(take(how, &path).expect(how));
        assert_owner_only(how, &path, false);
    }
}

#[test]
fn every_constructor_replaces_an_existing_sidecar_others_can_open() {
    for how in CONSTRUCTORS {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(".store.lock");
        plant_open_sidecar(how, &path);
        drop(take(how, &path).expect(how));
        assert_owner_only(how, &path, false);
    }
}

/// A sidecar whose DACL denies this account data access, in a directory the
/// account may delete from, is replaced too.
#[test]
fn a_sidecar_denying_the_user_data_access_is_replaced() {
    for how in CONSTRUCTORS {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(".store.lock");
        std::fs::write(&path, b"").expect("plant");
        let user = user_sid();
        // Read and write data denied, SYNCHRONIZE left: the replacement's open
        // asks for delete (through the folder) and SYNCHRONIZE only.
        let sddl = format!("O:{user}D:P(D;;0x3;;;{user})(A;;FA;;;{user})");
        plant_any(how, &path, &sddl);
        drop(take(how, &path).expect(how));
        assert_owner_only(how, &path, false);
    }
}

/// Item 3 (refusal mapping): an older build still holds the non-private
/// sidecar. Deleting it by name would split the lock, so it is left in
/// place: `try_lease` says `Refused`; the waiting constructors refuse at
/// their deadline with `PermissionDenied` naming the path and the rule, and
/// never advise deleting a file something holds. Once the holder is gone the
/// next attempt replaces it.
#[test]
fn a_sidecar_an_older_build_holds_is_not_deleted_and_is_refused_at_the_deadline() {
    for how in CONSTRUCTORS {
        if how == "acquire" {
            continue; // its 30 s heal bound has its own row
        }
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(".store.lock");
        plant_open_sidecar(how, &path);
        std::fs::write(&path, b"held").expect("marker");
        let holder = legacy_holder(&path);
        let error = take(how, &path).err().expect("refused while held");
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "{how}: {error}"
        );
        let text = error.to_string();
        assert!(text.contains(&path.display().to_string()), "{how}: {text}");
        assert!(!text.to_lowercase().contains("delete"), "{how}: {text}");
        assert_eq!(
            std::fs::metadata(&path).expect("still there").len(),
            4,
            "{how}"
        );
        drop(holder);
        drop(take(how, &path).expect("replaced once free"));
        assert_owner_only(how, &path, false);
    }
}

/// A private sidecar another handle holds is plain contention: `Held`, and
/// `TimedOut` at a deadline, never a refusal.
#[test]
fn a_private_sidecar_held_elsewhere_is_contention() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join(".store.lock");
    let _holder = ExclusiveFileLock::acquire(&path).expect("holder");
    assert!(matches!(
        ExclusiveFileLock::try_lease(&path).expect("probe"),
        Attempt::Held
    ));
    for how in ["lease", "acquire_until"] {
        let error = take(how, &path).err().expect("held");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{how}: {error}");
    }
}

/// Eight threads healing one non-private sidecar at once all take the lock,
/// one at a time, and leave an owner-only sidecar.
#[test]
fn concurrent_healers_serialize_and_leave_an_owner_only_sidecar() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().expect("dir");
    let path = Arc::new(dir.path().join(".store.lock"));
    plant_open_sidecar("healers", &path);
    let inside = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (path, inside, most, done, barrier) = (
                Arc::clone(&path),
                Arc::clone(&inside),
                Arc::clone(&most),
                Arc::clone(&done),
                Arc::clone(&barrier),
            );
            std::thread::spawn(move || {
                barrier.wait();
                let _lock = ExclusiveFileLock::acquire(&path).expect("healer");
                let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                // timing: fixture
                std::thread::sleep(Duration::from_millis(5));
                inside.fetch_sub(1, Ordering::SeqCst);
                done.fetch_add(1, Ordering::SeqCst);
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("join");
    }
    assert_eq!(done.load(Ordering::SeqCst), 8, "every healer took the lock");
    assert_eq!(most.load(Ordering::SeqCst), 1, "never two inside");
    assert_owner_only("healers", &path, false);
}

/// Item 1: a lock directory Everyone (or a specific foreign account) could
/// plant a sidecar in, or that cannot be judged, is refused by every
/// constructor with `PermissionDenied` naming the directory, and no command
/// in the text.
#[test]
fn a_lock_directory_others_can_write_is_refused() {
    let user = user_sid();
    let profile = format!("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})");
    let cases = [
        ("null DACL", format!("O:{user}D:NO_ACCESS_CONTROL")),
        (
            "everyone modify",
            format!("O:{user}D:P{profile}(A;OICI;0x1301bf;;;WD)"),
        ),
        (
            "delete-child only",
            format!("O:{user}D:P{profile}(A;;0x100040;;;WD)"),
        ),
        (
            "object ACE",
            format!("O:{user}D:P{profile}(OA;;FA;00000000-0000-0000-0000-000000000001;;WD)"),
        ),
    ];
    for (case, sddl) in cases {
        for how in CONSTRUCTORS {
            let row = format!("{case}/{how}");
            let parent = tempfile::tempdir().expect("dir");
            let dir = parent.path().join("store");
            std::fs::create_dir(&dir).expect("store dir");
            plant_any(&row, &dir, &sddl);
            let error = take(how, &dir.join(".store.lock"))
                .err()
                .unwrap_or_else(|| panic!("{row}: a writable lock directory was accepted"));
            assert_eq!(
                error.kind(),
                io::ErrorKind::PermissionDenied,
                "{row}: {error}"
            );
            let text = error.to_string();
            assert!(text.contains(&dir.display().to_string()), "{row}: {text}");
            assert!(!text.contains("icacls"), "{row}: {text}");
        }
    }
}

/// The default profile-folder shape (user, SYSTEM, Administrators, all
/// inherited to children) is accepted: the vault lock lives directly in the
/// home folder.
#[test]
fn the_default_profile_folder_shape_is_accepted() {
    let user = user_sid();
    // Numeric SIDs: SYSTEM and Administrators read back numerically.
    let sddl =
        format!("O:{user}D:P(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;{user})");
    for how in CONSTRUCTORS {
        let parent = tempfile::tempdir().expect("dir");
        let dir = parent.path().join("home");
        std::fs::create_dir(&dir).expect("home dir");
        plant_sddl(how, &dir, &sddl, &sddl);
        drop(take(how, &dir.join(".mcp-gateway-secrets.lock")).expect(how));
    }
}

/// Item 5: a junction among the lock path's ancestors is refused, naming the
/// directory, as a store directory behind a link is.
#[test]
fn a_lock_behind_a_junction_is_refused() {
    let parent = tempfile::tempdir().expect("dir");
    let target = parent.path().join("real");
    std::fs::create_dir(&target).expect("target");
    let link = parent.path().join("jx");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .expect("mklink");
    assert!(made.status.success(), "junction: {made:?}");
    for how in CONSTRUCTORS {
        let error = take(how, &link.join(".store.lock"))
            .err()
            .unwrap_or_else(|| panic!("{how}: a lock behind a junction was accepted"));
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "{how}: {error}"
        );
        assert!(
            error
                .to_string()
                .contains("is a link, or a link sits in its path"),
            "{how}: {error}"
        );
    }
}

/// Item 2: `acquire` blocks only on a sidecar it judged. While an older
/// build holds a non-private sidecar, `acquire` waits in its heal phase
/// instead of locking that file; once the holder is gone it replaces the file
/// and takes the lock on the owner-only one.
#[test]
fn acquire_never_blocks_on_an_unjudged_sidecar() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join(".store.lock");
    plant_open_sidecar("acquire", &path);
    let holder = legacy_holder(&path);
    let waiter = {
        let path = path.clone();
        std::thread::spawn(move || ExclusiveFileLock::acquire(&path))
    };
    // timing: precondition
    std::thread::sleep(Duration::from_millis(300));
    drop(holder);
    let lock = waiter.join().expect("join").expect("acquired once free");
    assert_owner_only("acquire", &path, false);
    drop(lock);
}

/// Item 3 (race mapping): another healer replaces the sidecar and takes the
/// lock between this probe's judgement and its replacement attempt. This
/// probe then meets an owner-only file held elsewhere: `Held`, not `Refused`.
#[test]
fn a_healer_that_loses_the_race_reads_held() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join(".store.lock");
    plant_open_sidecar("race", &path);
    let winner: Rc<RefCell<Option<ExclusiveFileLock>>> = Rc::default();
    let (kept, at) = (Rc::clone(&winner), path.clone());
    super::windows::after_judge_once(move || {
        std::fs::remove_file(&at).expect("nothing holds the original");
        *kept.borrow_mut() = Some(ExclusiveFileLock::acquire(&at).expect("the winner"));
    });
    assert!(matches!(
        ExclusiveFileLock::try_lease(&path).expect("probe"),
        Attempt::Held
    ));
    assert!(winner.borrow().is_some(), "the seam ran");
    assert_owner_only("race", &path, false);
}

/// A lock directory only broad local groups (`BUILTIN\Users`) may create files
/// in is common outside the profile: every constructor takes the lock there,
/// and one warning names the directory and the group.
#[test]
fn a_lock_directory_broad_local_groups_may_write_warns_and_proceeds() {
    let user = user_sid();
    let profile = format!("(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;{user})");
    let parent = tempfile::tempdir().expect("dir");
    let dir = parent.path().join("data");
    std::fs::create_dir(&dir).expect("data dir");
    plant_any(
        "broad",
        &dir,
        &format!("O:{user}D:P{profile}(A;OICI;0x1301bf;;;BU)"),
    );
    let ((), warnings) = crate::test_log_capture::capture_warnings(|| {
        for how in CONSTRUCTORS {
            drop(take(how, &dir.join(".store.lock")).expect(how));
        }
    });
    assert_eq!(
        warnings.matches("lock directory").count(),
        1,
        "one warning per directory: {warnings}"
    );
    assert!(warnings.contains(&dir.display().to_string()), "{warnings}");
    assert!(warnings.contains("BUILTIN\\Users"), "{warnings}");
    assert_owner_only("broad", &dir.join(".store.lock"), false);
}

/// A sidecar name left delete-pending (a healer's delete-on-close replace met
/// another open handle, as an antivirus or indexer handle does on CI) refuses
/// a new create with `ERROR_ACCESS_DENIED`. That is contention, not a refusal:
/// the probe answers `Held`, and the lock is taken once the name is free.
#[test]
fn a_delete_pending_sidecar_is_contention_not_an_error() {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_DELETE_ON_CLOSE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join(".store.lock");
    std::fs::write(&path, b"").expect("planted");
    // A stray reader that shares delete keeps the name alive after the delete.
    let keeper = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(share_all)
        .open(&path)
        .expect("keeper");
    let deleter = std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(share_all)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
        .open(&path)
        .expect("deleter");
    drop(deleter);
    let create = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path);
    assert_eq!(
        create.err().and_then(|e| e.raw_os_error()),
        Some(5),
        "premise: a delete-pending name refuses a create with ERROR_ACCESS_DENIED"
    );
    assert!(
        matches!(ExclusiveFileLock::try_lease(&path), Ok(Attempt::Held)),
        "a delete-pending sidecar is contention"
    );
    drop(keeper);
    drop(ExclusiveFileLock::acquire(&path).expect("taken once the name is free"));
    assert_owner_only("delete-pending", &path, false);
}

/// The delete-pending race, 50 times in one run: each iteration leaves a
/// fresh sidecar name delete-pending (the probe answers `Held`), then lets the
/// other handle close on a second thread while `acquire` races it. Whichever
/// side wins, `acquire` takes the lock; it never returns an error.
#[test]
fn a_delete_pending_race_never_fails_acquire() {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_DELETE_ON_CLOSE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let dir = tempfile::tempdir().expect("dir");
    for i in 0..50 {
        let path = dir.path().join(format!(".store-{i}.lock"));
        std::fs::write(&path, b"").expect("planted");
        let keeper = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(share_all)
            .open(&path)
            .expect("keeper");
        drop(
            std::fs::OpenOptions::new()
                .access_mode(DELETE)
                .share_mode(share_all)
                .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
                .open(&path)
                .expect("deleter"),
        );
        assert!(
            matches!(ExclusiveFileLock::try_lease(&path), Ok(Attempt::Held)),
            "iteration {i}: a delete-pending sidecar is contention"
        );
        let release = std::thread::spawn(move || {
            std::thread::yield_now();
            drop(keeper);
        });
        let lock = ExclusiveFileLock::acquire(&path);
        release.join().expect("release");
        assert!(lock.is_ok(), "iteration {i}: {:?}", lock.err());
        drop(lock);
        assert_owner_only("delete-pending race", &path, false);
    }
}
