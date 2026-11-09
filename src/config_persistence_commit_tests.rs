// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Primitive A's rows: a token only after the directory sync, the file flush
//! and a matching read-back, in that order; every other path names whether
//! the rename happened. Each row's red oracle is the assertion its doc names.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::commit::{
    Action, CommitToken, FileRevision, Found, NotDurable, Refusal, SyncKey, commit, verify,
};
use super::journal::fault::{self, Fault, HookAt};
use super::lock::Locked;
use super::{FileMode, Symlink, write_atomic};

const OLD: &[u8] = b"server:\n  port: 1\n";
const NEW: &[u8] = b"server:\n  port: 2\n";

/// A config holding `OLD` in a fresh directory.
fn config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_atomic(&path, OLD, FileMode::Private, Symlink::Replace).expect("seed");
    (dir, path)
}

fn lock(config: &Path) -> Locked {
    super::lock::lock_config_blocking(config, Instant::now() + Duration::from_secs(10), |_| {})
        .expect("lock")
}

/// The directory's entries other than the lock file.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n != ".gateway.yaml.lock")
        .collect();
    names.sort();
    names
}

fn hook(at: HookAt, f: impl Fn(&Path) + Send + Sync + 'static) -> Fault {
    Fault::Hook(at, Arc::new(f))
}

/// A1: a commit syncs the directory once, then returns the payload's
/// revision. Red oracle: the token.
#[test]
fn commit_writes_syncs_and_returns_the_payload_revision() {
    let (_dir, path) = config();
    let held = lock(&path);
    let before = fault::synced(&held.target);
    let token = commit(&held, &path, Action::Forward, NEW).expect("token");
    assert_eq!(token.revision(), &FileRevision::of(NEW));
    assert_eq!(std::fs::read(&path).expect("read"), NEW);
    assert_eq!(fault::synced(&held.target) - before, 1, "one real dir sync");
}

/// A2: a configured link re-pointed before the call refuses before any
/// write. Red oracle: `Refused(Moved)`.
#[cfg(unix)]
#[test]
fn commit_refuses_a_moved_path_before_writing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    let other = dir.path().join("other.yaml");
    let link = dir.path().join("gateway.yaml");
    write_atomic(&real, OLD, FileMode::Private, Symlink::Replace).expect("seed");
    write_atomic(&other, OLD, FileMode::Private, Symlink::Replace).expect("seed");
    std::os::unix::fs::symlink(&real, &link).expect("link");
    let held = lock(&link);
    let names = listing(dir.path());
    std::fs::remove_file(&link).expect("unlink");
    std::os::unix::fs::symlink(&other, &link).expect("re-point");
    let got = commit(&held, &link, Action::Forward, NEW);
    assert!(
        matches!(got, Err(NotDurable::Refused(Refusal::Moved))),
        "{got:?}"
    );
    assert_eq!(std::fs::read(&real).expect("read"), OLD);
    assert_eq!(listing(dir.path()), names, "no scratch left");
}

/// A3: a target deleted since the lock refuses, and nothing is created.
/// Red oracle: `Refused(Other)` naming the deletion.
#[test]
fn commit_refuses_a_target_deleted_since_the_lock() {
    let (dir, path) = config();
    let held = lock(&path);
    std::fs::remove_file(&path).expect("delete");
    let got = commit(&held, &path, Action::Forward, NEW);
    match got {
        Err(NotDurable::Refused(Refusal::Other(why))) => assert!(why.contains("deleted"), "{why}"),
        other => panic!("expected Refused(Other): {other:?}"),
    }
    assert!(!path.exists(), "nothing created");
    assert!(listing(dir.path()).is_empty(), "{:?}", listing(dir.path()));
}

/// A4: a failure before the rename leaves the old file. Red oracle: the
/// fired count (the stub already returns `Write`).
#[test]
fn a_write_failure_is_write_and_leaves_the_old_file() {
    let (dir, path) = config();
    let held = lock(&path);
    let names = listing(dir.path());
    let _armed = fault::set(&path, Fault::FailWrite);
    let got = commit(&held, &path, Action::Forward, NEW);
    assert_eq!(fault::fired(&path), 1, "the seam was reached");
    assert!(
        matches!(&got, Err(NotDurable::Write(e)) if e.to_string() == "injected write failure"),
        "{got:?}"
    );
    assert_eq!(std::fs::read(&path).expect("read"), OLD);
    assert_eq!(listing(dir.path()), names, "no scratch left");
}

/// A5: a dir-sync failure after the rename is `Sync`, per action; the other
/// action's seam never fires. Red oracle: `Sync`.
#[test]
fn a_dir_sync_failure_after_the_rename_is_sync() {
    for (armed, action, other) in [
        (
            SyncKey::Commit(Action::Forward),
            Action::Forward,
            Action::Restore,
        ),
        (
            SyncKey::Commit(Action::Restore),
            Action::Restore,
            Action::Forward,
        ),
    ] {
        let (_dir, path) = config();
        let held = lock(&path);
        let _armed = fault::set(&path, Fault::FailDirSync(armed));
        let got = commit(&held, &path, action, NEW);
        assert!(
            matches!(&got, Err(NotDurable::Sync(e)) if e.to_string() == "injected dir-sync failure"),
            "{action:?}: {got:?}"
        );
        assert_eq!(fault::fired(&path), 1, "{action:?}: the seam was reached");
        assert_eq!(std::fs::read(&path).expect("read"), NEW, "renamed");
        // The same seam armed for the other action does not fire here.
        let (_dir2, path2) = config();
        let held2 = lock(&path2);
        let _armed2 = fault::set(&path2, Fault::FailDirSync(SyncKey::Commit(other)));
        assert!(commit(&held2, &path2, action, NEW).is_ok(), "{action:?}");
        assert_eq!(fault::fired(&path2), 0, "{action:?}: other action's seam");
    }
}

/// Seed a link `gateway.yaml` -> `real.yaml`, plus `other.yaml`, both `OLD`.
#[cfg(unix)]
fn linked() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    let other = dir.path().join("other.yaml");
    let link = dir.path().join("gateway.yaml");
    write_atomic(&real, OLD, FileMode::Private, Symlink::Replace).expect("seed");
    write_atomic(&other, OLD, FileMode::Private, Symlink::Replace).expect("seed");
    std::os::unix::fs::symlink(&real, &link).expect("link");
    (dir, link, real, other)
}

/// A hook that re-points `link` at `to`.
#[cfg(unix)]
fn repoint(link: &Path, to: &Path) -> Fault {
    let (link, to) = (link.to_path_buf(), to.to_path_buf());
    hook(HookAt::BeforeRecheck, move |_| {
        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink(&to, &link).expect("re-point");
    })
}

/// A6: a re-point after the read-back is `Repointed`: the new bytes stand
/// on the old target. Red oracle: `Repointed(Moved)`.
#[cfg(unix)]
#[test]
fn a_repoint_after_the_read_back_is_repointed() {
    let (_dir, link, real, other) = linked();
    let held = lock(&link);
    let _armed = fault::set(&link, repoint(&link, &other));
    let got = commit(&held, &link, Action::Forward, NEW);
    assert!(
        matches!(got, Err(NotDurable::Repointed(Refusal::Moved))),
        "{got:?}"
    );
    assert_eq!(std::fs::read(&real).expect("read"), NEW, "new bytes stand");
}

/// A7: verify returns the commit's token and writes nothing. Red oracle:
/// the token equality.
#[test]
fn verify_returns_the_same_token_and_never_writes() {
    let (dir, path) = config();
    let held = lock(&path);
    let token: CommitToken = commit(&held, &path, Action::Forward, NEW).expect("token");
    let meta = std::fs::metadata(&path).expect("meta");
    let names = listing(dir.path());
    let before = fault::synced(&held.target);
    let again = verify(&held, &path, token.revision()).expect("verified");
    assert_eq!(again, token);
    assert_eq!(fault::synced(&held.target) - before, 1, "one real dir sync");
    let after = std::fs::metadata(&path).expect("meta");
    assert_eq!(after.modified().ok(), meta.modified().ok());
    #[cfg(unix)]
    assert_eq!(
        std::os::unix::fs::MetadataExt::ino(&after),
        std::os::unix::fs::MetadataExt::ino(&meta)
    );
    assert_eq!(std::fs::read(&path).expect("read"), NEW);
    assert_eq!(listing(dir.path()), names);
}

/// A8: after a lost entry the old bytes are found, never a token. Red
/// oracle: `NotOnDisk { found: Bytes(old) }`.
#[test]
fn verify_after_a_lost_entry_reports_the_old_bytes() {
    let (_dir, path) = config();
    let held = lock(&path);
    let got = verify(&held, &path, &FileRevision::of(NEW));
    assert!(
        matches!(&got, Err(NotDurable::NotOnDisk { found: Found::Bytes(r) }) if *r == FileRevision::of(OLD)),
        "{got:?}"
    );
}

/// A9: a target never created is `Missing`; one created and deleted refuses.
/// Red oracle: `NotOnDisk { found: Missing }`, then `Refused(Other)`.
#[test]
fn verify_on_a_missing_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let held = lock(&path);
    let got = verify(&held, &path, &FileRevision::of(NEW));
    assert!(
        matches!(
            got,
            Err(NotDurable::NotOnDisk {
                found: Found::Missing
            })
        ),
        "{got:?}"
    );
    let (_dir2, path2) = config();
    let held2 = lock(&path2);
    std::fs::remove_file(&path2).expect("delete");
    let got = verify(&held2, &path2, &FileRevision::of(NEW));
    assert!(
        matches!(&got, Err(NotDurable::Refused(Refusal::Other(why))) if why.contains("deleted")),
        "{got:?}"
    );
}

/// A10: verify's dir-sync failure is `Sync`. Red oracle: `Sync`.
#[test]
fn verify_dir_sync_failure_is_sync() {
    let (_dir, path) = config();
    let held = lock(&path);
    let _armed = fault::set(&path, Fault::FailDirSync(SyncKey::Verify));
    let got = verify(&held, &path, &FileRevision::of(OLD));
    assert!(matches!(got, Err(NotDurable::Sync(_))), "{got:?}");
    assert_eq!(fault::fired(&path), 1);
}

/// A11: verify re-pointed before its recheck refuses (nothing was written).
/// Red oracle: `Refused(Moved)`.
#[cfg(unix)]
#[test]
fn verify_repointed_is_refused() {
    let (_dir, link, _real, other) = linked();
    let held = lock(&link);
    let _armed = fault::set(&link, repoint(&link, &other));
    let got = verify(&held, &link, &FileRevision::of(OLD));
    assert!(
        matches!(got, Err(NotDurable::Refused(Refusal::Moved))),
        "{got:?}"
    );
}

/// Run `f` on its own thread; a call that blocks fails the row by name
/// after 2 s instead of hanging the suite.
#[cfg(unix)]
fn within_2s<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("{what}: blocked for 2 s"))
}

/// A hook that replaces the target with a FIFO.
#[cfg(unix)]
fn fifo_swap() -> Fault {
    hook(HookAt::BeforeReadBack, |target| {
        std::fs::remove_file(target).expect("remove");
        crate::test_fifo::make_fifo(target);
    })
}

/// A12: a FIFO swapped in before the read-back is never hashed and never
/// blocks. Red oracle: `NotOnDisk { found: NotAFile }`.
#[cfg(unix)]
#[test]
fn commit_rejects_a_fifo_swapped_in_before_the_read_back() {
    let (_dir, path) = config();
    let _armed = fault::set(&path, fifo_swap());
    let got = within_2s("commit", move || {
        let held = lock(&path);
        format!("{:?}", commit(&held, &path, Action::Forward, NEW))
    });
    assert!(got.contains("NotOnDisk { found: NotAFile }"), "{got}");
}

/// A13: a large file is hashed in chunks, not read whole. Red oracle: the
/// chunk count.
#[test]
fn read_back_hashes_a_large_file_in_chunks() {
    let big = vec![b'#'; 3 * 1024 * 1024];
    let (_dir, path) = config();
    let held = lock(&path);
    let before = crate::hashing::chunks_read();
    let token = commit(&held, &path, Action::Forward, &big).expect("token");
    assert_eq!(token.revision(), &FileRevision::of(&big));
    assert!(crate::hashing::chunks_read() - before > 1, "read in chunks");
}

/// A14: bytes changed before the read-back are reported as found. Red
/// oracle: `NotOnDisk { found: Bytes(changed) }`.
#[test]
fn commit_reports_bytes_changed_before_the_read_back() {
    const CHANGED: &[u8] = b"server:\n  port: 3\n";
    let (_dir, path) = config();
    let held = lock(&path);
    let _armed = fault::set(
        &path,
        hook(HookAt::BeforeReadBack, |t| {
            std::fs::write(t, CHANGED).expect("change");
        }),
    );
    let got = commit(&held, &path, Action::Forward, NEW);
    assert!(
        matches!(&got, Err(NotDurable::NotOnDisk { found: Found::Bytes(r) }) if *r == FileRevision::of(CHANGED)),
        "{got:?}"
    );
}

/// A15: a FIFO at the target makes verify return `NotAFile` without
/// blocking. Red oracle: `NotOnDisk { found: NotAFile }`.
#[cfg(unix)]
#[test]
fn verify_rejects_a_fifo_at_the_target() {
    let (_dir, path) = config();
    let got = within_2s("verify", move || {
        let held = lock(&path);
        std::fs::remove_file(&path).expect("remove");
        crate::test_fifo::make_fifo(&path);
        format!("{:?}", verify(&held, &path, &FileRevision::of(OLD)))
    });
    assert!(got.contains("NotOnDisk { found: NotAFile }"), "{got}");
}

/// A reader that yields `data` a few bytes at a time.
struct Short<'a>(&'a [u8], usize);

impl std::io::Read for Short<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.1 = self.1 % 7 + 1;
        let n = self.1.min(buf.len()).min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

/// A reader that fails after `ok` bytes.
struct FailsAfter(usize);

impl std::io::Read for FailsAfter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.0 == 0 {
            return Err(std::io::Error::other("disk gone"));
        }
        let n = self.0.min(buf.len());
        buf[..n].fill(b'x');
        self.0 -= n;
        Ok(n)
    }
}

/// A reader that is interrupted once, then yields `data`.
struct InterruptedOnce<'a>(&'a [u8], bool);

impl std::io::Read for InterruptedOnce<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.1 {
            self.1 = true;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.0.read(buf)
    }
}

/// A16: `of_reader` equals `of` at the buffer's edges, over short reads and
/// after an interrupted read, and a failed read gives no revision. Red
/// oracle: the equality.
#[test]
fn of_reader_matches_of() {
    const K: usize = 64 * 1024;
    for len in [0, 1, K, K + 1] {
        let bytes = vec![b'a'; len];
        let got = FileRevision::of_reader(bytes.as_slice()).expect("read");
        assert_eq!(got, FileRevision::of(&bytes), "len {len}");
    }
    let bytes: Vec<u8> = (0..=255u8).cycle().take(K + 13).collect();
    let got = FileRevision::of_reader(Short(&bytes, 0)).expect("short reads");
    assert_eq!(got, FileRevision::of(&bytes), "short reads");
    let got = FileRevision::of_reader(InterruptedOnce(&bytes, false)).expect("retried");
    assert_eq!(got, FileRevision::of(&bytes), "interrupted then read");
    assert!(
        FileRevision::of_reader(FailsAfter(70 * 1024)).is_err(),
        "mid-stream error"
    );
}

/// A hook that writes mismatching bytes, counting itself.
fn mismatch() -> (Fault, Arc<std::sync::atomic::AtomicUsize>) {
    let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&ran);
    let fault = hook(HookAt::BeforeReadBack, move |t| {
        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::fs::write(t, b"mismatch\n").expect("write");
    });
    (fault, ran)
}

/// A17: commit syncs before it reads back: with the sync failing, the
/// read-back hook never runs. Red oracle: `Sync`.
#[test]
fn commit_syncs_before_reading_back() {
    let (_dir, path) = config();
    let held = lock(&path);
    let (hooked, ran) = mismatch();
    let sync = Fault::FailDirSync(SyncKey::Commit(Action::Forward));
    let _armed = fault::set(&path, Fault::All(vec![sync, hooked]));
    let got = commit(&held, &path, Action::Forward, NEW);
    assert!(matches!(got, Err(NotDurable::Sync(_))), "{got:?}");
    assert_eq!(
        ran.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no read-back"
    );
}

/// A18: verify syncs before it reads back. Red oracle: `Sync`.
#[test]
fn verify_syncs_before_reading_back() {
    let (_dir, path) = config();
    let held = lock(&path);
    let (hooked, ran) = mismatch();
    let _armed = fault::set(
        &path,
        Fault::All(vec![Fault::FailDirSync(SyncKey::Verify), hooked]),
    );
    let got = verify(&held, &path, &FileRevision::of(OLD));
    assert!(matches!(got, Err(NotDurable::Sync(_))), "{got:?}");
    assert_eq!(
        ran.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no read-back"
    );
}

/// A19: a link swapped in at the target, even to a regular file holding the
/// payload, never earns a token: the configured path now resolves elsewhere,
/// so the recheck finds it moved. (A Kubernetes config map's links resolve
/// at lock time; its target is the final regular file.) Red oracle: `Repointed(Moved)`.
#[cfg(unix)]
#[test]
fn a_link_swapped_in_at_the_target_is_repointed() {
    let (dir, path) = config();
    let held = lock(&path);
    let beside = dir.path().join("mounted.yaml");
    let at = beside.clone();
    let _armed = fault::set(
        &path,
        hook(HookAt::BeforeReadBack, move |t| {
            std::fs::write(&at, NEW).expect("mounted");
            std::fs::remove_file(t).expect("remove");
            std::os::unix::fs::symlink(&at, t).expect("link");
        }),
    );
    let got = commit(&held, &path, Action::Forward, NEW);
    assert!(
        matches!(got, Err(NotDurable::Repointed(Refusal::Moved))),
        "{got:?}"
    );
}

/// A20: a failed file flush is `Sync`, never a token. Red oracle: `Sync`.
#[test]
fn a_file_flush_failure_is_sync() {
    let (_dir, path) = config();
    let held = lock(&path);
    let _armed = fault::set(&path, Fault::FailFileSync);
    let got = commit(&held, &path, Action::Forward, NEW);
    assert!(matches!(got, Err(NotDurable::Sync(_))), "{got:?}");
    assert_eq!(fault::fired(&path), 1, "the seam was reached");
    assert_eq!(std::fs::read(&path).expect("read"), NEW, "renamed");

    let (_dir2, path2) = config();
    write_atomic(&path2, NEW, FileMode::Private, Symlink::Replace).expect("seed");
    let held2 = lock(&path2);
    let _armed2 = fault::set(&path2, Fault::FailFileSync);
    let got = verify(&held2, &path2, &FileRevision::of(NEW));
    assert!(matches!(got, Err(NotDurable::Sync(_))), "{got:?}");
    assert_eq!(fault::fired(&path2), 1, "the seam was reached");
    assert_eq!(std::fs::read(&path2).expect("read"), NEW);
}

/// A21: a target deleted after the read-back refuses the token as
/// `Repointed`: the rename happened, so the refusal names that, on every
/// platform. Red oracle: `Repointed(Other)` naming the deletion.
#[test]
fn a_target_deleted_after_the_read_back_is_repointed() {
    let (_dir, path) = config();
    let held = lock(&path);
    let _armed = fault::set(
        &path,
        hook(HookAt::BeforeRecheck, |t| {
            std::fs::remove_file(t).expect("delete");
        }),
    );
    let got = commit(&held, &path, Action::Forward, NEW);
    assert!(
        matches!(&got, Err(NotDurable::Repointed(Refusal::Other(why))) if why.contains("deleted")),
        "{got:?}"
    );
}

/// Each power-loss mode gets its own fixture and armed directory.
fn crash_modes() -> [super::crash_fs::Mode; 3] {
    use super::crash_fs::Mode;
    [
        Mode::DropAll,
        Mode::KeepAll,
        Mode::KeepRenameDropData { seed: 3 },
    ]
}

/// A22: red oracle: token bytes survive every mode; restoring the immutable
/// arming snapshot would return OLD instead of the token's NEW bytes.
#[test]
fn a_token_survives_power_loss_in_every_mode() {
    for mode in crash_modes() {
        let (_dir, path) = config();
        let held = lock(&path);
        let _armed = super::crash_fs::arm_config(&held.target);
        let token = commit(&held, &path, Action::Forward, NEW).expect("token");
        super::crash_fs::cut(held.target.parent().unwrap(), mode);
        let bytes = std::fs::read(&path).expect("read after cut");
        assert_eq!(bytes, NEW, "{mode:?}");
        assert_eq!(&FileRevision::of(&bytes), token.revision(), "{mode:?}");
    }
}

/// A23: red oracle: a no-op cut wrongly keeps NEW under `DropAll`; restoring
/// the arming snapshot wrongly loses NEW in either keep mode.
#[test]
fn a_sync_failure_is_lost_under_drop_all_kept_under_keep_all() {
    for mode in crash_modes() {
        let (_dir, path) = config();
        let held = lock(&path);
        let _armed = super::crash_fs::arm_config(&held.target);
        let _fault = fault::set(&path, Fault::FailDirSync(SyncKey::Commit(Action::Forward)));
        let got = commit(&held, &path, Action::Forward, NEW);
        assert!(matches!(got, Err(NotDurable::Sync(_))), "{got:?}");
        assert_eq!(fault::fired(&path), 1, "sync failure reached");
        super::crash_fs::cut(held.target.parent().unwrap(), mode);
        let expected = match mode {
            super::crash_fs::Mode::DropAll => OLD,
            _ => NEW,
        };
        assert_eq!(
            std::fs::read(&path).expect("read after cut"),
            expected,
            "{mode:?}"
        );
    }
}

/// A24: red oracle: verified in-place bytes survive all modes; the immutable
/// arming-snapshot stub loses them. Removing flush must lose them in the model.
#[test]
fn verify_flushes_bytes_written_without_sync() {
    for mode in crash_modes() {
        let (_dir, path) = config();
        let held = lock(&path);
        let _armed = super::crash_fs::arm_config(&held.target);
        std::fs::write(&path, NEW).expect("unsynced in-place write");
        let token = verify(&held, &path, &FileRevision::of(NEW)).expect("token");
        super::crash_fs::cut(held.target.parent().unwrap(), mode);
        let bytes = std::fs::read(&path).expect("read after cut");
        assert_eq!(bytes, NEW, "{mode:?}");
        assert_eq!(&FileRevision::of(&bytes), token.revision(), "{mode:?}");
    }
}

/// A25 (register 1167): red oracle: deletion at `BeforeRecheck` is
/// Refused(Other) naming "deleted", never Repointed because verify wrote nothing.
#[test]
fn verify_after_a_delete_between_read_back_and_recheck_is_refused() {
    let (_dir, path) = config();
    let held = lock(&path);
    let _armed = fault::set(
        &path,
        hook(HookAt::BeforeRecheck, |t| {
            std::fs::remove_file(t).expect("delete");
        }),
    );
    let got = verify(&held, &path, &FileRevision::of(OLD));
    assert!(
        matches!(&got, Err(NotDurable::Refused(Refusal::Other(why))) if why.contains("deleted")),
        "{got:?}"
    );
}
