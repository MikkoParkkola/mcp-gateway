// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Power-loss rows with independent, hand-built projection observations.
//! The no-op stub is red for C1, C4, C5 and C8. R6's alternate immutable
//! arming-snapshot stub is the red oracle for C2, C3 and C6.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use super::crash_fs::{self, Mode, Overlay};
use super::{FileMode, Symlink, sync_dir_of, write_atomic};

const OLD: &[u8] = b"server:\n  port: 1\n";
const NEW: &[u8] = b"server:\n  port: 2\n";
const NAME: &str = "gateway.yaml";

fn config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(NAME);
    write_atomic(&path, OLD, FileMode::Private, Symlink::Replace).expect("seed");
    (dir, path)
}

fn observation(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([(NAME.to_owned(), bytes.to_vec())])
}

/// Synthetic identities let projection rows state the durable facts without
/// asking the overlay under test to compute their expected state.
fn durable(bytes: &[u8]) -> Overlay {
    Overlay {
        names: BTreeMap::from([(NAME.to_owned(), (1, 1))]),
        current: BTreeMap::from([(NAME.to_owned(), (1, 1))]),
        data: BTreeMap::from([((1, 1), bytes.to_vec())]),
        ..Overlay::default()
    }
}

/// C1: red oracle: the old generation survives, not the renamed bytes.
#[test]
fn an_unsynced_rename_is_lost_under_drop_all() {
    let (dir, path) = config();
    let _armed = crash_fs::arm(dir.path());
    write_atomic(&path, NEW, FileMode::Private, Symlink::Replace).expect("replace");
    let mut state = durable(OLD);
    state.current.insert(NAME.to_owned(), (1, 2));
    state.data.insert((1, 2), NEW.to_vec());
    let projected = crash_fs::project(&state, &observation(NEW), Mode::DropAll);
    crash_fs::cut(dir.path(), Mode::DropAll);
    assert_eq!(projected, observation(OLD), "old generation in projection");
    assert_eq!(std::fs::read(path).expect("read"), OLD);
}

/// C2: red oracle: a dir sync preserves the new generation, not arming bytes.
#[test]
fn a_dir_sync_makes_the_rename_survive_drop_all() {
    let (dir, path) = config();
    let _armed = crash_fs::arm(dir.path());
    write_atomic(&path, NEW, FileMode::Private, Symlink::Replace).expect("replace");
    sync_dir_of(&path).expect("dir sync");
    let mut state = durable(OLD);
    state.names.insert(NAME.to_owned(), (1, 2));
    state.current.insert(NAME.to_owned(), (1, 2));
    state.data.insert((1, 2), NEW.to_vec());
    let projected = crash_fs::project(&state, &observation(NEW), Mode::DropAll);
    crash_fs::cut(dir.path(), Mode::DropAll);
    assert_eq!(projected, observation(NEW));
    assert_eq!(std::fs::read(path).expect("read"), NEW);
}

/// C3: red oracle: `KeepAll` keeps current bytes, not the arming snapshot.
#[test]
fn keep_all_keeps_an_unsynced_rename() {
    let (dir, path) = config();
    let _armed = crash_fs::arm(dir.path());
    write_atomic(&path, NEW, FileMode::Private, Symlink::Replace).expect("replace");
    let projected = crash_fs::project(&durable(OLD), &observation(NEW), Mode::KeepAll);
    crash_fs::cut(dir.path(), Mode::KeepAll);
    assert_eq!(projected, observation(NEW));
    assert_eq!(std::fs::read(path).expect("read"), NEW);
}

/// C4: red oracle: the unsynced create vanishes and the deleted file returns.
#[test]
fn an_unsynced_create_vanishes_and_an_unsynced_delete_returns() {
    let (dir, path) = config();
    let _armed = crash_fs::arm(dir.path());
    let created = dir.path().join("created");
    std::fs::write(&created, NEW).expect("create");
    std::fs::remove_file(&path).expect("delete");
    let observed = BTreeMap::from([("created".to_owned(), NEW.to_vec())]);
    let projected = crash_fs::project(&durable(OLD), &observed, Mode::DropAll);
    crash_fs::cut(dir.path(), Mode::DropAll);
    assert_eq!(projected, observation(OLD));
    assert!(!created.exists(), "unsynced create vanished");
    assert_eq!(std::fs::read(path).expect("deleted file restored"), OLD);
}

/// C5: red oracle: exact seed % 16 torn tails after the durable prefix;
/// independent observations affect the result, and repeating a seed agrees.
#[test]
fn keep_rename_drop_data_tears_an_unsynced_append() {
    for seed in [0, 3, 11, 19] {
        for tail in [b"abcdefghijklmnop", b"ABCDEFGHIJKLMNOP"] {
            let expected = [OLD, &tail[..(seed % 16) as usize]].concat();
            for _ in 0..2 {
                let (dir, path) = config();
                let _armed = crash_fs::arm(dir.path());
                let mut file = OpenOptions::new().append(true).open(&path).expect("open");
                file.write_all(tail).expect("unsynced append");
                drop(file);
                let mode = Mode::KeepRenameDropData { seed };
                let observed = observation(&[OLD, tail.as_slice()].concat());
                let projected = crash_fs::project(&durable(OLD), &observed, mode);
                crash_fs::cut(dir.path(), mode);
                assert_eq!(projected, observation(&expected), "seed {seed}");
                assert_eq!(std::fs::read(path).expect("read"), expected, "seed {seed}");
            }
        }
    }
}

/// C6: red oracle: renamed, synced data stays whole even without a dir sync.
#[test]
fn keep_rename_drop_data_keeps_names_and_synced_data() {
    let (dir, path) = config();
    let _armed = crash_fs::arm(dir.path());
    write_atomic(&path, NEW, FileMode::Private, Symlink::Replace).expect("replace");
    let mut state = durable(OLD);
    state.current.insert(NAME.to_owned(), (1, 2));
    state.data.insert((1, 2), NEW.to_vec());
    let mode = Mode::KeepRenameDropData { seed: 3 };
    let projected = crash_fs::project(&state, &observation(NEW), mode);
    crash_fs::cut(dir.path(), mode);
    assert_eq!(projected, observation(NEW));
    assert_eq!(std::fs::read(path).expect("read"), NEW);
}

/// C7: red oracle: forgetting to arm fails with a useful name, caught and
/// checked here so a cut that silently does nothing fails at this assertion.
#[test]
fn cut_on_an_unarmed_dir_panics_by_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let caught = std::panic::catch_unwind(move || crash_fs::cut(&path, Mode::DropAll));
    let message = caught
        .err()
        .and_then(|e| e.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(
        message.contains("not armed"),
        "cut on an unarmed dir: {message:?}"
    );
}

/// C8: red oracle: flushing the second replacement cannot change the first
/// replacement's durable data before the second directory sync.
#[test]
fn an_in_place_flush_updates_only_the_current_generation() {
    const SECOND: &[u8] = b"server:\n  port: 3\n";
    const FLUSHED: &[u8] = b"server:\n  port: 4\n";
    for mode in [Mode::DropAll, Mode::KeepRenameDropData { seed: 3 }] {
        let (dir, path) = config();
        let _armed = crash_fs::arm(dir.path());
        write_atomic(&path, NEW, FileMode::Private, Symlink::Replace).expect("first");
        sync_dir_of(&path).expect("first dir sync");
        write_atomic(&path, SECOND, FileMode::Private, Symlink::Replace).expect("second");
        std::fs::write(&path, FLUSHED).expect("in-place write");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open flushed generation");
        file.sync_all().expect("data sync");
        crash_fs::note_flushed(&path, &mut file).expect("record flush");
        drop(file);

        // First replacement is the snapshot; only generation 3 was flushed.
        let mut state = durable(OLD);
        state.names.insert(NAME.to_owned(), (1, 2));
        state.data.insert((1, 2), NEW.to_vec());
        state.current.insert(NAME.to_owned(), (1, 3));
        state.data.insert((1, 3), FLUSHED.to_vec());
        let expected = match mode {
            Mode::DropAll => NEW,
            _ => FLUSHED,
        };
        let projected = crash_fs::project(&state, &observation(FLUSHED), mode);
        crash_fs::cut(dir.path(), mode);
        assert_eq!(projected, observation(expected), "{mode:?}");
        assert_eq!(std::fs::read(path).expect("read"), expected, "{mode:?}");
    }
}

/// C9: red oracle: after a replacement the overlay never saw (a plain
/// rename), a flush of the new file is what the keep modes keep: cut binds
/// names to the files it reads, not to a stale generation.
#[test]
fn an_unhooked_replacement_then_flush_keeps_the_flushed_bytes() {
    const FLUSHED: &[u8] = b"server:\n  port: 5\n";
    let (dir, path) = config();
    let _armed = crash_fs::arm(dir.path());
    let other = dir.path().join("replacement");
    std::fs::write(&other, FLUSHED).expect("replacement");
    std::fs::rename(&other, &path).expect("unhooked replace");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open replacement");
    file.sync_all().expect("data sync");
    crash_fs::note_flushed(&path, &mut file).expect("record flush");
    drop(file);
    crash_fs::cut(dir.path(), Mode::KeepRenameDropData { seed: 3 });
    assert_eq!(std::fs::read(&path).expect("read"), FLUSHED);
}

/// C10: red oracle: only the armed config's own lock sidecar is left out. A
/// foreign `.other.yaml.lock` beside an `other.yaml`, held under a byte-range
/// lock, stops arming by name; a harness that skipped any locked file, or
/// guessed the sidecar from a file name, would arm silently and fail here.
#[cfg(windows)]
#[test]
fn a_foreign_locked_file_is_refused_by_name() {
    let (dir, config) = config();
    std::fs::write(dir.path().join("other.yaml"), OLD).expect("seed");
    let foreign = dir.path().join(".other.yaml.lock");
    std::fs::write(&foreign, OLD).expect("seed");
    let held = std::fs::File::open(&foreign).expect("open");
    held.lock().expect("byte-range lock");
    let probe = std::fs::read(&foreign).expect_err("read under the lock");
    assert_eq!(probe.raw_os_error(), Some(33), "the lock blocks reads");
    let caught = std::panic::catch_unwind(move || drop(crash_fs::arm_config(&config)));
    let message = caught
        .err()
        .and_then(|e| e.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(
        message.contains(".other.yaml.lock"),
        "arm over a foreign locked file: {message:?}"
    );
    drop(held);
}

/// C11: red oracle: the armed config's lock sidecar is outside the model
/// whatever its lock state; a harness that snapshotted it would restore its
/// arming bytes under `DropAll`.
#[test]
fn the_config_lock_sidecar_is_left_untouched_by_a_cut() {
    let (dir, config) = config();
    let sidecar = super::lock::lock_path(&config);
    std::fs::write(&sidecar, b"armed").expect("seed sidecar");
    let _armed = crash_fs::arm_config(&config);
    std::fs::write(&sidecar, b"later").expect("rewrite sidecar");
    crash_fs::cut(dir.path(), Mode::DropAll);
    assert_eq!(std::fs::read(&sidecar).expect("sidecar"), b"later");
}

/// C12: red oracle: a directory sync never brings the excluded sidecar into
/// the model; a sync that recorded it would restore its synced bytes under
/// `DropAll`.
#[test]
fn a_dir_sync_leaves_the_config_lock_sidecar_out() {
    let (dir, config) = config();
    let _armed = crash_fs::arm_config(&config);
    let sidecar = super::lock::lock_path(&config);
    std::fs::write(&sidecar, b"synced").expect("create sidecar");
    sync_dir_of(&config).expect("dir sync");
    std::fs::write(&sidecar, b"later").expect("rewrite sidecar");
    crash_fs::cut(dir.path(), Mode::DropAll);
    assert_eq!(std::fs::read(&sidecar).expect("sidecar"), b"later");
}

/// A file whose unlink was lost comes back with its generation's mode, as the same inode would:
/// a writer that created a file too open is still caught after a cut.
#[cfg(unix)]
#[test]
fn a_restored_file_keeps_its_generation_mode() {
    use std::os::unix::fs::PermissionsExt as _;
    for mode in [0o600, 0o640] {
        let (dir, path) = config();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
        let _armed = crash_fs::arm(dir.path());
        std::fs::remove_file(&path).expect("an unsynced delete");
        crash_fs::cut(dir.path(), Mode::DropAll);
        let restored = std::fs::metadata(&path)
            .expect("restored")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            restored, mode,
            "the restored file has its generation's mode {mode:o}"
        );
    }
}
