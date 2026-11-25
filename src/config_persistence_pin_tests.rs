// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WRITER.7: the writer pins the file it replaces and settles the new copy's
//! access only after the bytes are in, so another writer's change during the
//! save refuses it instead of being overwritten or widened. Unprivileged rows;
//! the owner rows that need root are in `config_persistence_access_tests`.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use super::unix::seams::{self, Seams};
use super::{
    FileMode, Symlink, copy_keeping_access, refusal_code, write_atomic, write_atomic_checked,
};

const TARGET: &str = "state.json";
const MODES: [FileMode; 2] = [FileMode::Inherit, FileMode::Private];

/// A folder holding `state.json` ("old") at `mode`.
fn fixture(mode: u32) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join(TARGET);
    std::fs::write(&target, b"old").expect("target");
    set_mode(&target, mode);
    (dir, target)
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).expect("lstat").mode() & 0o7777
}

/// Every name in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The refusal for a target another writer changed, as the product words it.
fn changed_text(path: &Path) -> String {
    format!(
        "target-changed: refused to replace {}: another process replaced or changed the file \
         during the save. Nothing was written. Save again to write the new contents.",
        path.display()
    )
}

/// The save refused `target-changed`, typed and worded.
fn assert_changed(result: std::io::Result<()>, target: &Path, row: &str) {
    let error = result.expect_err(&format!("{row}: the save refuses"));
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{row}: kind"
    );
    assert_eq!(
        refusal_code(&error),
        Some("target-changed"),
        "{row}: typed code"
    );
    assert_eq!(error.to_string(), changed_text(target), "{row}: text");
}

/// P-swap (and S-typed for `target-changed`): another file is put in the
/// target's place just before the final checks. The save refuses, the
/// substitute is untouched, and no scratch is left.
#[test]
fn p_swap_refuses_target_changed() {
    for mode in MODES {
        let row = format!("P-swap/{mode:?}");
        let (dir, target) = fixture(0o600);
        let armed = seams::arm(
            dir.path(),
            Seams {
                before_verify: Some(Box::new(|target, _scratch| {
                    std::fs::rename(target, target.with_extension("old")).expect("move away");
                    std::fs::write(target, b"sub").expect("substitute");
                })),
                ..Seams::default()
            },
        );
        assert_changed(
            write_atomic(&target, b"new", mode, Symlink::Replace),
            &target,
            &row,
        );
        drop(armed);
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"sub",
            "{row}: substitute"
        );
        assert_eq!(
            names(dir.path()),
            ["state.json", "state.old"],
            "{row}: no scratch left"
        );
    }
}

/// P-inplace (mode): the target's mode changes in place (same inode) just
/// before the final checks. The save refuses and the change stays.
#[test]
fn p_inplace_mode_change_refuses() {
    for mode in MODES {
        let row = format!("P-inplace/{mode:?}");
        let (dir, target) = fixture(0o644);
        let armed = seams::arm(
            dir.path(),
            Seams {
                before_verify: Some(Box::new(|target, _scratch| set_mode(target, 0o600))),
                ..Seams::default()
            },
        );
        assert_changed(
            write_atomic(&target, b"new", mode, Symlink::Replace),
            &target,
            &row,
        );
        drop(armed);
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"old",
            "{row}: bytes"
        );
        assert_eq!(mode_of(&target), 0o600, "{row}: the outside change stays");
        assert_eq!(names(dir.path()), [TARGET], "{row}: no scratch left");
    }
}

/// P-scratch-swap: during `check` another file takes the scratch's name.
/// The save refuses rather than renaming that file over the target.
#[test]
fn p_scratch_swap_refuses() {
    for mode in MODES {
        let row = format!("P-scratch-swap/{mode:?}");
        let (dir, target) = fixture(0o600);
        let folder = dir.path().to_path_buf();
        let result = write_atomic_checked(&target, b"new", mode, Symlink::Replace, || {
            let scratch = names(&folder)
                .into_iter()
                .find(|name| name != TARGET)
                .expect("the scratch exists during check");
            let scratch = folder.join(scratch);
            std::fs::rename(&scratch, folder.join("moved")).expect("move the scratch");
            std::fs::write(&scratch, b"planted").expect("plant");
            Ok(())
        });
        assert_changed(result, &target, &row);
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"old",
            "{row}: target"
        );
    }
}

/// P-scratch-mutate: the new copy's mode is widened after the writer set it.
/// The save refuses instead of renaming a copy wider than it decided.
#[test]
fn p_scratch_mutate_refuses() {
    for mode in MODES {
        let row = format!("P-scratch-mutate/{mode:?}");
        let (dir, target) = fixture(0o600);
        let armed = seams::arm(
            dir.path(),
            Seams {
                before_verify: Some(Box::new(|_target, scratch| set_mode(scratch, 0o644))),
                ..Seams::default()
            },
        );
        assert_changed(
            write_atomic(&target, b"new", mode, Symlink::Replace),
            &target,
            &row,
        );
        drop(armed);
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"old",
            "{row}: target"
        );
        assert_eq!(names(dir.path()), [TARGET], "{row}: no scratch left");
    }
}

/// P-order-pin: when the first byte is written the new copy is mode 0000
/// and the writer's own; its group and mode are settled only after `check`.
#[test]
fn p_order_pin_writes_into_a_closed_scratch() {
    let euid = rustix::process::geteuid().as_raw();
    for (mode, steps) in [
        (
            FileMode::Inherit,
            &["write", "sync", "check", "chown", "chmod"][..],
        ),
        (FileMode::Private, &["write", "sync", "check", "chmod"][..]),
    ] {
        let row = format!("P-order-pin/{mode:?}");
        let (dir, target) = fixture(0o640);
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let armed = seams::arm(
            dir.path(),
            Seams {
                first_write: Some(Box::new(move |scratch| {
                    let meta = scratch.metadata().expect("fstat the scratch");
                    seen_tx
                        .send((meta.mode() & 0o7777, meta.uid()))
                        .expect("send");
                })),
                ..Seams::default()
            },
        );
        write_atomic(&target, b"new", mode, Symlink::Replace).expect("the save");
        assert_eq!(
            seen_rx.recv().expect("the hook ran"),
            (0, euid),
            "{row}: mode and owner at the first byte"
        );
        assert_eq!(armed.events(), steps, "{row}: order");
    }
}

/// P-setid (Linux): a set-id file saved by its owner keeps the bit; the
/// bytes go in before the mode is set, so writing cannot clear it.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn p_setid_kept() {
    let (_dir, target) = fixture(0o4755);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace).expect("the save");
    assert_eq!(mode_of(&target), 0o4755, "P-setid");
}

/// P-stat-error: a target that cannot be inspected is not "absent": the
/// save returns that error and creates no scratch, in both modes.
#[test]
fn p_stat_error_refuses_before_a_scratch() {
    for mode in MODES {
        let row = format!("P-stat-error/{mode:?}");
        let (dir, target) = fixture(0o600);
        let armed = seams::arm(
            dir.path(),
            Seams {
                open_error: Some(rustix::io::Errno::IO.raw_os_error()),
                ..Seams::default()
            },
        );
        let error = write_atomic(&target, b"new", mode, Symlink::Replace)
            .expect_err(&format!("{row}: the save refuses"));
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::IO.raw_os_error()),
            "{row}: the inspection's own error"
        );
        assert_eq!(armed.creates(), 0, "{row}: no scratch created");
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"old",
            "{row}: target"
        );
    }
}

/// P-symlink: `Replace` over a link swaps the link away and never writes
/// through it; a `Private` save still starts from a closed scratch.
#[test]
fn p_symlink_is_replaced() {
    for mode in MODES {
        let row = format!("P-symlink/{mode:?}");
        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("elsewhere");
        std::fs::write(&sentinel, b"sentinel").expect("sentinel");
        let link = dir.path().join(TARGET);
        std::os::unix::fs::symlink(&sentinel, &link).expect("link");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let armed = seams::arm(
            dir.path(),
            Seams {
                first_write: Some(Box::new(move |scratch| {
                    let mode = scratch.metadata().expect("fstat").mode() & 0o7777;
                    seen_tx.send(mode).expect("send");
                })),
                ..Seams::default()
            },
        );
        write_atomic(&link, b"new", mode, Symlink::Replace).expect("the save");
        drop(armed);
        let at_first_byte = seen_rx.recv().expect("the hook ran");
        if mode == FileMode::Private {
            assert_eq!(at_first_byte, 0, "{row}: closed scratch");
            assert_eq!(mode_of(&link), 0o600, "{row}: owner-only");
        }
        assert!(
            std::fs::symlink_metadata(&link).expect("lstat").is_file(),
            "{row}: a file now stands at the path"
        );
        assert_eq!(std::fs::read(&link).expect("read"), b"new", "{row}: bytes");
        assert_eq!(
            std::fs::read(&sentinel).expect("read"),
            b"sentinel",
            "{row}: sentinel"
        );
    }
}

/// P-copy (c): a backup whose destination is a link replaces the link and
/// never writes through it.
#[test]
fn p_copy_replaces_a_link_at_the_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("gateway.yaml");
    std::fs::write(&source, b"config").expect("source");
    set_mode(&source, 0o600);
    let sentinel = dir.path().join("elsewhere");
    std::fs::write(&sentinel, b"sentinel").expect("sentinel");
    let backup = dir.path().join("gateway.yaml.bak");
    std::os::unix::fs::symlink(&sentinel, &backup).expect("link");
    copy_keeping_access(&source, &backup).expect("the copy");
    assert!(
        std::fs::symlink_metadata(&backup).expect("lstat").is_file(),
        "P-copy(c): a file now stands at the backup path"
    );
    assert_eq!(
        std::fs::read(&backup).expect("read"),
        b"config",
        "P-copy(c): bytes"
    );
    assert_eq!(
        std::fs::read(&sentinel).expect("read"),
        b"sentinel",
        "P-copy(c): sentinel"
    );
}

/// P-copy (d): another file is swapped in at the source's path after the
/// source is modelled and put back before the final checks. The backup holds
/// the bytes of the file that was modelled, read through that one descriptor.
#[test]
fn p_copy_reads_the_modelled_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("gateway.yaml");
    std::fs::write(&source, b"config").expect("source");
    set_mode(&source, 0o600);
    let backup = dir.path().join("gateway.yaml.bak");
    let armed = seams::arm(
        dir.path(),
        Seams {
            after_model: Some(Box::new(|source, _backup| {
                std::fs::rename(source, source.with_extension("orig")).expect("move away");
                std::fs::write(source, b"swapped").expect("swap in");
            })),
            before_verify: Some(Box::new(|backup, _scratch| {
                let source = backup.with_extension("");
                std::fs::rename(source.with_extension("orig"), &source).expect("put back");
            })),
            ..Seams::default()
        },
    );
    copy_keeping_access(&source, &backup).expect("the copy");
    drop(armed);
    assert_eq!(
        std::fs::read(&backup).expect("read"),
        b"config",
        "P-copy(d): bytes"
    );
}

/// The writer's seams exist only under `cfg(test)`: a non-test build of the
/// writer names none of them, so no fault can be injected into a release.
#[test]
fn the_writer_seams_are_compiled_out_of_production() {
    use crate::test_source_text::production_text;
    // Premise: the scan blanks a gated seam call and keeps an ungated one.
    let probe = production_text(
        "fn a() { seams::open_error(p); }\nfn b() { #[cfg(test)] seams::created(p); }\n",
    );
    assert!(
        probe.contains("seams::open_error") && !probe.contains("seams::created"),
        "premise: {probe}"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in [
        "config_persistence_atomic.rs",
        "config_persistence_atomic_unix.rs",
    ] {
        let raw = std::fs::read_to_string(root.join(file)).expect("read the writer");
        // The calls live in the unix half; the parent only re-exports them.
        let used_here = if file.ends_with("_unix.rs") {
            "seams::"
        } else {
            "unix::seams"
        };
        assert!(
            raw.contains(used_here),
            "{file}: premise: the seams are named here"
        );
        let production = production_text(&raw);
        for seam in [
            "seams::",
            "mod seams",
            "open_error",
            "before_verify",
            "first_write",
        ] {
            assert!(
                !production.contains(seam),
                "{file}: a non-test build compiles `{seam}`"
            );
        }
    }
}

/// The premise a replace relies on to drop its journal without restoring
/// after a write error: `write_atomic` fails only before its rename. Each
/// path ends in the step holding the rename, and after the rename's own
/// error arm nothing can return an error.
#[test]
fn nothing_fallible_follows_the_writers_rename() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let body = |file: &str, start: &str| {
        let raw = std::fs::read_to_string(root.join(file)).expect("read the writer");
        let from = raw.find(start).expect("the function");
        let len = raw[from..].find("\n}\n").expect("its end");
        raw[from..from + len].to_owned()
    };
    for (file, start, tail) in [
        (
            "config_persistence_atomic.rs",
            "fn write_atomic_observed(",
            "write_at(&target, bytes, mode, observe, check)",
        ),
        (
            "config_persistence_atomic_unix.rs",
            "pub(super) fn write(",
            "finish(&save, file, filled, bytes)",
        ),
    ] {
        assert!(
            body(file, start).trim_end().ends_with(tail),
            "{file}: `{start}` no longer ends in `{tail}`"
        );
    }
    for (file, start) in [
        ("config_persistence_atomic_unix.rs", "fn finish("),
        ("config_persistence_atomic.rs", "fn write_at("),
    ] {
        let body = body(file, start);
        let after = &body[body.find("rename_with_retry(").expect("the rename")..];
        let arm = "return Err(e);";
        let after = &after[after.find(arm).expect("the rename's error arm") + arm.len()..];
        for fallible in ["?", "Err(", "return"] {
            assert!(
                !after.contains(fallible),
                "{file}: `{fallible}` after the rename in `{start}`: {after}"
            );
        }
    }
}

/// P-inplace (bytes): another writer rewrites the target in place, same
/// file, owner, mode and length, just before the final checks. The save
/// refuses and the other bytes stay. The fixture's modification time is set
/// in the past first, so the rewrite moves it whatever the clock's tick.
#[test]
fn p_inplace_rewrite_refuses() {
    for mode in MODES {
        let row = format!("P-inplace-bytes/{mode:?}");
        let (dir, target) = fixture(0o600);
        std::fs::File::options()
            .write(true)
            .open(&target)
            .and_then(|f| {
                f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1 << 30))
            })
            .expect("age the fixture");
        let armed = seams::arm(
            dir.path(),
            Seams {
                before_verify: Some(Box::new(|target, _scratch| {
                    std::fs::write(target, b"sub").expect("rewrite in place");
                })),
                ..Seams::default()
            },
        );
        assert_changed(
            write_atomic(&target, b"new", mode, Symlink::Replace),
            &target,
            &row,
        );
        drop(armed);
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"sub",
            "{row}: the other bytes"
        );
        assert_eq!(names(dir.path()), ["state.json"], "{row}: no scratch left");
    }
}

/// P-unmodelled: a target that was nothing, or a link, when the save looked
/// gets a regular file from another writer just before the final checks. The
/// save refuses and that file stays.
#[test]
fn p_a_file_put_where_nothing_or_a_link_was_refuses() {
    for (case, link) in [("absent", false), ("link", true)] {
        for mode in MODES {
            let row = format!("P-unmodelled/{case}/{mode:?}");
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join(TARGET);
            let mut left = vec![TARGET];
            if link {
                std::fs::write(dir.path().join("linked.json"), b"old").expect("link target");
                std::os::unix::fs::symlink("linked.json", &target).expect("link");
                left.insert(0, "linked.json");
            }
            let armed = seams::arm(
                dir.path(),
                Seams {
                    before_verify: Some(Box::new(|target, _scratch| {
                        let _ = std::fs::remove_file(target);
                        std::fs::write(target, b"sub").expect("another writer's file");
                    })),
                    ..Seams::default()
                },
            );
            assert_changed(
                write_atomic(&target, b"new", mode, Symlink::Replace),
                &target,
                &row,
            );
            drop(armed);
            assert_eq!(
                std::fs::read(&target).expect("read"),
                b"sub",
                "{row}: that file stays"
            );
            assert_eq!(names(dir.path()), left, "{row}: no scratch left");
        }
    }
}

/// How often a row repeats another writer's step until the entry it touched
/// shows a new change time: a coarse kernel clock keeps it for a few
/// milliseconds, and the row waits on the file, never on a clock.
const TRIES: usize = 1_000_000;

/// An entry's identity and change time, read without following a link.
fn stamp(path: &Path) -> (u64, u64, i64, i64) {
    let meta = std::fs::symlink_metadata(path).expect("lstat");
    (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec())
}

/// Run `step` until `path`'s identity or change time differs from `before`.
fn until_changed(path: &Path, before: (u64, u64, i64, i64), mut step: impl FnMut()) {
    for _ in 0..TRIES {
        step();
        if stamp(path) != before {
            return;
        }
    }
    panic!("{} kept its change time over {TRIES} tries", path.display());
}

/// P-inplace (times put back): the rewrite in place also sets the old
/// modification time back, same length. The change time, which no writer
/// can set, still moves: the save refuses and the other bytes stay.
#[test]
fn p_inplace_rewrite_with_its_old_mtime_refuses() {
    for mode in MODES {
        let row = format!("P-inplace-mtime/{mode:?}");
        let (dir, target) = fixture(0o600);
        let modelled = std::fs::metadata(&target).expect("stat");
        let (old, before) = (modelled.modified().expect("mtime"), stamp(&target));
        let armed = seams::arm(
            dir.path(),
            Seams {
                before_verify: Some(Box::new(move |target, _scratch| {
                    until_changed(target, before, || {
                        std::fs::write(target, b"sub").expect("rewrite in place");
                        let file = std::fs::File::options().write(true).open(target);
                        file.and_then(|f| f.set_modified(old))
                            .expect("old time back");
                    });
                    let now = std::fs::metadata(target).expect("stat");
                    assert_eq!(
                        (now.modified().expect("mtime"), now.len()),
                        (old, 3),
                        "the modification time and length are as modelled"
                    );
                })),
                ..Seams::default()
            },
        );
        assert_changed(
            write_atomic(&target, b"new", mode, Symlink::Replace),
            &target,
            &row,
        );
        drop(armed);
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"sub",
            "{row}: the other bytes"
        );
        assert_eq!(names(dir.path()), ["state.json"], "{row}: no scratch left");
    }
}

/// P-relink: the target is a link, and another writer either swaps in a link
/// of its own (which may reuse the old inode number) or renames the link away
/// and back (same inode, a new change time) before the final checks. The
/// save refuses and the link another writer left stays.
#[test]
fn p_a_link_touched_by_another_writer_refuses() {
    for (case, swap) in [("relink", true), ("renamed-back", false)] {
        for mode in MODES {
            let row = format!("P-relink/{case}/{mode:?}");
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join(TARGET);
            for name in ["linked.json", "theirs.json"] {
                std::fs::write(dir.path().join(name), b"old").expect("a link target");
            }
            std::os::unix::fs::symlink("linked.json", &target).expect("link");
            let before = stamp(&target);
            let armed = seams::arm(
                dir.path(),
                Seams {
                    before_verify: Some(Box::new(move |target, _scratch| {
                        let aside = target.with_extension("aside");
                        until_changed(target, before, || {
                            if swap {
                                std::fs::remove_file(target).expect("unlink");
                                std::os::unix::fs::symlink("theirs.json", target).expect("relink");
                            } else {
                                std::fs::rename(target, &aside).expect("rename away");
                                std::fs::rename(&aside, target).expect("rename back");
                            }
                        });
                    })),
                    ..Seams::default()
                },
            );
            assert_changed(
                write_atomic(&target, b"new", mode, Symlink::Replace),
                &target,
                &row,
            );
            drop(armed);
            let left = if swap { "theirs.json" } else { "linked.json" };
            assert_eq!(
                std::fs::read_link(&target).expect("still a link"),
                Path::new(left),
                "{row}: the link stays"
            );
            assert_eq!(
                names(dir.path()),
                ["linked.json", "state.json", "theirs.json"],
                "{row}: no scratch left"
            );
        }
    }
}
