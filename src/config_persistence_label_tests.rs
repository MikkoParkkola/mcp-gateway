// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WRITER.6: a replacement on Linux keeps the target's access labels
//! (`security.selinux`, `security.SMACK64`), set on the still-empty scratch
//! and read back, or refuses `label-not-kept`. The kernel's label calls are
//! replaced by an injected store: setting `security.*` needs an LSM policy or
//! `CAP_SYS_ADMIN` that the test hosts lack. The real-LSM proof is a VM job.

use std::path::{Path, PathBuf};

use super::pin_tests::names;
use super::unix::seams::{self, Call, FakeLabels, Seams, Times};
use super::{FileMode, Symlink, copy_keeping_access, refusal_code, write_atomic};

const SELINUX: &str = "security.selinux";
const SMACK: &str = "security.SMACK64";
const NAMES: [&str; 2] = [SELINUX, SMACK];
const MODES: [FileMode; 2] = [FileMode::Inherit, FileMode::Private];
const CONTEXT: &[u8] = b"system_u:object_r:etc_t:s0\0";
const SMACK_LABEL: &[u8] = b"Secret";

/// A folder holding `state.json` ("old", mode 0600).
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("state.json");
    std::fs::write(&target, b"old").expect("target");
    (dir, target)
}

/// The store armed for every save into `dir`.
fn arm(dir: &Path, labels: &FakeLabels) -> seams::Armed {
    arm_with(dir, labels, Seams::default())
}

fn arm_with(dir: &Path, labels: &FakeLabels, seams: Seams) -> seams::Armed {
    seams::arm(
        dir,
        Seams {
            labels: Some(labels.clone()),
            ..seams
        },
    )
}

/// Every set went to a scratch that was still mode 0000 and empty.
fn assert_set_on_the_empty_scratch(labels: &FakeLabels, row: &str) {
    let sets = labels.sets();
    assert!(!sets.is_empty(), "{row}: the labels were set");
    for set in sets {
        assert_eq!(
            (set.mode & 0o7777, set.size),
            (0, 0),
            "{row}: {} set on a closed, empty scratch",
            set.name
        );
    }
}

/// The save refused with `code`, the target still holds "old", and no
/// scratch is left beside it.
fn assert_refused(result: std::io::Result<()>, code: &str, dir: &Path, target: &Path, row: &str) {
    let error = result.expect_err(&format!("{row}: the save refuses"));
    assert_eq!(
        refusal_code(&error),
        Some(code),
        "{row}: typed code ({error})"
    );
    assert_eq!(
        std::fs::read(target).expect("read"),
        b"old",
        "{row}: target kept"
    );
    assert_eq!(names(dir), ["state.json"], "{row}: no scratch left");
}

/// L1: both labels are kept by an `Inherit` and a `Private` replacement,
/// each set while the scratch is closed and empty.
#[test]
fn l1_a_replacement_keeps_both_labels() {
    for mode in MODES {
        let row = format!("L1/{mode:?}");
        let (dir, target) = fixture();
        let labels = FakeLabels::default();
        labels.label(&target, SELINUX, CONTEXT);
        labels.label(&target, SMACK, SMACK_LABEL);
        let armed = arm(dir.path(), &labels);
        write_atomic(&target, b"new", mode, Symlink::Replace)
            .unwrap_or_else(|e| panic!("{row}: the save goes through: {e}"));
        drop(armed);
        assert_eq!(
            labels.get(&target, SELINUX).as_deref(),
            Some(CONTEXT),
            "{row}: selinux"
        );
        assert_eq!(
            labels.get(&target, SMACK).as_deref(),
            Some(SMACK_LABEL),
            "{row}: smack"
        );
        assert_set_on_the_empty_scratch(&labels, &row);
    }
}

/// L1 (backup leg): a backup keeps its source's labels.
#[test]
fn l1_a_backup_keeps_the_sources_labels() {
    let (dir, source) = fixture();
    let backup = dir.path().join("state.json.bak");
    let labels = FakeLabels::default();
    labels.label(&source, SELINUX, CONTEXT);
    labels.label(&source, SMACK, SMACK_LABEL);
    let armed = arm(dir.path(), &labels);
    copy_keeping_access(&source, &backup).expect("the backup goes through");
    drop(armed);
    assert_eq!(
        labels.get(&backup, SELINUX).as_deref(),
        Some(CONTEXT),
        "L1/backup: selinux"
    );
    assert_eq!(
        labels.get(&backup, SMACK).as_deref(),
        Some(SMACK_LABEL),
        "L1/backup: smack"
    );
    assert_set_on_the_empty_scratch(&labels, "L1/backup");
}

/// L1b: a scratch the folder already gives the target's label needs no set,
/// so a save without relabel rights still goes through.
#[test]
fn l1b_a_label_the_scratch_already_has_needs_no_set() {
    let (dir, target) = fixture();
    let labels = FakeLabels::default();
    labels.label(&target, SELINUX, CONTEXT);
    labels.folder_default(SELINUX, CONTEXT);
    labels.fail(Call::Set, SELINUX, libc::EPERM, Times::Always);
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace)
        .expect("L1b: the save goes through");
    drop(armed);
    assert!(labels.sets().is_empty(), "L1b: nothing was set");
}

/// L1c: an ordinary `SELinux` file (no SMACK label) keeps its context.
#[test]
fn l1c_one_label_present_and_one_absent_keeps_the_present_one() {
    let (dir, target) = fixture();
    let labels = FakeLabels::default();
    labels.label(&target, SELINUX, CONTEXT);
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace)
        .expect("L1c: the save goes through");
    drop(armed);
    assert_eq!(
        labels.get(&target, SELINUX).as_deref(),
        Some(CONTEXT),
        "L1c: selinux"
    );
    assert_eq!(
        labels.get(&target, SMACK),
        None,
        "L1c: no smack label invented"
    );
}

/// A target carrying both labels, with the store armed and `knob` applied.
fn labelled(knob: impl FnOnce(&FakeLabels)) -> (tempfile::TempDir, PathBuf, FakeLabels) {
    let (dir, target) = fixture();
    let labels = FakeLabels::default();
    labels.label(&target, SELINUX, CONTEXT);
    labels.label(&target, SMACK, SMACK_LABEL);
    knob(&labels);
    (dir, target, labels)
}

/// L2: a set the kernel refuses (no relabel right) refuses the save, naming
/// the attribute and the uid but never the label's value.
#[test]
fn l2_a_refused_set_refuses_label_not_kept() {
    for name in NAMES {
        let row = format!("L2/{name}");
        let (dir, target, labels) =
            labelled(|labels| labels.fail(Call::Set, name, libc::EPERM, Times::Always));
        let armed = arm(dir.path(), &labels);
        let result = write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace);
        drop(armed);
        let text = result
            .as_ref()
            .map_err(ToString::to_string)
            .err()
            .unwrap_or_default();
        assert_refused(result, "label-not-kept", dir.path(), &target, &row);
        let me = rustix::process::geteuid().as_raw();
        assert!(text.contains(name), "{row}: names {name}: {text}");
        assert!(
            text.contains(&format!("uid {me}")),
            "{row}: names the uid: {text}"
        );
        assert!(
            !text.contains("etc_t") && !text.contains("Secret"),
            "{row}: never the value: {text}"
        );
    }
}

/// L3: a set that does not read back as the target's bytes refuses.
#[test]
fn l3_a_read_back_that_differs_refuses_label_not_kept() {
    for name in NAMES {
        let row = format!("L3/{name}");
        let (dir, target, labels) = labelled(|labels| labels.rewrite_after_set(name, b"other"));
        let armed = arm(dir.path(), &labels);
        let result = write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace);
        drop(armed);
        assert_refused(result, "label-not-kept", dir.path(), &target, &row);
    }
}

/// L4: a label the writer cannot read (an error other than "none" or "not
/// supported") refuses before any byte is written; one failed read is
/// enough, and no retry passes over it.
#[test]
fn l4_an_unreadable_label_refuses_before_any_byte() {
    for name in NAMES {
        let row = format!("L4/{name}");
        let (dir, target, labels) =
            labelled(|labels| labels.fail(Call::Read, name, libc::EIO, Times::Once));
        let armed = arm(dir.path(), &labels);
        let result = write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace);
        let events = armed.events();
        drop(armed);
        assert_refused(result, "label-not-kept", dir.path(), &target, &row);
        assert!(
            !events.contains(&"write"),
            "{row}: no byte written: {events:?}"
        );
    }
}

/// L5: a target with no labels saves as before, and gains none.
#[test]
fn l5_a_target_without_labels_saves_and_gains_none() {
    let (dir, target) = fixture();
    let labels = FakeLabels::default();
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace).expect("L5: saved");
    drop(armed);
    for name in NAMES {
        assert_eq!(labels.get(&target, name), None, "L5: no {name}");
    }
}

/// L5b: a kernel without an LSM ("not supported" for both) saves as before.
#[test]
fn l5b_labels_not_supported_save_as_before() {
    let (dir, target) = fixture();
    let labels = FakeLabels::default();
    for name in NAMES {
        labels.fail(Call::Read, name, libc::EOPNOTSUPP, Times::Always);
    }
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace).expect("L5b: saved");
    drop(armed);
}

/// L6: a label changed on the scratch after it was set is another writer's
/// work: the save refuses `target-changed`.
#[test]
fn l6_a_scratch_label_changed_before_the_rename_refuses() {
    let (dir, target, labels) = labelled(|_| {});
    let store = labels.clone();
    let armed = arm_with(
        dir.path(),
        &labels,
        Seams {
            before_verify: Some(Box::new(move |_target, scratch| {
                store.label(scratch, SELINUX, b"other");
            })),
            ..Seams::default()
        },
    );
    let result = write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace);
    drop(armed);
    assert_refused(result, "target-changed", dir.path(), &target, "L6");
}

/// L7: a backup takes its labels from the source it reads, never from
/// whatever the source's name points at meanwhile: another file is swapped
/// in by name just after the source is opened and put back once the labels
/// have been read.
#[test]
fn l7_a_backup_keeps_the_labels_of_its_source_as_read() {
    let (dir, source, labels) = labelled(|_| {});
    let backup = dir.path().join("state.json.bak");
    let parked = dir.path().join("state.orig");
    let (store, swap_from, source_name) = (labels.clone(), parked.clone(), source.clone());
    // Put back once the labels are read; before the final checks at the
    // latest, so a writer that reads no labels fails on the label alone.
    let put_back = move || {
        if parked.exists() {
            std::fs::rename(&parked, &source_name).expect("put the source back");
        }
    };
    let also_put_back = put_back.clone();
    let armed = arm_with(
        dir.path(),
        &labels,
        Seams {
            after_model: Some(Box::new(move |source, _backup| {
                std::fs::rename(source, &swap_from).expect("park the source");
                std::fs::write(source, b"sub").expect("swap another file in");
                store.label(source, SELINUX, b"other");
            })),
            after_labels_read: Some(Box::new(move |_backup, _scratch| put_back())),
            before_verify: Some(Box::new(move |_backup, _scratch| also_put_back())),
            ..Seams::default()
        },
    );
    copy_keeping_access(&source, &backup).expect("L7: the backup goes through");
    drop(armed);
    assert_eq!(
        labels.get(&backup, SELINUX).as_deref(),
        Some(CONTEXT),
        "L7: source's own label"
    );
}

/// L8a: the target relabelled in place before the rename refuses.
#[test]
fn l8a_a_target_relabelled_during_the_save_refuses() {
    let (dir, target, labels) = labelled(|_| {});
    let store = labels.clone();
    let armed = arm_with(
        dir.path(),
        &labels,
        Seams {
            before_verify: Some(Box::new(move |target, _scratch| {
                store.label(target, SELINUX, b"other");
            })),
            ..Seams::default()
        },
    );
    let result = write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace);
    drop(armed);
    assert_refused(result, "target-changed", dir.path(), &target, "L8a");
}

/// L8b: another file put at the target's name while its labels are read
/// refuses before any byte, and stays as it was put.
#[test]
fn l8b_a_target_swapped_while_its_labels_are_read_refuses() {
    let (dir, target, labels) = labelled(|_| {});
    let armed = arm_with(
        dir.path(),
        &labels,
        Seams {
            after_labels_read: Some(Box::new(|target, _scratch| {
                let other = target.with_extension("sub");
                std::fs::write(&other, b"sub").expect("another file");
                std::fs::rename(&other, target).expect("swap it in");
            })),
            ..Seams::default()
        },
    );
    let result = write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace);
    let events = armed.events();
    drop(armed);
    let error = result.expect_err("L8b: the save refuses");
    assert_eq!(
        refusal_code(&error),
        Some("target-changed"),
        "L8b: code ({error})"
    );
    assert_eq!(
        std::fs::read(&target).expect("read"),
        b"sub",
        "L8b: the swapped file stays"
    );
    assert_eq!(names(dir.path()), ["state.json"], "L8b: no scratch left");
    assert!(
        !events.contains(&"write"),
        "L8b: no byte written: {events:?}"
    );
}

/// L9: a backup's source relabelled in place before the rename refuses.
#[test]
fn l9_a_backup_source_relabelled_during_the_copy_refuses() {
    let (dir, source, labels) = labelled(|_| {});
    let backup = dir.path().join("state.json.bak");
    let (store, relabel) = (labels.clone(), source.clone());
    let armed = arm_with(
        dir.path(),
        &labels,
        Seams {
            before_verify: Some(Box::new(move |_backup, _scratch| {
                store.label(&relabel, SELINUX, b"other");
            })),
            ..Seams::default()
        },
    );
    let error = copy_keeping_access(&source, &backup).expect_err("L9: the backup refuses");
    drop(armed);
    assert_eq!(
        refusal_code(&error),
        Some("target-changed"),
        "L9: code ({error})"
    );
    assert_eq!(
        names(dir.path()),
        ["state.json"],
        "L9: no backup, no scratch"
    );
}

/// L10: a target its owner cannot read, carrying no label, saves as before:
/// labels are read without opening the file.
#[test]
fn l10_an_unreadable_target_without_labels_saves() {
    use std::os::unix::fs::PermissionsExt as _;
    let (dir, target) = fixture();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let labels = FakeLabels::default();
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace).expect("L10: saved");
    drop(armed);
}

/// L11: a long context whose size changed between the probe and the read
/// is read again and kept.
#[test]
fn l11_a_long_label_that_grew_is_read_again_and_kept() {
    let long = vec![b'x'; 300];
    let (dir, target) = fixture();
    let labels = FakeLabels::default();
    labels.label(&target, SELINUX, &long);
    labels.erange_once();
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace).expect("L11: saved");
    drop(armed);
    assert_eq!(labels.get(&target, SELINUX), Some(long), "L11: kept whole");
}

/// A5: a filesystem without POSIX ACLs ("not supported" for the strip and
/// for the final check) saves as before, never as `target-changed`.
#[test]
fn a5_no_acl_support_saves_as_before() {
    const ACL: &str = "system.posix_acl_access";
    let (dir, target) = fixture();
    let labels = FakeLabels::default();
    labels.fail(Call::AclStrip, ACL, libc::EOPNOTSUPP, Times::Always);
    labels.fail(Call::AclRead, ACL, libc::EOPNOTSUPP, Times::Always);
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace).expect("A5: saved");
    drop(armed);
}

/// O1: the ACL is stripped and the labels read and set before the first
/// byte; the owner, group and mode follow the bytes.
#[test]
fn o1_labels_are_settled_before_any_byte() {
    let (dir, target, labels) = labelled(|_| {});
    let armed = arm(dir.path(), &labels);
    write_atomic(&target, b"new", FileMode::Inherit, Symlink::Replace).expect("O1: saved");
    let events = armed.events();
    drop(armed);
    assert_eq!(
        events,
        [
            "strip",
            "labels-read",
            "labels-set",
            "write",
            "sync",
            "check",
            "chown",
            "chmod"
        ],
        "O1: order"
    );
}
