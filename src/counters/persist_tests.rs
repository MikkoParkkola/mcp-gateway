// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `counters.json` (test plan T12, T14-T18, T32): what a save keeps,
//! what a bad file costs, and that a save never holds the store's lock.

use chrono_tz::UTC;

use super::persist::{CounterFile, Restored, Stage};
use super::*;

const T0: u64 = 1_792_454_400;
const VERSION: &str = "4.0.0";

fn call() -> Call<'static> {
    Call {
        caller: "key:a",
        server: Label::Known("s"),
        tool: Label::Known("t"),
        tally: Tally::default(),
    }
}

fn total(store: &CounterStore, now: u64) -> u64 {
    store
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            now,
            &UTC,
        )
        .points
        .iter()
        .map(|p| p.v)
        .sum()
}

fn restore(dir: &std::path::Path, now: u64, version: &str) -> Restored {
    CounterFile::restore(dir.join("counters.json"), now, version, &UTC)
}

#[test]
fn t12_a_saved_store_restores_its_series_markers_and_since() {
    let dir = tempfile::tempdir().unwrap();
    let first = restore(dir.path(), T0, VERSION);
    assert_eq!(
        first.store.since(),
        T0,
        "an empty store's first start sets since"
    );
    first.store.record(&call(), T0 + 10, &UTC);
    first.store.mark(MarkerKind::SwitchOff, Some("s"), T0 + 11);
    first.file.save(&first.store, VERSION, T0 + 12);
    let again = restore(dir.path(), T0 + 600, VERSION);
    assert_eq!(again.store.since(), T0, "since is restored, not reset");
    assert_eq!(total(&again.store, T0 + 600), 1);
    let kinds: Vec<MarkerKind> = again.store.markers(0).iter().map(|m| m.kind).collect();
    assert_eq!(kinds, vec![MarkerKind::SwitchOff, MarkerKind::Restart]);
}

#[test]
fn t14_a_bad_file_is_moved_aside_never_replaced_and_the_next_save_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("counters.json");
    for bad in [&b"{not json"[..], br#"{"version":99}"#] {
        std::fs::write(&path, bad).unwrap();
        let first = restore(dir.path(), T0, VERSION);
        assert_eq!(first.warnings, 1);
        assert_eq!(total(&first.store, T0), 0);
        let aside = dir.path().join(format!("counters.json.unreadable-{T0}"));
        assert_eq!(std::fs::read(&aside).unwrap(), bad, "original bytes kept");
        assert!(!path.exists());
        // A second failure in the same second takes a new name.
        std::fs::write(&path, b"also bad").unwrap();
        let _second = restore(dir.path(), T0, VERSION);
        assert_eq!(
            std::fs::read(&aside).unwrap(),
            bad,
            "first quarantine untouched"
        );
        let next = dir.path().join(format!("counters.json.unreadable-{T0}-1"));
        assert_eq!(std::fs::read(&next).unwrap(), b"also bad");
        first.file.save(&first.store, VERSION, T0 + 1);
        assert!(
            restore(dir.path(), T0 + 2, VERSION).warnings == 0,
            "the save is valid"
        );
        std::fs::remove_file(&aside).unwrap();
        std::fs::remove_file(&next).unwrap();
        std::fs::remove_file(&path).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn t15_a_failed_move_aside_disables_every_save() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("counters.json");
    std::fs::write(&path, b"{not json").unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let restored = restore(dir.path(), T0, VERSION);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(restored.file.disabled());
    restored.store.record(&call(), T0 + 1, &UTC);
    assert!(
        !restored
            .file
            .save_unless_busy(&restored.store, VERSION, T0 + 2)
    );
    restored.file.save(&restored.store, VERSION, T0 + 3);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"{not json",
        "never overwritten"
    );
}

#[test]
fn t16_a_save_skipped_while_another_writes_is_caught_up_later() {
    let dir = tempfile::tempdir().unwrap();
    let restored = restore(dir.path(), T0, VERSION);
    restored.store.record(&call(), T0 + 1, &UTC);
    {
        let _held = restored.file.hold_for_test();
        assert!(
            !restored
                .file
                .save_unless_busy(&restored.store, VERSION, T0 + 2)
        );
    }
    assert!(
        restored
            .file
            .save_unless_busy(&restored.store, VERSION, T0 + 3)
    );
    assert_eq!(
        total(&restore(dir.path(), T0 + 4, VERSION).store, T0 + 4),
        1
    );
}

#[test]
fn t17_neither_serialization_nor_the_write_holds_the_store_lock() {
    let dir = tempfile::tempdir().unwrap();
    let restored = restore(dir.path(), T0, VERSION);
    restored.store.record(&call(), T0 + 1, &UTC);
    let seen = std::cell::RefCell::new(Vec::new());
    restored
        .file
        .save_with(&restored.store, VERSION, T0 + 2, &|stage| {
            // A record would block here if the stage held the store's lock.
            seen.borrow_mut()
                .push((stage, restored.store.lock_is_free()));
        });
    assert_eq!(
        *seen.borrow(),
        vec![(Stage::Serializing, true), (Stage::Writing, true)]
    );
}

#[cfg(unix)]
#[test]
fn t18_the_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let restored = restore(dir.path(), T0, VERSION);
    restored.file.save(&restored.store, VERSION, T0 + 1);
    let mode = std::fs::metadata(dir.path().join("counters.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn t32_a_file_saved_by_another_version_marks_an_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let old = restore(dir.path(), T0, "3.5.1");
    old.file.save(&old.store, "3.5.1", T0 + 1);
    let new = restore(dir.path(), T0 + 2, VERSION);
    let upgrades: Vec<Option<String>> = new
        .store
        .markers(0)
        .into_iter()
        .filter(|m| m.kind == MarkerKind::Upgrade)
        .map(|m| m.subject)
        .collect();
    assert_eq!(upgrades, vec![Some("3.5.1 → 4.0.0".to_owned())]);
    new.file.save(&new.store, VERSION, T0 + 3);
    let same = restore(dir.path(), T0 + 4, VERSION);
    let count = same
        .store
        .markers(0)
        .iter()
        .filter(|m| m.kind == MarkerKind::Upgrade)
        .count();
    assert_eq!(count, 1, "the same version adds no second upgrade marker");
    let fresh = tempfile::tempdir().unwrap();
    assert!(
        restore(fresh.path(), T0, VERSION)
            .store
            .markers(0)
            .is_empty(),
        "a fresh install marks nothing"
    );
}
