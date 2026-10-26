// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rollback after a native create that timed out (ADR-028 §7 as amended for
//! B2b): the abandoned call may still land, so its entry is never deleted and
//! its index row stays live for the unused listing.

use std::collections::BTreeSet;

use super::tests::{Fake, count, three, vault};
use super::{SaveError, StoreError, save_secrets, unused_entries};

#[test]
fn a_timed_out_create_is_never_deleted_and_a_late_landing_is_listed() {
    let (dir, vault) = vault();
    let mut store = Fake::new();
    store.time_out_create = Some((2, false));
    let result = save_secrets(&vault, &store, &three(), |_| Ok::<_, ()>(()));
    assert!(
        matches!(result, Err(SaveError::Store(StoreError::TimedOut))),
        "{result:?}"
    );
    let live = super::index::Index::at(dir.path()).live().unwrap();
    assert_eq!(live.len(), 1, "only the timed-out row stays live: {live:?}");
    let late = live[0].name.clone();
    let calls = store.calls();
    assert!(
        !calls.contains(&format!("delete {late}")),
        "a timed-out create was deleted: {calls:?}"
    );
    // The first entry, created for certain, was removed.
    assert_eq!(count(&calls, "delete"), 1, "{calls:?}");
    assert!(store.names().is_empty());

    // The abandoned call lands after rollback: the listing finds it.
    assert!(
        unused_entries(&vault, &[&store], &BTreeSet::new())
            .unwrap()
            .is_empty()
    );
    store.land(&late);
    let unused = unused_entries(&vault, &[&store], &BTreeSet::new()).unwrap();
    assert_eq!(unused.len(), 1, "{unused:?}");
    assert_eq!(unused[0].name, late);
}

#[test]
fn a_timed_out_create_that_already_landed_is_still_kept() {
    let (dir, vault) = vault();
    let mut store = Fake::new();
    store.time_out_create = Some((1, true));
    let result = save_secrets(&vault, &store, &three(), |_| Ok::<_, ()>(()));
    assert!(
        matches!(result, Err(SaveError::Store(StoreError::TimedOut))),
        "{result:?}"
    );
    let calls = store.calls();
    assert_eq!(count(&calls, "delete"), 0, "{calls:?}");
    let live = super::index::Index::at(dir.path()).live().unwrap();
    assert_eq!(live.len(), 1, "{live:?}");
    assert_eq!(store.names(), vec![live[0].name.clone()]);
}

#[test]
fn a_timed_out_refusal_names_the_kept_entry_and_carries_no_value() {
    let reason = StoreError::TimedOut.reason();
    assert!(reason.contains("did not answer in time"), "{reason}");
    assert!(reason.contains("listed as unused"), "{reason}");
}

#[test]
fn the_kept_entry_warning_names_the_entry_and_never_the_value() {
    let (_dir, vault) = vault();
    let mut store = Fake::new();
    store.time_out_create = Some((1, true));
    let secret = [super::NewSecret {
        field: "auth.bearer_token",
        value: b"kc-sentinel-7f3a",
    }];
    let records = crate::test_log_capture::records(|| {
        let _ = save_secrets(&vault, &store, &secret, |_| Ok::<_, ()>(()));
    });
    let shown = format!("{records:?}");
    assert!(
        !shown.contains("kc-sentinel-7f3a"),
        "a value reached a log: {shown}"
    );
    // Entry names are not secret (ADR-028 rule 7); this line is how an
    // operator finds the kept entry.
    assert_eq!(
        crate::test_log_capture::count(&records, "WARN", "kept and listed as unused"),
        1,
        "{shown}"
    );
    assert!(shown.contains(&store.names()[0]), "{shown}");
}
