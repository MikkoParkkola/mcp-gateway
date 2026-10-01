// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The lease's generic-failure arm (MIK-7324.COV.3). `acquire_lease` is private
//! to the store, and the public `open` cannot reach this arm on unix: it pins
//! the directory to 0700 first, and a lease of any other kind is refused as
//! unsafe before `try_acquire` runs.

use super::{LEASE, StoreError, acquire_lease};

#[test]
fn a_lease_that_cannot_be_opened_is_unavailable_not_owned() {
    let root = tempfile::tempdir().unwrap();

    let missing_parent = root.path().join("absent").join(LEASE);
    assert!(matches!(
        acquire_lease(&missing_parent),
        Err(StoreError::Unavailable)
    ));

    // Controls: an openable lease is held, and a second attempt is "owned".
    let lease = root.path().join(LEASE);
    let held = acquire_lease(&lease).expect("a fresh lease is acquired");
    assert!(matches!(
        acquire_lease(&lease),
        Err(StoreError::AlreadyOwned)
    ));
    drop(held);
}
