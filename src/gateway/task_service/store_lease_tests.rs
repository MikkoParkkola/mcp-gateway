// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `acquire_lease` refusals that the store's public open path cannot reach on
//! unix: there, `prepare_dir` has already judged the directory private.

use super::{StoreError, acquire_lease};

/// A lease that cannot be created (its directory is gone) is not custody:
/// the store refuses as unavailable rather than pretending to hold it.
#[test]
fn a_lease_that_cannot_be_created_leaves_the_store_unavailable() {
    let root = tempfile::TempDir::new().expect("tempdir");
    let lease = root.path().join("gone").join("lease");

    let refused = acquire_lease(&lease).err();

    assert_eq!(refused, Some(StoreError::Unavailable));
}
