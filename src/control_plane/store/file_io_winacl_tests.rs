// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Table row for the control-plane store's own atomic writer: a collection it
//! writes in a folder that hands Everyone full access is owner-only, over an
//! existing file as well as a new one.

use super::{FaultPoint, write_atomic};
use crate::private_fs::test_support::{assert_owner_only, everyone_full_dir};

#[test]
fn the_store_writer_makes_owner_only_collections() {
    let row = "WINACL-T4 control-plane store write_atomic";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("grants.json");
    write_atomic(&path, b"[]", FaultPoint::None).unwrap();
    assert_owner_only(row, &path, false);
    write_atomic(&path, b"[1]", FaultPoint::None).unwrap();
    assert_owner_only(row, &path, false);
}
