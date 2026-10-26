// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Writing the upgrade stamp keeps an owner-only
//! stamp owner-only on Windows.

use crate::commands::winacl_test_support::{assert_owner_only, owner_only_file};

#[test]
fn writing_the_upgrade_stamp_keeps_it_owner_only() {
    let row = "WINACL-C5";
    let (_dir, path) = owner_only_file(row, "version-stamp");
    super::write_stamp(&path, "4.0.0").unwrap();
    assert_owner_only(row, &path);
}
