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

/// The upgrade's config backup keeps an owner-only config owner-only.
#[test]
fn the_upgrade_backup_of_an_owner_only_config_is_owner_only() {
    let row = "WINACL-B2";
    let (dir, _config) = owner_only_file(row, "gateway.yaml");
    let backup = super::backup_config(dir.path(), "3.5.1")
        .unwrap()
        .expect("a config to back up");
    assert_owner_only(row, &backup);
}
