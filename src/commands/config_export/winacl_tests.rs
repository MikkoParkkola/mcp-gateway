// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backup an import makes of the config it overwrites keeps an owner-only
//! config owner-only on Windows; a plain copy would take the folder's list.

use crate::commands::winacl_test_support::{assert_owner_only, owner_only_file};

#[test]
fn the_import_backup_of_an_owner_only_config_is_owner_only() {
    let row = "WINACL-B3";
    let (_dir, config) = owner_only_file(row, "claude_desktop_config.json");
    let backup = super::create_backup(&config)
        .unwrap()
        .expect("a config to back up");
    assert_owner_only(row, &backup);
}
