// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rewriting an imported capability file keeps an
//! owner-only file owner-only on Windows; capability YAML can hold tokens.

use crate::commands::winacl_test_support::{assert_owner_only, owner_only_file};

#[tokio::test]
async fn rewriting_a_capability_file_keeps_it_owner_only() {
    let row = "WINACL-C1";
    let (_dir, path) = owner_only_file(row, "imported.yaml");
    super::write_atomic(&path, "name: imported\n")
        .await
        .unwrap();
    assert_owner_only(row, &path);
}
