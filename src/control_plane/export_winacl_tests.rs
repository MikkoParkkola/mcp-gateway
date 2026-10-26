// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Saving the export cursor keeps an owner-only cursor
//! file owner-only on Windows. The folder hands Everyone full access.

use super::*;
use crate::private_fs::test_support::{assert_owner_only, everyone_full_dir, plant_owner_only};

#[test]
fn saving_the_export_cursor_keeps_an_owner_only_file_owner_only() {
    let row = "WINACL-C3";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("cursor.json");
    std::fs::write(&path, serde_json::to_vec(&ExportCursor::default()).unwrap()).unwrap();
    plant_owner_only(row, &path);
    let exp = LogExporter::open(
        ExportSource::Governance,
        dir.path().join("audit.jsonl"),
        path.clone(),
    )
    .unwrap();
    exp.persist_cursor(&exp.cursor().clone()).unwrap();
    assert_owner_only(row, &path, false);
}
