// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11-d2 (T10): `forced_revision` is compatible in both directions.
//!
//! Forward: an authority file written before A11 has no such key, and the
//! entry must read as never force-tried. Backward: an entry that was never
//! force-tried must not write the key at all, because a pre-A11 binary reads
//! `AuthorityEntry` with `deny_unknown_fields` and would refuse the whole
//! authority file after a rollback.

use super::super::AuthorityEntry;

const PRE_A11_ENTRY: &str = r#"{
    "generation": "fedcba9876543210fedcba9876543210",
    "token_revision": 3,
    "authorization_epoch": 1,
    "descriptor_revision": "0000000000000000000000000000000000000000000000000000000000000000",
    "record_basename": null,
    "record_sha256": null,
    "state": "connected",
    "legacy_migration": null
}"#;

#[test]
fn pre_a11_authority_entry_reads_as_never_force_tried() {
    let entry: AuthorityEntry =
        serde_json::from_str(PRE_A11_ENTRY).expect("a pre-A11 entry must still load");
    assert_eq!(entry.forced_revision, None);
    assert_eq!(entry.token_revision, 3);
}

#[test]
fn never_forced_entry_writes_no_forced_revision_key() {
    let entry: AuthorityEntry = serde_json::from_str(PRE_A11_ENTRY).expect("fixture loads");
    let written = serde_json::to_value(&entry).expect("entry serializes");
    let object = written.as_object().expect("an entry is a JSON object");
    assert!(
        !object.contains_key("forced_revision"),
        "a never-forced entry must stay readable by a pre-A11 binary (deny_unknown_fields); \
         wrote {written}"
    );
}
