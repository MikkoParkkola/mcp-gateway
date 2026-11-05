// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored identity becomes a verified one only through the checked
//! constructor: `StoredIdentity` has one way out, it calls
//! `VerifiedIdentity::checked`, and no `From` conversion exists anywhere.

const RECORDS: &str = include_str!("records.rs");

/// The body of `impl StoredIdentity { ... }` in records.rs.
fn stored_impl() -> &'static str {
    RECORDS
        .split("\nimpl StoredIdentity {\n")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("records.rs has `impl StoredIdentity`")
}

#[test]
fn a_stored_identity_is_verified_only_through_checked() {
    let body = stored_impl();
    let ways_out: Vec<&str> = body
        .split("fn ")
        .skip(1)
        .filter(|f| {
            f.split('{')
                .next()
                .is_some_and(|sig| sig.contains("VerifiedIdentity"))
        })
        .collect();
    assert_eq!(
        ways_out.len(),
        1,
        "one way to a VerifiedIdentity: {ways_out:?}"
    );
    assert!(
        ways_out[0].contains("VerifiedIdentity::checked("),
        "and it goes through checked: {}",
        ways_out[0]
    );
}

#[test]
fn no_conversion_turns_a_stored_identity_into_a_verified_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![root];
    let mut offenders = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("src dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("source");
                for spelling in ["From<StoredIdentity>", "From<&StoredIdentity>"] {
                    if text.contains(spelling) {
                        offenders.push(format!("{}: {spelling}", path.display()));
                    }
                }
            }
        }
    }
    // This file names both spellings in its own list, and only there.
    offenders.retain(|o| !o.contains("stored_identity_pin_tests.rs"));
    assert!(offenders.is_empty(), "{offenders:?}");
}
