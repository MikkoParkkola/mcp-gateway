// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The accessors return their own fields, and the identity's audit output is
//! unchanged by the move into this module.

use serde_json::json;

use super::VerifiedIdentity;

const ISSUER: &str = "https://idp.corp.test";
const EMAIL: &str = "person@corp.test";

fn full() -> VerifiedIdentity {
    VerifiedIdentity::checked(
        ISSUER.to_owned(),
        "subject-1".to_owned(),
        EMAIL.to_owned(),
        Some("Display Name".to_owned()),
        vec!["group-a".to_owned(), "group-b".to_owned()],
    )
    .expect("names someone")
}

/// Five distinct values, so an accessor returning another field fails.
#[test]
fn each_accessor_returns_its_own_field() {
    let identity = full();
    assert_eq!(identity.issuer(), ISSUER);
    assert_eq!(identity.subject(), "subject-1");
    assert_eq!(identity.email(), EMAIL);
    assert_eq!(identity.name(), Some("Display Name"));
    assert_eq!(identity.groups(), ["group-a", "group-b"]);
}

/// Audit output with no name and no groups: `name` is skipped when absent
/// (`skip_serializing_if`), `groups` is always written (the struct's serde
/// attributes in oidc/verified.rs).
#[test]
fn audit_output_without_name_or_groups_is_unchanged() {
    let identity = VerifiedIdentity::checked(
        ISSUER.to_owned(),
        "subject-1".to_owned(),
        EMAIL.to_owned(),
        None,
        Vec::new(),
    )
    .expect("names someone");
    assert_eq!(
        serde_json::to_value(&identity).expect("serializes"),
        json!({
            "subject": "subject-1",
            "email": EMAIL,
            "groups": [],
            "issuer": ISSUER,
        })
    );
}

/// Audit output with a name and groups: every field, under its own name.
#[test]
fn audit_output_with_name_and_groups_is_unchanged() {
    assert_eq!(
        serde_json::to_value(full()).expect("serializes"),
        json!({
            "subject": "subject-1",
            "email": EMAIL,
            "name": "Display Name",
            "groups": ["group-a", "group-b"],
            "issuer": ISSUER,
        })
    );
}
