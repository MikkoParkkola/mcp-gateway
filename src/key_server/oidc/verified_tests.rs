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

fn source() -> syn::File {
    syn::parse_file(include_str!("verified.rs")).expect("verified.rs parses")
}

/// The struct has exactly its five fields, and none is visible outside this
/// module: the only form accepted is inherited visibility, so a new field or
/// any `pub` form fails here first.
#[test]
fn every_field_is_private() {
    let fields: Vec<(String, bool)> = source()
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(s) if s.ident == "VerifiedIdentity" => Some(s),
            _ => None,
        })
        .expect("the struct")
        .fields
        .iter()
        .map(|f| {
            let name = f.ident.as_ref().expect("a named field").to_string();
            (name, matches!(f.vis, syn::Visibility::Inherited))
        })
        .collect();
    assert_eq!(
        fields,
        ["subject", "email", "name", "groups", "issuer"].map(|n| (n.to_owned(), true)),
    );
}

/// The test constructor and its chainers skip `checked`, so they exist only
/// in this crate's test build: one `#[cfg(test)]` impl, every fn in it
/// `pub(crate)`, and no other impl defining any of them.
#[test]
fn the_test_constructor_is_crate_only_and_test_only() {
    const NAMES: [&str; 6] = [
        "for_test",
        "with_subject",
        "with_email",
        "with_name",
        "with_groups",
        "with_issuer",
    ];
    let mut found = Vec::new();
    for item in source().items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        let gated = block.attrs.iter().any(|a| {
            a.path().is_ident("cfg") && a.parse_args::<syn::Ident>().is_ok_and(|i| i == "test")
        });
        for inner in &block.items {
            let syn::ImplItem::Fn(f) = inner else {
                continue;
            };
            let name = f.sig.ident.to_string();
            if !NAMES.contains(&name.as_str()) {
                continue;
            }
            let crate_only = matches!(&f.vis, syn::Visibility::Restricted(r)
                if r.in_token.is_none() && r.path.is_ident("crate"));
            found.push((name, gated, crate_only));
        }
    }
    assert_eq!(found, NAMES.map(|n| (n.to_owned(), true, true)));
}
