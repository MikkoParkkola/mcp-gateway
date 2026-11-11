// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The accessors return their own fields, and the identity's audit output is
//! unchanged by the move into this module.

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
    // Sorted, so the row does not pin source order; a second definition
    // of any name still fails on the count.
    found.sort();
    let mut expected = NAMES.map(|n| (n.to_owned(), true, true)).to_vec();
    expected.sort();
    assert_eq!(found, expected);
}

/// The struct's doc tests, as (fence, code) in source order.
fn doc_tests() -> Vec<(String, String)> {
    let item = source()
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Struct(s) if s.ident == "VerifiedIdentity" => Some(s),
            _ => None,
        })
        .expect("the struct");
    let mut tests = Vec::new();
    let mut open: Option<(String, Vec<String>)> = None;
    for attr in item.attrs.iter().filter(|a| a.path().is_ident("doc")) {
        let syn::Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = &nv.value
        else {
            continue;
        };
        let value = s.value();
        let line = value.strip_prefix(' ').unwrap_or(&value).to_owned();
        match (line.strip_prefix("```"), open.take()) {
            (Some(_), Some((fence, code))) => tests.push((fence, code.join("\n"))),
            (Some(fence), None) => open = Some((fence.to_owned(), Vec::new())),
            (None, Some((fence, mut code))) => {
                code.push(line);
                open = Some((fence, code));
            }
            (None, None) => {}
        }
    }
    tests
}

/// Every field a code block names, by struct-literal key or field access.
#[derive(Default)]
struct Named(Vec<String>);

impl<'ast> syn::visit::Visit<'ast> for Named {
    fn visit_expr_struct(&mut self, lit: &'ast syn::ExprStruct) {
        for field in &lit.fields {
            if let syn::Member::Named(ident) = &field.member {
                self.0.push(ident.to_string());
            }
        }
        syn::visit::visit_expr_struct(self, lit);
    }

    fn visit_expr_field(&mut self, access: &'ast syn::ExprField) {
        if let syn::Member::Named(ident) = &access.member {
            self.0.push(ident.to_string());
        }
        syn::visit::visit_expr_field(self, access);
    }
}

/// rustdoc checks a `compile_fail` block's error code only on nightly, and CI
/// builds on stable, so each privacy block must fail for the field's privacy
/// and no other reason: it parses, names the type by its real public path,
/// and names only real fields.
#[test]
fn each_privacy_doc_test_fails_only_on_privacy() {
    const FIELDS: [&str; 5] = ["subject", "email", "name", "groups", "issuer"];
    let tests = doc_tests();
    let fences: Vec<&str> = tests.iter().map(|(f, _)| f.as_str()).collect();
    assert_eq!(
        fences,
        [
            "compile_fail,E0277",
            "compile_fail,E0277",
            "",
            "compile_fail,E0451",
            "compile_fail,E0451",
            "compile_fail,E0616",
            "compile_fail,E0616",
        ]
    );
    for (fence, code) in tests
        .iter()
        .filter(|(f, _)| f.starts_with("compile_fail,E04") || f.starts_with("compile_fail,E06"))
    {
        // rustdoc wraps a block in `fn main`; parse it the same way.
        let wrapped = format!("fn main() {{\n{code}\n}}");
        let parsed = syn::parse_file(&wrapped).unwrap_or_else(|e| panic!("{fence}: {e}\n{code}"));
        assert!(
            code.contains("mcp_gateway::key_server::oidc::VerifiedIdentity"),
            "{fence}: {code}"
        );
        let mut named = Named::default();
        syn::visit::Visit::visit_file(&mut named, &parsed);
        assert!(!named.0.is_empty(), "{fence} names no field");
        for field in &named.0 {
            assert!(
                FIELDS.contains(&field.as_str()),
                "{fence}: `{field}` is not a field"
            );
        }
    }
}

/// The id computed from the pair agrees with the id of the identity built from
/// it, including the pair a naive join would collide on; a pair that names no
/// one has no id.
#[test]
fn the_actor_id_from_a_pair_matches_the_identitys() {
    for (issuer, subject) in [
        (ISSUER, "subject-1"),
        ("https://idp/a", "b:c"),
        ("https://idp/a:b", "c"),
    ] {
        let identity = VerifiedIdentity::checked(
            issuer.to_owned(),
            subject.to_owned(),
            EMAIL.to_owned(),
            None,
            Vec::new(),
        )
        .expect("names someone");
        assert_eq!(
            VerifiedIdentity::stable_actor_id_for(issuer, subject),
            Some(identity.stable_actor_id()),
            "{issuer} {subject}"
        );
    }
    assert_ne!(
        VerifiedIdentity::stable_actor_id_for("https://idp/a", "b:c"),
        VerifiedIdentity::stable_actor_id_for("https://idp/a:b", "c"),
    );
    for (issuer, subject) in [("", "s"), (ISSUER, ""), ("  ", "s"), (ISSUER, " \t")] {
        assert_eq!(
            VerifiedIdentity::stable_actor_id_for(issuer, subject),
            None,
            "{issuer:?} {subject:?}"
        );
    }
}

/// The formula itself, written out: length-prefixed components, lengths in
/// bytes (`ü` is two), so a change to the shared formula fails here even
/// though both functions would still agree with each other.
#[test]
fn the_actor_id_is_length_prefixed_in_bytes() {
    assert_eq!(
        VerifiedIdentity::stable_actor_id_for("https://idp", "\u{fc}"),
        Some("oidc:11:https://idp:2:\u{fc}".to_owned())
    );
    assert_eq!(
        VerifiedIdentity::stable_actor_id_for("https://\u{fc}.test", "s"),
        Some("oidc:15:https://\u{fc}.test:1:s".to_owned())
    );
}
