// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture rows for the identity-source pin: each way to create, alias or
//! change an identity in production code is either a counted row or refused.

use super::super::fragments::{live_base, pin_table, scratch_table, without_first_row};
use super::{LEAVES, Scan, crate_scan, differences, file_fingerprint, scan_file};

const LEAF: &str = "src/identity_grants/subject.rs";
const OTHER: &str = "src/a.rs";

fn scanned(file: &str, source: &str) -> Scan {
    let mut scan = Scan::default();
    scan_file(
        file,
        &syn::parse_file(source).expect("fixture parses"),
        &mut scan,
    );
    scan
}

fn value(scan: &Scan, owner: &str, kind: &str) -> Option<String> {
    scan.rows
        .iter()
        .find(|((_, o, k), _)| o == owner && k == kind)
        .map(|(_, v)| v.clone())
}

fn count(source: &str, owner: &str, kind: &str) -> Option<String> {
    value(&scanned(OTHER, source), owner, kind)
}

fn refused(file: &str, source: &str) -> Vec<String> {
    scanned(file, source).refused
}

#[test]
fn one_direct_call_counts_one() {
    let n = count(
        "fn f() { let _ = GrantSubject::new(a, b, None); }",
        "f",
        "new",
    );
    assert_eq!(n.as_deref(), Some("1"));
}

#[test]
fn a_second_call_in_one_function_counts_two() {
    let source = "fn f() { GrantSubject::new(a, b, None); GrantSubject::new(c, d, None); }";
    assert_eq!(count(source, "f", "new").as_deref(), Some("2"));
}

#[test]
fn a_call_through_self_in_the_types_impl_is_counted() {
    let source = "impl GrantSubject { fn g() -> Self { Self::new(a, b, None).unwrap() } }";
    assert_eq!(
        count(source, "GrantSubject::g", "new").as_deref(),
        Some("1")
    );
}

#[test]
fn a_constructor_passed_as_a_value_is_counted() {
    let source =
        "fn f(x: Option<(String, String)>) { x.map(|(a, b)| a).and_then(GrantSubject::new); }";
    assert_eq!(count(source, "f", "new").as_deref(), Some("1"));
}

#[test]
fn a_test_only_call_is_not_counted() {
    let source = "#[cfg(test)] fn f() { GrantSubject::new(a, b, None); }";
    assert!(scanned(OTHER, source).rows.is_empty());
}

#[test]
fn each_constructor_of_each_type_is_counted() {
    let source = "fn f() { VerifiedIdentity::checked(a, b, c, None, v); CertIdentity::from_der(d); CertIdentity::parse(d); }";
    for kind in ["checked", "from_der", "parse"] {
        assert_eq!(count(source, "f", kind).as_deref(), Some("1"), "{kind}");
    }
}

#[test]
fn self_parse_inside_the_cert_impl_is_counted() {
    let source = "impl CertIdentity { fn h(d: &[u8]) { Self::parse(d); } }";
    assert_eq!(
        count(source, "CertIdentity::h", "parse").as_deref(),
        Some("1")
    );
}

#[test]
fn a_struct_literal_in_any_module_is_counted() {
    let source = "fn mint() -> VerifiedIdentity { VerifiedIdentity { subject: s, email: e, name: None, groups: g, issuer: i } }";
    assert_eq!(count(source, "mint", "literal").as_deref(), Some("1"));
    let own =
        "impl GrantSubject { fn x() -> Self { Self { authority: a, subject: s, label: None } } }";
    assert_eq!(
        count(own, "GrantSubject::x", "literal").as_deref(),
        Some("1")
    );
}

#[test]
fn a_renamed_import_or_type_alias_is_refused() {
    assert_eq!(
        refused(OTHER, "use crate::identity_grants::GrantSubject as G;").len(),
        1
    );
    assert_eq!(
        refused(OTHER, "type G = crate::identity_grants::GrantSubject;").len(),
        1
    );
}

#[test]
fn a_constructor_in_a_static_initializer_is_counted_under_its_name() {
    let source = "static S: LazyLock<GrantSubject> = LazyLock::new(|| GrantSubject::new(a, b, None).unwrap());";
    assert_eq!(count(source, "S", "new").as_deref(), Some("1"));
}

#[test]
fn a_qualified_constructor_path_is_refused_called_or_as_a_value() {
    // A projection whose `as` part only holds the type still reaches it.
    let projected = "fn f() { <Vec<GrantSubject> as IntoIterator>::Item::new(a, b, None); }";
    assert_eq!(refused(OTHER, projected).len(), 1);
    assert_eq!(
        refused(OTHER, "fn f() { <GrantSubject>::new(a, b, None); }").len(),
        1
    );
    assert_eq!(
        refused(
            OTHER,
            "fn f(x: Option<u8>) { x.map(<CertIdentity>::parse); }"
        )
        .len(),
        1
    );
}

#[test]
fn a_macro_naming_an_identity_type_is_a_row() {
    let source = "fn f() { let _ = vec![GrantSubject::new(a, b, None)]; }";
    assert_eq!(count(source, "f", "macro").as_deref(), Some("1"));
    let in_impl = "impl GrantSubject { fn f() { let _ = vec![Self::new(a, b, None)]; } }";
    assert_eq!(
        count(in_impl, "GrantSubject::f", "macro").as_deref(),
        Some("1")
    );
}

#[test]
fn each_defining_module_has_a_whole_file_hash_row() {
    let scan = crate_scan();
    for file in LEAVES {
        let row = scan
            .rows
            .get(&(file.to_owned(), "<file>".to_owned(), "file".to_owned()));
        assert!(row.is_some_and(|h| h.len() == 64), "{file}: {row:?}");
    }
}

/// The hash is of the exact bytes: whitespace, a comment or one character
/// inside a string literal changes it (`"admin"` and `"admin "` differ).
#[test]
fn any_byte_change_to_a_defining_module_changes_its_hash() {
    let base = file_fingerprint(b"const ADMIN: &str = \"admin\";\n");
    for edited in [
        &b"const ADMIN: &str = \"admin \";\n"[..],
        b"const ADMIN: &str  = \"admin\";\n",
        b"/// Doc.\nconst ADMIN: &str = \"admin\";\n",
    ] {
        assert_ne!(
            base,
            file_fingerprint(edited),
            "{}",
            String::from_utf8_lossy(edited)
        );
    }
    assert_eq!(base, file_fingerprint(b"const ADMIN: &str = \"admin\";\n"));
}

#[test]
fn a_child_module_or_include_in_a_leaf_module_is_refused() {
    assert_eq!(refused(LEAF, "mod extra;").len(), 1);
    assert_eq!(refused(LEAF, "mod extra { }").len(), 1);
    assert_eq!(refused(LEAF, r#"include!("extra.rs");"#).len(), 1);
    assert!(refused(LEAF, "#[cfg(test)] mod tests;").is_empty());
}

#[test]
fn a_crate_macro_near_identity_fields_is_refused() {
    assert_eq!(
        refused(LEAF, "fn f(x: &mut GrantSubject) { alter!(x); }").len(),
        1
    );
    assert_eq!(
        refused(OTHER, "impl GrantSubject { fn f(&self) { alter!(self); } }").len(),
        1
    );
    assert_eq!(
        refused(
            LEAF,
            "macro_rules! alter { ($x:expr) => { $x.subject.clear() }; }"
        )
        .len(),
        1
    );
}

#[test]
fn a_listed_std_macro_near_identity_fields_is_allowed() {
    let source = r#"impl GrantSubject { fn f(&self) -> String { format!("{}", self.subject) } }"#;
    assert!(refused(LEAF, source).is_empty());
    assert!(refused(OTHER, "fn f() { alter!(1); }").is_empty());
}

/// Every identity source in production code is a reviewed row; a new one, a
/// changed count or fingerprint, a stale row or a refused form fails and
/// prints what to add, fix or remove.
#[test]
fn every_identity_source_is_a_reviewed_row() {
    let wrong = differences(&crate_scan(), &pin_table("identity_sources"));
    assert!(
        wrong.is_empty(),
        "identity sources differ from identity_sources.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A real row held only by a fragment still counts.
#[test]
fn a_required_row_can_live_in_a_fragment() {
    let (base, moved) = without_first_row(&live_base("identity_sources"));
    let (_root, table) = scratch_table("identity_sources", &base, &[("0.tsv", &moved)]);
    let wrong = differences(&crate_scan(), &table);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A stale row in a fragment fails, naming the fragment.
#[test]
fn a_stale_fragment_row_fails_naming_it() {
    let stale = "src/nowhere.rs\tf\tnew\t1\tnone\n";
    let (_root, table) = scratch_table(
        "identity_sources",
        &live_base("identity_sources"),
        &[("0.tsv", stale)],
    );
    let wrong = differences(&crate_scan(), &table);
    assert!(
        wrong
            .iter()
            .any(|l| l.contains("stale") && l.contains("0.tsv")),
        "{}",
        wrong.join("\n")
    );
}

/// A key held by the base and by a fragment fails, naming both files.
#[test]
fn a_key_repeated_across_files_fails_naming_both() {
    let (_, moved) = without_first_row(&live_base("identity_sources"));
    let (_root, table) = scratch_table(
        "identity_sources",
        &live_base("identity_sources"),
        &[("0.tsv", &moved)],
    );
    let wrong = differences(&crate_scan(), &table);
    assert!(
        wrong
            .iter()
            .any(|l| l.contains("identity_sources.tsv") && l.contains("0.tsv")),
        "{}",
        wrong.join("\n")
    );
}

/// The struct `name` in the crate file `file`.
fn identity_struct(file: &str, name: &str) -> syn::ItemStruct {
    let path = super::super::packaged::crate_root().join(file);
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    syn::parse_file(&source)
        .expect("parses")
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Struct(s) if s.ident == name => Some(s),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{name} in {file}"))
}

/// The two sealed types this change pins, with their public paths and fields.
const SEALED: [(&str, &str, &str, &[&str]); 2] = [
    (
        "src/identity_grants/subject.rs",
        "GrantSubject",
        "mcp_gateway::identity_grants::GrantSubject",
        &["authority", "subject", "label"],
    ),
    (
        "src/mtls/identity/cert.rs",
        "CertIdentity",
        "mcp_gateway::mtls::CertIdentity",
        &[
            "common_name",
            "organizational_unit",
            "san_uris",
            "san_dns_names",
            "display_name",
            "quota_principal",
        ],
    ),
];

/// Each sealed type has exactly its listed fields, every one private: a new
/// field, or any `pub` form on one, fails here first.
#[test]
fn every_field_of_each_sealed_type_is_private() {
    for (file, name, _, fields) in SEALED {
        let found: Vec<(String, bool)> = identity_struct(file, name)
            .fields
            .iter()
            .map(|f| {
                let ident = f.ident.as_ref().expect("a named field").to_string();
                (ident, matches!(f.vis, syn::Visibility::Inherited))
            })
            .collect();
        let want: Vec<(String, bool)> = fields.iter().map(|f| ((*f).to_owned(), true)).collect();
        assert_eq!(found, want, "{name}");
    }
}

/// The type's doc tests, as (fence, code) in source order.
fn doc_tests(item: &syn::ItemStruct) -> Vec<(String, String)> {
    let doc: Vec<String> = item
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("doc"))
        .filter_map(|a| match &a.meta {
            syn::Meta::NameValue(nv) => match &nv.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        })
        .map(|line| line.strip_prefix(' ').unwrap_or(&line).to_owned())
        .collect();
    let mut tests = Vec::new();
    let mut open: Option<(String, Vec<String>)> = None;
    for line in doc {
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
/// builds on stable, so each block must fail for the field's privacy and no
/// other reason: it parses, imports the type by its real public path, and
/// names only real fields. One literal, one functional update and one
/// assignment per type, then a compiling twin first.
#[test]
fn each_compile_fail_doc_test_fails_only_on_privacy() {
    for (file, name, path, fields) in SEALED {
        let tests = doc_tests(&identity_struct(file, name));
        let fences: Vec<&str> = tests.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(
            fences,
            [
                "",
                "compile_fail,E0451",
                "compile_fail,E0451",
                "compile_fail,E0616"
            ],
            "{name}"
        );
        for (fence, code) in &tests {
            // rustdoc wraps a block in `fn main`; parse it the same way.
            let wrapped = format!("fn main() {{\n{code}\n}}");
            let parsed =
                syn::parse_file(&wrapped).unwrap_or_else(|e| panic!("{name} {fence}: {e}\n{code}"));
            assert!(
                code.starts_with(&format!("use {path};")),
                "{name} {fence}: {code}"
            );
            // A compiling twin proves itself by compiling, and may use other
            // types' fields (a certificate's parameters); only a failing
            // block must fail for one of this type's fields.
            if !fence.starts_with("compile_fail") {
                continue;
            }
            let mut named = Named::default();
            syn::visit::Visit::visit_file(&mut named, &parsed);
            assert!(!named.0.is_empty(), "{name} {fence} names no field");
            for field in &named.0 {
                assert!(
                    fields.contains(&field.as_str()),
                    "{name} {fence}: `{field}` is not a field"
                );
            }
        }
    }
}

/// A raw identifier names the same type or constructor as the plain one.
#[test]
fn a_raw_identifier_is_the_same_name() {
    let source = "fn f() { VerifiedIdentity::r#checked(a, b, c, None, v); r#GrantSubject::new(a, b, None); }";
    assert_eq!(count(source, "f", "checked").as_deref(), Some("1"));
    assert_eq!(count(source, "f", "new").as_deref(), Some("1"));
    assert_eq!(
        refused(OTHER, "use crate::identity_grants::r#GrantSubject as G;").len(),
        1
    );
}

/// An associated type naming an identity type is an alias too, in a trait
/// impl or as a trait's default.
#[test]
fn an_associated_type_alias_is_refused() {
    assert_eq!(
        refused(
            OTHER,
            "impl Tr for X { type T = crate::identity_grants::GrantSubject; }"
        )
        .len(),
        1
    );
    assert_eq!(
        refused(OTHER, "trait Tr { type T = VerifiedIdentity; }").len(),
        1
    );
    assert!(refused(OTHER, "impl Tr for X { type T = String; }").is_empty());
}

/// Code read in by `include!` is not walked, so production code may not use it.
#[test]
fn include_is_refused_in_any_production_file() {
    assert_eq!(refused(OTHER, r#"include!("forge.rs");"#).len(), 1);
    assert_eq!(
        refused(OTHER, r#"fn f() { include!("forge.rs"); }"#).len(),
        1
    );
    assert!(refused(OTHER, r#"#[cfg(test)] mod t { include!("fixture.rs"); }"#).is_empty());
}

/// A crate macro may not take the name of a listed one, by definition or by
/// import, or the list would admit it.
#[test]
fn a_macro_named_like_a_listed_one_is_refused() {
    assert_eq!(refused(OTHER, "macro_rules! format { () => {} }").len(), 1);
    assert!(refused(OTHER, "macro_rules! own_helper { () => {} }").is_empty());
    // An import under a listed name is refused where it can reach identity
    // fields: in a defining file, or a file with an impl of an identity type.
    let near = "use other::thing as matches;\nimpl GrantSubject { fn f(&self) {} }";
    assert_eq!(refused(OTHER, near).len(), 1);
    assert_eq!(refused(LEAF, "use super::debug;").len(), 1);
    assert!(
        refused(
            OTHER,
            "use crate::gateway::trace;\nuse super::{warn, debug};"
        )
        .is_empty()
    );
    assert!(refused(LEAF, "use tracing::{debug, warn};").is_empty());
}

/// Near identity fields a listed macro is spelled only bare, or under a
/// trusted root: any other path to a macro is refused.
#[test]
fn a_listed_macro_is_trusted_only_bare_or_under_a_trusted_root() {
    for spelling in ["evil::format!(\"x\")", "crate::helpers::matches!(self, _)"] {
        let source = format!("impl GrantSubject {{ fn f(&self) {{ let _ = {spelling}; }} }}");
        assert_eq!(refused(OTHER, &source).len(), 1, "{spelling}");
    }
    for spelling in [
        "format!(\"x\")",
        "std::format!(\"x\")",
        "tracing::debug!(\"x\")",
    ] {
        let source = format!("impl GrantSubject {{ fn f(&self) {{ let _ = {spelling}; }} }}");
        assert!(refused(OTHER, &source).is_empty(), "{spelling}");
    }
}

/// Near identity fields, an import that can bring in a shadowing macro
/// unseen is refused: a glob, or a crate renamed to a trusted root.
#[test]
fn a_glob_or_a_root_rename_near_identity_fields_is_refused() {
    assert_eq!(refused(LEAF, "use evil::*;").len(), 1);
    assert_eq!(refused(LEAF, "use evil as std;").len(), 1);
    assert_eq!(refused(LEAF, "extern crate evil as tracing;").len(), 1);
    assert!(refused(OTHER, "use evil::*;\nuse evil as std;").is_empty());
}

/// `include!` inside another macro's arguments is still refused.
#[test]
fn include_inside_a_macro_is_refused() {
    assert_eq!(
        refused(OTHER, r#"fn f() { let _ = vec![include!("forge.rs")]; }"#).len(),
        1
    );
}

/// An alias whose type names an identity type anywhere is refused, `Self`
/// in an identity impl included.
#[test]
fn an_alias_naming_an_identity_type_anywhere_is_refused() {
    assert_eq!(
        refused(OTHER, "impl Tr for GrantSubject { type T = Self; }").len(),
        1
    );
    assert_eq!(refused(OTHER, "type G = <GrantSubject as Tr>::T;").len(), 1);
    // Holding one is not reaching one: a tuple or a Vec of identities has no
    // constructor of theirs to call (the router's caller tuples are aliases).
    assert!(refused(OTHER, "type V = Vec<VerifiedIdentity>;").is_empty());
    assert!(refused(OTHER, "type C<'a> = (Option<&'a GrantSubject>, u8);").is_empty());
    assert!(refused(OTHER, "impl Tr for Other { type T = Self; }").is_empty());
}
