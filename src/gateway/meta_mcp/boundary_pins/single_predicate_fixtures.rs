// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Negative fixtures for the single-predicate scan: each runs a literal source
//! through the same `offence` check the crate walk uses.

use super::*;
use syn::visit::Visit;

struct Fixture {
    file: String,
    func: Option<String>,
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for Fixture {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let saved = self.func.replace(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.func = saved;
    }

    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        let at = Place {
            file: self.file.clone(),
            func: self.func.clone(),
        };
        if let Some(kind) = offence(&at, expr) {
            self.found.push(kind.to_string());
        }
        syn::visit::visit_expr(self, expr);
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let at = Place {
            file: self.file.clone(),
            func: self.func.clone(),
        };
        if let Some(kind) = stmt_offence(&at, stmt) {
            self.found.push(kind.to_string());
        }
        syn::visit::visit_stmt(self, stmt);
    }
}

fn fixture_offences(file: &str, source: &str) -> Vec<String> {
    let parsed = syn::parse_file(source).expect("fixture parses");
    let mut fixture = Fixture {
        file: file.to_string(),
        func: None,
        found: Vec::new(),
    };
    fixture.visit_file(&parsed);
    fixture.found
}

/// T1c: a new comparison in an allowlisted file but a new fn is flagged.
#[test]
fn fixture_new_comparison_in_an_allowlisted_file_is_flagged() {
    let source = "fn other(c: &Client) -> bool { c.credential_kind == CredentialKind::ApiKey }";
    let found = fixture_offences("src/gateway/auth.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a new comparison in `other` was not flagged"
    );
}

/// T1c: a comparison split across lines is flagged.
#[test]
fn fixture_multiline_comparison_is_flagged() {
    let source = "fn check(c: &Client) -> bool {\n    c.credential_kind\n        ==\n        crate::security::audit::CredentialKind::ApiKey\n}";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a multiline comparison was not flagged"
    );
}

/// T1c: a `matches!` naming `ApiKey` is flagged.
#[test]
fn fixture_matches_macro_is_flagged() {
    let source = "fn check(k: Kind) -> bool { matches!(k, Kind::ApiKey | Kind::None) }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "`matches!` naming `ApiKey` was not flagged"
    );
}

/// T2 scan: a principal conjunct split across lines is flagged.
#[test]
fn fixture_principal_conjunct_multiline_is_flagged() {
    let source = "fn check(c: &Client) -> bool {\n    c.authenticated\n        && !c.principal.is_empty()\n}";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "principal"),
        "a multiline principal conjunct was not flagged"
    );
}

/// T1c: a struct literal minting `ApiKey` is not a comparison.
#[test]
fn fixture_struct_literal_is_not_flagged() {
    // Split over lines with an empty principal, so the MIK-6704 literal scan
    // reads this fixture as the anonymous identity it is.
    let source = "fn mint(base: Client) -> Client { AuthenticatedClient {
        principal: String::new(),
        credential_kind: CredentialKind::ApiKey, ..base } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(found.is_empty(), "a struct literal was flagged: {found:?}");
}

/// Grok round: the `if authenticated` filter shape from
/// `authenticated_principal` is flagged in a non-allowlisted fn.
#[test]
fn fixture_if_filter_principal_form_is_flagged() {
    let source = "fn other(authenticated: bool, principal: Option<&str>) -> Option<&str> { if authenticated { principal.filter(|p| !p.is_empty()) } else { None } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "principal"),
        "the if-filter principal form was not flagged"
    );
}

/// Lead ruling: a `match` that singles `ApiKey` out beside a wildcard is
/// flagged in a non-allowlisted fn.
#[test]
fn fixture_wildcard_api_key_match_is_flagged() {
    let source = "fn other(k: Kind) -> u32 { match k { Kind::ApiKey => 1, _ => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a wildcard `ApiKey` match was not flagged"
    );
}

/// Lead ruling: an `if let` that singles `ApiKey` out is flagged.
#[test]
fn fixture_if_let_api_key_is_flagged() {
    let source = "fn other(k: Kind) -> u32 { if let Kind::ApiKey = k { 1 } else { 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "an `if let` on `ApiKey` was not flagged"
    );
}

/// Lead ruling: an exhaustive dispatch over kinds is not a copy of the
/// `ApiKey` rule, so it is not flagged.
#[test]
fn fixture_exhaustive_kind_match_is_not_flagged() {
    let source = "fn other(k: Kind) -> u32 { match k { Kind::ApiKey => 1, Kind::StaticBearer => 2, Kind::None => 3 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.is_empty(),
        "an exhaustive kind match was flagged: {found:?}"
    );
}

/// A `let ... else` that singles `ApiKey` out is flagged.
#[test]
fn fixture_let_else_api_key_is_flagged() {
    let source = "fn other(k: Kind) -> u32 { let Kind::ApiKey = k else { return 0 }; 1 }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a `let ... else` on `ApiKey` was not flagged"
    );
}

/// MIK-8659: a nested binding beside an `ApiKey` arm is a catch-all, so the
/// `match` is flagged.
#[test]
fn fixture_nested_catch_all_api_key_match_is_flagged() {
    let source = "fn check(k: Option<Kind>) -> u8 { match k { Some(Kind::ApiKey) => 1, Some(other) => 0, None => 2 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a nested catch-all `ApiKey` match was not flagged"
    );
}

/// MIK-8659: an exhaustive nested dispatch over kinds is not a copy of the
/// `ApiKey` rule, so it is not flagged.
#[test]
fn fixture_exhaustive_nested_kind_match_is_not_flagged() {
    let source = "fn other(k: Option<Kind>) -> u8 { match k { Some(Kind::ApiKey) => 1, Some(Kind::StaticBearer) => 2, Some(Kind::None) => 3, None => 4 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.is_empty(),
        "an exhaustive nested kind match was flagged: {found:?}"
    );
}

/// Lead ruling: a bare `ApiKey` from `use Kind::*` is an `ApiKey` path, so
/// it is flagged beside a wildcard.
#[test]
fn fixture_imported_api_key_variant_is_flagged() {
    let source = "fn other(k: Kind) -> u32 { match k { ApiKey => 1, _ => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a bare `ApiKey` variant was not flagged"
    );
}

/// Lead ruling: bare uppercase idents are variants, so `StaticBearer` is
/// not a catch-all and the bare `match` is not flagged.
#[test]
fn fixture_bare_variant_is_not_a_catch_all() {
    let source =
        "fn other(k: Kind) -> u32 { match k { ApiKey => 1, StaticBearer => 2, None => 3 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.is_empty(),
        "a bare variant match was flagged: {found:?}"
    );
}

/// Lead ruling: a tuple arm with a wildcard at the `ApiKey` position is a
/// catch-all, so the `match` is flagged.
#[test]
fn fixture_tuple_catch_all_at_api_key_position_is_flagged() {
    let source =
        "fn other(k: Kind, x: u32) -> u32 { match (k, x) { (Kind::ApiKey, _) => 1, (_, _) => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a tuple catch-all at the `ApiKey` position was not flagged"
    );
}

/// Lead ruling: a tuple wildcard elsewhere is not a catch-all for the
/// `ApiKey` arm, so the exhaustive tuple `match` is not flagged.
#[test]
fn fixture_tuple_wildcard_elsewhere_is_not_flagged() {
    let source = "fn other(k: Kind, x: u32) -> u32 { match (k, x) { (Kind::ApiKey, _) => 1, (Kind::StaticBearer, _) => 2, (Kind::None, _) => 3 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.is_empty(),
        "a tuple wildcard elsewhere was flagged: {found:?}"
    );
}

/// MIK-8659: a `Pat::Struct` arm fails closed, so the `match` is flagged.
#[test]
fn fixture_struct_pattern_copy_is_flagged() {
    let source =
        "fn other(c: C) -> u32 { match c { C { kind: Kind::ApiKey } => 1, C { kind: _ } => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a struct `ApiKey` match was not flagged"
    );
}

/// MIK-8659: a `Pat::Slice` arm fails closed, so the `match` is flagged.
#[test]
fn fixture_slice_pattern_copy_is_flagged() {
    let source = "fn other(s: [Kind; 1]) -> u32 { match s { [Kind::ApiKey] => 1, [_] => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a slice `ApiKey` match was not flagged"
    );
}

/// MIK-8659: a tuple with `..` fails closed, so the `match` is flagged.
#[test]
fn fixture_rest_pattern_copy_is_flagged() {
    let source = "fn other(t: (u32, Kind, u32)) -> u32 { match t { (0, Kind::ApiKey, 0) => 1, (_first, ..) => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a `..` `ApiKey` match was not flagged"
    );
}

/// MIK-8659: a struct `..` arm is a catch-all, so the `match` is flagged.
#[test]
fn fixture_struct_rest_catch_all_is_flagged() {
    let source =
        "fn other(c: C) -> u32 { match c { C { kind: Kind::ApiKey } => 1, C { .. } => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a struct `..` catch-all was not flagged"
    );
}

/// MIK-8659: a slice `..` arm is a catch-all, so the `match` is flagged.
#[test]
fn fixture_slice_rest_catch_all_is_flagged() {
    let source = "fn other(s: [Kind; 1]) -> u32 { match s { [Kind::ApiKey] => 1, [..] => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a slice `..` catch-all was not flagged"
    );
}

/// MIK-8659: a tuple `(..)` arm is a catch-all, so the `match` is flagged.
#[test]
fn fixture_tuple_rest_catch_all_is_flagged() {
    let source =
        "fn other(t: (Kind, u32)) -> u32 { match t { (Kind::ApiKey, 0) => 1, (..) => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a tuple `(..)` catch-all was not flagged"
    );
}

/// MIK-8659: a tuple-struct `C(..)` arm is a catch-all, so the `match` is flagged.
#[test]
fn fixture_tuple_struct_rest_catch_all_is_flagged() {
    let source = "fn other(c: C) -> u32 { match c { C(Kind::ApiKey) => 1, C(..) => 0 } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(
        found.iter().any(|kind| kind == "ApiKey"),
        "a tuple-struct `C(..)` catch-all was not flagged"
    );
}
