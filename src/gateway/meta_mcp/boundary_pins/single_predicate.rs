// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659 T1c + T2 scan: one `ApiKey` predicate, one caller principal.
//!
//! A new inline copy of either predicate fails here until it is routed
//! through the shared body. Syntax scan over `syn::Expr`, not text, so a
//! copy split across lines is still found.

use std::path::Path;

use syn::visit::Visit;

use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// One reviewed site: file from `Place.file`, fn from `Place.func`, kind
/// (`ApiKey` or `principal`), and why it may stay.
const ALLOWLIST: &[(&str, &str, &str, &str)] = &[
    (
        "src/gateway/auth.rs",
        "api_key_name",
        "ApiKey",
        "the one predicate",
    ),
    (
        "src/gateway/auth.rs",
        "authenticated_principal",
        "principal",
        "the one predicate",
    ),
    (
        "src/events/records.rs",
        "bounded",
        "ApiKey",
        "delivery lifetime",
    ),
    (
        "src/events/services.rs",
        "admits_at",
        "ApiKey",
        "subscription admission",
    ),
];

fn is_allowlisted(at: &Place, kind: &str) -> bool {
    let Some(func) = at.func.as_deref() else {
        return false;
    };
    ALLOWLIST
        .iter()
        .any(|(file, want, want_kind, _)| *file == at.file && *want == func && *want_kind == kind)
}

fn is_api_key_path(expr: &syn::Expr) -> bool {
    let mut current = expr;
    loop {
        match current {
            syn::Expr::Group(group) => current = &group.expr,
            syn::Expr::Paren(paren) => current = &paren.expr,
            _ => break,
        }
    }
    match current {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.to_string() == "ApiKey"),
        _ => false,
    }
}

fn macro_mentions_api_key(mac: &syn::ExprMacro) -> bool {
    if !mac.mac.path.is_ident("matches") {
        return false;
    }
    mac.mac
        .tokens
        .to_string()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| word == "ApiKey")
}

fn is_api_key_comparison(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Binary(binary) => {
            matches!(binary.op, syn::BinOp::Eq | syn::BinOp::Ne)
                && (is_api_key_path(&binary.left) || is_api_key_path(&binary.right))
        }
        syn::Expr::Macro(mac) => macro_mentions_api_key(mac),
        _ => false,
    }
}

fn is_principal_receiver(expr: &syn::Expr) -> bool {
    let mut current = expr;
    loop {
        match current {
            syn::Expr::Group(group) => current = &group.expr,
            syn::Expr::Paren(paren) => current = &paren.expr,
            syn::Expr::Reference(reference) => current = &reference.expr,
            _ => break,
        }
    }
    match current {
        syn::Expr::Field(field) => match &field.member {
            syn::Member::Named(ident) => {
                let name = ident.to_string();
                name == "principal" || name == "credential_principal"
            }
            syn::Member::Unnamed(_) => false,
        },
        syn::Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            let name = segment.ident.to_string();
            name == "principal" || name == "credential_principal"
        }),
        _ => false,
    }
}

#[derive(Default)]
struct AuthProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for AuthProbe {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(ident) = &field.member
            && ident.to_string() == "authenticated"
        {
            self.found = true;
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.to_string() == "authenticated")
        {
            self.found = true;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

#[derive(Default)]
struct EmptyProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for EmptyProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method.to_string() == "is_empty" && is_principal_receiver(&call.receiver) {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn is_principal_conjunct(expr: &syn::Expr) -> bool {
    let syn::Expr::Binary(binary) = expr else {
        return false;
    };
    if !matches!(binary.op, syn::BinOp::And) {
        return false;
    }
    let mut auth = AuthProbe::default();
    auth.visit_expr(&binary.left);
    auth.visit_expr(&binary.right);
    if !auth.found {
        return false;
    }
    let mut empty = EmptyProbe::default();
    empty.visit_expr(&binary.left);
    empty.visit_expr(&binary.right);
    empty.found
}

fn offence(at: &Place, expr: &syn::Expr) -> Option<&'static str> {
    if is_api_key_comparison(expr) && !is_allowlisted(at, "ApiKey") {
        return Some("ApiKey");
    }
    if is_principal_conjunct(expr) && !is_allowlisted(at, "principal") {
        return Some("principal");
    }
    None
}

#[derive(Default)]
struct Offences {
    rows: Vec<String>,
    lines: std::collections::HashMap<String, Vec<String>>,
}

impl Offences {
    fn file_lines(&mut self, file: &str) -> &[String] {
        if !self.lines.contains_key(file) {
            let text = match std::fs::read_to_string(crate_root().join(file)) {
                Ok(text) => text,
                Err(_) => String::new(),
            };
            let owned: Vec<String> = text.lines().map(str::to_string).collect();
            self.lines.insert(file.to_string(), owned);
        }
        if let Some(cached) = self.lines.get(file) {
            cached
        } else {
            &[]
        }
    }

    fn line_of(&mut self, file: &str, func: Option<&str>, needle: &str) -> usize {
        let mut start = 0;
        {
            let lines = self.file_lines(file);
            if let Some(want) = func {
                for (index, line) in lines.iter().enumerate() {
                    if line.contains("fn ") && line.contains(want) {
                        start = index;
                        break;
                    }
                }
            }
        }
        let lines = self.file_lines(file);
        for (index, line) in lines.iter().enumerate().skip(start) {
            if line.contains(needle) {
                return index + 1;
            }
        }
        0
    }
}

impl Sink for Offences {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let Some(kind) = offence(at, expr) else {
            return;
        };
        let needle = if kind == "ApiKey" {
            "ApiKey"
        } else {
            "is_empty"
        };
        let line = self.line_of(&at.file, at.func.as_deref(), needle);
        self.rows.push(format!(
            "{}:{}:{line}: {kind}",
            at.file,
            at.func.as_deref().unwrap_or("-"),
        ));
    }
}

fn all_offences() -> Vec<String> {
    let mut sink = Offences::default();
    walk(crate_root(), &ROOTS, &mut sink).expect("the walk reads every module");
    let mut rows = sink.rows;
    rows.sort();
    rows
}

/// T1c: walking the crate reports no `ApiKey` comparison outside the
/// allowlist; the failure lists file, fn and line.
#[test]
fn single_api_key_predicate() {
    let offending: Vec<String> = all_offences()
        .into_iter()
        .filter(|row| row.ends_with("ApiKey"))
        .collect();
    assert!(
        offending.is_empty(),
        "new `ApiKey` comparison outside the predicate (route it through `api_key_name`): {}",
        offending.join(", ")
    );
}

/// T2 scan: walking the crate reports no principal conjunct outside the
/// allowlist; the failure lists file, fn and line.
#[test]
fn single_principal_predicate() {
    let offending: Vec<String> = all_offences()
        .into_iter()
        .filter(|row| row.ends_with("principal"))
        .collect();
    assert!(
        offending.is_empty(),
        "principal conjunct outside `authenticated_principal` (route it through the predicate): {}",
        offending.join(", ")
    );
}

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
    let source = "fn mint(base: Client) -> Client { AuthenticatedClient { credential_kind: CredentialKind::ApiKey, ..base } }";
    let found = fixture_offences("fixture.rs", source);
    assert!(found.is_empty(), "a struct literal was flagged: {found:?}");
}
