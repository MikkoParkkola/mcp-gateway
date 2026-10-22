// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659 T1c + T2 scan: one `ApiKey` predicate, one caller principal.
//!
//! A new inline copy of either predicate fails here until it is routed
//! through the shared body. Syntax scan, not text, so a copy split across
//! lines is still found.

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

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

fn allowlist_index(at: &Place, kind: &str) -> Option<usize> {
    let func = at.func.as_deref()?;
    ALLOWLIST.iter().position(|(file, want, want_kind, _)| {
        *file == at.file && *want == func && *want_kind == kind
    })
}

fn is_allowlisted(at: &Place, kind: &str) -> bool {
    allowlist_index(at, kind).is_some()
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
            .is_some_and(|segment| segment.ident == "ApiKey"),
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

#[derive(Default)]
struct ApiKeyPatProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for ApiKeyPatProbe {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "ApiKey")
        {
            self.found = true;
        }
        syn::visit::visit_path(self, path);
    }
}

fn pat_mentions_api_key(pat: &syn::Pat) -> bool {
    let mut probe = ApiKeyPatProbe::default();
    probe.visit_pat(pat);
    probe.found
}

#[derive(Default)]
struct CatchAllProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for CatchAllProbe {
    fn visit_pat_wild(&mut self, wild: &'ast syn::PatWild) {
        self.found = true;
        syn::visit::visit_pat_wild(self, wild);
    }

    fn visit_pat_ident(&mut self, binding: &'ast syn::PatIdent) {
        // Bare `None` parses as `Pat::Ident` yet matches one value, so it is
        // not a catch-all.
        if binding.subpat.is_none() && binding.ident != "None" {
            self.found = true;
        }
        syn::visit::visit_pat_ident(self, binding);
    }
}

fn is_catch_all(pat: &syn::Pat) -> bool {
    let mut probe = CatchAllProbe::default();
    probe.visit_pat(pat);
    probe.found
}

fn is_api_key_match(expr: &syn::Expr) -> bool {
    let syn::Expr::Match(matched) = expr else {
        return false;
    };
    matched.arms.iter().enumerate().any(|(index, arm)| {
        pat_mentions_api_key(&arm.pat)
            && matched
                .arms
                .iter()
                .enumerate()
                .any(|(other, candidate)| index != other && is_catch_all(&candidate.pat))
    })
}

fn is_api_key_let(expr: &syn::Expr) -> bool {
    let syn::Expr::Let(let_expr) = expr else {
        return false;
    };
    pat_mentions_api_key(&let_expr.pat)
}

fn is_api_key_check(expr: &syn::Expr) -> bool {
    is_api_key_comparison(expr) || is_api_key_match(expr) || is_api_key_let(expr)
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
            syn::Member::Named(ident) => *ident == "principal" || *ident == "credential_principal",
            syn::Member::Unnamed(_) => false,
        },
        syn::Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            segment.ident == "principal" || segment.ident == "credential_principal"
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
            && *ident == "authenticated"
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
            .is_some_and(|segment| segment.ident == "authenticated")
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
        if call.method == "is_empty" && is_principal_receiver(&call.receiver) {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct PrincipalProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for PrincipalProbe {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(ident) = &field.member
            && (*ident == "principal" || *ident == "credential_principal")
        {
            self.found = true;
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.path.segments.last().is_some_and(|segment| {
            segment.ident == "principal" || segment.ident == "credential_principal"
        }) {
            self.found = true;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

#[derive(Default)]
struct EmptyCallProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for EmptyCallProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "is_empty" {
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

fn is_principal_if_filter(expr: &syn::Expr) -> bool {
    let syn::Expr::If(if_expr) = expr else {
        return false;
    };
    let mut auth = AuthProbe::default();
    auth.visit_expr(&if_expr.cond);
    if !auth.found {
        return false;
    }
    let mut principal = PrincipalProbe::default();
    principal.visit_block(&if_expr.then_branch);
    if !principal.found {
        return false;
    }
    let mut empty = EmptyCallProbe::default();
    empty.visit_block(&if_expr.then_branch);
    empty.found
}

fn is_principal_check(expr: &syn::Expr) -> bool {
    is_principal_conjunct(expr) || is_principal_if_filter(expr)
}

fn detected_kind(expr: &syn::Expr) -> Option<&'static str> {
    if is_api_key_check(expr) {
        return Some("ApiKey");
    }
    if is_principal_check(expr) {
        return Some("principal");
    }
    None
}

fn offence(at: &Place, expr: &syn::Expr) -> Option<&'static str> {
    let kind = detected_kind(expr)?;
    if is_allowlisted(at, kind) {
        None
    } else {
        Some(kind)
    }
}

fn detected_stmt_kind(stmt: &syn::Stmt) -> Option<&'static str> {
    let syn::Stmt::Local(local) = stmt else {
        return None;
    };
    if local.else_branch.is_none() {
        return None;
    }
    pat_mentions_api_key(&local.pat).then_some("ApiKey")
}

fn stmt_offence(at: &Place, stmt: &syn::Stmt) -> Option<&'static str> {
    let kind = detected_stmt_kind(stmt)?;
    if is_allowlisted(at, kind) {
        None
    } else {
        Some(kind)
    }
}

struct Offences {
    rows: Vec<String>,
    matched: Vec<bool>,
    lines: std::collections::HashMap<String, Vec<String>>,
}

impl Offences {
    fn file_lines(&mut self, file: &str) -> &[String] {
        if !self.lines.contains_key(file) {
            let text = std::fs::read_to_string(crate_root().join(file))
                .expect("a walked production file is readable");
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

    fn record(&mut self, at: &Place, kind: &'static str) {
        if let Some(index) = allowlist_index(at, kind) {
            self.matched[index] = true;
            return;
        }
        let needle = if kind == "ApiKey" {
            "ApiKey"
        } else {
            "is_empty"
        };
        let _line = self.line_of(&at.file, at.func.as_deref(), needle);
        self.rows.push(format!(
            "{}:{}: {kind}",
            at.file,
            at.func.as_deref().unwrap_or("-"),
        ));
    }
}

impl Sink for Offences {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if let Some(kind) = detected_kind(expr) {
            self.record(at, kind);
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if let Some(kind) = detected_stmt_kind(stmt) {
            self.record(at, kind);
        }
    }
}

fn all_offences() -> (Vec<String>, Vec<bool>) {
    let mut sink = Offences {
        rows: Vec::new(),
        matched: vec![false; ALLOWLIST.len()],
        lines: std::collections::HashMap::new(),
    };
    walk(crate_root(), &ROOTS, &mut sink).expect("the walk reads every module");
    let mut rows = sink.rows;
    rows.sort();
    (rows, sink.matched)
}

fn unused_allowlist(matched: &[bool], kind: &str) -> Vec<String> {
    let mut unused = Vec::new();
    for (index, &(file, func, entry_kind, reason)) in ALLOWLIST.iter().enumerate() {
        if entry_kind == kind && !matched[index] {
            unused.push(format!("{file}:{func} ({reason})"));
        }
    }
    unused
}

/// T1c: walking the crate reports no `ApiKey` check outside the allowlist;
/// the failure lists file, fn and kind. Every allowlist entry of this kind
/// matched at least once, so a stale entry fails instead of lingering.
#[test]
fn single_api_key_predicate() {
    let (rows, matched) = all_offences();
    let offending: Vec<String> = rows
        .into_iter()
        .filter(|row| row.ends_with("ApiKey"))
        .collect();
    assert!(
        offending.is_empty(),
        "new `ApiKey` check outside the predicate (route it through `api_key_name`): {}",
        offending.join(", ")
    );
    let unused = unused_allowlist(&matched, "ApiKey");
    assert!(
        unused.is_empty(),
        "allowlist entries no detector hit (remove them): {}",
        unused.join(", ")
    );
}

/// T2 scan: walking the crate reports no principal check outside the
/// allowlist; the failure lists file, fn and kind. Every allowlist entry of
/// this kind matched at least once, so a stale entry fails instead of
/// lingering.
#[test]
fn single_principal_predicate() {
    let (rows, matched) = all_offences();
    let offending: Vec<String> = rows
        .into_iter()
        .filter(|row| row.ends_with("principal"))
        .collect();
    assert!(
        offending.is_empty(),
        "principal check outside `authenticated_principal` (route it through the predicate): {}",
        offending.join(", ")
    );
    let unused = unused_allowlist(&matched, "principal");
    assert!(
        unused.is_empty(),
        "allowlist entries no detector hit (remove them): {}",
        unused.join(", ")
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
    let source = "fn mint(base: Client) -> Client { AuthenticatedClient { credential_kind: CredentialKind::ApiKey, ..base } }";
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
