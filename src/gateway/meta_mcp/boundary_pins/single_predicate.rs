// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659 T1c + T2 scan: one `ApiKey` predicate, one caller principal.
//!
//! A new inline copy of either predicate fails here until it is routed
//! through the shared body. Syntax scan, not text, so a copy split across
//! lines is still found.
//!
//! ## Detection bounds
//!
//! The detector is hand-written and approximates "a copy of the API-key or
//! principal rule". Plain tuples use position matching: a wildcard counts
//! only at the same index where the `ApiKey` arm names `ApiKey`. Struct,
//! slice and `..` shapes fail closed: they can only over-flag, never miss,
//! and a flagged site is resolved by a reviewed allowlist entry or a
//! rewrite. The principal probe can over-flag when `authenticated` and an
//! `is_empty` on a principal appear in one expression without one guarding
//! the other (a known false-positive bound).

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
            matches!(binary.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
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

    fn visit_pat_ident(&mut self, binding: &'ast syn::PatIdent) {
        if binding.subpat.is_none() && binding.ident == "ApiKey" {
            self.found = true;
        }
        syn::visit::visit_pat_ident(self, binding);
    }
}

fn pat_mentions_api_key(pat: &syn::Pat) -> bool {
    let mut probe = ApiKeyPatProbe::default();
    probe.visit_pat(pat);
    probe.found
}

/// Whether `ident` starts uppercase, so a bare `Pat::Ident` is a variant.
fn is_uppercase_ident(ident: &syn::Ident) -> bool {
    ident
        .to_string()
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
}

/// Whether `binding` is a catch-all binding: no subpattern and lowercase.
/// A bare uppercase `Pat::Ident` is a variant, never a binding.
fn is_binding_ident(binding: &syn::PatIdent) -> bool {
    binding.subpat.is_none() && !is_uppercase_ident(&binding.ident)
}

/// Whether `pat` is a top-level `_` or binding.
fn is_top_level_catch_all(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Wild(_) => true,
        syn::Pat::Ident(binding) => is_binding_ident(binding),
        _ => false,
    }
}

/// Strip `Pat::Paren` and `Pat::Reference` wrappers from `pat`.
fn unwrap_pat(pat: &syn::Pat) -> &syn::Pat {
    let mut current = pat;
    loop {
        match current {
            syn::Pat::Paren(inner) => current = inner.pat.as_ref(),
            syn::Pat::Reference(inner) => current = inner.pat.as_ref(),
            _ => break,
        }
    }
    current
}

/// Whether `pat` holds a `_` or lowercase binding anywhere inside it.
///
/// Recurses through `Pat::Paren`, `Pat::Reference`, `Pat::Or`,
/// `Pat::Tuple`, `Pat::TupleStruct`, `Pat::Slice` and `Pat::Struct`; a bare
/// uppercase `Pat::Ident` is a variant and never counts.
fn pat_has_wildcard_or_binding(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Wild(_) => true,
        syn::Pat::Ident(binding) => {
            if is_binding_ident(binding) {
                return true;
            }
            if let Some((_, sub)) = &binding.subpat {
                return pat_has_wildcard_or_binding(sub);
            }
            false
        }
        syn::Pat::Paren(inner) => pat_has_wildcard_or_binding(&inner.pat),
        syn::Pat::Reference(inner) => pat_has_wildcard_or_binding(&inner.pat),
        syn::Pat::Or(or) => or.cases.iter().any(pat_has_wildcard_or_binding),
        syn::Pat::Tuple(tuple) => tuple.elems.iter().any(pat_has_wildcard_or_binding),
        syn::Pat::TupleStruct(ts) => ts.elems.iter().any(pat_has_wildcard_or_binding),
        syn::Pat::Slice(slice) => slice.elems.iter().any(pat_has_wildcard_or_binding),
        syn::Pat::Struct(strukt) => strukt
            .fields
            .iter()
            .any(|field| pat_has_wildcard_or_binding(&field.pat)),
        _ => false,
    }
}

/// Whether the `ApiKey` path in `pat` passes through an unmodeled shape.
///
/// A `Pat::Struct` or `Pat::Slice` is always unmodeled; a `Pat::Tuple` or
/// `Pat::TupleStruct` is unmodeled only when its `elems` hold a `Pat::Rest`.
/// Plain tuples recurse into the `elems` that name `ApiKey`.
fn api_path_uses_unmodeled(pat: &syn::Pat) -> bool {
    let unwrapped = unwrap_pat(pat);
    if matches!(unwrapped, syn::Pat::Struct(_) | syn::Pat::Slice(_)) {
        return pat_mentions_api_key(unwrapped);
    }
    if let syn::Pat::Tuple(tuple) = unwrapped {
        if tuple
            .elems
            .iter()
            .any(|elem| matches!(elem, syn::Pat::Rest(_)))
        {
            return pat_mentions_api_key(unwrapped);
        }
        return tuple
            .elems
            .iter()
            .filter(|elem| pat_mentions_api_key(elem))
            .any(api_path_uses_unmodeled);
    }
    if let syn::Pat::TupleStruct(ts) = unwrapped {
        if ts
            .elems
            .iter()
            .any(|elem| matches!(elem, syn::Pat::Rest(_)))
        {
            return pat_mentions_api_key(unwrapped);
        }
        return ts
            .elems
            .iter()
            .filter(|elem| pat_mentions_api_key(elem))
            .any(api_path_uses_unmodeled);
    }
    if let syn::Pat::Ident(binding) = unwrapped {
        if let Some((_, sub)) = &binding.subpat {
            return api_path_uses_unmodeled(sub);
        }
        return false;
    }
    if let syn::Pat::Or(or) = unwrapped {
        return or
            .cases
            .iter()
            .filter(|case| pat_mentions_api_key(case))
            .any(api_path_uses_unmodeled);
    }
    false
}

/// Whether `cand` is unmodeled at the position compared with `api`.
///
/// Follows the position rule through `Pat::Paren`, `Pat::Reference`,
/// `Pat::Or` and same-index `Pat::Tuple` / `Pat::TupleStruct` steps. A
/// `Pat::Struct`, a `Pat::Slice`, or a tuple / tuple-struct with a
/// `Pat::Rest` at the compared position counts as unmodeled.
fn cand_has_unmodeled_at_position(api: &syn::Pat, cand: &syn::Pat) -> bool {
    let api_unwrapped = unwrap_pat(api);
    let cand_unwrapped = unwrap_pat(cand);
    if !pat_mentions_api_key(api_unwrapped) {
        return false;
    }
    if matches!(cand_unwrapped, syn::Pat::Struct(_) | syn::Pat::Slice(_)) {
        return true;
    }
    if let syn::Pat::Tuple(tuple) = cand_unwrapped {
        if tuple
            .elems
            .iter()
            .any(|elem| matches!(elem, syn::Pat::Rest(_)))
        {
            return true;
        }
    }
    if let syn::Pat::TupleStruct(ts) = cand_unwrapped {
        if ts
            .elems
            .iter()
            .any(|elem| matches!(elem, syn::Pat::Rest(_)))
        {
            return true;
        }
    }
    if let syn::Pat::Ident(binding) = api_unwrapped {
        if let Some((_, sub)) = &binding.subpat {
            return cand_has_unmodeled_at_position(sub, cand_unwrapped);
        }
    }
    if let syn::Pat::Ident(binding) = cand_unwrapped {
        if let Some((_, sub)) = &binding.subpat {
            return cand_has_unmodeled_at_position(api_unwrapped, sub);
        }
    }
    if let syn::Pat::Or(or) = api_unwrapped {
        return or
            .cases
            .iter()
            .filter(|case| pat_mentions_api_key(case))
            .any(|case| cand_has_unmodeled_at_position(case, cand_unwrapped));
    }
    if let syn::Pat::Or(or) = cand_unwrapped {
        return or
            .cases
            .iter()
            .any(|case| cand_has_unmodeled_at_position(api_unwrapped, case));
    }
    if let (syn::Pat::Tuple(api_tuple), syn::Pat::Tuple(cand_tuple)) =
        (api_unwrapped, cand_unwrapped)
    {
        if api_tuple
            .elems
            .iter()
            .any(|elem| matches!(elem, syn::Pat::Rest(_)))
        {
            return true;
        }
        for (index, api_elem) in api_tuple.elems.iter().enumerate() {
            if !pat_mentions_api_key(api_elem) {
                continue;
            }
            if let Some(cand_elem) = cand_tuple.elems.iter().nth(index) {
                if cand_has_unmodeled_at_position(api_elem, cand_elem) {
                    return true;
                }
            }
        }
        return false;
    }
    if let (syn::Pat::TupleStruct(api_ts), syn::Pat::TupleStruct(cand_ts)) =
        (api_unwrapped, cand_unwrapped)
    {
        if api_ts
            .elems
            .iter()
            .any(|elem| matches!(elem, syn::Pat::Rest(_)))
        {
            return true;
        }
        for (index, api_elem) in api_ts.elems.iter().enumerate() {
            if !pat_mentions_api_key(api_elem) {
                continue;
            }
            if let Some(cand_elem) = cand_ts.elems.iter().nth(index) {
                if cand_has_unmodeled_at_position(api_elem, cand_elem) {
                    return true;
                }
            }
        }
        return false;
    }
    false
}

/// Whether `cand` catches the `ApiKey` position in `api`.
///
/// A top-level `_` or binding still counts. In a plain `Pat::Tuple` or
/// `Pat::TupleStruct` without `..`, only a wildcard or binding at the same
/// index where `api` names `ApiKey` counts, recursing through `Some(..)`,
/// `Pat::Paren` and `Pat::Reference`. A `Pat::Struct`, a `Pat::Slice`, or a
/// tuple / tuple-struct / slice with `Pat::Rest` fails closed: any `_` or
/// binding anywhere in `cand` then counts.
fn is_catch_all_for(api: &syn::Pat, cand: &syn::Pat) -> bool {
    let cand_unwrapped = unwrap_pat(cand);
    if is_top_level_catch_all(cand_unwrapped) {
        return true;
    }
    if api_path_uses_unmodeled(api) || cand_has_unmodeled_at_position(api, cand) {
        return pat_has_wildcard_or_binding(cand);
    }
    let api_unwrapped = unwrap_pat(api);
    if let syn::Pat::Ident(binding) = api_unwrapped {
        if let Some((_, sub)) = &binding.subpat {
            return is_catch_all_for(sub, cand_unwrapped);
        }
    }
    if let syn::Pat::Ident(binding) = cand_unwrapped {
        if let Some((_, sub)) = &binding.subpat {
            return is_catch_all_for(api_unwrapped, sub);
        }
    }
    if let syn::Pat::Or(or) = api_unwrapped {
        return or
            .cases
            .iter()
            .filter(|case| pat_mentions_api_key(*case))
            .any(|case| is_catch_all_for(case, cand_unwrapped));
    }
    if let syn::Pat::Or(or) = cand_unwrapped {
        return or
            .cases
            .iter()
            .any(|case| is_catch_all_for(api_unwrapped, case));
    }
    if let (syn::Pat::Tuple(api_tuple), syn::Pat::Tuple(cand_tuple)) =
        (api_unwrapped, cand_unwrapped)
    {
        for (index, api_elem) in api_tuple.elems.iter().enumerate() {
            if !pat_mentions_api_key(api_elem) {
                continue;
            }
            if let Some(cand_elem) = cand_tuple.elems.iter().nth(index) {
                if is_catch_all_for(api_elem, cand_elem) {
                    return true;
                }
            }
        }
        return false;
    }
    if let (syn::Pat::TupleStruct(api_ts), syn::Pat::TupleStruct(cand_ts)) =
        (api_unwrapped, cand_unwrapped)
    {
        for (index, api_elem) in api_ts.elems.iter().enumerate() {
            if !pat_mentions_api_key(api_elem) {
                continue;
            }
            if let Some(cand_elem) = cand_ts.elems.iter().nth(index) {
                if is_catch_all_for(api_elem, cand_elem) {
                    return true;
                }
            }
        }
        return false;
    }
    false
}

fn is_api_key_match(expr: &syn::Expr) -> bool {
    let syn::Expr::Match(matched) = expr else {
        return false;
    };
    matched.arms.iter().enumerate().any(|(index, arm)| {
        pat_mentions_api_key(&arm.pat)
            && matched.arms.iter().enumerate().any(|(other, candidate)| {
                index != other && is_catch_all_for(&arm.pat, &candidate.pat)
            })
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
    if !matches!(binary.op, syn::BinOp::And(_)) {
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
    if !local
        .init
        .as_ref()
        .is_some_and(|init| init.diverge.is_some())
    {
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
}

impl Offences {
    fn record(&mut self, at: &Place, kind: &'static str) {
        if let Some(index) = allowlist_index(at, kind) {
            self.matched[index] = true;
            return;
        }
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

#[path = "single_predicate_fixtures.rs"]
mod fixtures;
