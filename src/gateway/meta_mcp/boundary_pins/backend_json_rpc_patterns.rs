// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production pattern naming `JsonRpc` (match arm, `if let`, `let`,
//! `let else`, `matches!`; nested in `Err(..)`, tuples or `@` bindings) also
//! matches a backend's error the same way, or is a reviewed exclusion in
//! `backend_json_rpc_patterns.tsv`. A carry is an or-pattern whose
//! `BackendJsonRpc` alternative equals the `JsonRpc` one after renaming the
//! variant, or two arms of one match whose patterns, guards and bodies are
//! equal after that rename. Exclusions are counted per function, so a new
//! uncarried pattern in a listed function fails, and a row whose function has
//! no uncarried pattern left is stale.
//!
//! Arm-body pairing: an arm or `if let` matching `BackendJsonRpc` but not
//! `JsonRpc` must not build a `JsonRpc {..}` or `json_rpc(..)` in its body,
//! which would hand a backend's error on as the gateway's.
//!
//! What this cannot see: patterns inside macro bodies other than `matches!`,
//! and closure or function parameter patterns.

use std::collections::BTreeMap;
use std::path::Path;

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 2] = ["src/lib.rs", "src/main.rs"];
const CLASSES: [&str; 2] = ["gateway-only", "excluded"];

fn last_segment(path: &syn::Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

/// A node's shape as text, with `BackendJsonRpc` read as `JsonRpc`: two nodes
/// equal modulo the variant print the same.
#[derive(Default)]
struct Print(Vec<String>);

impl<'ast> Visit<'ast> for Print {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        let name = ident.to_string();
        self.0.push(if name == "BackendJsonRpc" {
            "JsonRpc".to_owned()
        } else {
            name
        });
    }
    fn visit_lit(&mut self, lit: &'ast syn::Lit) {
        self.0.push(match lit {
            syn::Lit::Int(i) => i.base10_digits().to_owned(),
            syn::Lit::Str(s) => format!("{:?}", s.value()),
            syn::Lit::Bool(b) => b.value.to_string(),
            _ => "<lit>".to_owned(),
        });
    }
    fn visit_un_op(&mut self, op: &'ast syn::UnOp) {
        self.0
            .push(format!("un{}", matches!(op, syn::UnOp::Neg(_))));
    }
    fn visit_pat_rest(&mut self, _: &'ast syn::PatRest) {
        self.0.push("..".to_owned());
    }
    fn visit_pat_wild(&mut self, _: &'ast syn::PatWild) {
        self.0.push("_".to_owned());
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        syn::visit::visit_macro(self, mac);
        let tokens = mac.tokens.to_string();
        self.0.push(tokens.replace("BackendJsonRpc", "JsonRpc"));
    }
}

fn print_pat(pat: &syn::Pat) -> Vec<String> {
    let mut print = Print::default();
    print.visit_pat(pat);
    print.0
}

fn print_arm(arm: &syn::Arm) -> Vec<String> {
    let mut print = Print::default();
    print.visit_arm(arm);
    print.0
}

/// Whether `pat` names the enum variant `variant` anywhere in it.
fn names(pat: &syn::Pat, variant: &str) -> bool {
    struct Find<'v>(&'v str, bool);
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.1 |= last_segment(path).is_some_and(|n| n == self.0);
        }
    }
    let mut find = Find(variant, false);
    find.visit_pat(pat);
    find.1
}

/// Whether every `JsonRpc` in `pat` sits in an or-pattern with an equal
/// `BackendJsonRpc` twin.
fn carried(pat: &syn::Pat) -> bool {
    use syn::Pat as P;
    if !names(pat, "JsonRpc") {
        return true;
    }
    let own = |path: &syn::Path| last_segment(path).is_some_and(|n| n == "JsonRpc");
    match pat {
        P::Or(or) => or.cases.iter().all(|case| {
            !names(case, "JsonRpc")
                || or.cases.iter().any(|twin| {
                    names(twin, "BackendJsonRpc")
                        && !names(twin, "JsonRpc")
                        && print_pat(twin) == print_pat(case)
                })
                || carried_inside(case)
        }),
        P::Path(p) => !own(&p.path),
        P::Struct(s) => !own(&s.path) && s.fields.iter().all(|f| carried(&f.pat)),
        P::TupleStruct(t) => !own(&t.path) && t.elems.iter().all(carried),
        _ => carried_inside(pat),
    }
}

/// `carried` for the patterns directly inside a wrapper pattern.
fn carried_inside(pat: &syn::Pat) -> bool {
    use syn::Pat as P;
    match pat {
        P::Tuple(t) => t.elems.iter().all(carried),
        P::Slice(s) => s.elems.iter().all(carried),
        P::Reference(r) => carried(&r.pat),
        P::Paren(p) => carried(&p.pat),
        P::Ident(i) => i.subpat.as_ref().is_none_or(|(_, sub)| carried(sub)),
        P::Struct(_) | P::TupleStruct(_) | P::Path(_) | P::Or(_) => carried(pat),
        _ => false,
    }
}

/// Whether `expr` builds the gateway's variant: a `JsonRpc {..}` literal or a
/// `json_rpc(..)` call.
fn builds_gateway_error(expr: &syn::Expr) -> bool {
    struct Find(bool);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr(&mut self, expr: &'ast syn::Expr) {
            self.0 |= match expr {
                syn::Expr::Struct(s) => last_segment(&s.path).is_some_and(|n| n == "JsonRpc"),
                syn::Expr::Call(c) => match c.func.as_ref() {
                    syn::Expr::Path(p) => last_segment(&p.path).is_some_and(|n| n == "json_rpc"),
                    _ => false,
                },
                _ => false,
            };
            syn::visit::visit_expr(self, expr);
        }
    }
    let mut find = Find(false);
    find.visit_expr(expr);
    find.0
}

/// A pattern that matches only a backend's error.
fn backend_only(pat: &syn::Pat) -> bool {
    names(pat, "BackendJsonRpc") && !names(pat, "JsonRpc")
}

/// `matches!(expr, pat)`'s pattern.
fn matches_pattern(mac: &syn::Macro) -> Option<syn::Pat> {
    if mac
        .path
        .segments
        .last()
        .is_none_or(|s| s.ident != "matches")
    {
        return None;
    }
    let parser = |input: syn::parse::ParseStream| {
        input.parse::<syn::Expr>()?;
        input.parse::<syn::Token![,]>()?;
        let pat = syn::Pat::parse_multi_with_leading_vert(input)?;
        // The guard, if any: skipped, the pattern is what is pinned.
        input.step(|cursor| {
            let mut rest = *cursor;
            while let Some((_, next)) = rest.token_tree() {
                rest = next;
            }
            Ok(((), rest))
        })?;
        Ok(pat)
    };
    mac.parse_body_with(parser).ok()
}

/// (file, function) -> uncarried `JsonRpc` patterns.
type Found = BTreeMap<(String, String), usize>;

#[derive(Default)]
struct Patterns {
    uncarried: Found,
    /// Backend-only arms that build the gateway's variant: file, function.
    rebuilt: Vec<String>,
}

impl Patterns {
    fn note(&mut self, at: &Place, pat: &syn::Pat, carry: bool) {
        if names(pat, "JsonRpc") && !carry {
            let func = at.func.clone().unwrap_or_else(|| "-".to_owned());
            *self.uncarried.entry((at.file.clone(), func)).or_default() += 1;
        }
    }

    fn pair(&mut self, at: &Place, pat: &syn::Pat, body: &syn::Expr) {
        if backend_only(pat) && builds_gateway_error(body) {
            let func = at.func.as_deref().unwrap_or("-");
            self.rebuilt.push(format!("{}\t{func}", at.file));
        }
    }

    fn arms(&mut self, at: &Place, arms: &[syn::Arm]) {
        for arm in arms {
            // A split carry: another arm equal to this one modulo the variant.
            let split = arms
                .iter()
                .any(|twin| backend_only(&twin.pat) && print_arm(twin) == print_arm(arm));
            self.note(at, &arm.pat, split || carried(&arm.pat));
            self.pair(at, &arm.pat, &arm.body);
        }
    }
}

impl Sink for Patterns {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        match expr {
            syn::Expr::Match(m) => self.arms(at, &m.arms),
            syn::Expr::Let(l) => self.note(at, &l.pat, carried(&l.pat)),
            syn::Expr::If(i) => {
                if let syn::Expr::Let(l) = i.cond.as_ref() {
                    let body = syn::Expr::Block(syn::ExprBlock {
                        attrs: Vec::new(),
                        label: None,
                        block: i.then_branch.clone(),
                    });
                    self.pair(at, &l.pat, &body);
                }
            }
            syn::Expr::Macro(m) => {
                if let Some(pat) = matches_pattern(&m.mac) {
                    self.note(at, &pat, carried(&pat));
                }
            }
            _ => {}
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        match stmt {
            syn::Stmt::Local(local) => self.note(at, &local.pat, carried(&local.pat)),
            syn::Stmt::Macro(m) => {
                if let Some(pat) = matches_pattern(&m.mac) {
                    self.note(at, &pat, carried(&pat));
                }
            }
            _ => {}
        }
    }
}

fn scan(root: &Path, roots: &[&str]) -> Patterns {
    let mut patterns = Patterns::default();
    walk(root, roots, &mut patterns).expect("the walk reads every module");
    patterns
}

/// The reviewed exclusions: file, function, count, class, reason.
const LISTED: &str = include_str!("backend_json_rpc_patterns.tsv");

/// What differs between `found` and the exclusions in `listed`.
fn diff(found: &Found, listed: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    let mut want = BTreeMap::new();
    for line in listed
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, count, class, reason] = cols[..] else {
            wrong.push(format!("not five columns: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            wrong.push(format!("no class or no reason: {line}"));
        }
        let Ok(count) = count.parse::<usize>() else {
            wrong.push(format!("count is not a number: {line}"));
            continue;
        };
        want.insert((file.to_owned(), func.to_owned()), count);
    }
    for ((file, func), count) in found {
        match want.get(&(file.clone(), func.clone())) {
            Some(listed) if listed == count => {}
            Some(listed) => wrong.push(format!("listed {listed}, found {count}: {file}\t{func}")),
            None => wrong.push(format!(
                "unlisted: {file}\t{func}\t{count}\t<class>\t<reason>"
            )),
        }
    }
    for (file, func) in want.keys().filter(|k| !found.contains_key(*k)) {
        wrong.push(format!("stale (carried now, or gone): {file}\t{func}"));
    }
    wrong
}

/// Every production `JsonRpc` pattern carries the backend's variant or is a
/// listed exclusion, and no backend-only arm rebuilds the gateway's variant.
#[test]
fn every_json_rpc_pattern_carries_the_backend_variant_or_is_excluded() {
    let patterns = scan(crate_root(), &ROOTS);
    let mut wrong = diff(&patterns.uncarried, LISTED);
    for site in &patterns.rebuilt {
        wrong.push(format!("BackendJsonRpc arm builds JsonRpc: {site}"));
    }
    assert!(
        wrong.is_empty(),
        "JSON-RPC error patterns differ from backend_json_rpc_patterns.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[path = "backend_json_rpc_patterns_fixtures.rs"]
mod fixtures;
