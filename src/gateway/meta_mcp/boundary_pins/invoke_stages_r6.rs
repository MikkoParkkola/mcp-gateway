// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the R6 allowlist checker.

use std::collections::HashSet;

use syn::visit::Visit;

use super::invoke_stages_allow::STD_OK;
use super::invoke_stages_rules::FoundFunc;

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn is_self_expr(expr: &syn::Expr) -> bool {
    if let syn::Expr::Path(plain) = expr
        && plain.qself.is_none()
        && plain.path.segments.len() == 1
        && plain
            .path
            .segments
            .first()
            .is_some_and(|seg| seg.ident == "self")
    {
        true
    } else {
        false
    }
}

/// The allowlist comparison form: the move drops the caller's module prefix.
fn canonical(path: &str) -> String {
    let mut rest = path;
    loop {
        if let Some(stripped) = rest.strip_prefix("super::") {
            rest = stripped;
            continue;
        }
        if let Some(stripped) = rest.strip_prefix("self::") {
            rest = stripped;
            continue;
        }
        if let Some(stripped) = rest.strip_prefix("crate::gateway::meta_mcp::") {
            rest = stripped;
            continue;
        }
        break;
    }
    rest.to_string()
}

fn is_allowed(dep: &str, allow: &[&str]) -> bool {
    let canon = canonical(dep);
    allow.iter().any(|entry| canonical(entry) == canon)
}

fn type_text(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(plain) => path_text(&plain.path),
        syn::Type::Reference(borrow) => type_text(borrow.elem.as_ref()),
        _ => String::from("_"),
    }
}

fn qualified_text(qself: &syn::QSelf, path: &syn::Path) -> String {
    let ty = type_text(&qself.ty);
    let segs: Vec<String> = path
        .segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect();
    let at = qself.position.min(segs.len());
    let inside = if qself.as_token.is_some() {
        let trait_path = segs[..at].join("::");
        if trait_path.is_empty() {
            ty
        } else {
            format!("{ty} as {trait_path}")
        }
    } else {
        ty
    };
    let rest = segs[at..].join("::");
    if rest.is_empty() {
        format!("<{inside}>")
    } else {
        format!("<{inside}>::{rest}")
    }
}

struct Locals {
    names: HashSet<String>,
}

impl<'ast> Visit<'ast> for Locals {
    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        // Any binding hides an external call of the same name, wherever it sits.
        self.names.insert(pat.ident.to_string());
        syn::visit::visit_pat_ident(self, pat);
    }
}

struct BodyDeps<'a> {
    locals: HashSet<String>,
    allow: &'a [&'a str],
    r6_hits: Vec<String>,
}

impl BodyDeps<'_> {
    fn check_r6(&mut self, dep: &str, what: &str) {
        // A bare local name is the function's own binding, never a dependency.
        if !dep.contains("::") && !dep.contains('.') && self.locals.contains(dep) {
            return;
        }
        if is_allowed(dep, STD_OK) || is_allowed(dep, self.allow) {
            return;
        }
        self.r6_hits.push(format!("R6: undeclared {what} `{dep}`"));
    }

    fn check_r6_path(&mut self, path: &syn::Path, what: &str) {
        let text = path_text(path);
        if text == "self" {
            return;
        }
        if path.segments.len() == 1
            && let Some(seg) = path.segments.first()
            && self.locals.contains(&seg.ident.to_string())
        {
            return;
        }
        self.check_r6(&text, what);
    }

    fn check_r6_qualified(&mut self, qself: &syn::QSelf, path: &syn::Path, what: &str) {
        let text = qualified_text(qself, path);
        if is_allowed(&text, STD_OK) || is_allowed(&text, self.allow) {
            return;
        }
        self.r6_hits.push(format!("R6: undeclared {what} `{text}`"));
    }
}

impl<'ast> Visit<'ast> for BodyDeps<'_> {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if is_self_expr(&field.base) {
            if let syn::Member::Named(member) = &field.member {
                let dep = format!("self.{member}");
                self.check_r6(&dep, "self access");
            }
            return;
        }
        self.visit_expr(&field.base);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if is_self_expr(&call.receiver) {
            let dep = format!("self.{}", call.method);
            self.check_r6(&dep, "self access");
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        self.visit_expr(&call.receiver);
        for arg in &call.args {
            self.visit_expr(arg);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(callee) = call.func.as_ref() {
            if let Some(qself) = callee.qself.as_ref() {
                self.check_r6_qualified(qself, &callee.path, "call");
            } else {
                self.check_r6_path(&callee.path, "call");
            }
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        self.visit_expr(&call.func);
        for arg in &call.args {
            self.visit_expr(arg);
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(qself) = path.qself.as_ref() {
            self.check_r6_qualified(qself, &path.path, "callback");
        } else {
            self.check_r6_path(&path.path, "callback");
        }
        syn::visit::visit_expr_path(self, path);
    }
}

/// R6: every dependency of the stage body is in its allowlist.
pub(super) fn check_r6(found: &FoundFunc<'_>, stage_allow: &[&str]) -> Vec<String> {
    // Function-wide locals first, so a later binding still hides an earlier call.
    let mut locals = Locals {
        names: HashSet::new(),
    };
    for input in &found.sig.inputs {
        locals.visit_fn_arg(input);
    }
    locals.visit_block(found.block);
    let mut seen = BodyDeps {
        locals: locals.names,
        allow: stage_allow,
        r6_hits: Vec::new(),
    };
    seen.visit_block(found.block);
    seen.r6_hits
}
