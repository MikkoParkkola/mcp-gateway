// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the R6 allowlist and R9 macro checkers.

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

struct MacroScan {
    calls: Vec<String>,
    selves: Vec<String>,
    bare: usize,
}

fn scan_cursor(mut cursor: syn::buffer::Cursor<'_>, out: &mut MacroScan) {
    while !cursor.eof() {
        if let Some((dot, after_dot)) = cursor.punct() {
            if dot.as_char() == '.' {
                if let Some((_, after_field)) = after_dot.ident() {
                    if let Some((inner, _, _, after_group)) = after_field.any_group() {
                        scan_cursor(inner, out);
                        cursor = after_group;
                    } else {
                        cursor = after_field;
                    }
                    continue;
                }
                cursor = after_dot;
                continue;
            }
            cursor = after_dot;
            continue;
        }
        if let Some((ident, rest)) = cursor.ident() {
            let name = ident.to_string();
            if let Some((bang, after_bang)) = rest.punct() {
                if bang.as_char() == '!'
                    && let Some((inner, _, _, after_group)) = after_bang.any_group()
                {
                    scan_cursor(inner, out);
                    cursor = after_group;
                    continue;
                }
            }
            if name == "self" {
                let mut is_path = false;
                if let Some((first, after_first)) = rest.punct() {
                    if first.as_char() == ':'
                        && let Some((second, _)) = after_first.punct()
                        && second.as_char() == ':'
                    {
                        is_path = true;
                    }
                }
                if !is_path {
                    if let Some((dot, after_dot)) = rest.punct() {
                        if dot.as_char() == '.' {
                            if let Some((field, after_field)) = after_dot.ident() {
                                out.selves.push(format!("self.{field}"));
                                cursor = after_field;
                                continue;
                            }
                            cursor = after_dot;
                            continue;
                        }
                    }
                    out.bare += 1;
                    cursor = rest;
                    continue;
                }
            }
            let mut parts = vec![name];
            let mut cur = rest;
            loop {
                let mut advanced = false;
                if let Some((first, after_first)) = cur.punct() {
                    if first.as_char() == ':'
                        && let Some((second, after_second)) = after_first.punct()
                        && second.as_char() == ':'
                        && let Some((next, after_ident)) = after_second.ident()
                    {
                        parts.push(next.to_string());
                        cur = after_ident;
                        advanced = true;
                    }
                }
                if !advanced {
                    break;
                }
            }
            if let Some((bang, after_bang)) = cur.punct() {
                if bang.as_char() == '!'
                    && let Some((inner, _, _, after_group)) = after_bang.any_group()
                {
                    scan_cursor(inner, out);
                    cursor = after_group;
                    continue;
                }
            }
            if let Some((inner, delim, _, after_group)) = cur.any_group() {
                let kind = format!("{delim:?}");
                if kind == "Parenthesis" {
                    out.calls.push(parts.join("::"));
                }
                scan_cursor(inner, out);
                cursor = after_group;
                continue;
            }
            cursor = cur;
            continue;
        }
        if let Some((_, rest)) = cursor.literal() {
            cursor = rest;
            continue;
        }
        if let Some((inner, _, _, rest)) = cursor.any_group() {
            scan_cursor(inner, out);
            cursor = rest;
            continue;
        }
        break;
    }
}

fn scan_macro_tokens(mac: &syn::Macro) -> MacroScan {
    let buffer = syn::buffer::TokenBuffer::new2(mac.tokens.clone());
    let mut out = MacroScan {
        calls: Vec::new(),
        selves: Vec::new(),
        bare: 0,
    };
    scan_cursor(buffer.begin(), &mut out);
    out
}

struct ScopeDeps<'a> {
    scopes: Vec<HashSet<String>>,
    allow: &'a [&'a str],
    r6_hits: Vec<String>,
    r9_hits: Vec<String>,
}

impl ScopeDeps<'_> {
    fn is_visible(&self, name: &str) -> bool {
        self.scopes.iter().any(|scope| scope.contains(name))
    }

    fn visible_set(&self) -> HashSet<String> {
        let mut out = HashSet::new();
        for scope in &self.scopes {
            out.extend(scope.iter().cloned());
        }
        out
    }

    fn check_r6(&mut self, dep: &str, what: &str) {
        if !dep.contains("::") && !dep.contains('.') && self.is_visible(dep) {
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
            && self.is_visible(&seg.ident.to_string())
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

impl<'ast, 'b> Visit<'ast> for ScopeDeps<'b> {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.scopes.push(HashSet::new());
        syn::visit::visit_block(self, block);
        self.scopes.pop();
    }

    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(pat.ident.to_string());
        }
        syn::visit::visit_pat_ident(self, pat);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.scopes.push(HashSet::new());
        for input in &closure.inputs {
            self.visit_pat(input);
        }
        self.visit_expr(&closure.body);
        self.scopes.pop();
    }

    fn visit_item_fn(&mut self, func: &'ast syn::ItemFn) {
        self.scopes.push(HashSet::new());
        for input in &func.sig.inputs {
            self.visit_fn_arg(input);
        }
        self.visit_block(func.block.as_ref());
        self.scopes.pop();
    }

    fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
        self.scopes.push(HashSet::new());
        for input in &method.sig.inputs {
            self.visit_fn_arg(input);
        }
        self.visit_block(&method.block);
        self.scopes.pop();
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let visible = self.visible_set();
        let scan = scan_macro_tokens(mac);
        for dep in scan.selves {
            if !is_allowed(&dep, STD_OK) && !is_allowed(&dep, self.allow) {
                self.r9_hits
                    .push(format!("R9: undeclared self access `{dep}` in a macro"));
            }
        }
        for dep in scan.calls {
            if !dep.contains("::") && visible.contains(&dep) {
                continue;
            }
            if !is_allowed(&dep, STD_OK) && !is_allowed(&dep, self.allow) {
                self.r9_hits
                    .push(format!("R9: undeclared call `{dep}` in a macro"));
            }
        }
    }

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

fn ordered_hits(found: &FoundFunc<'_>, allow: &[&str]) -> (Vec<String>, Vec<String>) {
    let mut seen = ScopeDeps {
        scopes: vec![HashSet::new()],
        allow,
        r6_hits: Vec::new(),
        r9_hits: Vec::new(),
    };
    for input in &found.sig.inputs {
        seen.visit_fn_arg(input);
    }
    for stmt in &found.block.stmts {
        seen.visit_stmt(stmt);
    }
    (seen.r6_hits, seen.r9_hits)
}

/// R6: every dependency of the stage body is in its allowlist.
pub(super) fn check_r6(found: &FoundFunc<'_>, stage_allow: &[&str]) -> Vec<String> {
    ordered_hits(found, stage_allow).0
}

/// R9: macro arguments hold only allowlisted calls and self accesses.
pub(super) fn check_r9(found: &FoundFunc<'_>, stage_allow: &[&str]) -> Vec<String> {
    let mut hits = ordered_hits(found, stage_allow).1;
    hits.sort();
    hits.dedup();
    hits
}

struct MacroClones {
    macros: Vec<syn::Macro>,
}

impl Visit<'_> for MacroClones {
    fn visit_macro(&mut self, mac: &syn::Macro) {
        self.macros.push(mac.clone());
    }
}

/// Bare `self` uses hiding inside macro token trees, for R8.
pub(super) fn macro_bare_self_count(found: &FoundFunc<'_>) -> usize {
    let mut seen = MacroClones { macros: Vec::new() };
    seen.visit_block(found.block);
    let mut total = 0;
    for mac in &seen.macros {
        total += scan_macro_tokens(mac).bare;
    }
    total
}
