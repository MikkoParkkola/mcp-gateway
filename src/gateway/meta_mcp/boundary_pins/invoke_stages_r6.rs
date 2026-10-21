// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the R6 allowlist and R9 macro checkers.

use std::collections::HashSet;

use syn::visit::Visit;

use super::invoke_stages_allow::{OUT_TYPES, STD_OK};
use super::invoke_stages_rules::FoundFunc;

fn in_list(list: &[&str], name: &str) -> bool {
    list.iter().any(|item| *item == name)
}

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn is_self(expr: &syn::Expr) -> bool {
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

struct Locals {
    names: HashSet<String>,
}

impl<'ast> Visit<'ast> for Locals {
    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        self.names.insert(pat.ident.to_string());
        syn::visit::visit_pat_ident(self, pat);
    }
}

fn local_names(found: &FoundFunc<'_>) -> HashSet<String> {
    let mut seen = Locals {
        names: HashSet::new(),
    };
    for input in &found.sig.inputs {
        seen.visit_fn_arg(input);
    }
    seen.visit_block(found.block);
    seen.names
}

fn is_ctor(path: &syn::Path, in_type: &str) -> bool {
    if let Some(first) = path.segments.first() {
        let first = first.ident.to_string();
        first == in_type || OUT_TYPES.iter().any(|out| *out == first)
    } else {
        false
    }
}

struct Deps<'a> {
    locals: &'a HashSet<String>,
    allow: &'a [&'a str],
    in_type: &'a str,
    tag: &'a str,
    hits: Vec<String>,
}

impl Deps<'_> {
    fn check(&mut self, dep: &str, what: &str) {
        if self.locals.contains(dep) {
            return;
        }
        if in_list(STD_OK, dep) || in_list(self.allow, dep) {
            return;
        }
        self.hits
            .push(format!("{}: undeclared {what} `{dep}`", self.tag));
    }

    fn check_path(&mut self, path: &syn::Path, what: &str) {
        if is_ctor(path, self.in_type) {
            return;
        }
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
        self.check(&text, what);
    }
}

impl<'ast> Visit<'ast> for Deps<'ast> {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if is_self(&field.base) {
            if let syn::Member::Named(member) = &field.member {
                let dep = format!("self.{member}");
                self.check(&dep, "self access");
            }
            return;
        }
        self.visit_expr(&field.base);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if is_self(&call.receiver) {
            let dep = format!("self.{}", call.method);
            self.check(&dep, "self access");
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
        if let syn::Expr::Path(callee) = call.func.as_ref()
            && callee.qself.is_none()
        {
            self.check_path(&callee.path, "call");
        } else {
            self.visit_expr(&call.func);
        }
        for arg in &call.args {
            self.visit_expr(arg);
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.qself.is_none() {
            self.check_path(&path.path, "callback");
        }
        syn::visit::visit_expr_path(self, path);
    }
}

/// R6: every dependency of the stage body is in its allowlist.
pub(super) fn check_r6(found: &FoundFunc<'_>, stage_allow: &[&str], in_type: &str) -> Vec<String> {
    let locals = local_names(found);
    let mut seen = Deps {
        locals: &locals,
        allow: stage_allow,
        in_type,
        tag: "R6",
        hits: Vec::new(),
    };
    seen.visit_block(found.block);
    seen.hits
}

struct Macros<'a> {
    tokens: Vec<String>,
    _held: std::marker::PhantomData<&'a ()>,
}

impl<'ast> Visit<'ast> for Macros<'ast> {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens.push(mac.tokens.to_string());
        syn::visit::visit_macro(self, mac);
    }
}

fn split_top(text: &str, open: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quote = false;
    let mut escaped = false;
    let mut start = 0usize;
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quote = false;
            }
        } else if ch == '"' {
            quote = true;
        } else if ch == '(' || ch == '{' || ch == '[' {
            depth += 1;
        } else if ch == ')' || ch == '}' || ch == ']' {
            if depth > 0 {
                depth -= 1;
            }
        } else if ch == open && depth == 0 {
            parts.push(text[start..index].to_string());
            start = index + 1;
        }
        index += 1;
    }
    parts.push(text[start..].to_string());
    let _ = open;
    parts
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

fn ident_before(text: &str, mut end: usize) -> Option<(usize, usize, String)> {
    let bytes = text.as_bytes();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut start = end;
    while start > 0 && is_ident_char(bytes[start - 1] as char) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    Some((start, end, text[start..end].to_string()))
}

fn char_before(text: &str, mut pos: usize) -> Option<char> {
    let bytes = text.as_bytes();
    while pos > 0 && bytes[pos - 1].is_ascii_whitespace() {
        pos -= 1;
    }
    if pos == 0 {
        None
    } else {
        Some(bytes[pos - 1] as char)
    }
}

fn full_path_before(text: &str, end: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut cursor = end;
    loop {
        let (start, _, ident) = ident_before(text, cursor)?;
        parts.push(ident);
        let mut probe = start;
        let bytes = text.as_bytes();
        while probe > 0 && bytes[probe - 1].is_ascii_whitespace() {
            probe -= 1;
        }
        if probe >= 2 && bytes[probe - 1] == b':' && bytes[probe - 2] == b':' {
            cursor = probe - 2;
            continue;
        }
        break;
    }
    parts.reverse();
    Some(parts.join("::"))
}

struct Raw {
    calls: Vec<String>,
    selves: Vec<String>,
}

fn scan_raw(text: &str) -> Raw {
    let mut out = Raw {
        calls: Vec::new(),
        selves: Vec::new(),
    };
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'(' {
            if let Some((start, _, ident)) = ident_before(text, index) {
                let before = if start > 0 {
                    char_before(text, start)
                } else {
                    None
                };
                if before == Some('!') {
                    // A nested macro invocation, never a call.
                } else if before == Some('.') {
                    let mut probe = start;
                    while probe > 0 && text.as_bytes()[probe - 1].is_ascii_whitespace() {
                        probe -= 1;
                    }
                    if probe > 0 {
                        probe -= 1;
                    }
                    if let Some((_, _, owner)) = ident_before(text, probe) {
                        if owner == "self" {
                            out.selves.push(format!("self.{ident}"));
                        }
                    }
                } else if before == Some(':') {
                    if let Some(path) = full_path_before(text, index) {
                        out.calls.push(path);
                    }
                } else {
                    out.calls.push(ident);
                }
            }
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let mut end = index;
            while end < bytes.len() && is_ident_char(bytes[end] as char) {
                end += 1;
            }
            if text[index..end] == *"self" {
                let mut probe = end;
                while probe < bytes.len() && bytes[probe].is_ascii_whitespace() {
                    probe += 1;
                }
                if probe < bytes.len() && bytes[probe] == b'.' {
                    probe += 1;
                    while probe < bytes.len() && bytes[probe].is_ascii_whitespace() {
                        probe += 1;
                    }
                    let mut tail = probe;
                    while tail < bytes.len() && is_ident_char(bytes[tail] as char) {
                        tail += 1;
                    }
                    if tail > probe {
                        out.selves.push(format!("self.{}", &text[probe..tail]));
                    }
                }
            }
            index = end;
            continue;
        }
        index += 1;
    }
    out
}

struct BareSelves {
    hits: usize,
}

impl<'ast> Visit<'ast> for BareSelves {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if is_self(&field.base) {
            return;
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if is_self(&call.receiver) {
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && path
                .path
                .segments
                .first()
                .is_some_and(|seg| seg.ident == "self")
        {
            self.hits += 1;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

/// R9: macro arguments hold only allowlisted calls and no bare `self`.
pub(super) fn check_r9(found: &FoundFunc<'_>, stage_allow: &[&str]) -> Vec<String> {
    let locals = local_names(found);
    let mut macros = Macros {
        tokens: Vec::new(),
        _held: std::marker::PhantomData,
    };
    macros.visit_block(found.block);
    let mut hits = Vec::new();
    for tokens in &macros.tokens {
        for part in split_top(tokens, ',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Ok(expr) = syn::parse_str::<syn::Expr>(part) {
                let mut deps = Deps {
                    locals: &locals,
                    allow: stage_allow,
                    in_type: "",
                    tag: "R9",
                    hits: Vec::new(),
                };
                deps.visit_expr(&expr);
                hits.extend(deps.hits);
                let mut selves = BareSelves { hits: 0 };
                selves.visit_expr(&expr);
                for _ in 0..selves.hits {
                    hits.push(String::from("R9: bare `self` inside a macro"));
                }
            }
        }
        let raw = scan_raw(tokens);
        for dep in raw.selves {
            if !in_list(STD_OK, &dep) && !in_list(stage_allow, &dep) {
                hits.push(format!("R9: undeclared self access `{dep}` in a macro"));
            }
        }
        for dep in raw.calls {
            if locals.contains(&dep) {
                continue;
            }
            let first = dep.split("::").next().map_or(String::new(), str::to_string);
            if OUT_TYPES.iter().any(|out| *out == first) {
                continue;
            }
            if !in_list(STD_OK, &dep) && !in_list(stage_allow, &dep) {
                hits.push(format!("R9: undeclared call `{dep}` in a macro"));
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}
