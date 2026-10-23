// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8663 T6 scan: one argument strip, one MCP result payload reader.
//!
//! Rule A (strip): outside the allowlisted functions, no production function
//! removes a gateway directive (`EXECUTION_DIRECTIVES`) by its literal name.
//! `admission::execution_arguments` removes them from the list itself, so it
//! never matches and needs no entry.
//!
//! Rule B (payload): a production function that reaches `structuredContent`
//! AND reaches a `content` text that it JSON-parses is a payload decoder. One
//! decoder is the rule (`tool_result_payload`); a second copy fails here.
//!
//! Syntax scan, per function body. Reaching a field means a `get`, `get_mut`
//! or `pointer` call, or an index, with that string literal. The parse must
//! take content text: a `from_str` / `from_value` call whose input reads a
//! `content` or `text` field or a binding that holds one (a `let`, or a
//! closure parameter fed one), or such a parse passed by path along a chain
//! that reads one. Test-only statements inside a production body are
//! skipped.
//!
//! ## Decoders that are not payload readers (MIK-8734)
//!
//! - `src/gateway/router/watch_poll.rs` `application_value` is a total reader
//!   for the watch source (first block, raw-text fallback); it is a Rule B
//!   decoder and is allowlisted with that reason.
//! - `src/capability/executor/mcp.rs` (the MCP process path) returns the
//!   whole `content` array and parses no text, and `mcp_rounds.rs`
//!   `prepare_object` reads neither field: neither matches Rule B.

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, expr_attrs, item_attrs, test_only, walk};
use crate::gateway::meta_mcp::admission::EXECUTION_DIRECTIVES;

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Rule A: functions that may remove a directive by name, and why.
const STRIP_ALLOW: &[(&str, &str, &str)] = &[(
    "src/gateway/meta_mcp/invoke/projection.rs",
    "extract_client_claim",
    "reads the claim before the shared strip removes it",
)];

/// Rule B: payload decoders that may exist, and why.
const DECODER_ALLOW: &[(&str, &str, &str)] = &[
    (
        "src/protocol/messages.rs",
        "tool_result_payload",
        "the one strict payload reader",
    ),
    (
        "src/gateway/router/watch_poll.rs",
        "application_value",
        "MIK-8734: the watch source's total reader of native results",
    ),
];

/// What one function body does with an MCP result and its arguments.
#[derive(Default)]
struct Body {
    structured: bool,
    /// Bindings that hold a `content` or `text` value (a `let`, or a
    /// closure parameter fed one), so a parse of them parses content text.
    text_vars: std::collections::HashSet<String>,
    /// A `from_str` / `from_value` whose input is content text.
    content_parse: bool,
    removes: Vec<String>,
}

fn literal(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) => Some(text.value()),
        syn::Expr::Group(group) => literal(&group.expr),
        syn::Expr::Paren(paren) => literal(&paren.expr),
        _ => None,
    }
}

fn is_content_field(name: &str) -> bool {
    name == "content" || name == "text" || name.starts_with("/content")
}

fn is_parse_path(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Path(path)
    if path.path.segments.last().is_some_and(|segment| {
        segment.ident == "from_str" || segment.ident == "from_value"
    }))
}

/// Whether `expr` reads a `content`/`text` field, or names a binding that
/// holds one.
struct Mentions<'v> {
    vars: &'v std::collections::HashSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for Mentions<'_> {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if matches!(method.as_str(), "get" | "get_mut" | "pointer")
            && call
                .args
                .first()
                .and_then(literal)
                .is_some_and(|name| is_content_field(&name))
        {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_index(&mut self, index: &'ast syn::ExprIndex) {
        if literal(&index.index).is_some_and(|name| is_content_field(&name)) {
            self.found = true;
        }
        syn::visit::visit_expr_index(self, index);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path
            .path
            .get_ident()
            .is_some_and(|ident| self.vars.contains(&ident.to_string()))
        {
            self.found = true;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

fn pattern_idents(pat: &syn::Pat, out: &mut Vec<String>) {
    struct Idents<'o>(&'o mut Vec<String>);
    impl<'ast> Visit<'ast> for Idents<'_> {
        fn visit_pat_ident(&mut self, binding: &'ast syn::PatIdent) {
            self.0.push(binding.ident.to_string());
            syn::visit::visit_pat_ident(self, binding);
        }
    }
    Idents(out).visit_pat(pat);
}

/// Whether a statement or expression is test-only code (`#[cfg(test)]`).
fn stmt_is_test_only(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Local(local) => test_only(&local.attrs),
        syn::Stmt::Item(item) => test_only(item_attrs(item)),
        syn::Stmt::Expr(expr, _) => test_only(expr_attrs(expr)),
        syn::Stmt::Macro(mac) => test_only(&mac.attrs),
    }
}

impl Body {
    fn mentions(&self, expr: &syn::Expr) -> bool {
        let mut probe = Mentions {
            vars: &self.text_vars,
            found: false,
        };
        probe.visit_expr(expr);
        probe.found
    }

    fn decodes(&self) -> bool {
        self.structured && self.content_parse
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        // gpt impl r1: test-only statements in a production body are not
        // production behaviour (the T3 probe is one).
        if !stmt_is_test_only(stmt) {
            syn::visit::visit_stmt(self, stmt);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init
            && self.mentions(&init.expr)
        {
            let mut names = Vec::new();
            pattern_idents(&local.pat, &mut names);
            self.text_vars.extend(names);
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if let Some(name) = call.args.first().and_then(literal) {
            if matches!(method.as_str(), "get" | "get_mut" | "pointer")
                && (name == "structuredContent" || name.starts_with("/structuredContent"))
            {
                self.structured = true;
            }
            if method == "remove" && EXECUTION_DIRECTIVES.contains(&name.as_str()) {
                self.removes.push(name);
            }
        }
        // A chain fed content text hands it on: to a parse passed by path
        // (`.and_then(serde_json::from_str)`), or to a closure's parameters.
        if self.mentions(&call.receiver) {
            for arg in &call.args {
                if is_parse_path(arg) {
                    self.content_parse = true;
                }
                if let syn::Expr::Closure(closure) = arg {
                    let mut names = Vec::new();
                    for input in &closure.inputs {
                        pattern_idents(input, &mut names);
                    }
                    self.text_vars.extend(names);
                }
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_index(&mut self, index: &'ast syn::ExprIndex) {
        if literal(&index.index).is_some_and(|name| name == "structuredContent") {
            self.structured = true;
        }
        syn::visit::visit_expr_index(self, index);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if is_parse_path(&call.func) && call.args.first().is_some_and(|arg| self.mentions(arg)) {
            self.content_parse = true;
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn body_of(block: &syn::Block) -> Body {
    let mut body = Body::default();
    body.visit_block(block);
    body
}

fn allowed(list: &[(&str, &str, &str)], file: &str, func: &str) -> Option<usize> {
    list.iter()
        .position(|(want_file, want_func, _)| *want_file == file && *want_func == func)
}

/// Offences and used allowlist entries, gathered per function.
struct Findings {
    rows: Vec<String>,
    strip_used: Vec<bool>,
    decoder_used: Vec<bool>,
}

impl Findings {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            strip_used: vec![false; STRIP_ALLOW.len()],
            decoder_used: vec![false; DECODER_ALLOW.len()],
        }
    }

    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        let body = body_of(block);
        for name in &body.removes {
            match allowed(STRIP_ALLOW, file, func) {
                Some(index) => self.strip_used[index] = true,
                None => self.rows.push(format!("{file}:{func}: strip `{name}`")),
            }
        }
        if body.decodes() {
            match allowed(DECODER_ALLOW, file, func) {
                Some(index) => self.decoder_used[index] = true,
                None => self.rows.push(format!("{file}:{func}: payload decoder")),
            }
        }
    }
}

impl Sink for Findings {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(function) => {
                self.function(&at.file, &function.sig.ident.to_string(), &function.block);
            }
            syn::Item::Impl(block) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(method) = member
                        && !test_only(&method.attrs)
                    {
                        self.function(&at.file, &method.sig.ident.to_string(), &method.block);
                    }
                }
            }
            syn::Item::Trait(block) => {
                for member in &block.items {
                    if let syn::TraitItem::Fn(method) = member
                        && let Some(default) = &method.default
                        && !test_only(&method.attrs)
                    {
                        self.function(&at.file, &method.sig.ident.to_string(), default);
                    }
                }
            }
            _ => {}
        }
    }
}

fn unused(list: &[(&str, &str, &str)], used: &[bool]) -> Vec<String> {
    list.iter()
        .zip(used)
        .filter(|(_, used)| !**used)
        .map(|((file, func, reason), _)| format!("{file}:{func} ({reason})"))
        .collect()
}

fn crate_findings() -> Findings {
    let mut findings = Findings::new();
    walk(crate_root(), &ROOTS, &mut findings).expect("the walk reads every module");
    findings.rows.sort();
    findings
}

/// T6 Rule A: no production function strips a gateway directive by hand;
/// `execution_arguments` is the one strip (DUPC-6.PR6.4). Every allowlist
/// entry must still match, so a stale one fails.
#[test]
fn one_directive_strip() {
    let findings = crate_findings();
    let offending: Vec<&String> = findings
        .rows
        .iter()
        .filter(|row| row.contains(": strip "))
        .collect();
    assert!(
        offending.is_empty(),
        "a gateway directive is removed by hand (call `admission::execution_arguments`): {offending:?}"
    );
    let stale = unused(STRIP_ALLOW, &findings.strip_used);
    assert!(
        stale.is_empty(),
        "strip allowlist entries nothing matched: {stale:?}"
    );
}

/// T6 Rule B: one MCP result payload decoder, `tool_result_payload`
/// (DUPC-6.PR6.5). Every allowlist entry must still match.
#[test]
fn one_payload_reader() {
    let findings = crate_findings();
    let offending: Vec<&String> = findings
        .rows
        .iter()
        .filter(|row| row.ends_with(": payload decoder"))
        .collect();
    assert!(
        offending.is_empty(),
        "a second MCP result payload decoder (call `protocol::tool_result_payload`): {offending:?}"
    );
    let stale = unused(DECODER_ALLOW, &findings.decoder_used);
    assert!(
        stale.is_empty(),
        "decoder allowlist entries nothing matched: {stale:?}"
    );
}

#[path = "single_reader_fixtures.rs"]
mod fixtures;
