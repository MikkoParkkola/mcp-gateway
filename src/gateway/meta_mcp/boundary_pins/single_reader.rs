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
//! or `pointer` call, or an index, with that string literal; parsing means a
//! call to a path ending in `from_str` or `from_value`.
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
use super::scan::{Place, Sink, test_only, walk};
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
    content_text: bool,
    parses: bool,
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

impl Body {
    fn field(&mut self, name: &str) {
        if name == "structuredContent" || name.starts_with("/structuredContent") {
            self.structured = true;
        }
        if name == "content" || name.starts_with("/content") {
            self.content_text = true;
        }
    }

    fn decodes(&self) -> bool {
        self.structured && self.content_text && self.parses
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if let Some(name) = call.args.first().and_then(literal) {
            if matches!(method.as_str(), "get" | "get_mut" | "pointer") {
                self.field(&name);
            }
            if method == "remove" && EXECUTION_DIRECTIVES.contains(&name.as_str()) {
                self.removes.push(name);
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_index(&mut self, index: &'ast syn::ExprIndex) {
        if let Some(name) = literal(&index.index) {
            self.field(&name);
        }
        syn::visit::visit_expr_index(self, index);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "from_str" || segment.ident == "from_value")
        {
            self.parses = true;
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
