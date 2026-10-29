// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production await on a backend transport sits inside
//! `backend_wait(..)`, so `mcp_gateway_added_latency_seconds` subtracts it.
//! A transport request outside the helper would count backend time as time
//! the gateway added.
//!
//! Syntax scan: a call of a transport request method whose receiver is named
//! `transport` (a binding or a field). The `Backend` methods of the same
//! names funnel into the wrapped send in `request_attempted` and are not
//! transports. ponytail: a transport bound under another name is missed;
//! the site list below fails if one of the known sites moves or vanishes.

use std::collections::BTreeSet;

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The transport methods that send a request and await its answer.
const METHODS: [&str; 3] = [
    "request",
    "request_with_headers",
    "request_with_task_capability",
];

/// The helper that measures a backend wait.
const WRAPPER: &str = "backend_wait";

/// (file, function) of every transport request the scan should find.
const SITES: [(&str, &str); 5] = [
    ("src/backend/era.rs", "probe"),
    ("src/backend/era.rs", "start_detached_http"),
    ("src/backend/list_drain.rs", "drain_list_pages"),
    ("src/backend/ops.rs", "request_attempted"),
    ("src/backend/probe.rs", "health_probe"),
];

fn names_transport(receiver: &syn::Expr) -> bool {
    match receiver {
        syn::Expr::Path(p) => p.path.is_ident("transport"),
        syn::Expr::Field(f) => matches!(&f.member, syn::Member::Named(n) if n == "transport"),
        syn::Expr::Paren(p) => names_transport(&p.expr),
        syn::Expr::Reference(r) => names_transport(&r.expr),
        _ => false,
    }
}

/// One function body: its transport requests, and which were unwrapped.
#[derive(Default)]
struct Body {
    depth: usize,
    found: usize,
    unwrapped: usize,
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let wraps = matches!(call.func.as_ref(), syn::Expr::Path(p)
            if p.path.segments.last().is_some_and(|s| s.ident == WRAPPER));
        self.depth += usize::from(wraps);
        syn::visit::visit_expr_call(self, call);
        self.depth -= usize::from(wraps);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if METHODS.contains(&call.method.to_string().as_str()) && names_transport(&call.receiver) {
            self.found += 1;
            self.unwrapped += usize::from(self.depth == 0);
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct Waits {
    sites: BTreeSet<(String, String)>,
    unwrapped: Vec<String>,
}

impl Waits {
    fn function(&mut self, file: &str, func: &str, attrs: &[syn::Attribute], block: &syn::Block) {
        if test_only(attrs) {
            return;
        }
        let mut body = Body::default();
        body.visit_block(block);
        if body.found > 0 {
            self.sites.insert((file.to_owned(), func.to_owned()));
        }
        if body.unwrapped > 0 {
            self.unwrapped
                .push(format!("{file} {func}: {} unwrapped", body.unwrapped));
        }
    }
}

impl Sink for Waits {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(f) => {
                self.function(&at.file, &f.sig.ident.to_string(), &f.attrs, &f.block)
            }
            syn::Item::Impl(block) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(m) = member {
                        self.function(&at.file, &m.sig.ident.to_string(), &m.attrs, &m.block);
                    }
                }
            }
            _ => {}
        }
    }
}

#[test]
fn every_backend_transport_wait_is_measured() {
    let mut waits = Waits::default();
    walk(crate_root(), &ROOTS, &mut waits).expect("the walk reads every module");
    let expected: BTreeSet<(String, String)> = SITES
        .iter()
        .map(|(file, func)| ((*file).to_owned(), (*func).to_owned()))
        .collect();
    assert_eq!(waits.sites, expected, "the transport request sites changed");
    assert!(
        waits.unwrapped.is_empty(),
        "transport waits outside {WRAPPER}:\n{}",
        waits.unwrapped.join("\n")
    );
}
