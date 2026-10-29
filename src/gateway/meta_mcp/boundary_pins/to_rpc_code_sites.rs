// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production fn that reads `Error::to_rpc_code` is a reviewed row in
//! `to_rpc_code_sites.tsv`, with why its frame needs no origin from the
//! error, or why it builds no frame. A frame built from an error that can be a
//! backend failure goes through `JsonRpcResponse::of_error` (or
//! `of_error_text`), which records the origin the error count reads; a new
//! site, or a reviewed one moved to another fn, fails here until reviewed.
//!
//! Syntax scan with `syn`: zero-argument calls of the method, per fn body,
//! test code excluded.

use std::collections::BTreeSet;

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The reviewed rows: file, fn, reason.
const LISTED: &str = include_str!("to_rpc_code_sites.tsv");

#[derive(Default)]
struct Body {
    reads: usize,
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "to_rpc_code" && call.args.is_empty() {
            self.reads += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct Sites {
    found: BTreeSet<(String, String)>,
}

impl Sites {
    fn function(&mut self, file: &str, func: &str, attrs: &[syn::Attribute], block: &syn::Block) {
        if test_only(attrs) {
            return;
        }
        let mut body = Body::default();
        body.visit_block(block);
        if body.reads > 0 {
            self.found.insert((file.to_owned(), func.to_owned()));
        }
    }
}

impl Sink for Sites {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(f) => {
                self.function(&at.file, &f.sig.ident.to_string(), &f.attrs, &f.block)
            }
            syn::Item::Impl(block) if !test_only(&block.attrs) => {
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

/// The `(file, fn)` rows of the table, and the rows that carry no reason.
fn listed() -> (BTreeSet<(String, String)>, Vec<String>) {
    let mut rows = BTreeSet::new();
    let mut bad = Vec::new();
    for line in LISTED
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        match line.split('\t').collect::<Vec<_>>()[..] {
            [file, func, reason] if !reason.trim().is_empty() => {
                rows.insert((file.to_owned(), func.to_owned()));
            }
            _ => bad.push(line.to_owned()),
        }
    }
    (rows, bad)
}

#[test]
fn every_rpc_code_read_is_a_reviewed_site() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    let (rows, bad) = listed();
    assert!(
        bad.is_empty(),
        "rows without three columns or a reason: {bad:?}"
    );
    let unlisted: Vec<_> = sites.found.difference(&rows).collect();
    let stale: Vec<_> = rows.difference(&sites.found).collect();
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "to_rpc_code reads changed; build a frame from a backend-failure error \
         through JsonRpcResponse::of_error, or review the site into \
         to_rpc_code_sites.tsv. unlisted: {unlisted:?}; stale rows: {stale:?}"
    );
}
