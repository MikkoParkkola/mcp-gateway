// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production fn that reads `Error::to_rpc_code` is a reviewed row in
//! `to_rpc_code_sites.tsv`, with its number of reads and why its frame needs
//! no origin from the error, or why it builds no frame. A frame built from an
//! error that can be a backend failure goes through `JsonRpcResponse::of_error`
//! (or `of_error_text`), which records the origin the error count reads; a new
//! site, a reviewed one moved to another fn, or an extra read in a listed fn
//! fails here until reviewed.
//!
//! Syntax scan with `syn`, test code excluded. A read is a method call, a
//! path naming the fn (`Error::to_rpc_code(&e)`, `.map(Error::to_rpc_code)`),
//! or the name among a macro's tokens (`error!(code = e.to_rpc_code())`), in
//! free fns, impl fns and trait default bodies.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

const NAME: &str = "to_rpc_code";

/// The reviewed rows: file, fn, reads, reason.
const LISTED: &str = include_str!("to_rpc_code_sites.tsv");

/// (file, fn) -> reads.
type Reads = BTreeMap<(String, String), usize>;

#[derive(Default)]
struct Body {
    reads: usize,
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == NAME && call.args.is_empty() {
            self.reads += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.path.segments.last().is_some_and(|s| s.ident == NAME) {
            self.reads += 1;
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // A macro's arguments are tokens, not parsed expressions: count the
        // name among them as whole identifiers.
        self.reads += mac
            .tokens
            .to_string()
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|word| *word == NAME)
            .count();
        syn::visit::visit_macro(self, mac);
    }
}

#[derive(Default)]
struct Sites {
    found: Reads,
}

impl Sites {
    fn function(&mut self, file: &str, func: &str, attrs: &[syn::Attribute], block: &syn::Block) {
        if test_only(attrs) {
            return;
        }
        let mut body = Body::default();
        body.visit_block(block);
        if body.reads > 0 {
            *self
                .found
                .entry((file.to_owned(), func.to_owned()))
                .or_default() += body.reads;
        }
    }
}

impl Sink for Sites {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(f) => {
                self.function(&at.file, &f.sig.ident.to_string(), &f.attrs, &f.block);
            }
            syn::Item::Impl(block) if !test_only(&block.attrs) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(m) = member {
                        self.function(&at.file, &m.sig.ident.to_string(), &m.attrs, &m.block);
                    }
                }
            }
            syn::Item::Trait(block) if !test_only(&block.attrs) => {
                for member in &block.items {
                    if let syn::TraitItem::Fn(m) = member
                        && let Some(default) = &m.default
                    {
                        self.function(&at.file, &m.sig.ident.to_string(), &m.attrs, default);
                    }
                }
            }
            _ => {}
        }
    }
}

/// The table's reads per `(file, fn)`, and the rows that are malformed or
/// carry no reason.
fn listed() -> (Reads, Vec<String>) {
    let mut rows = Reads::new();
    let mut bad = Vec::new();
    for line in LISTED
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        match line.split('\t').collect::<Vec<_>>()[..] {
            [file, func, reads, reason] if !reason.trim().is_empty() => match reads.parse() {
                Ok(n) => {
                    rows.insert((file.to_owned(), func.to_owned()), n);
                }
                Err(_) => bad.push(line.to_owned()),
            },
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
        "rows without four columns, a read count or a reason: {bad:?}"
    );
    let keys: BTreeSet<_> = sites.found.keys().chain(rows.keys()).collect();
    let differ: Vec<String> = keys
        .into_iter()
        .filter(|key| sites.found.get(*key) != rows.get(*key))
        .map(|key| {
            format!(
                "{}\t{}\tfound {}\tlisted {}",
                key.0,
                key.1,
                sites.found.get(key).copied().unwrap_or(0),
                rows.get(key).copied().unwrap_or(0)
            )
        })
        .collect();
    assert!(
        differ.is_empty(),
        "to_rpc_code reads changed; build a frame from a backend-failure error \
         through JsonRpcResponse::of_error, or review the site into \
         to_rpc_code_sites.tsv:\n{}",
        differ.join("\n")
    );
}

/// A read counts in each of its three forms, so a site cannot hide in a
/// macro or behind a path.
#[test]
fn a_read_is_counted_in_a_call_a_path_and_a_macro() {
    let block: syn::Block = syn::parse_quote!({
        let a = e.to_rpc_code();
        let b = errs.iter().map(Error::to_rpc_code);
        tracing::error!(code = e.to_rpc_code(), "failed");
    });
    let mut body = Body::default();
    body.visit_block(&block);
    assert_eq!(body.reads, 3);
}
