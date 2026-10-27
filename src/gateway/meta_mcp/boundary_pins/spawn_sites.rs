// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every place production code starts a task is listed in `spawn_sites.tsv`,
//! keyed by (file, function, kind) with the number of such calls. A call's
//! delivery record is a task-local cell, so a refusal raised inside a spawned
//! task never reaches it: each spawn says why that loses nothing. A new site,
//! a second call inside a listed function, a row with no class, or a row
//! nothing matches fails.
//!
//! Classes: `raised-at-join` (the caller awaits the task in its own task and
//! records a refusal the task returns, as the OAuth token step does),
//! `own-cell` (the task serves deliveries itself and opens a cell for each),
//! `no-refusal-inside` (nothing the task runs refuses a call), and
//! `outside-calls` (it runs at start-up or in the background, and no call's
//! answer waits on it). Syntax scan, per function body; a spawn reached
//! through a method (`JoinSet::spawn`) or passed by path is missed, as in the
//! other pins.

use std::collections::BTreeMap;

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, expr_attrs, item_attrs, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// (file, function, kind) -> calls.
type Counts = BTreeMap<(String, String, String), usize>;

/// The kinds of spawning call one function body makes.
#[derive(Default)]
struct Body {
    kinds: BTreeMap<String, usize>,
}

fn ends_with(path: &syn::Path, tail: &[&str]) -> bool {
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    segs.len() >= tail.len() && segs[segs.len() - tail.len()..].iter().eq(tail.iter())
}

fn stmt_is_test_only(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Local(local) => test_only(&local.attrs),
        syn::Stmt::Item(item) => test_only(item_attrs(item)),
        syn::Stmt::Expr(expr, _) => test_only(expr_attrs(expr)),
        syn::Stmt::Macro(mac) => test_only(&mac.attrs),
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        if !stmt_is_test_only(stmt) {
            syn::visit::visit_stmt(self, stmt);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = call.func.as_ref() {
            let path = &p.path;
            let kind =
                if ends_with(path, &["tokio", "spawn"]) || ends_with(path, &["task", "spawn"]) {
                    Some("spawn")
                } else if ends_with(path, &["spawn_blocking"]) {
                    Some("spawn-blocking")
                } else {
                    None
                };
            if let Some(kind) = kind {
                *self.kinds.entry(kind.to_owned()).or_default() += 1;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[derive(Default)]
struct Sites {
    counts: Counts,
}

impl Sites {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        let mut body = Body::default();
        body.visit_block(block);
        for (kind, n) in body.kinds {
            *self
                .counts
                .entry((file.to_owned(), func.to_owned(), kind))
                .or_default() += n;
        }
    }
}

impl Sink for Sites {
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

/// The reviewed list: file, function, kind, count, class, reason.
const LISTED: &str = include_str!("spawn_sites.tsv");
const CLASSES: [&str; 4] = [
    "raised-at-join",
    "own-cell",
    "no-refusal-inside",
    "outside-calls",
];

/// The listed counts, and the rows that are malformed or carry no class.
fn listed() -> (Counts, Vec<String>) {
    let mut counts = Counts::new();
    let mut bad = Vec::new();
    for line in LISTED
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, kind, n, class, reason] = cols[..] else {
            bad.push(format!("not six columns: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            bad.push(format!("no class or no reason: {line}"));
        }
        let Ok(n) = n.parse::<usize>() else {
            bad.push(format!("count is not a number: {line}"));
            continue;
        };
        counts.insert((file.to_owned(), func.to_owned(), kind.to_owned()), n);
    }
    (counts, bad)
}

/// Every task production code starts is a reviewed row with a class, with
/// its exact count; a new spawn, a changed count or a stale row fails and
/// prints the rows to add, fix or remove.
#[test]
fn every_spawn_site_is_classified() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    let (want, bad) = listed();
    let mut wrong: Vec<String> = bad;
    for (key, n) in &sites.counts {
        match want.get(key) {
            Some(m) if m == n => {}
            Some(m) => wrong.push(format!("count {m} -> {n}: {}\t{}\t{}", key.0, key.1, key.2)),
            None => wrong.push(format!(
                "unlisted: {}\t{}\t{}\t{n}\t<class>\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for key in want.keys().filter(|k| !sites.counts.contains_key(*k)) {
        wrong.push(format!("stale: {}\t{}\t{}", key.0, key.1, key.2));
    }
    assert!(
        wrong.is_empty(),
        "spawn sites differ from spawn_sites.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The scanner counts both spawn kinds, and a second spawn in one function.
#[test]
fn the_scanner_counts_each_spawn_kind() {
    let block: syn::Block = syn::parse_quote!({
        tokio::spawn(a);
        tokio::task::spawn(b);
        tokio::task::spawn_blocking(c);
    });
    let mut sites = Sites::default();
    sites.function("a.rs", "f", &block);
    let key = |kind: &str| ("a.rs".to_owned(), "f".to_owned(), kind.to_owned());
    assert_eq!(sites.counts.get(&key("spawn")), Some(&2));
    assert_eq!(sites.counts.get(&key("spawn-blocking")), Some(&1));
}
