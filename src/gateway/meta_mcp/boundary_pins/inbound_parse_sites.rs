// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every place production code under src/transport, src/a2a and src/backend
//! parses inbound JSON is listed in `inbound_parse_sites.tsv` with its class
//! (MIK-9035 T1.31). A new parse site, a changed count, a stale row, or a
//! `scrubbed` function that lost its scrub call fails.
//!
//! Classes:
//! - `scrubbed`: the function itself calls one of [`SCRUB_CALLS`].
//! - `scrubbed-by`: the reason starts `by <file>::<function>:`, naming the
//!   function every result of this one passes; that function must call one
//!   of [`SCRUB_CALLS`].
//! - `post-transport`: parses a result the transport already scrubbed.
//! - `not-backend-data`: reads no backend content (a log level).
//!
//! Syntax scan, per function body, like the other pins.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 1] = ["src/lib.rs"];
const SCOPES: [&str; 3] = ["src/transport/", "src/a2a/", "src/backend/"];

/// The calls that remove a backend's injected values.
const SCRUB_CALLS: [&str; 7] = [
    "ingress_scrub",
    "scrub_frame",
    "withheld",
    "scrub_answer",
    "scrub_response_with",
    "scrub_text",
    "scrubbed",
];

/// (file, function, kind) -> parses.
type Counts = BTreeMap<(String, String, String), usize>;

#[derive(Default)]
struct Body {
    kinds: BTreeMap<String, usize>,
    scrubs: bool,
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

impl Body {
    fn count(&mut self, kind: &str) {
        *self.kinds.entry(kind.to_owned()).or_default() += 1;
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = call.func.as_ref() {
            let segs = segments(&p.path);
            let tail: Vec<&str> = segs
                .iter()
                .rev()
                .take(2)
                .rev()
                .map(String::as_str)
                .collect();
            match tail.as_slice() {
                [
                    "serde_json",
                    f @ ("from_str" | "from_slice" | "from_value" | "from_reader"),
                ] => {
                    self.count(f);
                }
                ["JsonRpcMessage", "from_line"] => self.count("from_line"),
                ["McpFrame", "from_text"] => self.count("from_text"),
                _ => {}
            }
            if segs
                .last()
                .is_some_and(|f| SCRUB_CALLS.contains(&f.as_str()))
            {
                self.scrubs = true;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if method == "json" && call.args.is_empty() {
            self.count("json");
        }
        if SCRUB_CALLS.contains(&method.as_str()) {
            self.scrubs = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct Sites {
    counts: Counts,
    /// (file, function) of every function that calls a scrub.
    scrubbing: BTreeSet<(String, String)>,
}

impl Sites {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        if !SCOPES.iter().any(|scope| file.starts_with(scope)) {
            return;
        }
        let mut body = Body::default();
        body.visit_block(block);
        if body.scrubs {
            self.scrubbing.insert((file.to_owned(), func.to_owned()));
        }
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
            _ => {}
        }
    }
}

/// The reviewed list: file, function, kind, count, class, reason.
const LISTED: &str = include_str!("inbound_parse_sites.tsv");
const CLASSES: [&str; 4] = [
    "scrubbed",
    "scrubbed-by",
    "post-transport",
    "not-backend-data",
];

struct Row {
    count: usize,
    class: String,
    reason: String,
}

/// The table's rows by (file, function, kind).
type Rows = BTreeMap<(String, String, String), Row>;

fn listed() -> (Rows, Vec<String>) {
    let mut rows = BTreeMap::new();
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
        let Ok(count) = n.parse::<usize>() else {
            bad.push(format!("count is not a number: {line}"));
            continue;
        };
        let previous = rows.insert(
            (file.to_owned(), func.to_owned(), kind.to_owned()),
            Row {
                count,
                class: class.to_owned(),
                reason: reason.to_owned(),
            },
        );
        if previous.is_some() {
            bad.push(format!("duplicate row: {line}"));
        }
    }
    (rows, bad)
}

/// The function a `scrubbed-by` reason names: `by <file>::<function>:`.
fn named_scrubber(reason: &str) -> Option<(String, String)> {
    // Up to the first ": ", so the `::` inside the name is kept.
    let (named, _) = reason.strip_prefix("by ")?.split_once(": ")?;
    let (file, func) = named.rsplit_once("::")?;
    Some((file.to_owned(), func.to_owned()))
}

/// What is wrong with the scan against the table.
fn differences(sites: &Sites) -> Vec<String> {
    let (want, mut wrong) = listed();
    for (key, n) in &sites.counts {
        match want.get(key) {
            Some(row) if row.count == *n => {}
            Some(row) => wrong.push(format!(
                "count {} -> {n}: {}\t{}\t{}",
                row.count, key.0, key.1, key.2
            )),
            None => wrong.push(format!(
                "unlisted: {}\t{}\t{}\t{n}\t<class>\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for (key, row) in &want {
        if !sites.counts.contains_key(key) {
            wrong.push(format!("stale: {}\t{}\t{}", key.0, key.1, key.2));
        }
        let at = (key.0.clone(), key.1.clone());
        match row.class.as_str() {
            "scrubbed" if !sites.scrubbing.contains(&at) => {
                wrong.push(format!("lost its scrub call: {}\t{}", key.0, key.1));
            }
            "scrubbed-by" => match named_scrubber(&row.reason) {
                Some(by) if sites.scrubbing.contains(&by) => {}
                Some(by) => wrong.push(format!(
                    "{}\t{}: {}::{} does not scrub",
                    key.0, key.1, by.0, by.1
                )),
                None => wrong.push(format!(
                    "{}\t{}: reason must start `by <file>::<function>:`",
                    key.0, key.1
                )),
            },
            _ => {}
        }
    }
    wrong
}

/// Every inbound parse in the three trees is a reviewed row, and every
/// scrubbing claim still holds.
#[test]
fn every_inbound_parse_site_is_classified() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    let wrong = differences(&sites);
    assert!(
        wrong.is_empty(),
        "inbound parse sites differ from inbound_parse_sites.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The pin's own proof: a new parse site fails, and a `scrubbed` function
/// that loses its scrub call fails.
#[test]
fn a_new_site_and_a_lost_scrub_both_fail() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    let added: syn::Block = syn::parse_quote!({
        let _v: serde_json::Value = serde_json::from_str(text)?;
    });
    let mut with_new = Sites {
        counts: sites.counts.clone(),
        scrubbing: sites.scrubbing.clone(),
    };
    with_new.function("src/transport/fake.rs", "fake_parse", &added);
    assert!(
        differences(&with_new)
            .iter()
            .any(|w| w.starts_with("unlisted: src/transport/fake.rs")),
        "a new parse site passed"
    );
    let mut lost = Sites {
        counts: sites.counts.clone(),
        scrubbing: sites.scrubbing.clone(),
    };
    lost.scrubbing.remove(&(
        "src/transport/stdio.rs".to_owned(),
        "handle_response".to_owned(),
    ));
    assert!(
        differences(&lost)
            .iter()
            .any(|w| w.starts_with("lost its scrub call: src/transport/stdio.rs")),
        "a lost scrub call passed"
    );
}
