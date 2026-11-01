// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every place production code creates or replaces a file is listed in
//! `creation_sites.tsv` with its permission class, keyed by (file, function,
//! kind) with the number of such calls. A new site, a second call inside a
//! listed function, a row with no class, or a row nothing matches fails.
//!
//! Classes: `helper` (the call is one of the crate's private-file or atomic
//! writers, whose results the Windows table test checks), `no-secret` (the
//! file holds nothing secret and needs no owner-only list), `test-only`
//! (reached only from test support). Syntax scan, per function body; a call
//! passed by path (`.map(File::create)`) is missed, as in the other pins.

use std::collections::BTreeMap;

use syn::visit::Visit;

use super::fragments::{Table, live_base, pin_table, scratch_table, without_first_row};
use super::packaged::crate_root;
use super::scan::{Place, Sink, expr_attrs, item_attrs, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The crate's own writers: a call to one is a `helper` site.
const HELPERS: [&str; 8] = [
    "write_atomic",
    "copy_keeping_access",
    "create_new_private",
    "create_private_replacing",
    "create_file_private",
    "create_dir_private",
    "create_file_like",
    "create_like",
];

/// (file, function, kind) -> calls.
type Counts = BTreeMap<(String, String, String), usize>;

/// The kinds of creating call one function body makes.
#[derive(Default)]
struct Body {
    kinds: BTreeMap<String, usize>,
}

fn last_segment(path: &syn::Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

fn ends_with(path: &syn::Path, tail: &[&str]) -> bool {
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    segs.len() >= tail.len() && segs[segs.len() - tail.len()..].iter().eq(tail.iter())
}

fn is_true(expr: &syn::Expr) -> bool {
    matches!(
        expr,
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Bool(b),
            ..
        }) if b.value
    )
}

fn stmt_is_test_only(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Local(local) => test_only(&local.attrs),
        syn::Stmt::Item(item) => test_only(item_attrs(item)),
        syn::Stmt::Expr(expr, _) => test_only(expr_attrs(expr)),
        syn::Stmt::Macro(mac) => test_only(&mac.attrs),
    }
}

impl Body {
    fn count(&mut self, kind: &str) {
        *self.kinds.entry(kind.to_owned()).or_default() += 1;
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
            if ends_with(path, &["File", "create"]) || ends_with(path, &["File", "create_new"]) {
                self.count("file-create");
            } else if ends_with(path, &["fs", "write"]) {
                self.count("fs-write");
            } else if ends_with(path, &["fs", "copy"]) {
                self.count("fs-copy");
            } else if let Some(name) = last_segment(path)
                && HELPERS.contains(&name.as_str())
            {
                self.count(&format!("helper:{name}"));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if (method == "create" || method == "create_new") && call.args.first().is_some_and(is_true)
        {
            self.count("open-create");
        }
        syn::visit::visit_expr_method_call(self, call);
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

const CLASSES: [&str; 3] = ["helper", "no-secret", "test-only"];

/// The listed counts from the reviewed `creation_sites` table (file, function,
/// kind, count, class, reason), and the rows that are malformed or carry no
/// class.
fn listed(table: &Table) -> (Counts, Vec<String>) {
    let mut counts = Counts::new();
    let mut bad = Vec::new();
    let listed = table.text();
    for line in listed
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

/// Every creating call in production code is a reviewed row with a class,
/// with its exact count; a new call, a changed count or a stale row fails
/// and prints the rows to add, fix or remove.
#[test]
fn every_file_creation_site_is_classified() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    let wrong = differences(&sites.counts, &pin_table("creation_sites"));
    assert!(
        wrong.is_empty(),
        "file creation sites differ from creation_sites.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// What differs between the counted sites and the reviewed table: malformed
/// rows, changed counts, unlisted sites and stale rows.
fn differences(found: &Counts, table: &Table) -> Vec<String> {
    let (want, bad) = listed(table);
    let mut wrong: Vec<String> = bad;
    for (key, n) in found {
        match want.get(key) {
            Some(m) if m == n => {}
            Some(m) => wrong.push(format!("count {m} -> {n}: {}\t{}\t{}", key.0, key.1, key.2)),
            None => wrong.push(format!(
                "unlisted: {}\t{}\t{}\t{n}\t<class>\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for key in want.keys().filter(|k| !found.contains_key(*k)) {
        wrong.push(format!("stale: {}\t{}\t{}", key.0, key.1, key.2));
    }
    wrong
}

/// The scanner sees a second create inside a function it has already counted.
#[test]
fn a_second_create_in_one_function_changes_its_count() {
    let one: syn::Block = syn::parse_quote!({
        std::fs::write(p, b)?;
    });
    let two: syn::Block = syn::parse_quote!({
        std::fs::write(p, b)?;
        std::fs::write(q, b)?;
    });
    let mut sites = Sites::default();
    sites.function("a.rs", "f", &one);
    sites.function("b.rs", "f", &two);
    let key = |file: &str| (file.to_owned(), "f".to_owned(), "fs-write".to_owned());
    assert_eq!(sites.counts.get(&key("a.rs")), Some(&1));
    assert_eq!(sites.counts.get(&key("b.rs")), Some(&2));
}

/// Every creating call the walk counts, by (file, function, kind).
fn counted() -> Counts {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    sites.counts
}

/// FRAG.2 through the real comparison: a real row held only by a fragment
/// still counts.
#[test]
fn creation_sites_reads_a_required_row_from_a_fragment() {
    let (base, moved) = without_first_row(&live_base("creation_sites"));
    let (_root, table) = scratch_table("creation_sites", &base, &[("1.tsv", &moved)]);
    let wrong = differences(&counted(), &table);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// FRAG.2: a stale row in a fragment fails, naming the fragment.
#[test]
fn creation_sites_rejects_a_stale_fragment_row() {
    let stale = "src/nowhere.rs\tf\tfs-write\t1\thelper\tnone\n";
    let (_root, table) = scratch_table(
        "creation_sites",
        &live_base("creation_sites"),
        &[("1.tsv", stale)],
    );
    let wrong = differences(&counted(), &table);
    assert!(
        wrong
            .iter()
            .any(|l| l.contains("stale") && l.contains("1.tsv")),
        "{}",
        wrong.join("\n")
    );
}

/// FRAG.2: a key held by the base and by a fragment fails, naming both files
/// (a map insert would keep only the last).
#[test]
fn creation_sites_key_repeated_across_files_fails_naming_both() {
    let (_, moved) = without_first_row(&live_base("creation_sites"));
    let (_root, table) = scratch_table(
        "creation_sites",
        &live_base("creation_sites"),
        &[("1.tsv", &moved)],
    );
    let wrong = differences(&counted(), &table);
    assert!(
        wrong
            .iter()
            .any(|l| l.contains("creation_sites.tsv") && l.contains("1.tsv")),
        "{}",
        wrong.join("\n")
    );
}

/// A key listed twice in one file fails (a map insert would keep only one).
#[test]
fn creation_sites_key_repeated_in_one_file_fails() {
    let (_, moved) = without_first_row(&live_base("creation_sites"));
    let base = format!("{}{moved}", live_base("creation_sites"));
    let (_root, table) = scratch_table("creation_sites", &base, &[]);
    let wrong = differences(&counted(), &table);
    assert!(
        wrong.iter().any(|l| l.contains("repeated")),
        "{}",
        wrong.join("\n")
    );
}

/// A key the table lacks is listed to add, in the reader's own fragment.
#[test]
fn creation_sites_missing_key_is_listed_to_add_in_your_fragment() {
    let (base, _) = without_first_row(&live_base("creation_sites"));
    let (_root, table) = scratch_table("creation_sites", &base, &[]);
    let wrong = differences(&counted(), &table).join("\n");
    assert!(wrong.contains("rows to add"), "{wrong}");
    assert!(wrong.contains("creation_sites.d/<ticket>.tsv"), "{wrong}");
}

/// A row whose value changed under the same key names the file to edit.
#[test]
fn creation_sites_changed_value_names_the_owning_file() {
    let (base, moved) = without_first_row(&live_base("creation_sites"));
    let mut cols: Vec<&str> = moved.trim_end().split('\t').collect();
    cols[3] = "999";
    let changed = format!("{}\n", cols.join("\t"));
    let (_root, table) = scratch_table("creation_sites", &base, &[("1.tsv", &changed)]);
    let wrong = differences(&counted(), &table).join("\n");
    assert!(
        wrong.contains("edit this row in") && wrong.contains("1.tsv"),
        "{wrong}"
    );
}
