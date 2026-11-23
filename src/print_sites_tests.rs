// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! LOGINJ.7: nothing in production code writes to stdout or stderr except at a reviewed site. The gateway's log is
//! escaped (LOGINJ.6), so a direct print is the only way text from gateway.yaml could reach stderr raw; this row
//! makes the next such print fail CI instead of becoming a ticket.
//!
//! Every production file is parsed with syn. A site is a `println!`, `eprintln!`, `print!`, `eprint!` or `dbg!`
//! invocation, or a call to a function named `stdout` or `stderr`; one written inside another macro's tokens (a
//! `writeln!(std::io::stderr(), ..)`, a print nested in a `select!`) counts too, found by reading the tokens without
//! expanding them. Items compiled only under test are skipped. Each site is keyed by its file, its owner (the
//! enclosing modules, impl type and function) and its text, and must match `print_sites.tsv`:
//! - `T` rows: a function whose output is the terminal of a CLI subcommand; every print inside it is allowed.
//! - `P` rows: one exact site elsewhere, with the reason it cannot carry a forged line.
//!
//! A failure prints the unlisted sites as rows to review and add. Limits: a print macro or a `stdout`/`stderr`
//! function imported under another name is not seen, nor is a handle created outside the scanned tree.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::visit::Visit;

use crate::test_source_text::{rust_files, test_only};

/// Macros that print to stdout or stderr themselves.
const PRINT_MACROS: [&str; 5] = ["println", "eprintln", "print", "eprint", "dbg"];

/// Functions that hand out a process stream.
const STREAMS: [&str; 2] = ["stdout", "stderr"];

/// The trees scanned, from the crate's manifest directory.
const TREES: [&str; 2] = ["src", "crates"];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    owner: String,
    text: String,
}

/// Walks one file's syntax tree, keeping the owner path of every node it visits.
struct Finder {
    file: String,
    owner: Vec<String>,
    found: Vec<Site>,
}

impl Finder {
    fn record(&mut self, text: String) {
        self.found.push(Site {
            file: self.file.clone(),
            owner: self.owner.join("::"),
            text,
        });
    }

    fn within(&mut self, part: String, walk: impl FnOnce(&mut Self)) {
        self.owner.push(part);
        walk(self);
        self.owner.pop();
    }
}

fn path_text(path: &syn::Path) -> String {
    let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    names.join("::")
}

/// Whether `tokens` hold, at any depth, a print macro (`name !`) or a stream call (`stdout ( )`).
fn tokens_print(tokens: &TokenStream) -> bool {
    let trees: Vec<TokenTree> = tokens.clone().into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        let hit = match tree {
            TokenTree::Group(group) => tokens_print(&group.stream()),
            TokenTree::Ident(ident) => {
                let name = ident.to_string();
                match trees.get(at + 1) {
                    Some(TokenTree::Punct(p)) => {
                        p.as_char() == '!' && PRINT_MACROS.contains(&name.as_str())
                    }
                    Some(TokenTree::Group(g)) => {
                        g.delimiter() == Delimiter::Parenthesis
                            && g.stream().is_empty()
                            && STREAMS.contains(&name.as_str())
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        if hit {
            return true;
        }
    }
    false
}

impl<'ast> Visit<'ast> for Finder {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let skip = match item {
            syn::Item::Fn(f) => test_only(&f.attrs),
            syn::Item::Mod(m) => test_only(&m.attrs),
            syn::Item::Impl(i) => test_only(&i.attrs),
            syn::Item::Const(c) => test_only(&c.attrs),
            syn::Item::Static(s) => test_only(&s.attrs),
            syn::Item::Macro(m) => test_only(&m.attrs),
            syn::Item::Trait(t) => test_only(&t.attrs),
            _ => false,
        };
        if !skip {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        self.within(module.ident.to_string(), |me| {
            syn::visit::visit_item_mod(me, module)
        });
    }

    fn visit_item_impl(&mut self, block: &'ast syn::ItemImpl) {
        let target = match &*block.self_ty {
            syn::Type::Path(typed) => path_text(&typed.path),
            _ => String::from("impl"),
        };
        self.within(target, |me| syn::visit::visit_item_impl(me, block));
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.within(function.sig.ident.to_string(), |me| {
            syn::visit::visit_item_fn(me, function)
        });
    }

    fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
        if !test_only(&method.attrs) {
            self.within(method.sig.ident.to_string(), |me| {
                syn::visit::visit_impl_item_fn(me, method)
            });
        }
    }

    fn visit_trait_item_fn(&mut self, method: &'ast syn::TraitItemFn) {
        self.within(method.sig.ident.to_string(), |me| {
            syn::visit::visit_trait_item_fn(me, method)
        });
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let own = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if PRINT_MACROS.contains(&own.as_str()) || tokens_print(&mac.tokens) {
            self.record(format!("{}!({})", path_text(&mac.path), mac.tokens));
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(callee) = &*call.func
            && call.args.is_empty()
            && callee
                .path
                .segments
                .last()
                .is_some_and(|s| STREAMS.contains(&s.ident.to_string().as_str()))
        {
            self.record(format!("{}()", path_text(&callee.path)));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// The sites in one file's text, or why it could not be read as Rust.
fn sites_in(file: &str, text: &str) -> Result<Vec<Site>, String> {
    let parsed = syn::parse_file(text).map_err(|e| format!("{file} does not parse: {e}"))?;
    let mut finder = Finder {
        file: file.to_owned(),
        owner: Vec::new(),
        found: Vec::new(),
    };
    finder.visit_file(&parsed);
    Ok(finder.found)
}

/// A file that only tests compile, by its path: the same rule LOGINJ.6 uses for its scan.
fn test_file(rel: &str) -> bool {
    rel.ends_with("_tests.rs")
        || rel.contains("_tests/")
        || rel.contains("/tests/")
        || rel == "src/test_log_capture.rs"
        || rel.starts_with("src/test_support/")
}

/// `path` under `base`, written with `/` whatever the platform.
fn slash_path(base: &Path, path: &Path) -> String {
    let inner = path.strip_prefix(base).unwrap_or(path);
    let parts: Vec<String> = inner
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    parts.join("/")
}

/// One allowlist row of `print_sites.tsv`.
struct Allowed {
    tier: char,
    file: String,
    owner: String,
    text: String,
}

fn allowlist() -> Vec<Allowed> {
    let mut rows = Vec::new();
    for line in include_str!("print_sites.tsv").lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let cells: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            cells.len(),
            5,
            "a print_sites.tsv row has 5 cells: {line:?}"
        );
        assert!(
            !cells[4].trim().is_empty(),
            "a print_sites.tsv row needs its reason: {line:?}"
        );
        rows.push(Allowed {
            tier: cells[0].chars().next().unwrap_or(' '),
            file: cells[1].to_owned(),
            owner: cells[2].to_owned(),
            text: cells[3].to_owned(),
        });
    }
    rows
}

/// Whether `owner` is `function` or nested inside it.
fn inside(owner: &str, function: &str) -> bool {
    owner == function
        || owner
            .strip_prefix(function)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// Whether `site` is allowed: a `T` row names its function (or one it is nested in), or a `P` row names it exactly.
fn covered(site: &Site, rows: &[Allowed]) -> bool {
    rows.iter().any(|row| {
        row.file == site.file
            && match row.tier {
                'T' => inside(&site.owner, &row.owner),
                'P' => site.owner == row.owner && site.text == row.text,
                other => panic!("unknown tier {other:?} in print_sites.tsv"),
            }
    })
}

/// Every site in the production tree, sorted.
fn production_sites() -> Vec<Site> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sites = Vec::new();
    for tree in TREES {
        let mut paths = Vec::new();
        rust_files(&base.join(tree), &mut paths);
        for file in paths {
            let rel = slash_path(base, &file);
            if !test_file(&rel) {
                let source =
                    std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{rel}: {e}"));
                sites.extend(sites_in(&rel, &source).unwrap_or_else(|e| panic!("{e}")));
            }
        }
    }
    sites.sort();
    sites
}

/// L2: every production site is allowlisted, and every row still names something that exists.
#[test]
fn every_print_in_production_code_is_a_reviewed_site() {
    let rows = allowlist();
    let sites = production_sites();
    let unlisted: Vec<String> = sites
        .iter()
        .filter(|site| !covered(site, &rows))
        .map(|s| format!("P\t{}\t{}\t{}\t<reason>", s.file, s.owner, s.text))
        .collect();
    assert!(
        unlisted.is_empty(),
        "{} print site(s) not in print_sites.tsv; review each, then add a row:\n{}",
        unlisted.len(),
        unlisted.join("\n")
    );
    let owners: BTreeSet<(&str, &str)> = sites
        .iter()
        .map(|s| (s.file.as_str(), s.owner.as_str()))
        .collect();
    let names_something = |row: &Allowed| match row.tier {
        'P' => sites
            .iter()
            .any(|s| s.file == row.file && s.owner == row.owner && s.text == row.text),
        _ => owners
            .iter()
            .any(|(file, owner)| *file == row.file && inside(owner, &row.owner)),
    };
    let stale: Vec<String> = rows
        .iter()
        .filter(|row| !names_something(row))
        .map(|row| format!("{}\t{}\t{}\t{}", row.tier, row.file, row.owner, row.text))
        .collect();
    assert!(
        stale.is_empty(),
        "print_sites.tsv rows that match no site (gone or changed; a changed P site needs a fresh review):\n{}",
        stale.join("\n")
    );
}

/// L2a, L2c, L2d: a print planted in serve-path code is not covered by any row, so it would fail L2. The serve
/// functions and the two helpers they call in `src/commands/` are never terminal output.
#[test]
fn a_print_planted_in_the_serve_path_is_not_covered() {
    let rows = allowlist();
    let serve_path = [
        ("src/gateway/server/support.rs", "log_startup_banner"),
        ("src/commands/mod.rs", "load_for_serve"),
        ("src/commands/upgrade.rs", "check_upgrade"),
        ("src/cli/entry.rs", "run_server"),
        ("src/cli/entry.rs", "run_stdio_server"),
    ];
    for (file, owner) in serve_path {
        let planted = Site {
            file: file.to_owned(),
            owner: owner.to_owned(),
            text: String::from("eprintln!(\"{}\" , config . name)"),
        };
        assert!(
            !covered(&planted, &rows),
            "{file} {owner}: a planted print is allowed"
        );
    }
}

/// L2b: a `P` site whose arguments change is no longer the reviewed site.
#[test]
fn a_reviewed_site_with_changed_arguments_is_not_covered() {
    let rows = allowlist();
    let reviewed = rows
        .iter()
        .find(|row| row.tier == 'P')
        .expect("at least one P row");
    let edited = Site {
        file: reviewed.file.clone(),
        owner: reviewed.owner.clone(),
        text: format!("{} /* now quoting a value */", reviewed.text),
    };
    assert!(
        !covered(&edited, &rows),
        "an edited P site is still allowed"
    );
}

fn found(text: &str) -> Vec<(String, String)> {
    let sites = sites_in("src/fixture.rs", text).expect("the fixture parses");
    sites.into_iter().map(|s| (s.owner, s.text)).collect()
}

/// L2e: a print nested in another macro's tokens is a site, found without expanding the outer macro.
#[test]
fn a_print_inside_another_macro_is_found() {
    let hits = found("fn run() { tokio::select! { _ = a() => { eprintln!(\"x\") } } }");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, "run", "{hits:?}");
    assert!(hits[0].1.contains("eprintln"), "{hits:?}");
}

/// L2f, L2h: `dbg!` and a fully qualified `std::eprintln!` are sites.
#[test]
fn dbg_and_a_qualified_print_are_found() {
    let hits = found("fn a() { dbg!(1); } fn b() { std::eprintln!(\"x\"); }");
    let owners: Vec<&str> = hits.iter().map(|(owner, _)| owner.as_str()).collect();
    assert_eq!(owners, ["a", "b"], "{hits:?}");
}

/// L2g: a write to a stream handed out inside the macro's own arguments is a site; so is a handle taken outside one.
#[test]
fn a_write_to_stderr_is_found() {
    let hits = found(
        "fn a() { let _ = writeln!(std::io::stderr(), \"x\"); } \
         fn b() { let mut out = std::io::stdout(); out.flush().ok(); }",
    );
    let owners: Vec<&str> = hits.iter().map(|(owner, _)| owner.as_str()).collect();
    assert_eq!(owners, ["a", "b"], "{hits:?}");
}

/// L2i: a print under `#[cfg(test)]` is not a production site; one in a method is keyed by its type.
#[test]
fn test_only_prints_are_skipped_and_methods_are_keyed_by_type() {
    let hits = found(
        "#[cfg(test)] mod tests { fn t() { println!(\"x\"); } } \
         struct S; impl S { fn m(&self) { eprint!(\"y\"); } #[cfg(test)] fn t(&self) { print!(\"z\"); } }",
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, "S::m", "{hits:?}");
}

/// A production file that syn cannot parse fails the scan rather than hiding a print.
#[test]
fn a_file_that_does_not_parse_is_refused() {
    let Err(why) = sites_in("src/broken.rs", "fn a( {") else {
        panic!("an unparsable file was scanned as clean");
    };
    assert!(why.contains("src/broken.rs"), "{why}");
}
