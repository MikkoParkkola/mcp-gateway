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

use crate::test_source_files::rust_files;
use crate::test_source_text::test_only;

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
            syn::visit::visit_item_mod(me, module);
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
            syn::visit::visit_item_fn(me, function);
        });
    }

    fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
        if !test_only(&method.attrs) {
            self.within(method.sig.ident.to_string(), |me| {
                syn::visit::visit_impl_item_fn(me, method);
            });
        }
    }

    fn visit_trait_item_fn(&mut self, method: &'ast syn::TraitItemFn) {
        self.within(method.sig.ident.to_string(), |me| {
            syn::visit::visit_trait_item_fn(me, method);
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

    // A site is where a print or a stream handle is made. A serve-path call into a tier T output fn, or a write
    // through a handle whose creation site is already listed, changes no site, so this check does not see it.
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
    Ok(sites_of(file, &parsed))
}

fn sites_of(file: &str, parsed: &syn::File) -> Vec<Site> {
    let mut finder = Finder {
        file: file.to_owned(),
        owner: Vec::new(),
        found: Vec::new(),
    };
    finder.visit_file(parsed);
    finder.found
}

/// The directory a file's out-of-line child modules live in: its own folder for `lib.rs`, `main.rs` and `mod.rs`,
/// otherwise a folder named after the file.
fn module_dir(rel: &str) -> String {
    let (folder, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    match name {
        "lib.rs" | "main.rs" | "mod.rs" => folder.to_owned(),
        _ => rel.trim_end_matches(".rs").to_owned(),
    }
}

/// The `#[path = ".."]` of a module item, if it has one.
fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| match &attr.meta {
        syn::Meta::NameValue(pair) if pair.path.is_ident("path") => match &pair.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(text),
                ..
            }) => Some(text.value()),
            _ => None,
        },
        _ => None,
    })
}

/// The module stems (a path without `.rs`) that `items` declare under a test-only cfg, or declare at all when
/// `inherited` (the declaring file or module compiles only under test): the stem's own file and every file below it
/// compile only under test. `dir` is where `items`' out-of-line children live and `folder` is the declaring file's
/// own folder, which a `#[path]` is relative to.
fn test_module_stems(
    items: &[syn::Item],
    dir: &str,
    folder: &str,
    inherited: bool,
    out: &mut Vec<String>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let name = module.ident.to_string();
        match (&module.content, inherited || test_only(&module.attrs)) {
            (None, true) => out.push(match path_attr(&module.attrs) {
                Some(path) => format!("{folder}/{}", path.trim_end_matches(".rs")),
                None => format!("{dir}/{name}"),
            }),
            (Some(_), true) => out.push(format!("{dir}/{name}")),
            (Some((_, inner)), false) => {
                test_module_stems(inner, &format!("{dir}/{name}"), folder, false, out);
            }
            (None, false) => {}
        }
    }
}

/// Whether `rel` is the file of module `stem` or below it.
fn under_stem(rel: &str, stem: &str) -> bool {
    rel.strip_prefix(stem)
        .is_some_and(|rest| rest == ".rs" || rest.starts_with('/'))
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

/// Every site in the production tree, sorted. A file is left out when only tests compile it: by its path (the rule
/// above), or because the `mod` item that declares it is under a test-only cfg, which covers every file below it.
fn production_sites() -> Vec<Site> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut parsed = Vec::new();
    for tree in TREES {
        let mut paths = Vec::new();
        rust_files(&base.join(tree), &mut paths);
        for file in paths {
            let rel = slash_path(base, &file);
            let source = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{rel}: {e}"));
            let tree =
                syn::parse_file(&source).unwrap_or_else(|e| panic!("{rel} does not parse: {e}"));
            parsed.push((rel, tree));
        }
    }
    // A module a test-only file declares is test-only too, so repeat until no new stem appears.
    let mut stems: Vec<String> = Vec::new();
    let test_only_file =
        |rel: &str, stems: &[String]| test_file(rel) || stems.iter().any(|s| under_stem(rel, s));
    loop {
        let mut found = Vec::new();
        for (rel, tree) in &parsed {
            let folder = rel.rsplit_once('/').map_or("", |(folder, _)| folder);
            let inherited = test_only_file(rel, &stems);
            test_module_stems(&tree.items, &module_dir(rel), folder, inherited, &mut found);
        }
        found.sort();
        found.dedup();
        if found == stems {
            break;
        }
        stems = found;
    }
    let mut sites = Vec::new();
    for (rel, tree) in &parsed {
        if !test_only_file(rel, &stems) {
            sites.extend(sites_of(rel, tree));
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

/// L2j: a file whose declaring `mod` item is test-only is not scanned, nor anything below it, nor what a test-only
/// file declares in turn; a `#[path]` is read from the declaring file's folder.
#[test]
fn modules_declared_under_test_are_found_from_their_declaration() {
    let declaring = syn::parse_file(
        "#[cfg(test)] mod a; #[cfg(test)] #[path = \"b_rows.rs\"] mod b; \
         mod c { #[cfg(test)] mod d; } mod e;",
    )
    .expect("parses");
    let mut stems = Vec::new();
    test_module_stems(
        &declaring.items,
        &module_dir("src/x/y.rs"),
        "src/x",
        false,
        &mut stems,
    );
    assert_eq!(
        stems,
        ["src/x/y/a", "src/x/b_rows", "src/x/y/c/d"],
        "{stems:?}"
    );
    let mut inherited = Vec::new();
    test_module_stems(&declaring.items, "src/t", "src", true, &mut inherited);
    assert!(
        inherited.contains(&String::from("src/t/e")),
        "{inherited:?}"
    );
    assert!(under_stem("src/x/y/a.rs", "src/x/y/a"));
    assert!(under_stem("src/x/y/a/deep.rs", "src/x/y/a"));
    assert!(!under_stem("src/x/y/ab.rs", "src/x/y/a"));
    assert_eq!(module_dir("src/lib.rs"), "src");
    assert_eq!(module_dir("src/x/mod.rs"), "src/x");
}

/// A production file that syn cannot parse fails the scan rather than hiding a print.
#[test]
fn a_file_that_does_not_parse_is_refused() {
    let Err(why) = sites_in("src/broken.rs", "fn a( {") else {
        panic!("an unparsable file was scanned as clean");
    };
    assert!(why.contains("src/broken.rs"), "{why}");
}
