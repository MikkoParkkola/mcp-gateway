// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WIRE.6: the journal drain and the session machinery it stands on build into production, while
//! their fault points (`fault::`) and observation points (`observe::`) exist only in tests. This
//! row parses every product file of that code and fails on any such call that a non-test build
//! would compile: each one must sit under `#[cfg(test)]`, on itself or on an enclosing item.

use syn::visit::Visit;

// The shared test-only cfg reader, never a private copy of it (check_cfg_reader_copies).
use crate::test_source_text::test_only;

/// Paths into the test-only seams, by the module names the product files use for them.
const SEAMS: [&str; 3] = ["fault", "observe", "crash_fs"];

/// The attributes written on an expression statement, for the expression kinds the drain uses.
fn expr_attrs(expr: &syn::Expr) -> &[syn::Attribute] {
    match expr {
        syn::Expr::Call(e) => &e.attrs,
        syn::Expr::MethodCall(e) => &e.attrs,
        syn::Expr::Try(e) => &e.attrs,
        syn::Expr::Macro(e) => &e.attrs,
        syn::Expr::Block(e) => &e.attrs,
        syn::Expr::If(e) => &e.attrs,
        syn::Expr::Assign(e) => &e.attrs,
        syn::Expr::Let(e) => &e.attrs,
        _ => &[],
    }
}

/// Every seam path a non-test build compiles, as `file:line path`.
#[derive(Default)]
struct Ungated {
    file: String,
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for Ungated {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            _ => &[],
        };
        if !test_only(attrs) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if !test_only(&function.attrs) {
            syn::visit::visit_impl_item_fn(self, function);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(local) => &local.attrs,
            syn::Stmt::Expr(expr, _) => expr_attrs(expr),
            syn::Stmt::Macro(mac) => &mac.attrs,
            syn::Stmt::Item(_) => &[],
        };
        if !test_only(attrs) {
            syn::visit::visit_stmt(self, stmt);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        // A seam module followed by an item in it: `fault::hit`, `drain::fault::Fault`.
        let into_seam = names
            .windows(2)
            .any(|pair| SEAMS.contains(&pair[0].as_str()));
        if into_seam {
            let line = path
                .segments
                .first()
                .map_or(0, |segment| segment.ident.span().start().line);
            self.found
                .push(format!("{}:{line} {}", self.file, names.join("::")));
        }
        syn::visit::visit_path(self, path);
    }
}

fn ungated(file: &str, text: &str) -> Vec<String> {
    let parsed = syn::parse_file(text).unwrap_or_else(|error| panic!("{file} parses: {error}"));
    let mut scan = Ungated {
        file: file.to_owned(),
        ..Ungated::default()
    };
    scan.visit_file(&parsed);
    scan.found
}

/// The product files of the promoted code: the v2 journal and its drain (test files excluded),
/// and the startup gate that drives them.
fn product_files() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<String> = std::fs::read_dir(root.join("src"))
        .expect("list src")
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| {
            name.starts_with("config_persistence_journal_v2")
                && std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext == "rs")
                && !name.ends_with("_tests.rs")
        })
        .map(|name| format!("src/{name}"))
        .collect();
    files.push("src/config_reload/startup_settle.rs".to_owned());
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let text = std::fs::read_to_string(root.join(&file)).expect("read a product file");
            (file, text)
        })
        .collect()
}

#[test]
fn promoted_drain_compiles_no_seam_outside_tests() {
    const ROW: &str = "promoted_drain_compiles_no_seam_outside_tests";
    // Premise: the scan sees an ungated call, and passes the gated forms the drain uses.
    let probe = "fn a(p: &Path) { fault::hit(p, At::X); }\n\
                 fn b(p: &Path) { #[cfg(test)] fault::hit(p, At::X).ok(); }\n\
                 #[cfg(test)] fn c(p: &Path) { observe::note(p, E); }\n\
                 #[cfg(all(test, unix))] use super::fault;\n";
    let seen = ungated("probe.rs", probe);
    assert_eq!(
        seen,
        vec!["probe.rs:1 fault::hit".to_owned()],
        "{ROW}: premise: only the ungated call is reported"
    );

    let files = product_files();
    assert!(
        files.iter().any(|(file, _)| file.ends_with("_drain.rs"))
            && files
                .iter()
                .any(|(file, _)| file.ends_with("journal_v2.rs")),
        "{ROW}: premise: the scan covers the drain and the journal, got {:?}",
        files.iter().map(|(file, _)| file).collect::<Vec<_>>()
    );
    let found: Vec<String> = files
        .iter()
        .flat_map(|(file, text)| ungated(file, text))
        .collect();
    assert!(
        found.is_empty(),
        "{ROW}: test-only seams a non-test build would compile: {found:#?}"
    );
}
