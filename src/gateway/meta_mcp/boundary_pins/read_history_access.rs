// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cross-tenant read verdict is made in one place: every producer reaches
//! the process's read history through the outbound judge, which decides
//! whether to judge at all (`judge::judging`). A second path to the history
//! could judge, or skip judging, on a switch of its own.
//!
//! Syntax scan of the production nodes (test-only code is skipped by cfg
//! evaluation, never by filename): a method call `.reads()` (the firewall's
//! accessor to the history) outside the judge is a finding, and so is a
//! `.reserve(..)` call in a production file that names the history
//! (`ReadHistory` or `tenant_reads::`) outside the judge and the history's
//! own module. The positive control requires the judge's own `.reads()`
//! call, so the scan cannot pass by seeing nothing.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];
const JUDGE: &str = "src/gateway/outbound/judge.rs";
const HISTORY: &str = "src/security/tenant_reads.rs";

#[derive(Default)]
struct Access {
    /// Files with a production `.reads()` call, one entry per call.
    readers: Vec<String>,
    /// Files with a production `.reserve(..)` call, one entry per call.
    reservers: Vec<String>,
}

impl Access {
    /// A macro's arguments are tokens, not parsed expressions, so they are
    /// matched as text with the spacing removed.
    fn tokens(&mut self, at: &Place, mac: &syn::Macro) {
        let text: String = mac
            .tokens
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        for _ in 0..(text.matches(".reads()").count() + text.matches("::reads(").count()) {
            self.readers.push(at.file.clone());
        }
        for _ in 0..(text.matches(".reserve(").count() + text.matches("::reserve(").count()) {
            self.reservers.push(at.file.clone());
        }
    }
}

impl Sink for Access {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        match expr {
            syn::Expr::MethodCall(call) if call.method == "reads" && call.args.is_empty() => {
                self.readers.push(at.file.clone());
            }
            syn::Expr::MethodCall(call) if call.method == "reserve" => {
                self.reservers.push(at.file.clone());
            }
            // A path call: `Firewall::reads(&f)`, `ReadHistory::reserve(&h, ..)`.
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(path) = &*call.func {
                    match path
                        .path
                        .segments
                        .last()
                        .map(|s| s.ident.to_string())
                        .as_deref()
                    {
                        Some("reads") => self.readers.push(at.file.clone()),
                        Some("reserve") => self.reservers.push(at.file.clone()),
                        _ => {}
                    }
                }
            }
            syn::Expr::Macro(mac) => self.tokens(at, &mac.mac),
            _ => {}
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if let syn::Stmt::Macro(mac) = stmt {
            self.tokens(at, &mac.mac);
        }
    }

    fn item(&mut self, at: &Place, item: &syn::Item) {
        if let syn::Item::Macro(mac) = item {
            self.tokens(at, &mac.mac);
        }
    }
}

/// Whether the production part of `file` names the read history.
fn names_the_history(file: &str) -> bool {
    let text = std::fs::read_to_string(crate_root().join(file)).expect("read source");
    let code = crate::test_source_text::production_text(&text);
    code.contains("ReadHistory") || code.contains("tenant_reads::")
}

#[test]
fn the_read_history_is_reached_from_the_judge_alone() {
    let mut access = Access::default();
    walk(crate_root(), &ROOTS, &mut access).expect("the crate walks");
    assert_eq!(
        access.readers,
        [JUDGE],
        "only the judge calls `.reads()` on a firewall (and the walk saw its call)"
    );
    assert!(
        access.reservers.iter().any(|file| file == JUDGE),
        "the walk saw the judge's own `.reserve(..)` (positive control)"
    );
    let mut reservers: Vec<&String> = access
        .reservers
        .iter()
        .filter(|file| *file != JUDGE && *file != HISTORY && names_the_history(file))
        .collect();
    reservers.dedup();
    assert!(
        reservers.is_empty(),
        "reserves on the read history outside the judge: {reservers:?}"
    );
}

/// What the walk does with an expression (scan.rs `visit_expr`): the sink
/// sees it, then every expression inside it.
struct Mirror<'a>(&'a mut Access, Place);

impl<'ast> syn::visit::Visit<'ast> for Mirror<'_> {
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        self.0.expr(&self.1, expr);
        syn::visit::visit_expr(self, expr);
    }
}

/// The sink sees the history however a reader is spelled: a method or path
/// call, raw or not, a path taken as a value or called in parentheses, a
/// turbofish, inside a macro's arguments or not. Each fixture counts exactly
/// once; a field named `reads`, a longer name and a one-segment call count
/// nothing.
#[test]
fn macro_wrapped_and_path_calls_are_seen() {
    for (source, readers, reservers) in [
        ("assert!(firewall.reads().len() > 0)", 1, 0),
        ("Firewall::reads(&firewall)", 1, 0),
        ("ReadHistory::reserve(&history, key)", 0, 1),
        ("debug_assert!(history.reserve(key).is_ok())", 0, 1),
        ("firewall.r#reads()", 1, 0),
        ("Firewall::r#reads(&f)", 1, 0),
        ("{ let read = Firewall::reads; read(f) }", 1, 0),
        ("(Firewall::reads)(f)", 1, 0),
        ("<Firewall>::reads(&f)", 1, 0),
        ("history.r#reserve(k)", 0, 1),
        ("ReadHistory::r#reserve(&h, k)", 0, 1),
        ("m!(f.r#reads())", 1, 0),
        ("m!((Firewall::reads)(f))", 1, 0),
        ("m!({ let r = Firewall::reads; })", 1, 0),
        ("m!(f.reads::<>())", 1, 0),
        ("m!(h.reserve::<>(k))", 0, 1),
        ("m!(self.reads)", 0, 0),
        ("Firewall::reads_all(&f)", 0, 0),
        ("reads(f)", 0, 0),
    ] {
        let expr: syn::Expr = syn::parse_str(source).expect("an expression");
        let mut access = Access::default();
        let at = Place {
            file: "src/elsewhere.rs".to_owned(),
            func: None,
        };
        syn::visit::Visit::visit_expr(&mut Mirror(&mut access, at), &expr);
        assert_eq!(
            (access.readers.len(), access.reservers.len()),
            (readers, reservers),
            "{source}"
        );
    }
    let stmt: syn::Stmt =
        syn::parse_str("println!(\"{}\", firewall.reads().len());").expect("a statement");
    let mut access = Access::default();
    let at = Place {
        file: "src/elsewhere.rs".to_owned(),
        func: None,
    };
    access.stmt(&at, &stmt);
    assert_eq!(access.readers.len(), 1, "a statement macro is seen");
}
