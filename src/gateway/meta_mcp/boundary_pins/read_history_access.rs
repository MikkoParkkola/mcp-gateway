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

/// The sink sees the history reached through a macro's arguments and through
/// a path call, not only through a plain method call.
#[test]
fn macro_wrapped_and_path_calls_are_seen() {
    let at = Place {
        file: "src/elsewhere.rs".to_owned(),
        func: None,
    };
    let mut access = Access::default();
    for source in [
        "assert!(firewall.reads().len() > 0)",
        "Firewall::reads(&firewall)",
        "ReadHistory::reserve(&history, key)",
        "debug_assert!(history.reserve(key).is_ok())",
    ] {
        let expr: syn::Expr = syn::parse_str(source).expect("an expression");
        access.expr(&at, &expr);
    }
    let stmt: syn::Stmt =
        syn::parse_str("println!(\"{}\", firewall.reads().len());").expect("a statement");
    access.stmt(&at, &stmt);
    assert_eq!(access.readers.len(), 3, "readers: {:?}", access.readers);
    assert_eq!(
        access.reservers.len(),
        2,
        "reservers: {:?}",
        access.reservers
    );
}
