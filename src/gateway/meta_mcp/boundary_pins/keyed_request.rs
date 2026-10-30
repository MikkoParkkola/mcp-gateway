// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! POLICY.2: every gateway route scans a request with the caller's proven
//! key (`Firewall::check_request_keyed`). The public `check_request` resolves
//! the key as not known, which drops every `keys`-scoped allow, so no
//! production code may call it; tests and the `tests/` crates may.
//!
//! Syntax scan of the production nodes (test-only code is skipped): a method
//! call or a path call named `check_request` is a finding. The positive
//! control counts the keyed calls, so the scan cannot pass by seeing nothing.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The keyed request scans: the meta chokepoint (stdio), the direct route,
/// the `/mcp` route stage, the watch poll, and the public `check_request`
/// itself, which delegates with the key not known.
const KEYED_CALLERS: usize = 5;

#[derive(Default)]
struct Calls {
    unkeyed: Vec<String>,
    keyed: usize,
}

fn called(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::MethodCall(call) => Some(call.method.to_string()),
        syn::Expr::Call(call) => match &*call.func {
            syn::Expr::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        },
        _ => None,
    }
}

impl Sink for Calls {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        match called(expr).as_deref() {
            Some("check_request") => self.unkeyed.push(at.file.clone()),
            Some("check_request_keyed") => self.keyed += 1,
            _ => {}
        }
    }
}

#[test]
fn no_production_request_scan_drops_the_callers_key() {
    let mut calls = Calls::default();
    walk(crate_root(), &ROOTS, &mut calls).expect("the crate walks");
    assert!(
        calls.unkeyed.is_empty(),
        "production code calls check_request, which resolves the key as not known; call \
         check_request_keyed with the caller's proven key: {:?}",
        calls.unkeyed
    );
    assert_eq!(
        calls.keyed, KEYED_CALLERS,
        "the keyed request scans the walk saw (positive control)"
    );
}
