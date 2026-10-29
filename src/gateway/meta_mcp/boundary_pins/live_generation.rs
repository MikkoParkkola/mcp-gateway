// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K21 (ADR-023, amended): every generation production publishes is built by
//! `Generation::prepare`, which resolves the key table and runs the reload
//! refusals. A production call to `LiveConfig::new`, `LiveConfig::set` or
//! `Generation::of` would publish a generation that skipped them, so none may
//! exist outside the listed exemptions.
//!
//! Syntax scan, per expression: a path call ending in `LiveConfig::new` or
//! `Generation::of`, and a `.set(..)` method call on a receiver whose last
//! name is `live_config` or `live`. A call reached through an alias or a
//! differently named receiver is missed, as in the other pins.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Production sites that may build a generation without `prepare`, and why.
const ALLOW: &[(&str, &str, &str)] = &[];

/// The last identifier of a receiver expression (`state.live_config` ->
/// `live_config`).
fn receiver_name(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()),
        syn::Expr::Field(field) => match &field.member {
            syn::Member::Named(name) => Some(name.to_string()),
            syn::Member::Unnamed(_) => None,
        },
        syn::Expr::Paren(paren) => receiver_name(&paren.expr),
        syn::Expr::Reference(reference) => receiver_name(&reference.expr),
        _ => None,
    }
}

/// `Type::func` when `path` ends in those two segments.
fn ends_with(path: &syn::Path, ty: &str, func: &str) -> bool {
    let mut segments = path.segments.iter().rev();
    segments.next().is_some_and(|s| s.ident == func)
        && segments.next().is_some_and(|s| s.ident == ty)
}

#[derive(Default)]
struct Calls {
    rows: Vec<String>,
}

impl Sink for Calls {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let func = at.func.as_deref().unwrap_or("<module>");
        let found = match expr {
            syn::Expr::Call(call) => match call.func.as_ref() {
                syn::Expr::Path(path) if ends_with(&path.path, "LiveConfig", "new") => {
                    Some("LiveConfig::new")
                }
                syn::Expr::Path(path) if ends_with(&path.path, "Generation", "of") => {
                    Some("Generation::of")
                }
                _ => None,
            },
            syn::Expr::MethodCall(call)
                if call.method == "set"
                    && receiver_name(&call.receiver)
                        .is_some_and(|name| name == "live_config" || name == "live") =>
            {
                Some("LiveConfig::set")
            }
            _ => None,
        };
        if let Some(kind) = found
            && !ALLOW
                .iter()
                .any(|(file, allowed, _)| *file == at.file && *allowed == func)
        {
            self.rows.push(format!("{}:{func}: {kind}", at.file));
        }
    }
}

/// K21: no production path publishes a generation that skipped `prepare`.
#[test]
fn k21_every_published_generation_is_prepared() {
    let mut calls = Calls::default();
    walk(crate_root(), &ROOTS, &mut calls).expect("the walk reads every module");
    calls.rows.sort();
    assert!(
        calls.rows.is_empty(),
        "a production generation skips `Generation::prepare`:\n{}",
        calls.rows.join("\n")
    );
}
