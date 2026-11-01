// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K21 (ADR-023, amended): every generation production publishes is built by
//! `Generation::prepare`, which resolves the key table and runs the reload
//! refusals. A production call to `LiveConfig::new`, `LiveConfig::set` or
//! `Generation::of` would publish a generation that skipped them, so none may
//! exist outside the listed exemptions. And production seeds a `LiveConfig`
//! through `LiveConfig::from_prepared` at exactly the startup sites below, so
//! production cannot construct one without a prepared generation.
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

/// The production calls to `Generation::prepare_startup`, which seeds a
/// generation without the reload refusals: (file, function).
const STARTUP_SEEDS: &[(&str, &str)] = &[
    ("src/config_reload/mod.rs", "new"),
    ("src/gateway/mod.rs", "live_config"),
    ("src/gateway/server/run.rs", "run"),
    ("src/gateway/server/stdio_loop.rs", "run_stdio_on"),
];

/// The production calls to `LiveConfig::from_prepared` by name: (file,
/// function). `LiveConfig::new` reaches it as `Self::from_prepared`, and its
/// own production callers are refused above.
const SEEDS: &[(&str, &str)] = &[
    ("src/gateway/mod.rs", "live_config"),
    ("src/gateway/server/run.rs", "run"),
    ("src/gateway/server/stdio_loop.rs", "run_stdio_on"),
];

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
    seeds: Vec<(String, String)>,
    startup_seeds: Vec<(String, String)>,
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
                syn::Expr::Path(path) if ends_with(&path.path, "Generation", "prepare_startup") => {
                    self.startup_seeds.push((at.file.clone(), func.to_owned()));
                    None
                }
                syn::Expr::Path(path) if ends_with(&path.path, "LiveConfig", "from_prepared") => {
                    self.seeds.push((at.file.clone(), func.to_owned()));
                    None
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
    calls.seeds.sort();
    let want: Vec<(String, String)> = SEEDS
        .iter()
        .map(|(file, func)| ((*file).to_owned(), (*func).to_owned()))
        .collect();
    assert_eq!(
        calls.seeds, want,
        "production seeds a LiveConfig somewhere other than the startup sites"
    );
    calls.startup_seeds.sort();
    let want: Vec<(String, String)> = STARTUP_SEEDS
        .iter()
        .map(|(file, func)| ((*file).to_owned(), (*func).to_owned()))
        .collect();
    assert_eq!(
        calls.startup_seeds, want,
        "production builds a startup generation somewhere other than the listed sites"
    );
}
