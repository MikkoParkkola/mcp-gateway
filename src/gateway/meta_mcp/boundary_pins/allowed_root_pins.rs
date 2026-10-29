// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-tool allowed folders: where the firewall is built and called (rows
//! R38b, P1, P2 of the allowed-folder test plan). Syntax scan over
//! production code, test-only code skipped by cfg as in the other pins.
//!
//! - R38b: `check_request_keyed` and `rescan` each call `root_check` and
//!   `apply_roots`; `check_request` only delegates to `check_request_keyed`.
//! - P1: every production `Firewall::from_config` sits in
//!   `response_firewall`, which also calls `with_registries`.
//! - P2: a `check_request_keyed` or `rescan` call passing `None` for the
//!   sending backend is one of the listed live-lookup fallbacks.

use std::collections::{BTreeMap, BTreeSet};

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The live-lookup fallbacks (design section 3): file, function, method and
/// the reason no sending instance exists there.
const FALLBACKS: [(&str, &str, &str, &str); 4] = [
    (
        "src/gateway/router/handlers/dispatch_tools_call.rs",
        "tools_call",
        "check_request_keyed",
        "the /mcp route scan: its targets carry no instance, and the chokepoint re-judges",
    ),
    (
        "src/gateway/meta_mcp/invoke/chokepoint.rs",
        "route_request_scan",
        "check_request_keyed",
        "the route scan the stdio route stage uses; the chokepoint re-runs the checks",
    ),
    (
        "src/gateway/router/watch_poll.rs",
        "poll_capability",
        "check_request_keyed",
        "capability watch polling: a capability route, refused under a root rule",
    ),
    (
        "src/security/firewall/mod.rs",
        "check_request",
        "check_request_keyed",
        "a public delegator whose embedder callers have no backend instance",
    ),
];

#[derive(Default)]
struct Calls {
    /// (file, function) -> the names it calls, by function or method.
    by_fn: BTreeMap<(String, String), BTreeSet<String>>,
    /// (file, function) of each production `Firewall::from_config`.
    builds: Vec<(String, String)>,
    /// (file, function, method) of each call passing `None` last.
    none_sites: Vec<(String, String, String)>,
}

fn key(at: &Place) -> (String, String) {
    (at.file.clone(), at.func.clone().unwrap_or_default())
}

fn is_none(expr: Option<&syn::Expr>) -> bool {
    matches!(expr, Some(syn::Expr::Path(p)) if p.path.is_ident("None"))
}

impl Sink for Calls {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        match expr {
            syn::Expr::MethodCall(call) => {
                let method = call.method.to_string();
                self.by_fn
                    .entry(key(at))
                    .or_default()
                    .insert(method.clone());
                if matches!(method.as_str(), "check_request_keyed" | "rescan")
                    && is_none(call.args.last())
                {
                    let (file, func) = key(at);
                    self.none_sites.push((file, func, method));
                }
            }
            syn::Expr::Call(call) => {
                let syn::Expr::Path(path) = &*call.func else {
                    return;
                };
                let segs: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                if let Some(last) = segs.last() {
                    self.by_fn.entry(key(at)).or_default().insert(last.clone());
                }
                if segs.ends_with(&["Firewall".to_string(), "from_config".to_string()]) {
                    self.builds.push(key(at));
                }
            }
            _ => {}
        }
    }
}

fn scan() -> Calls {
    let mut calls = Calls::default();
    walk(crate_root(), &ROOTS, &mut calls).expect("the crate walks");
    calls
}

fn called(calls: &Calls, file: &str, func: &str) -> BTreeSet<String> {
    let key = (file.to_string(), func.to_string());
    calls
        .by_fn
        .get(&key)
        .cloned()
        .unwrap_or_else(|| panic!("{file}::{func} not found"))
}

/// R38b: both entry points run the folder check; `check_request` adds none.
#[test]
fn r38b_both_entry_points_call_the_folder_check() {
    let calls = scan();
    let file = "src/security/firewall/mod.rs";
    for entry in ["check_request_keyed", "rescan"] {
        let names = called(&calls, file, entry);
        for needed in ["root_check", "apply_roots"] {
            assert!(
                names.contains(needed),
                "{entry} does not call {needed}: {names:?}"
            );
        }
    }
    let delegate = called(&calls, file, "check_request");
    assert_eq!(
        delegate,
        BTreeSet::from(["check_request_keyed".to_string()]),
        "check_request only delegates"
    );
}

/// P1: every production firewall is built in `response_firewall`, which
/// wires the registries the folder check reads.
#[test]
fn p1_production_firewalls_are_built_with_registries() {
    let calls = scan();
    let home = (
        "src/gateway/server/build_meta.rs".to_string(),
        "response_firewall".to_string(),
    );
    assert!(!calls.builds.is_empty(), "the scan found no build");
    for site in &calls.builds {
        assert_eq!(site, &home, "a firewall built outside response_firewall");
    }
    let names = called(&calls, &home.0, &home.1);
    assert!(
        names.contains("with_registries"),
        "response_firewall: {names:?}"
    );
}

/// P2: a call passing no sending backend is a listed fallback; any other
/// fails until it is added here, and to design section 3, with its reason.
#[test]
fn p2_no_backend_calls_are_listed_fallbacks() {
    let calls = scan();
    let mut stray = Vec::new();
    for (file, func, method) in &calls.none_sites {
        let listed = FALLBACKS
            .iter()
            .any(|(f, fun, m, _why)| f == file && fun == func && m == method);
        if !listed {
            stray.push(format!("{file}::{func} {method}(.., None)"));
        }
    }
    assert!(
        stray.is_empty(),
        "unlisted calls without the sending backend:\n{}",
        stray.join("\n")
    );
}
