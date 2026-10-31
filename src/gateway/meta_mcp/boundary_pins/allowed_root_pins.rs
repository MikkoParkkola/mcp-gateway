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
//! - P2: every production `check_request_keyed` and `rescan` call site is
//!   listed as passing the sending backend or as a live-lookup fallback
//!   passing `None`; an unlisted site fails whatever it passes.

use std::collections::{BTreeMap, BTreeSet};

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// What a call site passes for the sending backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pass {
    /// The instance that sends: the folder check classifies it.
    Instance,
    /// `None`: a live-lookup fallback, for the stated reason (design
    /// section 3).
    Fallback(&'static str),
}

/// Every production `check_request_keyed` and `rescan` call: file, function,
/// method and what it passes. A call site not listed here fails P2, whatever
/// it passes, so the instance-passing guarantee cannot erode silently.
const SITES: [(&str, &str, &str, Pass); 6] = [
    (
        "src/gateway/router/handlers/dispatch_tools_call.rs",
        "tools_call",
        "check_request_keyed",
        Pass::Fallback(
            "the /mcp route scan: its targets carry no instance, and the chokepoint re-judges",
        ),
    ),
    (
        "src/gateway/meta_mcp/invoke/chokepoint.rs",
        "route_request_scan",
        "check_request_keyed",
        Pass::Fallback(
            "the route scan the stdio route stage uses; the chokepoint re-runs the checks",
        ),
    ),
    (
        "src/gateway/router/watch_poll.rs",
        "poll_capability",
        "check_request_keyed",
        Pass::Fallback("capability watch polling: a capability route, refused under a root rule"),
    ),
    (
        "src/security/firewall/mod.rs",
        "check_request",
        "check_request_keyed",
        Pass::Fallback(
            "a public delegator whose embedder callers have no backend instance, so the \
             live-lookup fallback is the only option there",
        ),
    ),
    (
        "src/gateway/router/backend_handlers.rs",
        "guard_tool_call",
        "check_request_keyed",
        Pass::Instance,
    ),
    (
        "src/gateway/meta_mcp/invoke/chokepoint.rs",
        "rescan_outbound",
        "rescan",
        Pass::Instance,
    ),
];

#[derive(Default)]
struct Calls {
    /// (file, function) -> the names it calls, by function or method.
    by_fn: BTreeMap<(String, String), BTreeSet<String>>,
    /// (file, function) of each production `Firewall::from_config`.
    builds: Vec<(String, String)>,
    /// (file, function, method, passes `None` last) of each check call.
    sites: Vec<(String, String, String, bool)>,
}

fn key(at: &Place) -> (String, String) {
    (at.file.clone(), at.func.clone().unwrap_or_default())
}

/// `None` or `Option::None` as the last argument.
fn is_none(expr: Option<&syn::Expr>) -> bool {
    matches!(expr, Some(syn::Expr::Path(p))
        if p.path.segments.last().is_some_and(|s| s.ident == "None"))
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
                if matches!(method.as_str(), "check_request_keyed" | "rescan") {
                    let (file, func) = key(at);
                    self.sites
                        .push((file, func, method, is_none(call.args.last())));
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
                // A capitalised last segment is a tuple struct or variant
                // being built (`ServerOf::Backend(server)`), not a call.
                if let Some(last) = segs.last().filter(|s| !s.starts_with(char::is_uppercase)) {
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

/// P2: every check call site is listed; a fallback passes `None` and an
/// instance site does not; no listed row is stale. A new site fails until it
/// is added here, and to design section 3, with what it passes and why.
#[test]
fn p2_every_check_call_site_is_listed() {
    let calls = scan();
    let mut wrong = Vec::new();
    for (file, func, method, none) in &calls.sites {
        let listed = SITES
            .iter()
            .find(|(f, fun, m, _)| f == file && fun == func && m == method);
        match listed {
            None => wrong.push(format!("unlisted: {file}::{func} {method}")),
            Some((.., Pass::Fallback(_))) if !none => {
                wrong.push(format!(
                    "listed as a fallback, passes an instance: {file}::{func}"
                ));
            }
            Some((.., Pass::Instance)) if *none => {
                wrong.push(format!(
                    "passes None, not the sending instance: {file}::{func} {method}"
                ));
            }
            Some(_) => {}
        }
    }
    for (file, func, method, _) in SITES {
        let found = calls
            .sites
            .iter()
            .any(|(f, fun, m, _)| f == file && fun == func && m == method);
        if !found {
            wrong.push(format!("stale row: {file}::{func} {method}"));
        }
    }
    assert!(wrong.is_empty(), "check call sites:\n{}", wrong.join("\n"));
}
