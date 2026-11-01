// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production `impl Transport for ..` runs each sending method's body
//! inside `backend_request(..)` (which also marks the answer as a backend's)
//! or `backend_wait(..)`, so `mcp_gateway_added_latency_seconds`
//! subtracts the time a call waits on a backend's transport. The impl is the
//! one place every backend request and notification passes, whoever calls it
//! and under whatever name the transport is held; a new transport fails here
//! until its sending methods are wrapped.
//!
//! The trait's own default bodies only delegate to another sending method or
//! refuse without I/O, so they need no wrap. Syntax scan with `syn`.

use std::collections::BTreeSet;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The trait methods that send to a backend and wait for it.
const SENDING: [&str; 5] = [
    "request",
    "request_with_headers",
    "request_with_task_capability",
    "notify",
    "notify_with_headers",
];

/// The helpers that measure a backend wait.
const WRAPPERS: [&str; 2] = ["backend_request", "backend_wait"];

/// The production transports. A new one is a reviewed addition here, and
/// keeps the scan from passing because it found nothing.
const TRANSPORTS: [&str; 4] = [
    "A2aTransport",
    "HttpTransport",
    "StdioTransport",
    "WebSocketTransport",
];

/// The body is exactly `backend_request(..).await` or `backend_wait(..).await`.
fn wrapped(block: &syn::Block) -> bool {
    let [syn::Stmt::Expr(syn::Expr::Await(awaited), None)] = block.stmts.as_slice() else {
        return false;
    };
    matches!(awaited.base.as_ref(), syn::Expr::Call(call)
        if matches!(call.func.as_ref(), syn::Expr::Path(p)
            if p.path.segments.last().is_some_and(|s| WRAPPERS.iter().any(|w| s.ident == w))))
}

#[derive(Default)]
struct Impls {
    found: BTreeSet<String>,
    unwrapped: Vec<String>,
}

impl Sink for Impls {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        let syn::Item::Impl(block) = item else {
            return;
        };
        let Some((_, trait_path, _)) = &block.trait_ else {
            return;
        };
        if test_only(&block.attrs)
            || trait_path
                .segments
                .last()
                .is_none_or(|s| s.ident != "Transport")
        {
            return;
        }
        let syn::Type::Path(self_ty) = block.self_ty.as_ref() else {
            return;
        };
        let Some(name) = self_ty.path.segments.last().map(|s| s.ident.to_string()) else {
            return;
        };
        for member in &block.items {
            if let syn::ImplItem::Fn(method) = member
                && SENDING.contains(&method.sig.ident.to_string().as_str())
                && !wrapped(&method.block)
            {
                self.unwrapped
                    .push(format!("{} {name}::{}", at.file, method.sig.ident));
            }
        }
        self.found.insert(name);
    }
}

#[test]
fn every_transport_send_is_measured_as_backend_wait() {
    let mut impls = Impls::default();
    walk(crate_root(), &ROOTS, &mut impls).expect("the walk reads every module");
    let expected: BTreeSet<String> = TRANSPORTS.iter().map(|t| (*t).to_owned()).collect();
    assert_eq!(impls.found, expected, "the production transports changed");
    assert!(
        impls.unwrapped.is_empty(),
        "sending methods not run inside {WRAPPERS:?}:\n{}",
        impls.unwrapped.join("\n")
    );
}
