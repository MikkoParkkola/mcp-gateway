// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every backend send in `src/`, by the function it sits in, and whether that
//! function delivers the send's error or drops it. A refusal the send meets
//! (a refused redirect hop) raises `refused` on the open delivery cell, so a
//! send whose error is dropped inside a caller's dispatch must run in a
//! discarded cell (`delivery_facts::discarded`), or the caller's answer would
//! record a refusal it never got. A new send site fails until classified.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The transport's send methods.
const SENDS: [&str; 5] = [
    "request_with_headers",
    "request_with_headers_lent",
    "request_with_task_capability",
    "notify_with_headers",
    "notify_with_headers_lent",
];

/// What a send site's function does with the send's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Returns it, or answers the caller with it: the refusal is the answer.
    Delivered,
    /// Drops it: the send runs in a discarded cell.
    Dropped,
}

/// Every send site, by `file\tfunction`.
const SITES: [(&str, Fate); 15] = [
    ("src/backend/era.rs\tprobe", Fate::Dropped),
    (
        "src/backend/list_drain.rs\tdrain_list_pages",
        Fate::Delivered,
    ),
    ("src/backend/ops.rs\tnotify", Fate::Delivered),
    ("src/backend/ops.rs\tnotify_with_headers", Fate::Delivered),
    (
        "src/backend/ops.rs\tnotify_with_headers_lent",
        Fate::Delivered,
    ),
    ("src/backend/ops.rs\trequest", Fate::Delivered),
    ("src/backend/ops.rs\trequest_attempted", Fate::Delivered),
    ("src/backend/ops.rs\trequest_with_headers", Fate::Delivered),
    (
        "src/gateway/meta_mcp/caller_forward.rs\tforward_for_caller",
        Fate::Delivered,
    ),
    (
        "src/gateway/meta_mcp/invoke/dispatch.rs\tdispatch_to_backend",
        Fate::Delivered,
    ),
    (
        "src/gateway/meta_mcp/upstream.rs\tdeclares_tasks",
        Fate::Dropped,
    ),
    (
        "src/gateway/router/backend_handlers/direct_caller.rs\tforward_notification",
        Fate::Delivered,
    ),
    (
        "src/gateway/router/backend_handlers/direct_send.rs\tsend_in_scope",
        Fate::Delivered,
    ),
    (
        "src/transport/http/transport_impl.rs\tnotify",
        Fate::Delivered,
    ),
    (
        "src/transport/http/transport_impl.rs\trequest",
        Fate::Delivered,
    ),
];

/// Per site: every send, and the sends nested inside a `discarded(..)` call.
#[derive(Default)]
struct Found {
    sends: std::collections::BTreeMap<String, usize>,
    wrapped: std::collections::BTreeMap<String, usize>,
}

fn is_send(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::MethodCall(call) if SENDS.contains(&call.method.to_string().as_str()))
}

/// Counts the sends under one expression.
struct Sends(usize);

impl<'ast> syn::visit::Visit<'ast> for Sends {
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if is_send(expr) {
            self.0 += 1;
        }
        syn::visit::visit_expr(self, expr);
    }
}

impl Sink for Found {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let Some(func) = &at.func else { return };
        let site = format!("{}\t{func}", at.file);
        if is_send(expr) {
            *self.sends.entry(site.clone()).or_default() += 1;
        }
        if let syn::Expr::Call(call) = expr
            && let syn::Expr::Path(path) = &*call.func
            && path
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "discarded")
        {
            let mut inside = Sends(0);
            for arg in &call.args {
                syn::visit::Visit::visit_expr(&mut inside, arg);
            }
            *self.wrapped.entry(site).or_default() += inside.0;
        }
    }
}

/// Per send, not per function: in a function that drops its error every send
/// sits inside `discarded(..)`, and in one that delivers it none does. The
/// check is per function, so an error dropped further up the call chain is
/// not seen; every drop today is at the send site.
#[test]
fn every_send_that_drops_its_error_runs_in_a_discarded_cell() {
    let mut found = Found::default();
    walk(crate_root(), &ROOTS, &mut found).expect("the crate walks");
    let listed: std::collections::BTreeMap<&str, Fate> = SITES.into_iter().collect();
    let have: Vec<&str> = found.sends.keys().map(String::as_str).collect();
    let want: Vec<&str> = listed.keys().copied().collect();
    assert_eq!(have, want, "send sites changed; classify each in SITES");
    for (site, fate) in listed {
        let sends = found.sends[site];
        let wrapped = found.wrapped.get(site).copied().unwrap_or(0);
        let expected = if fate == Fate::Dropped { sends } else { 0 };
        assert_eq!(
            wrapped, expected,
            "{site}: {sends} sends, {wrapped} in a discarded cell"
        );
    }
}
