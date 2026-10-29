// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The error count reads the JSON-RPC error a response carries from a marker
//! set where a typed frame becomes the HTTP response, never from a body. So
//! the places that take a frame (`JsonRpcResponse`, `OutboundFrame`,
//! `Egressed`) and return an axum `Response` are a closed list: a new one
//! fails here until it is either routed through the marking funnels or
//! reviewed in as a non-funnel with its reason.
//!
//! Known ceiling: a frame passed as a `serde_json::Value` is not seen, and
//! neither is a function that builds its `Response` from a frame it reached
//! some other way (a field, a task-local). Syntax scan with `syn`.

use std::collections::BTreeSet;

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The types that mean a function holds a typed frame.
const FRAMES: [&str; 3] = ["JsonRpcResponse", "OutboundFrame", "Egressed"];

/// The marking funnels: where a typed frame becomes the response and its
/// error is read off the frame.
const FUNNELS: [&str; 2] = ["to_http", "build_response"];

/// Reviewed non-funnels, each with why it needs no marking of its own.
const NOT_FUNNELS: [(&str, &str); 3] = [
    (
        "held_body",
        "only called by `to_http`, which marks the response it returns",
    ),
    (
        "first_event_wins_stream",
        "classifies the terminal answer itself and marks its response `StreamAccounted`",
    ),
    (
        "request_scoped_event_stream",
        "re-frames a response already built, keeping its extensions and so its marker",
    ),
];

/// Every last path segment in a type.
#[derive(Default)]
struct Names(BTreeSet<String>);

impl<'ast> Visit<'ast> for Names {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(last) = path.segments.last() {
            self.0.insert(last.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }
}

fn names_of(
    types: impl IntoIterator<Item = impl std::borrow::Borrow<syn::Type>>,
) -> BTreeSet<String> {
    let mut names = Names::default();
    for ty in types {
        names.visit_type(ty.borrow());
    }
    names.0
}

/// Whether `sig` takes a typed frame and returns an axum `Response`.
fn frame_to_response(sig: &syn::Signature) -> bool {
    let params = sig.inputs.iter().filter_map(|input| match input {
        syn::FnArg::Typed(typed) => Some(typed.ty.as_ref().clone()),
        syn::FnArg::Receiver(_) => None,
    });
    let syn::ReturnType::Type(_, ret) = &sig.output else {
        return false;
    };
    let takes_frame = names_of(params)
        .iter()
        .any(|n| FRAMES.contains(&n.as_str()));
    takes_frame && names_of([ret.as_ref().clone()]).contains("Response")
}

#[derive(Default)]
struct Found(Vec<String>);

impl Found {
    fn note(&mut self, at: &Place, sig: &syn::Signature) {
        if frame_to_response(sig) {
            self.0.push(format!("{} {}", at.file, sig.ident));
        }
    }
}

impl Sink for Found {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(function) if !test_only(&function.attrs) => {
                self.note(at, &function.sig);
            }
            syn::Item::Impl(block) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(method) = member
                        && !test_only(&method.attrs)
                    {
                        self.note(at, &method.sig);
                    }
                }
            }
            _ => {}
        }
    }
}

#[test]
fn every_frame_to_response_function_is_a_funnel_or_reviewed() {
    let mut found = Found::default();
    walk(crate_root(), &ROOTS, &mut found).expect("the walk reads every module");
    let unreviewed: Vec<&String> = found
        .0
        .iter()
        .filter(|entry| {
            let name = entry.rsplit(' ').next().unwrap_or_default();
            !FUNNELS.contains(&name) && !NOT_FUNNELS.iter().any(|(n, _)| *n == name)
        })
        .collect();
    assert!(
        unreviewed.is_empty(),
        "functions taking a typed frame and returning a Response that are neither a marking \
         funnel {FUNNELS:?} nor reviewed in NOT_FUNNELS:\n{unreviewed:#?}"
    );
    for funnel in FUNNELS {
        assert!(
            found
                .0
                .iter()
                .any(|entry| entry.ends_with(&format!(" {funnel}"))),
            "the funnel {funnel} is no longer found: the scan saw nothing"
        );
    }
}

#[test]
fn the_scan_sees_a_frame_to_response_signature_and_skips_others() {
    let seen: syn::Signature =
        syn::parse_str("fn f(x: crate::protocol::JsonRpcResponse) -> axum::response::Response")
            .expect("a signature");
    let other: syn::Signature =
        syn::parse_str("fn g(x: String) -> axum::response::Response").expect("a signature");
    let value: syn::Signature =
        syn::parse_str("fn h(x: serde_json::Value) -> Response").expect("a signature");
    assert!(frame_to_response(&seen));
    assert!(!frame_to_response(&other));
    assert!(!frame_to_response(&value), "a Value is the known ceiling");
}
