// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The census of what builds a call's decision object. One literal builds it
//! (`Noted::decision`), and four entry points reach that literal: the meta
//! call and the direct call through `DispatchNotes::decided`, the router's
//! refusal record and the replay record. Each runs inside the call's token
//! scope, and a real-token row per entry point pins that
//! (`router/direct_audit_tests/token_reach.rs`). The census is read from the
//! syntax of every production file the crate compiles, by the shared walk
//! (test-only code skipped by cfg, never by file name): a method call named
//! `decision` or `decided`, the same call written through its type
//! (`Noted::decision(..)`, `DispatchNotes::decided(..)`), and every `Decision {
//! .. }` literal. A builder added anywhere changes the counts and fails here.
//! The census proves only that the set changed: the change that adds a site
//! must also bring it inside the token scope and add its real-token row, which
//! review checks, since no count can. Grant-decision rows are another record
//! kind, joined to their call by its trace, and are not counted.

use std::collections::BTreeMap;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// What `expr` is, if it builds the decision object or reaches its builder.
fn kind_of(expr: &syn::Expr) -> Option<&'static str> {
    match expr {
        syn::Expr::MethodCall(call) if call.method == "decision" => Some("noted.decision"),
        syn::Expr::MethodCall(call) if call.method == "decided" => Some("notes.decided"),
        syn::Expr::Call(call) => {
            let syn::Expr::Path(path) = &*call.func else {
                return None;
            };
            let names: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            match names.as_slice() {
                [.., owner, name] if owner == "Noted" && name == "decision" => {
                    Some("noted.decision")
                }
                [.., owner, name] if owner == "DispatchNotes" && name == "decided" => {
                    Some("notes.decided")
                }
                _ => None,
            }
        }
        syn::Expr::Struct(literal)
            if literal
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Decision") =>
        {
            Some("Decision literal")
        }
        _ => None,
    }
}

/// (file, enclosing fn, kind) -> how many.
#[derive(Default)]
struct Census(BTreeMap<(String, String, &'static str), usize>);

impl Sink for Census {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if let Some(kind) = kind_of(expr) {
            let func = at.func.clone().unwrap_or_default();
            *self.0.entry((at.file.clone(), func, kind)).or_default() += 1;
        }
    }
}

fn site(file: &str, func: &str, kind: &'static str) -> (String, String, &'static str) {
    (file.to_owned(), func.to_owned(), kind)
}

#[test]
fn a_call_decision_has_exactly_its_known_builders() {
    let mut census = Census::default();
    walk(crate_root(), &ROOTS, &mut census).expect("the walk reads every module");
    let want = BTreeMap::from([
        // The one literal, and its callers: DispatchNotes::decided (two arms),
        // the replay record and the router's refusal record.
        (
            site(
                "src/security/decision_record.rs",
                "decision",
                "Decision literal",
            ),
            1,
        ),
        (
            site(
                "src/gateway/meta_mcp/invoke/audit_decision.rs",
                "decided",
                "noted.decision",
            ),
            2,
        ),
        (
            site(
                "src/gateway/meta_mcp/invoke/audit_replay.rs",
                "audit_replay",
                "noted.decision",
            ),
            1,
        ),
        (
            site(
                "src/gateway/router/meta_refusal_audit.rs",
                "write",
                "noted.decision",
            ),
            1,
        ),
        // DispatchNotes::decided's callers: the meta call and the direct call.
        (
            site(
                "src/gateway/meta_mcp/invoke/audit.rs",
                "audit_invocation",
                "notes.decided",
            ),
            1,
        ),
        (
            site(
                "src/gateway/router/backend_handlers/direct_audit.rs",
                "record",
                "notes.decided",
            ),
            1,
        ),
    ]);
    assert_eq!(census.0, want);
}

/// Each way of writing a builder counts, and look-alikes do not: so the census
/// above cannot stay unchanged while a new builder is added.
#[test]
fn every_way_of_writing_a_builder_is_counted() {
    for (form, kind) in [
        ("noted.decision(a, b)", "noted.decision"),
        ("noted . decision ( a )", "noted.decision"),
        ("Noted::decision(&noted, a)", "noted.decision"),
        (
            "crate::security::decision_record::Noted::decision(&n)",
            "noted.decision",
        ),
        ("notes.decided(meta, outcome, kind)", "notes.decided"),
        ("DispatchNotes::decided(&notes, meta)", "notes.decided"),
        ("Decision { v: 2, ..base }", "Decision literal"),
        (
            "crate::security::decision_record::Decision { v: 2 }",
            "Decision literal",
        ),
    ] {
        let expr: syn::Expr = syn::parse_str(form).expect("a fixture expression");
        assert_eq!(kind_of(&expr), Some(kind), "{form}");
    }
    for other in [
        "stdio_seams::decided()",
        "decision(a)",
        "x.decide()",
        "Decided { v: 1 }",
        "Decision::Allow",
    ] {
        let expr: syn::Expr = syn::parse_str(other).expect("a fixture expression");
        assert_eq!(kind_of(&expr), None, "{other}");
    }
}
