// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where an error becomes a delivered frame, or a gateway refusal is built,
//! in `src/gateway` production code (refusals anywhere in `src/`). A gateway refusal records `refused` only
//! where it is delivered (sealed errors at the outlets, the rest per site),
//! so a new framing site or a new refusal must be looked at, not slipped in.
//!
//! Two baselines, compared exactly (a count that moves up or down, or a key
//! that appears or vanishes, fails):
//! - `delivery_framing_inventory.tsv`: the generic error builders and
//!   seal-erasing conversions, by (file, fn, needle, count). Inventoried,
//!   not classified.
//! - `delivery_refusals.tsv`: every gateway refusal built or answered, by
//!   (file, fn, needle, count, class): a call to a `*refusal`, `refuse_*` or
//!   `gateway_refused` function or one handed on as a value, a `Refused::of`
//!   answer, and an `Error::Forbidden`, `GatewayRefused` or
//!   `ResponseFirewallRefused` built. Classified per site.
//!
//! Regenerating either is a reviewed diff, never a silent refresh: run this
//! test, copy the printed table, and put the diff in front of a reviewer.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Callee names (the last path segment, or a method name) inventoried.
const BUILDERS: [&str; 11] = [
    // The scrub's refusal read where a backend error is delivered outside
    // the outlet: a new delivery site of a backend error needs one.
    "echo_refusal_delivered",
    "build_error_response",
    "build_error_response_with_data",
    "build_http_error_response",
    "build_http_response",
    "build_response",
    "error_response_preserving_status",
    "dispatch_error_result",
    "to_value_lossy",
    "delivery_refusal_error",
    "gateway_error",
];

/// What a refusal site does with respect to the delivery record.
const CLASSES: [&str; 6] = [
    // Frames or returns the delivered refusal and records it: a seal read at
    // an outlet, or a raise here or at the caller that delivers it (the note
    // says which). There is no class for a delivered refusal left unrecorded.
    "recorded",
    // Builds a refusal another site delivers and records.
    "feeds",
    // A predicate, an audit row, a memo or a copy: never the delivered answer.
    "not-delivered",
    // Delivered, but not a gateway policy decision: a client-protocol
    // rejection or an internal failure (a credential mint, the audit sink).
    "not-a-decision",
    // Answered where no call delivery is recorded (sessions, accounts, SSE,
    // start-up, the admin UI, authentication before a call exists).
    "no-record",
    // A refusal a composite step absorbs or a stored answer replays: stated
    // by the composite's or the replay's own record rules.
    "composite-or-replay",
];

/// Known gaps, each fixed by a follow-up that deletes its slug here when it
/// flips the last `pending:<slug>` row: a row left pending then fails, and
/// so does a slug with no rows.
const PENDING: [&str; 1] = ["capability-refusals"];

#[derive(Default)]
struct Found {
    builders: std::collections::BTreeMap<String, usize>,
    refusals: std::collections::BTreeMap<String, usize>,
}

/// A function that builds or answers a refusal, by its name: `*refusal`,
/// `refuse_*`, or the sealed constructor `gateway_refused`.
fn is_refusal_name(name: &str) -> bool {
    name.ends_with("refusal") || name.starts_with("refuse_") || name == "gateway_refused"
}

/// Combinators whose argument is a function: a refusal name there is a
/// refusal function handed on, never a local value.
const COMBINATORS: [&str; 10] = [
    "map",
    "map_err",
    "and_then",
    "or_else",
    "ok_or_else",
    "map_or_else",
    "unwrap_or_else",
    "inspect_err",
    "then",
    "filter_map",
];

/// The arguments of a combinator call; none for any other expression.
fn call_args(expr: &syn::Expr) -> Vec<&syn::Expr> {
    match expr {
        syn::Expr::MethodCall(call) if COMBINATORS.contains(&call.method.to_string().as_str()) => {
            call.args.iter().collect()
        }
        _ => Vec::new(),
    }
}

/// Whether `path` names `Error::<variant>` (by its last two segments).
fn is_error_variant(path: &syn::Path, variant: &str) -> bool {
    let mut segments = path.segments.iter().rev();
    segments.next().is_some_and(|s| s.ident == variant)
        && segments.next().is_some_and(|s| s.ident == "Error")
}

fn callee(expr: &syn::Expr) -> Option<(Option<String>, String)> {
    match expr {
        syn::Expr::MethodCall(call) => Some((None, call.method.to_string())),
        syn::Expr::Call(call) => match &*call.func {
            syn::Expr::Path(path) => {
                let segments: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                let last = segments.last()?.clone();
                let owner = segments.len().checked_sub(2).map(|i| segments[i].clone());
                Some((owner, last))
            }
            _ => None,
        },
        _ => None,
    }
}

impl Sink for Found {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        // A refusal built anywhere in the crate can reach a delivered answer
        // (the playbook engine, the firewall, the transports), so every
        // refusal in `src/` is classified. Only `src/gateway` frames answers,
        // so the builder inventory stays there.
        let framing = at.file.starts_with("src/gateway/");
        if !at.file.starts_with("src/") {
            return;
        }
        let func = at.func.clone().unwrap_or_else(|| "<module>".to_string());
        let note = |table: &mut std::collections::BTreeMap<String, usize>, needle: &str| {
            *table
                .entry(format!("{}\t{func}\t{needle}", at.file))
                .or_default() += 1;
        };
        let note_builder = |table: &mut std::collections::BTreeMap<String, usize>, needle: &str| {
            if framing {
                note(table, needle);
            }
        };
        if let syn::Expr::Struct(literal) = expr
            && literal
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "JsonRpc")
        {
            note_builder(&mut self.builders, "Error::JsonRpc{}");
        }
        // The gateway's own refusal variants, built without a `*refusal`
        // function (a firewall or authorization refusal at a chokepoint).
        if let syn::Expr::Struct(literal) = expr
            && is_error_variant(&literal.path, "Forbidden")
        {
            note(&mut self.refusals, "Error::Forbidden{}");
        }
        if let syn::Expr::Path(path) = expr
            && is_error_variant(&path.path, "ResponseFirewallRefused")
        {
            note(&mut self.refusals, "Error::ResponseFirewallRefused");
        }
        if let syn::Expr::Struct(literal) = expr
            && is_error_variant(&literal.path, "GatewayRefused")
        {
            note(&mut self.refusals, "Error::GatewayRefused{}");
        }
        // A refusal function handed on as a value (`.map_err(refusal)`); a
        // local named `refusal` passed to `Err(..)` is not one.
        for arg in call_args(expr) {
            if let syn::Expr::Path(path) = arg
                && let Some(last) = path.path.segments.last()
                && is_refusal_name(&last.ident.to_string())
            {
                note(&mut self.refusals, &format!("{} (as value)", last.ident));
            }
        }
        let Some((owner, name)) = callee(expr) else {
            return;
        };
        match (owner.as_deref(), name.as_str()) {
            (Some("JsonRpcResponse"), "error" | "error_with_data") => {
                note_builder(&mut self.builders, &format!("JsonRpcResponse::{name}"));
            }
            (Some("Error"), "json_rpc") => note_builder(&mut self.builders, "Error::json_rpc"),
            (_, builder) if BUILDERS.contains(&builder) => {
                note_builder(&mut self.builders, builder);
            }
            (Some("Refused"), "of") => note(&mut self.refusals, "Refused::of"),
            (_, refusal) if is_refusal_name(refusal) => note(&mut self.refusals, refusal),
            _ => {}
        }
    }
}

fn found() -> Found {
    let mut found = Found::default();
    walk(crate_root(), &ROOTS, &mut found).expect("the crate walks");
    found
}

fn table(rows: &std::collections::BTreeMap<String, usize>) -> Vec<String> {
    rows.iter().map(|(key, n)| format!("{key}\t{n}")).collect()
}

fn pinned(text: &str, columns: usize) -> Vec<String> {
    let mut rows: Vec<String> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').take(columns).collect::<Vec<_>>().join("\t"))
        .collect();
    rows.sort();
    rows
}

const REGENERATE: &str = "regenerate: cargo test --lib delivery_framing -- --nocapture, copy the \
                          printed table into the .tsv, and have the diff reviewed";

#[test]
fn every_generic_framing_site_is_inventoried() {
    let have = table(&found().builders);
    let want = pinned(include_str!("delivery_framing_inventory.tsv"), 4);
    if have != want {
        println!(
            "BEGIN delivery_framing_inventory.tsv\n{}\nEND",
            have.join("\n")
        );
    }
    assert_eq!(have, want, "framing sites changed; {REGENERATE}");
}

#[test]
fn every_refusal_site_is_classified() {
    let have = table(&found().refusals);
    let text = include_str!("delivery_refusals.tsv");
    let want = pinned(text, 4);
    if have != want {
        println!("BEGIN delivery_refusals.tsv\n{}\nEND", have.join("\n"));
    }
    assert_eq!(
        have, want,
        "refusal sites changed; classify each new one; {REGENERATE}"
    );
    for row in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let class = row.split('\t').nth(4).unwrap_or("");
        let pending = class
            .strip_prefix("pending:")
            .is_some_and(|slug| PENDING.contains(&slug));
        assert!(
            CLASSES.contains(&class) || pending,
            "unclassified refusal site: {row}"
        );
    }
    // A slug whose last row was flipped must go too, or it re-admits rows.
    for slug in PENDING {
        assert!(
            text.contains(&format!("\tpending:{slug}\t")),
            "pending:{slug} has no rows left; delete it from PENDING"
        );
    }
}
