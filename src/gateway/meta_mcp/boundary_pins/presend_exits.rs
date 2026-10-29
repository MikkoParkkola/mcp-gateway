// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every function on the meta path that leaves a call refused before its
//! backend says so: it settles through `settle_pre_send`, which marks the
//! invocation refused, or marks the invocation (`note_pre_send`) or the task
//! worker's round (`note_round`) itself, or is listed as excluded with its
//! reason in `presend_exits.tsv`. A refused call left unmarked is recorded as
//! a call a backend ran (a relay replay call, a single call's answer taken for
//! the backend's), so a new exit fails here until it is classified.
//!
//! A refusal exit is a nonce refund asked (`ask_refund`, `ask_if_transient`),
//! a pre-dispatch error test (`is_pre_dispatch`), or an idempotency
//! reservation released by hand (`.release()` on a receiver named for a
//! reservation). Syntax scan, per function body, as the other pins: a call
//! passed by path is missed.
//!
//! The scope stops at `src/gateway/meta_mcp/` because every record a refused
//! call could be miscounted in is written there: the dispatch log's targets
//! and the relay replay calls (the step funnel), and the task worker's round.
//! The worker opens the log's scope but writes nothing to it, the direct
//! route and the router write neither, and the worker's own refusals settle
//! with the `not_executed` marker. `every_call_record_writer_is_on_the_meta_path`
//! pins that: a writer elsewhere fails until this scope widens.

use std::collections::BTreeMap;

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 2] = ["src/lib.rs", "src/main.rs"];
/// The meta path: the invoke funnel, the dispatch around it, the task replay.
const SCOPE: &str = "src/gateway/meta_mcp/";
const CLASSES: [&str; 3] = ["settles", "marks", "excluded"];

/// What one function body does: its refusal exits, and how it marks them.
#[derive(Default)]
struct Body {
    exits: usize,
    settles: bool,
    marks: bool,
}

fn last_segment(path: &syn::Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

/// A receiver named for an idempotency reservation (`reservation`,
/// `idem_reservation`, `self.reservation`).
fn is_reservation(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Path(p) => last_segment(&p.path).is_some_and(|n| n.contains("reservation")),
        syn::Expr::Field(f) => match &f.member {
            syn::Member::Named(ident) => ident.to_string().contains("reservation"),
            syn::Member::Unnamed(_) => false,
        },
        _ => false,
    }
}

impl Body {
    fn call(&mut self, name: &str) {
        match name {
            "ask_refund" | "ask_if_transient" | "is_pre_dispatch" => self.exits += 1,
            "settle_pre_send" => self.settles = true,
            "note_pre_send" | "note_round" => self.marks = true,
            _ => {}
        }
    }

    fn class(&self) -> &'static str {
        if self.settles {
            "settles"
        } else if self.marks {
            "marks"
        } else {
            "excluded"
        }
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = call.func.as_ref()
            && let Some(name) = last_segment(&p.path)
        {
            self.call(&name);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if method == "release" && is_reservation(&call.receiver) {
            self.exits += 1;
        } else {
            self.call(&method);
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// (file, function) -> (exits, class).
type Found = BTreeMap<(String, String), (usize, &'static str)>;

#[derive(Default)]
struct Exits {
    found: Found,
}

impl Exits {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        let mut body = Body::default();
        body.visit_block(block);
        if body.exits > 0 {
            let entry = self
                .found
                .entry((file.to_owned(), func.to_owned()))
                .or_insert((0, "excluded"));
            entry.0 += body.exits;
            entry.1 = body.class();
        }
    }
}

impl Sink for Exits {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        if !at.file.starts_with(SCOPE) {
            return;
        }
        match item {
            syn::Item::Fn(function) if !test_only(&function.attrs) => {
                self.function(&at.file, &function.sig.ident.to_string(), &function.block);
            }
            syn::Item::Impl(block) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(method) = member
                        && !test_only(&method.attrs)
                    {
                        self.function(&at.file, &method.sig.ident.to_string(), &method.block);
                    }
                }
            }
            _ => {}
        }
    }
}

/// The reviewed list: file, function, exits, class, reason.
const LISTED: &str = include_str!("presend_exits.tsv");

/// The listed rows, and the ones that are malformed.
fn listed() -> (BTreeMap<(String, String), (usize, String)>, Vec<String>) {
    let mut rows = BTreeMap::new();
    let mut bad = Vec::new();
    for line in LISTED
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, n, class, reason] = cols[..] else {
            bad.push(format!("not five columns: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            bad.push(format!("no class or no reason: {line}"));
        }
        let Ok(n) = n.parse::<usize>() else {
            bad.push(format!("exits is not a number: {line}"));
            continue;
        };
        rows.insert((file.to_owned(), func.to_owned()), (n, class.to_owned()));
    }
    (rows, bad)
}

/// Every pre-send refusal exit on the meta path is a reviewed row whose class
/// matches what its function does; a new exit, a changed count, a function
/// that stopped marking, or a stale row fails and prints the row to fix.
#[test]
fn every_pre_send_refusal_exit_is_marked_or_excluded() {
    let mut exits = Exits::default();
    walk(crate_root(), &ROOTS, &mut exits).expect("the walk reads every module");
    let (want, bad) = listed();
    let mut wrong = bad;
    for ((file, func), (n, class)) in &exits.found {
        match want.get(&(file.clone(), func.clone())) {
            Some((m, c)) if m == n && c == class => {}
            Some((m, c)) => {
                wrong.push(format!("listed {m} {c}, found {n} {class}: {file}\t{func}"))
            }
            None => wrong.push(format!("unlisted: {file}\t{func}\t{n}\t{class}\t<reason>")),
        }
    }
    for (file, func) in want.keys().filter(|k| !exits.found.contains_key(*k)) {
        wrong.push(format!("stale: {file}\t{func}"));
    }
    assert!(
        wrong.is_empty(),
        "pre-send refusal exits differ from presend_exits.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The scanner tells the three classes apart, and counts a hand-released
/// reservation as an exit but not another `release`.
#[test]
fn the_scanner_classes_each_kind_of_exit() {
    let class = |block: syn::Block| {
        let mut body = Body::default();
        body.visit_block(&block);
        (body.exits, body.class())
    };
    assert_eq!(
        class(syn::parse_quote!({
            ask_refund(caller);
            settle_pre_send(caller, exit);
        })),
        (1, "settles")
    );
    assert_eq!(
        class(syn::parse_quote!({
            reservation.release();
            note_pre_send(PreSend::Refused);
        })),
        (1, "marks")
    );
    assert_eq!(
        class(syn::parse_quote!({
            if e.is_pre_dispatch() {
                idem_reservation.release();
            }
        })),
        (2, "excluded")
    );
    assert_eq!(
        class(syn::parse_quote!({
            slot.release();
        })),
        (0, "excluded")
    );
}

/// The writers of the records a refused call could be miscounted in.
const RECORD_WRITERS: [&str; 3] = ["note_replay_call", "note_completed", "note_round"];

/// Calls to a record writer outside the meta path.
#[derive(Default)]
struct Writers {
    outside: Vec<String>,
}

impl Sink for Writers {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let name = match expr {
            syn::Expr::Call(call) => match call.func.as_ref() {
                syn::Expr::Path(p) => last_segment(&p.path),
                _ => None,
            },
            syn::Expr::MethodCall(call) => Some(call.method.to_string()),
            _ => None,
        };
        if let Some(name) = name
            && RECORD_WRITERS.contains(&name.as_str())
            && !at.file.starts_with(SCOPE)
        {
            self.outside.push(format!("{}: {name}", at.file));
        }
    }
}

/// The refusal-exit scan covers the meta path because only it writes the
/// records; a writer elsewhere means the scope must widen.
#[test]
fn every_call_record_writer_is_on_the_meta_path() {
    let mut writers = Writers::default();
    walk(crate_root(), &ROOTS, &mut writers).expect("the walk reads every module");
    assert!(
        writers.outside.is_empty(),
        "call-record writers outside {SCOPE}; widen the refusal-exit scan:\n{}",
        writers.outside.join("\n")
    );
}
