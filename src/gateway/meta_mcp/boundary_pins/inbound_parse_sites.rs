// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every place production code under src/transport, src/a2a and src/backend
//! parses inbound JSON is listed in `inbound_parse_sites.tsv` with its class
//! (MIK-9035 T1.31). A new parse site, a changed count, a stale row, or a
//! `scrubbed` function that lost its scrub call fails.
//!
//! Classes:
//! - `scrubbed`: the function itself calls one of [`SCRUB_CALLS`], outside
//!   any branch, before its first [`SINK_CALLS`] call.
//! - `scrubbed-by`: the reason starts `by <file>::<function>:`, naming the
//!   function every result of this one passes; that function must call one
//!   of [`SCRUB_CALLS`], and it or a direct caller must reach this one over
//!   callee names. A result handed over a channel names the receiving
//!   function instead: `by <file>::<function> via <file>::<function>:`.
//! - `post-transport`: parses a result the transport already scrubbed.
//! - `not-backend-data`: reads no backend content (a log level).
//!
//! Syntax scan, per function body, like the other pins. Its limits: order
//! is source order (a call counts after its arguments), not flow analysis;
//! a branch is an `if` (unless its condition names `needles`, the value
//! set's own guard), a match arm or a closure, while a loop body is not;
//! reach follows callee names within one tree, to every function of that
//! name, and never into macros or across trees; a `via` hop is named, not
//! proven. The behaviour rows stay the primary proof.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 1] = ["src/lib.rs"];
const SCOPES: [&str; 3] = ["src/transport/", "src/a2a/", "src/backend/"];

/// The calls that remove a backend's injected values.
const SCRUB_CALLS: [&str; 8] = [
    "scrub_note",
    "ingress_scrub",
    "scrub_frame",
    "withheld",
    "scrub_answer",
    "scrub_response_with",
    "scrub_text",
    "scrubbed",
];

/// (file, function, kind) -> parses.
type Counts = BTreeMap<(String, String, String), usize>;

/// (file, function).
type Func = (String, String);

/// The calls that hand a frame on: a scrub must come before the first.
const SINK_CALLS: [&str; 4] = ["publish", "send", "try_send", "deliver"];

/// Where a function's scrub stands against its first hand-off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Guard {
    /// A scrub outside any branch comes before the first sink call.
    Guarded,
    /// Every scrub sits in a branch, a match arm or a closure.
    BranchOnly,
    /// The first unbranched scrub comes after a sink call.
    Late,
}

#[derive(Default)]
struct Body {
    kinds: BTreeMap<String, usize>,
    /// Callee names: a path call's last segment, a method's name.
    calls: BTreeSet<String>,
    scrubs: bool,
    /// Calls seen so far; a call is numbered after its arguments, the order
    /// they run in.
    seq: usize,
    depth: usize,
    first_sink: Option<usize>,
    first_top_scrub: Option<usize>,
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

/// Whether an expression names `needles`: an `if` on the value set holding
/// is the transport's own guard, not a branch around the scrub.
#[derive(Default)]
struct Mentions(bool);

impl<'ast> Visit<'ast> for Mentions {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0 |= ident == "needles";
    }
}

impl Body {
    fn count(&mut self, kind: &str) {
        *self.kinds.entry(kind.to_owned()).or_default() += 1;
    }

    /// Records a call by name, after its arguments were visited.
    fn called(&mut self, name: &str) {
        self.seq += 1;
        self.calls.insert(name.to_owned());
        if SINK_CALLS.contains(&name) && self.first_sink.is_none() {
            self.first_sink = Some(self.seq);
        }
        if SCRUB_CALLS.contains(&name) {
            self.scrubs = true;
            if self.depth == 0 && self.first_top_scrub.is_none() {
                self.first_top_scrub = Some(self.seq);
            }
        }
    }

    fn branched<F: FnOnce(&mut Self)>(&mut self, visit: F) {
        self.depth += 1;
        visit(self);
        self.depth -= 1;
    }

    fn guard(&self) -> Option<Guard> {
        if !self.scrubs {
            return None;
        }
        Some(match (self.first_top_scrub, self.first_sink) {
            (None, _) => Guard::BranchOnly,
            (Some(scrub), Some(sink)) if sink < scrub => Guard::Late,
            _ => Guard::Guarded,
        })
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        syn::visit::visit_expr_call(self, call);
        if let syn::Expr::Path(p) = call.func.as_ref() {
            let segs = segments(&p.path);
            let tail: Vec<&str> = segs
                .iter()
                .rev()
                .take(2)
                .rev()
                .map(String::as_str)
                .collect();
            match tail.as_slice() {
                [
                    "serde_json",
                    f @ ("from_str" | "from_slice" | "from_value" | "from_reader"),
                ] => {
                    self.count(f);
                }
                ["JsonRpcMessage", "from_line"] => self.count("from_line"),
                ["McpFrame", "from_text"] => self.count("from_text"),
                _ => {}
            }
            if let Some(name) = segs.last() {
                self.called(name);
            }
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        let method = call.method.to_string();
        if method == "json" && call.args.is_empty() {
            self.count("json");
        }
        self.called(&method);
    }

    fn visit_expr_if(&mut self, expr: &'ast syn::ExprIf) {
        self.visit_expr(&expr.cond);
        let mut guard = Mentions::default();
        guard.visit_expr(&expr.cond);
        if guard.0 {
            self.visit_block(&expr.then_branch);
        } else {
            self.branched(|body| body.visit_block(&expr.then_branch));
        }
        if let Some((_, other)) = &expr.else_branch {
            self.branched(|body| body.visit_expr(other));
        }
    }

    fn visit_expr_match(&mut self, expr: &'ast syn::ExprMatch) {
        self.visit_expr(&expr.expr);
        self.branched(|body| {
            for arm in &expr.arms {
                body.visit_arm(arm);
            }
        });
    }

    fn visit_expr_closure(&mut self, expr: &'ast syn::ExprClosure) {
        self.branched(|body| syn::visit::visit_expr_closure(body, expr));
    }
}

#[derive(Default)]
struct Sites {
    counts: Counts,
    /// Every function that calls a scrub anywhere in its body.
    scrubbing: BTreeSet<Func>,
    /// Where each scrubbing function's scrub stands.
    guards: BTreeMap<Func, Guard>,
    /// Callee names of every function in the three trees.
    calls: BTreeMap<Func, BTreeSet<String>>,
}

/// The tree (one of [`SCOPES`]) a file sits in.
fn tree(file: &str) -> Option<&'static str> {
    SCOPES.iter().copied().find(|scope| file.starts_with(scope))
}

impl Sites {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        if tree(file).is_none() {
            return;
        }
        let mut body = Body::default();
        body.visit_block(block);
        let at = (file.to_owned(), func.to_owned());
        if let Some(guard) = body.guard() {
            self.scrubbing.insert(at.clone());
            // Two bodies under one name: the weaker guard stands.
            let held = self.guards.entry(at.clone()).or_insert(guard);
            if *held == Guard::Guarded {
                *held = guard;
            }
        }
        self.calls
            .entry(at)
            .or_default()
            .extend(body.calls.iter().cloned());
        for (kind, n) in body.kinds {
            *self
                .counts
                .entry((file.to_owned(), func.to_owned(), kind))
                .or_default() += n;
        }
    }

    /// Whether `to` is reached from `from` over callee names. A name leads
    /// to every function of that name in the caller's own tree; a call into
    /// another tree is not followed.
    fn reaches(&self, from: &Func, to: &Func) -> bool {
        let mut seen = BTreeSet::from([from.clone()]);
        let mut queue = vec![from.clone()];
        while let Some(at) = queue.pop() {
            if &at == to {
                return true;
            }
            let Some(names) = self.calls.get(&at) else {
                continue;
            };
            let here = tree(&at.0);
            for next in self
                .calls
                .keys()
                .filter(|(file, func)| names.contains(func) && tree(file) == here)
            {
                if seen.insert(next.clone()) {
                    queue.push(next.clone());
                }
            }
        }
        false
    }

    /// Whether the scrubber, or a function that calls it, reaches `target`:
    /// the parse's result can meet the scrub there.
    fn connected(&self, scrubber: &Func, target: &Func) -> bool {
        let here = tree(&scrubber.0);
        std::iter::once(scrubber)
            .chain(self.calls.iter().filter_map(|(at, names)| {
                (names.contains(&scrubber.1) && tree(&at.0) == here).then_some(at)
            }))
            .any(|from| self.reaches(from, target))
    }
}

impl Sink for Sites {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(function) => {
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

/// The reviewed list: file, function, kind, count, class, reason.
const LISTED: &str = include_str!("inbound_parse_sites.tsv");
const CLASSES: [&str; 4] = [
    "scrubbed",
    "scrubbed-by",
    "post-transport",
    "not-backend-data",
];

struct Row {
    count: usize,
    class: String,
    reason: String,
}

/// The table's rows by (file, function, kind).
type Rows = BTreeMap<(String, String, String), Row>;

fn listed(text: &str) -> (Rows, Vec<String>) {
    let mut rows = BTreeMap::new();
    let mut bad = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, kind, n, class, reason] = cols[..] else {
            bad.push(format!("not six columns: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            bad.push(format!("no class or no reason: {line}"));
        }
        let Ok(count) = n.parse::<usize>() else {
            bad.push(format!("count is not a number: {line}"));
            continue;
        };
        let previous = rows.insert(
            (file.to_owned(), func.to_owned(), kind.to_owned()),
            Row {
                count,
                class: class.to_owned(),
                reason: reason.to_owned(),
            },
        );
        if previous.is_some() {
            bad.push(format!("duplicate row: {line}"));
        }
    }
    (rows, bad)
}

fn func_of(named: &str) -> Option<Func> {
    let (file, func) = named.rsplit_once("::")?;
    Some((file.to_owned(), func.to_owned()))
}

/// What a `scrubbed-by` reason names: `by <file>::<function>:`, or
/// `by <file>::<function> via <file>::<function>:` when the result crosses
/// a channel and the scrubber reaches the receiving function instead.
fn named_scrubber(reason: &str) -> Option<(Func, Option<Func>)> {
    // Up to the first ": ", so the `::` inside the name is kept.
    let (named, _) = reason.strip_prefix("by ")?.split_once(": ")?;
    match named.split_once(" via ") {
        Some((by, via)) => Some((func_of(by)?, Some(func_of(via)?))),
        None => Some((func_of(named)?, None)),
    }
}

/// What is wrong with the scan against the table `text`.
fn differences(sites: &Sites, text: &str) -> Vec<String> {
    let (want, mut wrong) = listed(text);
    for (key, n) in &sites.counts {
        match want.get(key) {
            Some(row) if row.count == *n => {}
            Some(row) => wrong.push(format!(
                "count {} -> {n}: {}\t{}\t{}",
                row.count, key.0, key.1, key.2
            )),
            None => wrong.push(format!(
                "unlisted: {}\t{}\t{}\t{n}\t<class>\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for (key, row) in &want {
        if !sites.counts.contains_key(key) {
            wrong.push(format!("stale: {}\t{}\t{}", key.0, key.1, key.2));
        }
        let at = (key.0.clone(), key.1.clone());
        match row.class.as_str() {
            "scrubbed" => match sites.guards.get(&at) {
                Some(Guard::Guarded) => {}
                Some(Guard::BranchOnly) => {
                    wrong.push(format!("scrubs only in a branch: {}\t{}", key.0, key.1));
                }
                Some(Guard::Late) => {
                    wrong.push(format!("scrubs after a send: {}\t{}", key.0, key.1));
                }
                None => wrong.push(format!("lost its scrub call: {}\t{}", key.0, key.1)),
            },
            "scrubbed-by" => match named_scrubber(&row.reason) {
                Some((by, _)) if !sites.scrubbing.contains(&by) => wrong.push(format!(
                    "{}\t{}: {}::{} does not scrub",
                    key.0, key.1, by.0, by.1
                )),
                Some((by, via)) => {
                    let target = via.unwrap_or_else(|| at.clone());
                    if !sites.connected(&by, &target) {
                        wrong.push(format!(
                            "{}\t{}: {}::{} does not reach {}::{}",
                            key.0, key.1, by.0, by.1, target.0, target.1
                        ));
                    }
                }
                None => wrong.push(format!(
                    "{}\t{}: reason must start `by <file>::<function>:`",
                    key.0, key.1
                )),
            },
            _ => {}
        }
    }
    wrong
}

fn scanned() -> Sites {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    sites
}

/// Every inbound parse in the three trees is a reviewed row, and every
/// scrubbing claim still holds.
#[test]
fn every_inbound_parse_site_is_classified() {
    let wrong = differences(&scanned(), LISTED);
    assert!(
        wrong.is_empty(),
        "inbound parse sites differ from inbound_parse_sites.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The pin's own proof: a new parse site fails, and a `scrubbed` function
/// that loses its scrub call fails.
#[test]
fn a_new_site_and_a_lost_scrub_both_fail() {
    let sites = scanned();
    let added: syn::Block = syn::parse_quote!({
        let _v: serde_json::Value = serde_json::from_str(text)?;
    });
    let mut with_new = scanned();
    with_new.function("src/transport/fake.rs", "fake_parse", &added);
    assert!(
        differences(&with_new, LISTED)
            .iter()
            .any(|w| w.starts_with("unlisted: src/transport/fake.rs")),
        "a new parse site passed"
    );
    let mut lost = sites;
    lost.guards.remove(&(
        "src/transport/stdio.rs".to_owned(),
        "handle_response".to_owned(),
    ));
    assert!(
        differences(&lost, LISTED)
            .iter()
            .any(|w| w.starts_with("lost its scrub call: src/transport/stdio.rs")),
        "a lost scrub call passed"
    );
}

fn guard_of(block: &syn::Block) -> Option<Guard> {
    let mut body = Body::default();
    body.visit_block(block);
    body.guard()
}

/// The order check's own proof (lead ruling G10): a scrub after the first
/// send, and a scrub only in a branch, both fail; the transport's `if` on
/// its value set is not a branch.
#[test]
fn a_late_scrub_and_a_branch_only_scrub_both_fail() {
    let late: syn::Block = syn::parse_quote!({
        let mut frame = McpFrame::from_text(text)?;
        let _ = tx.send(frame.clone());
        scrub_frame(needles, &mut frame);
    });
    assert_eq!(guard_of(&late), Some(Guard::Late));
    let branch: syn::Block = syn::parse_quote!({
        let mut frame = McpFrame::from_text(text)?;
        if frame.is_notification() {
            scrub_frame(set, &mut frame);
        }
        let _ = tx.send(frame);
    });
    assert_eq!(guard_of(&branch), Some(Guard::BranchOnly));
    let held: syn::Block = syn::parse_quote!({
        let mut frame = McpFrame::from_text(text)?;
        if let Some(needles) = inner.needles.get() {
            scrub_frame(needles, &mut frame);
        }
        let _ = tx.send(frame);
    });
    assert_eq!(guard_of(&held), Some(Guard::Guarded));
}

/// The reach check's own proof: a `scrubbed-by` row naming a scrubber that
/// never meets the parse fails.
#[test]
fn a_disconnected_scrubber_fails() {
    let mut sites = scanned();
    let planted: syn::Block = syn::parse_quote!({
        let _v: serde_json::Value = serde_json::from_str(text)?;
    });
    sites.function("src/transport/fake.rs", "fake_parse", &planted);
    let table = format!(
        "{LISTED}\nsrc/transport/fake.rs\tfake_parse\tfrom_str\t1\tscrubbed-by\t\
         by src/transport/stdio.rs::handle_response: planted\n"
    );
    assert!(
        differences(&sites, &table)
            .iter()
            .any(|w| w.starts_with("src/transport/fake.rs\tfake_parse: ")
                && w.contains("does not reach")),
        "a disconnected scrubber passed"
    );
}
