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
//! A row counts its refusal exits and its refusal marks apart, so a removed
//! mark is never offset by an added exit. A refusal exit is a nonce refund
//! asked (`ask_refund`, `ask_if_transient`), a pre-dispatch error test
//! (`is_pre_dispatch`, or `delivery_facts::unsent`, which also reads a refusal
//! the backend's own send recorded), or an idempotency reservation released by hand
//! (`.release()` on a receiver named for a reservation). A refusal mark is a
//! `note_pre_send` or `note_round` call whose argument names `Refused`: so
//! every hand-marked plain-error exit is a row, and removing its mark fails
//! here.
//!
//! What this cannot see: a new plain-error exit (a bare `Err` before the
//! backend) that carries none of those markers. A syntax scan cannot tell it
//! from an error after the send; such an exit is caught by its own refused-call
//! row, not here. Per function body, as the other pins: a function is keyed by
//! name within its file, and a call passed by path is missed.
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

use super::fragments::{Table, live_base, pin_table, scratch_table, shown, without_first_row};
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
    /// Calls that mark the call refused (`note_pre_send`, `note_round` with a
    /// `Refused` argument): a hand mark removed changes this count.
    refusal_marks: usize,
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
            "ask_refund" | "ask_if_transient" | "is_pre_dispatch" | "unsent" | "nothing_sent" => {
                self.exits += 1;
            }
            "settle_pre_send" => self.settles = true,
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

/// Whether `expr` names `Refused` anywhere (a path, a match arm's value).
fn names_refused(expr: &syn::Expr) -> bool {
    struct Find(bool);
    impl<'ast> Visit<'ast> for Find {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.0 |= last_segment(path).is_some_and(|n| n == "Refused");
            syn::visit::visit_path(self, path);
        }
    }
    let mut find = Find(false);
    find.visit_expr(expr);
    find.0
}

impl Body {
    /// A refusal mark: the call is refused before its backend, by hand.
    fn mark(&mut self, name: &str, first: Option<&syn::Expr>) {
        if (name == "note_pre_send" || name == "note_round") && first.is_some_and(names_refused) {
            self.refusal_marks += 1;
            self.marks = true;
        }
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = call.func.as_ref()
            && let Some(name) = last_segment(&p.path)
        {
            self.call(&name);
            self.mark(&name, call.args.first());
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

/// (file, function) -> (exits, marks, class).
type Found = BTreeMap<(String, String), (usize, usize, &'static str)>;

#[derive(Default)]
struct Exits {
    found: Found,
}

impl Exits {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        let mut body = Body::default();
        body.visit_block(block);
        if body.exits + body.refusal_marks > 0 {
            let entry = self
                .found
                .entry((file.to_owned(), func.to_owned()))
                .or_insert((0, 0, "excluded"));
            entry.0 += body.exits;
            entry.1 += body.refusal_marks;
            entry.2 = body.class();
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

/// (file, function) -> (exits, marks, class, the table file listing it).
type Listed = BTreeMap<(String, String), (usize, usize, String, String)>;

/// The listed rows from the reviewed `presend_exits` table (file, function,
/// exits, marks, class, reason), and the ones that are malformed.
fn listed(table: &Table) -> (Listed, Vec<String>) {
    let mut rows = Listed::new();
    let mut bad = Vec::new();
    for (path, line) in table.rows() {
        let at = shown(path);
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, exits, marks, class, reason] = cols[..] else {
            bad.push(format!("not six columns in {at}: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            bad.push(format!("no class or no reason in {at}: {line}"));
        }
        let (Ok(exits), Ok(marks)) = (exits.parse::<usize>(), marks.parse::<usize>()) else {
            bad.push(format!("exits or marks is not a number in {at}: {line}"));
            continue;
        };
        let value = (exits, marks, class.to_owned(), at.clone());
        if let Some((.., earlier)) = rows.insert((file.to_owned(), func.to_owned()), value) {
            bad.push(format!(
                "repeated key in {earlier} and {at}: {file}\t{func}"
            ));
        }
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
    let wrong = differences(&exits.found, &pin_table("presend_exits"));
    assert!(
        wrong.is_empty(),
        "pre-send refusal exits differ from presend_exits.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// What differs between the found exits and the reviewed table: malformed
/// rows, changed counts or classes, unlisted functions and stale rows.
fn differences(found: &Found, table: &Table) -> Vec<String> {
    let (want, bad) = listed(table);
    let mut wrong = bad;
    let mut add = Vec::new();
    for ((file, func), (e, m, class)) in found {
        match want.get(&(file.clone(), func.clone())) {
            Some((we, wm, c, _)) if we == e && wm == m && c == class => {}
            Some((we, wm, c, at)) => wrong.push(format!(
                "listed {we} exits {wm} marks {c}, found {e} exits {m} marks {class}, edit this row in {at}: {file}\t{func}"
            )),
            None => add.push(format!("{file}\t{func}\t{e}\t{m}\t{class}\t<reason>")),
        }
    }
    for ((file, func), (.., at)) in want.iter().filter(|(k, _)| !found.contains_key(*k)) {
        wrong.push(format!("stale, remove from {at}: {file}\t{func}"));
    }
    if !add.is_empty() {
        wrong.push(format!(
            "rows to add ({}; put these in your fragment presend_exits.d/<ticket>.tsv):",
            add.len()
        ));
        wrong.extend(add);
    }
    wrong
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

/// A `Clear` note is not a refusal mark; a `Refused` one, in a match arm too,
/// is.
#[test]
fn only_a_refused_note_is_a_refusal_mark() {
    let marks = |block: syn::Block| {
        let mut body = Body::default();
        body.visit_block(&block);
        body.refusal_marks
    };
    assert_eq!(
        marks(syn::parse_quote!({
            note_pre_send(PreSend::Clear);
        })),
        0
    );
    assert_eq!(
        marks(syn::parse_quote!({
            note_round(PreSend::Refused);
        })),
        1
    );
    assert_eq!(
        marks(syn::parse_quote!({
            note_pre_send(match exit {
                Served(_) => PreSend::Clear,
                _ => PreSend::Refused,
            });
        })),
        1
    );
}

/// Every pre-send refusal exit the walk finds, by (file, function).
fn found() -> Found {
    let mut exits = Exits::default();
    walk(crate_root(), &ROOTS, &mut exits).expect("the walk reads every module");
    exits.found
}

/// FRAG.2 through the real comparison: a real row held only by a fragment
/// still counts.
#[test]
fn presend_exits_reads_a_required_row_from_a_fragment() {
    let (base, moved) = without_first_row(&live_base("presend_exits"));
    let (_root, table) = scratch_table("presend_exits", &base, &[("1.tsv", &moved)]);
    let wrong = differences(&found(), &table);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// FRAG.2: a stale row in a fragment fails, naming the fragment.
#[test]
fn presend_exits_rejects_a_stale_fragment_row() {
    let stale = "src/nowhere.rs\tf\t1\t1\tmarks\tnone\n";
    let (_root, table) = scratch_table(
        "presend_exits",
        &live_base("presend_exits"),
        &[("1.tsv", stale)],
    );
    let wrong = differences(&found(), &table);
    assert!(
        wrong
            .iter()
            .any(|l| l.contains("stale") && l.contains("1.tsv")),
        "{}",
        wrong.join("\n")
    );
}

/// FRAG.2: a key held by the base and by a fragment fails, naming both files.
#[test]
fn presend_exits_key_repeated_across_files_fails_naming_both() {
    let (_, moved) = without_first_row(&live_base("presend_exits"));
    let (_root, table) = scratch_table(
        "presend_exits",
        &live_base("presend_exits"),
        &[("1.tsv", &moved)],
    );
    let wrong = differences(&found(), &table);
    assert!(
        wrong
            .iter()
            .any(|l| l.contains("presend_exits.tsv") && l.contains("1.tsv")),
        "{}",
        wrong.join("\n")
    );
}

/// A key listed twice in one file fails.
#[test]
fn presend_exits_key_repeated_in_one_file_fails() {
    let (_, moved) = without_first_row(&live_base("presend_exits"));
    let base = format!("{}{moved}", live_base("presend_exits"));
    let (_root, table) = scratch_table("presend_exits", &base, &[]);
    let wrong = differences(&found(), &table);
    assert!(
        wrong.iter().any(|l| l.contains("repeated")),
        "{}",
        wrong.join("\n")
    );
}

/// A key the table lacks is listed to add, in the reader's own fragment.
#[test]
fn presend_exits_missing_key_is_listed_to_add_in_your_fragment() {
    let (base, _) = without_first_row(&live_base("presend_exits"));
    let (_root, table) = scratch_table("presend_exits", &base, &[]);
    let wrong = differences(&found(), &table).join("\n");
    assert!(wrong.contains("rows to add"), "{wrong}");
    assert!(wrong.contains("presend_exits.d/<ticket>.tsv"), "{wrong}");
}

/// A row whose value changed under the same key names the file to edit.
#[test]
fn presend_exits_changed_value_names_the_owning_file() {
    let (base, moved) = without_first_row(&live_base("presend_exits"));
    let mut cols: Vec<&str> = moved.trim_end().split('\t').collect();
    cols[2] = "999";
    let changed = format!("{}\n", cols.join("\t"));
    let (_root, table) = scratch_table("presend_exits", &base, &[("1.tsv", &changed)]);
    let wrong = differences(&found(), &table).join("\n");
    assert!(
        wrong.contains("edit this row in") && wrong.contains("1.tsv"),
        "{wrong}"
    );
}
