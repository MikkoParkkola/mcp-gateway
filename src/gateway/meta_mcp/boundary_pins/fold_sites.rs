// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a folded failure is made and counted, as reviewed rows of
//! `fold_sites.tsv`, one table per kind (the first column):
//!
//! - `is_error`: every production `"isError": true` JSON literal, per function,
//!   with its class. A `gateway-folded` literal is the gateway's own refusal
//!   folded into a tool result: its function must also call `gateway_folded`,
//!   which always counts the gateway's origin (a `folded` call could name any
//!   origin). A `dispatch-error` literal folds a dispatch failure with that
//!   failure's own origin: its function must call `folded`. The other classes
//!   (`stored-notice`, `other-route`) are read, not checked. Checked per
//!   function, as every pin here is: a call on another branch of the same
//!   function passes.
//! - `setter`: every production call of a delivery-fact fold setter, per file.
//! - `count`: every production call that counts an answer or reads its marker,
//!   per file.
//!
//! A new site, a moved call or a changed count fails and prints the row.
//! What this cannot see: a literal outside a macro body (a raw string), or a
//! call passed by path.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 2] = ["src/lib.rs", "src/main.rs"];
const SETTERS: [&str; 6] = [
    "folded",
    "gateway_folded",
    "step_carried",
    "wrapped_step",
    "step_tool_failed",
    "stamp_folded",
];
const COUNTS: [&str; 4] = [
    "count_answer",
    "count_framed",
    "RpcError::of_frame",
    "RpcError::of_value",
];
const CLASSES: [&str; 4] = [
    "gateway-folded",
    "stored-notice",
    "other-route",
    "dispatch-error",
];
/// How `"isError": true` prints inside a macro's tokens.
const IS_ERROR: &str = "\"isError\" : true";

/// The name a call is keyed by: its last path segment, or the last two for
/// a marker read (`RpcError::of_frame`).
fn call_name(path: &syn::Path) -> Option<String> {
    let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    let last = names.last()?;
    if SETTERS.contains(&last.as_str()) || COUNTS.contains(&last.as_str()) {
        return Some(last.clone());
    }
    let pair = names[names.len().saturating_sub(2)..].join("::");
    COUNTS.contains(&pair.as_str()).then_some(pair)
}

#[derive(Default)]
struct Sites {
    /// (file, function) -> `"isError": true` literals.
    is_error: BTreeMap<(String, String), usize>,
    /// (kind, call, file) -> calls; kind is `setter` or `count`.
    calls: BTreeMap<(String, String, String), usize>,
    /// (file, function) -> the setters it calls.
    setters_in: BTreeMap<(String, String), BTreeSet<String>>,
    /// Functions that read the error marker off a response
    /// (`get::<RpcError>()`).
    marker_reads: BTreeSet<(String, String)>,
    /// Functions that put a value on a response's extensions.
    marker_inserts: BTreeSet<(String, String)>,
}

impl Sites {
    fn literals(&mut self, at: &Place, mac: &syn::Macro) {
        let found = mac.tokens.to_string().matches(IS_ERROR).count();
        if found > 0 {
            let func = at.func.clone().unwrap_or_else(|| "-".to_owned());
            *self.is_error.entry((at.file.clone(), func)).or_default() += found;
        }
        // A call inside a macro body (`stream!`, `select!`) is read from its
        // tokens: `name (` after a non-identifier token that is not `fn`.
        let text = mac.tokens.to_string();
        // Token text spacing is the printer's: compare with it removed.
        let packed: String = text.split_whitespace().collect();
        if packed.contains("get::<RpcError>()") {
            self.marker_reads.insert(place(at));
        }
        if packed.contains("extensions_mut().insert(") {
            self.marker_inserts.insert(place(at));
        }
        for name in SETTERS.iter().chain(&COUNTS) {
            let spelled = format!("{} (", name.replace("::", " :: "));
            for (i, _) in text.match_indices(&spelled) {
                let before = text[..i].trim_end();
                let joined = before.ends_with(|c: char| c.is_alphanumeric() || c == '_');
                if !joined && !before.ends_with(" fn") && before != "fn" {
                    self.call(at, name);
                }
            }
        }
    }

    /// A method call that reads the marker or writes a response extension.
    fn method(&mut self, at: &Place, call: &syn::ExprMethodCall) {
        let reads = call.method == "get"
            && call.turbofish.as_ref().is_some_and(|t| {
                t.args.iter().any(|arg| {
                    matches!(arg, syn::GenericArgument::Type(syn::Type::Path(p))
                        if p.path.segments.last().is_some_and(|s| s.ident == "RpcError"))
                })
            });
        if reads {
            self.marker_reads.insert(place(at));
        }
        let inserts = call.method == "insert"
            && matches!(call.receiver.as_ref(), syn::Expr::MethodCall(r) if r.method == "extensions_mut");
        if inserts {
            self.marker_inserts.insert(place(at));
        }
    }

    fn call(&mut self, at: &Place, name: &str) {
        let kind = if SETTERS.contains(&name) {
            "setter"
        } else {
            "count"
        };
        let key = (kind.to_owned(), name.to_owned(), at.file.clone());
        *self.calls.entry(key).or_default() += 1;
        let func = at.func.clone().unwrap_or_else(|| "-".to_owned());
        let names = self.setters_in.entry((at.file.clone(), func)).or_default();
        names.insert(name.to_owned());
    }
}

impl Sink for Sites {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        match expr {
            syn::Expr::Macro(m) => self.literals(at, &m.mac),
            syn::Expr::MethodCall(call) => self.method(at, call),
            syn::Expr::Call(call) => {
                let syn::Expr::Path(p) = call.func.as_ref() else {
                    return;
                };
                let Some(name) = call_name(&p.path) else {
                    return;
                };
                self.call(at, &name);
            }
            _ => {}
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if let syn::Stmt::Macro(m) = stmt {
            self.literals(at, &m.mac);
        }
    }
}

/// The (file, function) a node sits in.
fn place(at: &Place) -> (String, String) {
    (
        at.file.clone(),
        at.func.clone().unwrap_or_else(|| "-".to_owned()),
    )
}

/// The streamed and the buffered count read one marker: every function that
/// counts an answer reads it off the response (`get::<RpcError>()`), and
/// every function that builds it (`of_frame`, `of_value`) puts it on the
/// response it returns. So a delivery path that stops using the marker, or
/// builds one it never attaches, fails here. Per function, like the rest of
/// this pin.
fn marker_path(sites: &Sites) -> Vec<String> {
    let mut wrong = Vec::new();
    for (key, names) in &sites.setters_in {
        let (file, func) = key;
        // The count functions themselves take the marker as a parameter.
        let forwards = file == "src/gateway/health_metrics/layers.rs"
            && matches!(func.as_str(), "count_answer" | "count_framed");
        let counts =
            !forwards && (names.contains("count_answer") || names.contains("count_framed"));
        if counts && !sites.marker_reads.contains(key) {
            wrong.push(format!("counts without reading the marker: {file}\t{func}"));
        }
        let builds = names.contains("RpcError::of_frame") || names.contains("RpcError::of_value");
        if builds && !sites.marker_inserts.contains(key) {
            wrong.push(format!(
                "builds the marker without attaching it: {file}\t{func}"
            ));
        }
    }
    wrong
}

fn scan(root: &Path, roots: &[&str]) -> Sites {
    let mut sites = Sites::default();
    walk(root, roots, &mut sites).expect("the walk reads every module");
    sites
}

/// The reviewed rows: `is_error` file, function, count, class; `setter` or
/// `count` call, file, count.
const LISTED: &str = include_str!("fold_sites.tsv");

/// The listed `is_error` rows: (file, function) -> (count, class).
type IsErrorRows = BTreeMap<(String, String), (usize, String)>;
/// The listed call rows: (kind, call, file) -> count.
type CallRows = BTreeMap<(String, String, String), usize>;

/// The listed rows of both tables, and the lines that are malformed.
fn listed(text: &str) -> (IsErrorRows, CallRows, Vec<String>) {
    let (mut is_error, mut calls, mut bad) = (BTreeMap::new(), BTreeMap::new(), Vec::new());
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let count = match cols[..] {
            ["is_error", _, _, count, class] => {
                if !CLASSES.contains(&class) {
                    bad.push(format!("unknown class: {line}"));
                }
                count
            }
            ["setter" | "count", _, _, count] => count,
            _ => {
                bad.push(format!("malformed row: {line}"));
                continue;
            }
        };
        let Ok(n) = count.parse::<usize>() else {
            bad.push(format!("count is not a number: {line}"));
            continue;
        };
        let owned = |i: usize| cols[i].to_owned();
        if cols[0] == "is_error" {
            is_error.insert((owned(1), owned(2)), (n, owned(4)));
        } else {
            calls.insert((owned(0), owned(1), owned(2)), n);
        }
    }
    (is_error, calls, bad)
}

/// The setter a literal of `class` must call in its own function, if any.
fn required_setter(class: &str) -> Option<&'static str> {
    match class {
        "gateway-folded" => Some("gateway_folded"),
        "dispatch-error" => Some("folded"),
        _ => None,
    }
}

/// Whether the function at `key` calls `setter`.
fn function_calls(sites: &Sites, key: &(String, String), setter: &str) -> bool {
    sites
        .setters_in
        .get(key)
        .is_some_and(|s| s.contains(setter))
}

/// What differs between the scan and the rows in `text`.
fn diff(sites: &Sites, text: &str) -> Vec<String> {
    let (is_error, calls, mut wrong) = listed(text);
    for (key, count) in &sites.is_error {
        let (file, func) = key;
        match is_error.get(key) {
            Some((n, class)) if n == count => {
                if let Some(setter) = required_setter(class)
                    && !function_calls(sites, key, setter)
                {
                    wrong.push(format!("{class}, no {setter} call: {file}\t{func}"));
                }
            }
            Some((n, _)) => wrong.push(format!("listed {n}, found {count}: {file}\t{func}")),
            None => wrong.push(format!(
                "unlisted: is_error\t{file}\t{func}\t{count}\t<class>"
            )),
        }
    }
    for (file, func) in is_error.keys().filter(|k| !sites.is_error.contains_key(*k)) {
        wrong.push(format!("stale: is_error\t{file}\t{func}"));
    }
    for (key, count) in &sites.calls {
        let (kind, call, file) = key;
        match calls.get(key) {
            Some(n) if n == count => {}
            Some(n) => wrong.push(format!("listed {n}, found {count}: {kind}\t{call}\t{file}")),
            None => wrong.push(format!("unlisted: {kind}\t{call}\t{file}\t{count}")),
        }
    }
    for (kind, call, file) in calls.keys().filter(|k| !sites.calls.contains_key(*k)) {
        wrong.push(format!("stale: {kind}\t{call}\t{file}"));
    }
    wrong
}

/// Every production fold literal, fold setter and count site is a listed row.
#[test]
fn every_fold_and_count_site_is_listed() {
    let wrong = diff(&scan(crate_root(), &ROOTS), LISTED);
    assert!(
        wrong.is_empty(),
        "fold and count sites differ from fold_sites.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The streamed count (`count_framed`) and the buffered one (`count_answer`)
/// read the same marker, built by `of_frame`/`of_value` and attached to the
/// response, so a streamed answer is counted as its buffered twin is.
#[test]
fn every_count_reads_the_marker_its_builders_attach() {
    let wrong = marker_path(&scan(crate_root(), &ROOTS));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A count that does not read the marker fails, inside a macro body too; a
/// builder that does not attach it fails; reading and attaching passes.
#[test]
fn a_count_or_builder_off_the_marker_path_fails() {
    let good = "fn layer(r: R) { let m = r.extensions().get::<RpcError>().copied(); count_answer(1, m); }
        fn emit(r: R) { let s = stream! { let m = r.extensions().get::<RpcError>().copied(); count_framed(1, m, false); }; }
        fn build(a: A) -> R { let marker = RpcError::of_frame(&a); let mut r = R::new(); r.extensions_mut().insert(marker); r }";
    assert_eq!(marker_path(&scan_fixture(good)), Vec::<String>::new());
    for (bad, line) in [
        (
            "fn layer(r: R) { count_answer(1, None); }",
            "counts without reading the marker",
        ),
        (
            "fn emit() { let s = stream! { count_framed(1, None, false); }; }",
            "counts without reading the marker",
        ),
        (
            "fn build(a: A) { let _ = RpcError::of_value(&a, o, f); }",
            "builds the marker without attaching it",
        ),
    ] {
        let wrong = marker_path(&scan_fixture(bad));
        assert!(
            wrong.iter().any(|w| w.starts_with(line)),
            "{bad}: {wrong:?}"
        );
    }
}

/// Scan `source` as a one-file crate.
fn scan_fixture(source: &str) -> Sites {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join("src")).expect("src dir");
    std::fs::write(root.path().join("src/lib.rs"), source).expect("write lib.rs");
    scan(root.path(), &["src/lib.rs"])
}

const FIXTURE: &str = "fn refuse() {
        delivery_facts::gateway_folded(-32001);
        let _ = json!({\"content\": [], \"isError\": true});
        health_metrics::count_answer(200, None);
        let _ = RpcError::of_frame(&rpc);
    }
    fn notice() -> Value { json!({\"isError\": true}) }
    #[cfg(test)] mod tests { fn t() { folded(m); json!({\"isError\": true}); } }";

const FIXTURE_ROWS: &str = "is_error\tsrc/lib.rs\trefuse\t1\tgateway-folded
is_error\tsrc/lib.rs\tnotice\t1\tstored-notice
setter\tgateway_folded\tsrc/lib.rs\t1
count\tcount_answer\tsrc/lib.rs\t1
count\tRpcError::of_frame\tsrc/lib.rs\t1
";

/// The fixture's rows match exactly; test code is not counted.
#[test]
fn the_fixture_rows_match() {
    let sites = scan_fixture(FIXTURE);
    assert_eq!(diff(&sites, FIXTURE_ROWS), Vec::<String>::new());
}

/// An added literal, setter call or count call each fails as unlisted.
#[test]
fn an_added_site_fails_in_each_table() {
    for (added, row) in [
        (
            "fn more() { json!({\"isError\": true}); }",
            "unlisted: is_error",
        ),
        (
            "fn more() { step_carried(None); }",
            "unlisted: setter\tstep_carried",
        ),
        (
            "fn more() { let s = stream! { delivery_facts::wrapped_step(); }; }",
            "unlisted: setter\twrapped_step",
        ),
        (
            "fn more() { count_framed(1, None, false); }",
            "unlisted: count\tcount_framed",
        ),
        (
            "fn more() { RpcError::of_value(&v, o, f); }",
            "unlisted: count\tRpcError::of_value",
        ),
    ] {
        let wrong = diff(&scan_fixture(&format!("{FIXTURE}\n{added}")), FIXTURE_ROWS);
        assert!(
            wrong.iter().any(|w| w.starts_with(row)),
            "{added}: {wrong:?}"
        );
    }
}

/// A `gateway-folded` literal whose function does not fold fails.
#[test]
fn a_gateway_folded_literal_must_fold() {
    let rows = FIXTURE_ROWS.replace("notice\t1\tstored-notice", "notice\t1\tgateway-folded");
    let wrong = diff(&scan_fixture(FIXTURE), &rows);
    assert!(
        wrong
            .iter()
            .any(|w| w.starts_with("gateway-folded, no gateway_folded call")),
        "{wrong:?}"
    );
}

/// A `gateway-folded` literal whose function folds through `folded` (any
/// origin, a backend's included) fails; so does a `dispatch-error` literal
/// whose function folds nothing.
#[test]
fn a_fold_must_use_the_setter_its_class_names() {
    let source = "fn refuse() {
        delivery_facts::folded(RpcError { code: 1, origin: Origin::Backend });
        let _ = json!({\"isError\": true});
    }
    fn dispatch() { let _ = json!({\"isError\": true}); }";
    let rows = "is_error\tsrc/lib.rs\trefuse\t1\tgateway-folded
is_error\tsrc/lib.rs\tdispatch\t1\tdispatch-error
setter\tfolded\tsrc/lib.rs\t1
";
    let wrong = diff(&scan_fixture(source), rows);
    assert!(
        wrong
            .iter()
            .any(|w| w.starts_with("gateway-folded, no gateway_folded call")),
        "{wrong:?}"
    );
    assert!(
        wrong
            .iter()
            .any(|w| w.starts_with("dispatch-error, no folded call")),
        "{wrong:?}"
    );
}
