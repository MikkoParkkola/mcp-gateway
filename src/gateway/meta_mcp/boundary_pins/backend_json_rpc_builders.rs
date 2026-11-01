// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production builder of a JSON-RPC error is a reviewed row of
//! `backend_json_rpc_builders.tsv` with a one-line reason: a `JsonRpc {..}`
//! literal or a `json_rpc(..)` call is the gateway's own error (class
//! `gateway`), a `backend_json_rpc(..)` call is a backend's, either taken
//! off the wire (`origin`) or rebuilt from a frame or error that already
//! carried a backend's origin (`rebuild`). A
//! `BackendJsonRpc {..}` literal outside `src/error.rs` fails outright: the
//! constructor is the only way to mark an error as the backend's.
//!
//! What this cannot see: a builder inside a macro body, or a call passed by
//! path. Rows are keyed by function name within a file, as the other pins.

use std::collections::BTreeMap;
use std::path::Path;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 2] = ["src/lib.rs", "src/main.rs"];
/// The one file allowed to write a `BackendJsonRpc {..}` literal.
const CONSTRUCTOR_FILE: &str = "src/error.rs";
/// Where a backend's error is taken off the wire.
const ORIGIN_FILES: [&str; 3] = [
    "src/transport/http/mod.rs",
    "src/gateway/meta_mcp/invoke/dispatch.rs",
    "src/backend/list_drain.rs",
];
/// Where a backend's error is rebuilt, keeping its origin.
const REBUILD_FILES: [&str; 2] = [
    "src/gateway/meta_mcp/search/chain_exec.rs",
    "src/gateway/meta_mcp/invoke/dispatch_guards.rs",
];

/// The class a builder of `kind` in `file` must carry, if it may exist there.
fn class_of(file: &str, kind: &str) -> Option<&'static str> {
    match kind {
        "literal" | "json_rpc" => Some("gateway"),
        "backend_json_rpc" if ORIGIN_FILES.contains(&file) => Some("origin"),
        "backend_json_rpc" if REBUILD_FILES.contains(&file) => Some("rebuild"),
        _ => None,
    }
}

fn last_segment(path: &syn::Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

/// (file, function, kind) -> count.
type Found = BTreeMap<(String, String, String), usize>;

#[derive(Default)]
struct Builders {
    found: Found,
    strays: Vec<String>,
}

impl Sink for Builders {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let kind = match expr {
            syn::Expr::Struct(lit) => match last_segment(&lit.path).as_deref() {
                Some("JsonRpc") => "literal",
                Some("BackendJsonRpc") if at.file != CONSTRUCTOR_FILE => {
                    let func = at.func.as_deref().unwrap_or("-");
                    self.strays.push(format!("{}\t{func}", at.file));
                    return;
                }
                _ => return,
            },
            syn::Expr::Call(call) => match call.func.as_ref() {
                syn::Expr::Path(p) => match last_segment(&p.path).as_deref() {
                    Some("json_rpc") => "json_rpc",
                    Some("backend_json_rpc") => "backend_json_rpc",
                    _ => return,
                },
                _ => return,
            },
            _ => return,
        };
        let func = at.func.clone().unwrap_or_else(|| "-".to_owned());
        *self
            .found
            .entry((at.file.clone(), func, kind.to_owned()))
            .or_default() += 1;
    }
}

fn scan(root: &Path, roots: &[&str]) -> Builders {
    let mut builders = Builders::default();
    walk(root, roots, &mut builders).expect("the walk reads every module");
    builders
}

/// The reviewed list: file, function, kind, count, class.
const LISTED: &str = include_str!("backend_json_rpc_builders.tsv");

/// What differs between `found` and the rows in `listed`, each line the row
/// to add or fix; empty when they agree.
fn diff(found: &Found, listed: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    let mut want = BTreeMap::new();
    for line in listed
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, kind, count, class, reason] = cols[..] else {
            wrong.push(format!("not six columns: {line}"));
            continue;
        };
        if reason.trim().is_empty() {
            wrong.push(format!("no reason: {line}"));
        }
        let Ok(count) = count.parse::<usize>() else {
            wrong.push(format!("count is not a number: {line}"));
            continue;
        };
        if class_of(file, kind) != Some(class) {
            wrong.push(format!("class must be {:?}: {line}", class_of(file, kind)));
        }
        want.insert((file.to_owned(), func.to_owned(), kind.to_owned()), count);
    }
    for (key, count) in found {
        let (file, func, kind) = key;
        let class = class_of(file, kind).unwrap_or("<unclassed: not an origin or rebuild file>");
        match want.get(key) {
            Some(listed) if listed == count => {}
            Some(listed) => wrong.push(format!(
                "listed {listed}, found {count}: {file}\t{func}\t{kind}\t{count}\t{class}\t<reason>"
            )),
            None => wrong.push(format!(
                "unlisted: {file}\t{func}\t{kind}\t{count}\t{class}\t<reason>"
            )),
        }
    }
    for (file, func, kind) in want.keys().filter(|k| !found.contains_key(*k)) {
        wrong.push(format!("stale: {file}\t{func}\t{kind}"));
    }
    wrong
}

/// Every production JSON-RPC error builder is a listed row of the right class,
/// and no `BackendJsonRpc` literal exists outside its constructor.
#[test]
fn every_json_rpc_error_builder_is_listed() {
    let builders = scan(crate_root(), &ROOTS);
    let mut wrong = diff(&builders.found, LISTED);
    for stray in &builders.strays {
        wrong.push(format!(
            "BackendJsonRpc literal outside {CONSTRUCTOR_FILE}: {stray}"
        ));
    }
    assert!(
        wrong.is_empty(),
        "JSON-RPC error builders differ from backend_json_rpc_builders.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Scan `source` as a one-file crate.
fn scan_fixture(source: &str) -> Builders {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(root.path().join("src")).expect("src dir");
    std::fs::write(root.path().join("src/lib.rs"), source).expect("write lib.rs");
    scan(root.path(), &["src/lib.rs"])
}

/// An unlisted call fails, a listed one passes, and test code is not counted.
#[test]
fn an_unlisted_builder_fails() {
    let source = "fn probe() { let _ = Error::json_rpc(1, \"x\"); }
        #[cfg(test)] mod tests { fn t() { let _ = Error::json_rpc(1, \"x\"); } }";
    let found = scan_fixture(source).found;
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(diff(&found, "src/lib.rs\tprobe\tjson_rpc\t1\tgateway\tr\n").is_empty());
    let unreasoned = diff(&found, "src/lib.rs\tprobe\tjson_rpc\t1\tgateway\t \n");
    assert!(
        unreasoned.iter().any(|w| w.starts_with("no reason:")),
        "{unreasoned:?}"
    );
    let wrong = diff(&found, "");
    assert!(
        wrong.iter().any(|w| w.starts_with("unlisted:")),
        "{wrong:?}"
    );
    let origin = diff(&found, "src/lib.rs\tprobe\tjson_rpc\t1\torigin\tr\n");
    assert!(
        origin.iter().any(|w| w.starts_with("class must be")),
        "{origin:?}"
    );
    let backend = scan_fixture("fn f(e: E) { Error::backend_json_rpc(e); }").found;
    let unclassed = diff(&backend, "");
    assert!(
        unclassed.iter().any(|w| w.contains("<unclassed")),
        "{unclassed:?}"
    );
}

/// A `BackendJsonRpc` literal outside the constructor fails in each path form.
#[test]
fn a_stray_backend_literal_fails() {
    for path in [
        "BackendJsonRpc",
        "Error::BackendJsonRpc",
        "crate::Error::BackendJsonRpc",
        "Self::BackendJsonRpc",
    ] {
        let source = format!("fn f() {{ let _ = {path} {{ code: 1, message: m, data: None }}; }}");
        let strays = scan_fixture(&source).strays;
        assert_eq!(strays, ["src/lib.rs\tf"], "{path}");
    }
}
