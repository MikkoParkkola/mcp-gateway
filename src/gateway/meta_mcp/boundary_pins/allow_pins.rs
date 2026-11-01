// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B T1b, T2a and T1f (test plan v2 §3): every production allow
//! of the registry ban, with what it covers, and the ban's own config.

use std::path::Path;

use syn::visit::Visit;

use super::ci_wiring::{assert_ci_registry_ban_conf_dir, checked_in_workflow};
use super::fragments::{
    Table, live_base, multiset_delta, pin_table, scratch_table, without_first_row,
};
use super::packaged::{PinnedFile, repo_file};
use super::scan::{Place, Sink, expr_attrs, item_attrs, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The banned names: the dedicated config's 18 methods and 2 APIs.
const BANNED: [&str; 20] = [
    "subscribe_started",
    "reload_read_slot",
    "lock_reload",
    "register",
    "observe_breakers",
    "enforce_destinations",
    "set_change_feed",
    "catalogue_hook",
    "nudge_catalogue",
    "nudge_catalogue_scanned",
    "nudge_surfaced",
    "resolve_unwarmed",
    "with_membership",
    "get",
    "all",
    "statuses",
    "remove",
    "stop_all",
    "resolve_propagation_credential",
    "resolve_propagation_headers",
];

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The reason's class word of an allow naming `clippy::disallowed_methods`
/// (a plain allow, an expect, or one under `cfg_attr`), if it is one.
fn ban_allow(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        let text = attr.meta.to_token_stream_string();
        if text.contains("disallowed_methods")
            && (text.contains("allow") || text.contains("expect"))
        {
            let class = text
                .split("reason")
                .nth(1)
                .and_then(|r| r.split('"').nth(1))
                .and_then(|r| r.split(':').next())
                .unwrap_or("-")
                .to_string();
            return Some(class);
        }
    }
    None
}

trait TokenText {
    fn to_token_stream_string(&self) -> String;
}

impl TokenText for syn::Meta {
    fn to_token_stream_string(&self) -> String {
        match self {
            syn::Meta::Path(p) => path_text(p),
            syn::Meta::List(l) => format!("{}({})", path_text(&l.path), l.tokens),
            syn::Meta::NameValue(nv) => path_text(&nv.path),
        }
    }
}

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// The banned names a node references, as calls or as paths, with counts:
/// a second raw call inside one allow changes its row.
#[derive(Default)]
struct Names(std::collections::BTreeMap<String, usize>);

impl<'ast> Visit<'ast> for Names {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        // `get` with no argument is a `OnceLock` read; the registry's takes a name.
        if BANNED.contains(&name.as_str()) && !(name == "get" && call.args.is_empty()) {
            *self.0.entry(name).or_default() += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        // A path names a banned method only on its own type: `Cell::get` is not
        // `BackendRegistry::get`.
        let segs: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        if let [.., owner, name] = segs.as_slice()
            && BANNED.contains(&name.as_str())
            && ["BackendRegistry", "MetaMcp", "Self"].contains(&owner.as_str())
        {
            *self.0.entry(name.clone()).or_default() += 1;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

/// One row per production allow: file, fn, node kind, class, names inside.
/// A list, not a set: two like allows in one fn are two rows.
#[derive(Default)]
struct Allows(Vec<String>);

impl Allows {
    fn row(&mut self, at: &Place, kind: &str, class: &str, names: Names) {
        let names: Vec<String> = names
            .0
            .into_iter()
            .map(|(n, c)| format!("{n}x{c}"))
            .collect();
        self.0.push(format!(
            "{}\t{}\t{kind}\t{class}\t{}",
            at.file,
            at.func.as_deref().unwrap_or("-"),
            names.join(",")
        ));
    }
}

impl Sink for Allows {
    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(local) => &local.attrs,
            syn::Stmt::Macro(mac) => &mac.attrs,
            syn::Stmt::Expr(expr, _) => expr_attrs(expr),
            syn::Stmt::Item(_) => &[],
        };
        if let Some(class) = ban_allow(attrs) {
            let mut names = Names::default();
            names.visit_stmt(stmt);
            self.row(at, "statement", &class, names);
        }
    }

    fn item(&mut self, at: &Place, item: &syn::Item) {
        if let Some(class) = ban_allow(item_attrs(item)) {
            let mut names = Names::default();
            names.visit_item(item);
            self.row(at, "item", &class, names);
        }
    }

    fn file(&mut self, at: &Place, file: &syn::File) {
        if let Some(class) = ban_allow(&file.attrs) {
            let mut names = Names::default();
            names.visit_file(file);
            self.row(at, "module", &class, names);
        }
    }
}

fn inventory() -> Vec<String> {
    let mut allows = Allows::default();
    walk(crate_root(), &ROOTS, &mut allows).expect("the walk reads every module");
    let mut rows = allows.0;
    rows.sort();
    rows
}

/// T1b: every production allow of the registry ban, as (file, fn, node
/// kind, reason class, banned names inside), equals `allows.tsv`. A new
/// allow, an allow moved to a fn, or a second raw call inside one is a
/// reviewed diff. Pre-existing clock and home allows are rows too, with no
/// banned name inside. Mutants: M19d (a second raw call in an allowed
/// statement), T1b-m1 (an allow moved to its fn), T1b-m2 (a registry read
/// added inside the clock module's allow).
#[test]
fn t1b_every_production_allow_of_the_ban_is_pinned() {
    let actual = inventory();
    allows_check(&actual, &pin_table("allows")).unwrap_or_else(|m| panic!("{m}"));
    let classes = [
        "Visibility",
        "Discovery",
        "Background",
        "Admin",
        "Lifecycle",
    ];
    for row in &actual {
        let fields: Vec<&str> = row.split('\t').collect();
        if !fields[4].is_empty() {
            assert!(
                classes.contains(&fields[3]),
                "an allow covering a banned name has no Unscoped class: {row}"
            );
            assert_eq!(
                fields[2], "statement",
                "an allow covering a banned name is not on a statement: {row}"
            );
        }
    }
}

/// T2a: no production allow of the ban under the router: its reads go
/// through `backend_for` or `Registry` with a literal class. Mutant T2a-m1:
/// an allowed raw read in `accounts.rs`.
#[test]
fn t2a_the_router_holds_no_allow_of_the_ban() {
    let router: Vec<String> = inventory()
        .into_iter()
        .filter(|row| row.starts_with("src/gateway/router/"))
        .collect();
    assert!(router.is_empty(), "router allow: {router:?}");
}

/// T1f: the dedicated config's MIK-8387 span, byte for byte; nothing but
/// comments outside it; and the pre-push step names its directory. Mutants:
/// M19g (an entry deleted), T1f-m2 (an entry below the end marker), T1f-m3
/// (pre-push's path changed).
#[test]
fn t1f_the_ban_config_and_its_wiring_are_pinned() {
    // The config and pre-push are repo tooling, not shipped in the published
    // crate: the whole check is checkout-only (the span below is read from the
    // config, so it cannot run without it).
    let Some(config) = repo_file(PinnedFile::RegistryBanClippy) else {
        return;
    };
    let (before, rest) = config
        .split_once("# MIK-8387 begin\n")
        .expect("begin marker");
    let (span, after) = rest.split_once("# MIK-8387 end\n").expect("end marker");
    for line in before.lines().chain(after.lines()) {
        assert!(
            line.trim().is_empty() || line.trim_start().starts_with('#'),
            "content outside the span: {line}"
        );
    }
    assert_eq!(span, include_str!("registry_ban_span.toml"), "span differs");
    let Some(pre_push) = repo_file(PinnedFile::PrePush) else {
        return;
    };
    assert!(
        pre_push.contains("export CLIPPY_CONF_DIR=\"$REPO_ROOT/scripts/lint/registry-ban\""),
        "pre-push does not name scripts/lint/registry-ban"
    );
    // MIK-8481: the Linux CI step, the required check, names it too. This is
    // the one assertion against the checked-in file, so a failure names it.
    let Some(ci) = checked_in_workflow() else {
        return;
    };
    let outcome = std::panic::catch_unwind(move || assert_ci_registry_ban_conf_dir(&ci));
    if let Err(payload) = outcome {
        let detail = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        panic!(".github/workflows/ci.yml: {detail}");
    }
}

/// The class-taking operations and the scoped read.
const OPS: [&str; 7] = [
    "scoped_get",
    "get_for",
    "all_for",
    "membership_for",
    "statuses_for",
    "subscribe_started_for",
    "nudge_catalogue_for",
];

/// T1a's and T1d's rows: (file, fn, op, class) for every operation call, and
/// every `Registry::new` call site.
#[derive(Default)]
struct Ops {
    rows: Vec<String>,
    bad: Vec<String>,
    news: Vec<String>,
}

impl Sink for Ops {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let func = at.func.as_deref().unwrap_or("-");
        match expr {
            syn::Expr::MethodCall(call) if OPS.contains(&call.method.to_string().as_str()) => {
                let op = call.method.to_string();
                let class = if op == "scoped_get" {
                    "scoped".to_string()
                } else {
                    match call.args.first() {
                        Some(syn::Expr::Path(p)) if p.path.segments.len() >= 2 => p
                            .path
                            .segments
                            .last()
                            .map(|s| s.ident.to_string())
                            .unwrap_or_default(),
                        _ => {
                            self.bad.push(format!(
                                "{}::{func}: {op} with a non-literal class",
                                at.file
                            ));
                            return;
                        }
                    }
                };
                self.rows
                    .push(format!("{}\t{func}\t{op}\t{class}", at.file));
            }
            syn::Expr::Path(p) => {
                let segs: Vec<String> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                if let Some(last) = segs.last() {
                    if OPS.contains(&last.as_str()) && segs.len() > 1 {
                        self.bad.push(format!(
                            "{}::{func}: {} referenced outside a call",
                            at.file,
                            segs.join("::")
                        ));
                    }
                    // `Registry` is gateway-private: a `Registry::new` outside
                    // the gateway is another type of that name.
                    if last == "new"
                        && segs.len() >= 2
                        && segs[segs.len() - 2] == "Registry"
                        && at.file.starts_with("src/gateway/")
                    {
                        self.news.push(format!("{}\t{func}", at.file));
                    }
                }
            }
            _ => {}
        }
    }
}

fn ops() -> Ops {
    let mut ops = Ops::default();
    walk(crate_root(), &ROOTS, &mut ops).expect("the walk reads every module");
    ops.rows.sort();
    ops.news.sort();
    ops
}

fn pinned(text: &str) -> Vec<String> {
    let mut rows: Vec<String> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    rows.sort();
    rows
}

/// T1a: every class-taking operation call in production, by (file, fn, op,
/// class), equals `scoped_backends_classes.tsv`; the receiver follows from
/// the op's name. A class must be a literal `Unscoped::X`, and an op named
/// outside a call position fails. Mutants: M19b (one class swapped), M19b2
/// (a new classed read).
#[test]
fn t1a_every_classed_read_is_pinned() {
    let found = ops();
    assert!(
        found.bad.is_empty(),
        "unclassifiable operation use: {:?}",
        found.bad
    );
    classes_check(&found.rows, &pin_table("scoped_backends_classes"))
        .unwrap_or_else(|m| panic!("{m}"));
}

/// The allow table check: `actual` against the pinned rows of `table`.
fn allows_check(actual: &[String], table: &Table) -> Result<(), String> {
    let pinned: Vec<(&Path, &str)> = table
        .rows()
        .iter()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(file, l)| (file.as_path(), l.as_str()))
        .collect();
    multiset_delta("allows", actual, &pinned).map_or(Ok(()), Err)
}

/// The class table check: the found rows against the pinned rows of `table`.
fn classes_check(found: &[String], table: &Table) -> Result<(), String> {
    let pinned: Vec<(&Path, &str)> = table
        .rows()
        .iter()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(file, l)| (file.as_path(), l.as_str()))
        .collect();
    multiset_delta("scoped_backends_classes", found, &pinned).map_or(Ok(()), Err)
}

/// T1d: the `Registry::new` call sites. Mutant T1d-m1: a second one.
#[test]
fn t1d_registry_construction_sites_are_pinned() {
    let found = ops();
    assert_eq!(
        found.news,
        pinned(
            "src/gateway/meta_mcp/construction.rs\tbuild\nsrc/gateway/meta_mcp/upstream.rs\tnew"
        ),
        "unpinned Registry::new"
    );
}

/// FRAG.2 through the allow check's own path: a real row held only by a
/// fragment still counts.
#[test]
fn allows_reads_a_required_row_from_a_fragment() {
    let (base, moved) = without_first_row(&live_base("allows"));
    let (_root, table) = scratch_table("allows", &base, &[("1.tsv", &moved)]);
    allows_check(&inventory(), &table).unwrap_or_else(|m| panic!("{m}"));
}

/// FRAG.2: a stale row in a fragment fails the allow check, naming the
/// fragment that holds it.
#[test]
fn allows_rejects_a_stale_fragment_row() {
    let stale = "src/nowhere.rs\tnothing\tstatement\tLifecycle\tgetx1\n";
    let (_root, table) = scratch_table("allows", &live_base("allows"), &[("1.tsv", stale)]);
    let err = allows_check(&inventory(), &table).expect_err("a stale fragment row fails");
    assert!(err.contains("1.tsv"), "{err}");
}

/// FRAG.2 through the class check's own path: a real row held only by a
/// fragment still counts.
#[test]
fn scoped_classes_reads_a_required_row_from_a_fragment() {
    let (base, moved) = without_first_row(&live_base("scoped_backends_classes"));
    let (_root, table) = scratch_table("scoped_backends_classes", &base, &[("1.tsv", &moved)]);
    classes_check(&ops().rows, &table).unwrap_or_else(|m| panic!("{m}"));
}

/// FRAG.2: a stale row in a fragment fails the class check, naming the
/// fragment that holds it.
#[test]
fn scoped_classes_rejects_a_stale_fragment_row() {
    let stale = "src/nowhere.rs\tnothing\tget\tVisibility\n";
    let (_root, table) = scratch_table(
        "scoped_backends_classes",
        &live_base("scoped_backends_classes"),
        &[("1.tsv", stale)],
    );
    let err = classes_check(&ops().rows, &table).expect_err("a stale fragment row fails");
    assert!(err.contains("1.tsv"), "{err}");
}

/// A legitimately repeated allow row (two identical statements in one fn)
/// may have its copies in different files: the counts add up.
#[test]
fn a_legitimate_repeat_may_split_across_files() {
    let base = live_base("allows");
    let mut seen = std::collections::BTreeSet::new();
    let repeated = base
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .find(|l| !seen.insert(*l))
        .expect("allows.tsv holds a repeated row")
        .to_owned();
    let at = base
        .rfind(&format!("{repeated}\n"))
        .expect("the second copy");
    let rest = format!("{}{}", &base[..at], &base[at + repeated.len() + 1..]);
    let (_root, table) = scratch_table("allows", &rest, &[("1.tsv", &format!("{repeated}\n"))]);
    allows_check(&inventory(), &table).unwrap_or_else(|m| panic!("{m}"));
}

/// A row the table lacks is listed to add, in the reader's own fragment.
#[test]
fn a_missing_allow_row_is_listed_to_add_in_your_fragment() {
    let (base, _) = without_first_row(&live_base("allows"));
    let (_root, table) = scratch_table("allows", &base, &[]);
    let err = allows_check(&inventory(), &table).expect_err("a missing row fails");
    assert!(err.contains("rows to add"), "{err}");
    assert!(err.contains("allows.d/<ticket>.tsv"), "{err}");
}
