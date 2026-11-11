// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every place production code writes gateway.yaml, or puts a backend into a
//! config, is listed in `secret_writers.tsv` with what it does with a
//! secret-shaped backend value, keyed by (file, function, kind) with the
//! number of such calls. A new write path is a new call of one of the named
//! writers, so it fails until someone says how it treats a credential.
//!
//! Kinds: `persist:<writer>`, a call of a config writer (the locked editors,
//! the audited replace, the reload mutation, the CLI's `config_write::write`
//! wrapper); `backends.<method>`, an `insert`/`entry`/`extend` on a field or
//! binding named `backends`; `env.<method>`, `headers.<method>`, `env=`,
//! `headers=`, a backend value map changed in place or replaced (any struct's
//! `env`/`headers` field: a runtime one is classed `not-written`).
//!
//! Classes: `layer` (a writer other rows call; what reaches it is classed
//! at its callers), `stores` (a literal the shared rule stores goes to the secret
//! store first, `crate::config::secret_values`), `refuses` (a literal is
//! refused), `no-backend-values` (writes no backend env or header value it
//! was given), `not-written` (a runtime map, never saved to a file),
//! `copies-literal` (a known gap; the reason names its follow-up).
//!
//! An inventory, not a proof: a syntax scan per function body. A new caller
//! of a listed function that itself calls a writer (`add_backend` inside an
//! existing write) adds no row; the classes of the listed writers are what
//! review checks.

use std::collections::BTreeMap;

use syn::visit::Visit;

use super::fragments::{Table, live_base, pin_table, scratch_table, shown, without_first_row};
use super::packaged::crate_root;
use super::scan::{Place, Sink, expr_attrs, item_attrs, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The config writers, from the public editors down to the atomic write, and
/// the web UI's one write wrapper: a call of one is a `persist:<name>` site.
/// Found by the scan and cross-checked by a text search of the tree (the
/// review packet lists both).
const WRITERS: [&str; 14] = [
    "edit_config",
    "write_config_and_reload",
    "write_config_and_reload_outcome",
    "mutate_config_and_reload_with",
    "edit_config_text",
    "write_config",
    "write_config_text",
    "write_config_with",
    "write_spliced",
    "write_yaml_at",
    "replace_audited",
    "replace_detached",
    "write_audited",
    "mutate_config_and_reload",
];

/// The gateway's config-mutation methods (`ReloadContext`): a method call of
/// one is a `persist:<name>` site.
const WRITER_METHODS: [&str; 5] = [
    "write_and_reload_outcome",
    "write_and_reload_outcome_within",
    "mutate_and_reload_outcome",
    "mutate_and_reload_outcome_within",
    "mutate_locked",
];

/// (file, function, kind) -> calls.
type Counts = BTreeMap<(String, String, String), usize>;

/// The writing calls one function body makes.
#[derive(Default)]
struct Body {
    kinds: BTreeMap<String, usize>,
}

fn stmt_is_test_only(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Local(local) => test_only(&local.attrs),
        syn::Stmt::Item(item) => test_only(item_attrs(item)),
        syn::Stmt::Expr(expr, _) => test_only(expr_attrs(expr)),
        syn::Stmt::Macro(mac) => test_only(&mac.attrs),
    }
}

impl Body {
    fn count(&mut self, kind: String) {
        *self.kinds.entry(kind).or_default() += 1;
    }
}

impl<'ast> Visit<'ast> for Body {
    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        if !stmt_is_test_only(stmt) {
            syn::visit::visit_stmt(self, stmt);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = call.func.as_ref() {
            let segs: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            match segs.as_slice() {
                [.., last] if WRITERS.contains(&last.as_str()) => {
                    self.count(format!("persist:{last}"));
                }
                [.., module, last] if module == "config_write" && last == "write" => {
                    self.count("persist:config_write".to_owned());
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if WRITER_METHODS.contains(&method.as_str()) {
            self.count(format!("persist:{method}"));
        }
        // A field named `backends` (`config.backends`), or a binding of that
        // name (a map built up and then put into a config).
        let on_backends = match call.receiver.as_ref() {
            syn::Expr::Field(field) => {
                matches!(&field.member, syn::Member::Named(name) if name == "backends")
            }
            syn::Expr::Path(path) => path.path.is_ident("backends"),
            _ => false,
        };
        if ["insert", "entry", "extend"].contains(&method.as_str()) && on_backends {
            self.count(format!("backends.{method}"));
        }
        // A backend value map changed in place: `<x>.env.insert(..)`.
        if ["insert", "entry", "extend"].contains(&method.as_str())
            && let Some(map) = value_map(call.receiver.as_ref())
        {
            self.count(format!("{map}.{method}"));
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        // A backend value map replaced whole: `<x>.env = ..`.
        if let Some(map) = value_map(assign.left.as_ref()) {
            self.count(format!("{map}="));
        }
        syn::visit::visit_expr_assign(self, assign);
    }
}

/// `env` or `headers` when `expr` is a field of that name (`<x>.env`).
fn value_map(expr: &syn::Expr) -> Option<&'static str> {
    let syn::Expr::Field(field) = expr else {
        return None;
    };
    match &field.member {
        syn::Member::Named(name) if name == "env" => Some("env"),
        syn::Member::Named(name) if name == "headers" => Some("headers"),
        _ => None,
    }
}

#[derive(Default)]
struct Sites {
    counts: Counts,
}

impl Sites {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        let mut body = Body::default();
        body.visit_block(block);
        for (kind, n) in body.kinds {
            *self
                .counts
                .entry((file.to_owned(), func.to_owned(), kind))
                .or_default() += n;
        }
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
            syn::Item::Trait(block) => {
                for member in &block.items {
                    if let syn::TraitItem::Fn(method) = member
                        && let Some(default) = &method.default
                        && !test_only(&method.attrs)
                    {
                        self.function(&at.file, &method.sig.ident.to_string(), default);
                    }
                }
            }
            _ => {}
        }
    }
}

const CLASSES: [&str; 6] = [
    "layer",
    "stores",
    "refuses",
    "no-backend-values",
    "not-written",
    "copies-literal",
];

/// (file, function, kind) -> (count, the table file listing it).
type Listed = BTreeMap<(String, String, String), (usize, String)>;

/// The listed counts from the reviewed table (file, function, kind, count,
/// class, reason), and the rows that are malformed or carry no class.
fn listed(table: &Table) -> (Listed, Vec<String>) {
    let mut counts = Listed::new();
    let mut bad = Vec::new();
    for (path, line) in table.rows() {
        let at = shown(path);
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, kind, n, class, reason] = cols[..] else {
            bad.push(format!("not six columns in {at}: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            bad.push(format!("no class or no reason in {at}: {line}"));
        }
        let Ok(n) = n.parse::<usize>() else {
            bad.push(format!("count is not a number in {at}: {line}"));
            continue;
        };
        let key = (file.to_owned(), func.to_owned(), kind.to_owned());
        if let Some((_, earlier)) = counts.insert(key, (n, at.clone())) {
            bad.push(format!(
                "repeated key in {earlier} and {at}: {file}\t{func}\t{kind}"
            ));
        }
    }
    (counts, bad)
}

/// What differs between the counted sites and the reviewed table.
fn differences(found: &Counts, table: &Table) -> Vec<String> {
    let (want, bad) = listed(table);
    let mut wrong: Vec<String> = bad;
    let mut add = Vec::new();
    for (key, n) in found {
        match want.get(key) {
            Some((m, _)) if m == n => {}
            Some((m, at)) => wrong.push(format!(
                "count {m} -> {n}, edit this row in {at}: {}\t{}\t{}",
                key.0, key.1, key.2
            )),
            None => add.push(format!(
                "{}\t{}\t{}\t{n}\t<class>\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for (key, (_, at)) in want.iter().filter(|(k, _)| !found.contains_key(*k)) {
        wrong.push(format!(
            "stale, remove from {at}: {}\t{}\t{}",
            key.0, key.1, key.2
        ));
    }
    if !add.is_empty() {
        wrong.push(format!(
            "rows to add ({}; say how each treats a credential, in your fragment secret_writers.d/<ticket>.tsv):",
            add.len()
        ));
        wrong.extend(add);
    }
    wrong
}

/// Every write path the walk counts, by (file, function, kind).
fn counted() -> Counts {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    sites.counts
}

/// W1 (CLIADD.7): every config write and backend insert in production code
/// is a reviewed row with a class and its exact count.
#[test]
fn w1_every_config_writer_is_classified() {
    let wrong = differences(&counted(), &pin_table("secret_writers"));
    assert!(
        wrong.is_empty(),
        "config writers differ from secret_writers.tsv ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// W1 is not vacuous: the walk finds the writers this family fixed.
#[test]
fn w1_the_walk_finds_the_known_writers() {
    let found = counted();
    for (file, func, kind) in [
        (
            "src/commands/add_remove.rs",
            "run_add_command",
            "persist:config_write",
        ),
        (
            "src/commands/setup.rs",
            "import_servers",
            "persist:config_write",
        ),
        ("src/cli_support.rs", "adopt_with", "backends.insert"),
    ] {
        let key = (file.to_owned(), func.to_owned(), kind.to_owned());
        assert!(found.contains_key(&key), "{key:?} not found");
    }
}

/// ADMINTOK.1/.5 / design 5, A6: the existing writer inventory binds init
/// to its executable custody row and requires stored, rather than literal, custody.
#[test]
fn w1_init_is_stored_and_bound_to_its_executable_custody_row() {
    let case = "admintok_1_init_writes_only_a_reference_and_one_store_entry";
    let source = std::fs::read_to_string(crate_root().join("tests/init_admin_token.rs"))
        .expect("init behavioral row");
    let parsed = syn::parse_file(&source).expect("row parses");
    assert!(
        parsed
            .items
            .iter()
            .any(|item| matches!(item, syn::Item::Fn(f)
        if f.sig.ident == case && f.attrs.iter().any(|a| a.path().get_ident().is_some_and(|name| name == "test"))))
    );
    let key = (
        "src/cli_support/init.rs".to_owned(),
        "write_init_files".to_owned(),
        "persist:edit_config_text".to_owned(),
    );
    assert_eq!(
        counted().get(&key),
        Some(&1),
        "existing walker must find init"
    );
    let table = pin_table("secret_writers");
    let (_, line) = table
        .rows()
        .iter()
        .find(|(_, line)| {
            line.starts_with(
                "src/cli_support/init.rs\twrite_init_files\tpersist:edit_config_text\t",
            )
        })
        .expect("one reviewed init row");
    assert!(line.contains(&format!("tests/init_admin_token.rs::{case}")));
    assert_eq!(
        line.split('\t').nth(4),
        Some("stores"),
        "init must store its bearer"
    );
}

/// W1r: a new writer fails, whatever its layout: a call split over lines, a
/// helper that writes, a backends map reached through a binding, and a
/// local map named `backends`.
#[test]
fn w1r_a_new_writer_is_listed_to_add() {
    let body: syn::Block = syn::parse_quote!({
        crate::config_persistence::edit_config(path, mode, |config| {
            let target = &mut *config;
            target.backends.insert(name, backend);
            Ok(())
        })?;
        super::config_write::write(path, mode, |c| add_backend(c, n, r))?;
        let mut backends = BTreeMap::new();
        backends.insert(name, backend);
        backend.env.insert(key, value);
        backend.headers = headers;
        crate::config_reload::write_config_and_reload(path, config).await?;
    });
    let mut sites = Sites::default();
    sites.function("src/new.rs", "plant", &body);
    let wrong = differences(&sites.counts, &pin_table("secret_writers")).join("\n");
    for (kind, n) in [
        ("persist:edit_config", 1),
        ("persist:config_write", 1),
        ("backends.insert", 2),
        ("env.insert", 1),
        ("headers=", 1),
        ("persist:write_config_and_reload", 1),
    ] {
        assert!(
            wrong.contains(&format!("src/new.rs\tplant\t{kind}\t{n}\t<class>")),
            "{kind}: {wrong}"
        );
    }
}

/// W1s: a row nothing matches fails as stale, naming its file.
#[test]
fn w1s_a_stale_row_fails_naming_its_file() {
    let stale = "src/nowhere.rs\tf\tpersist:edit_config\t1\tstores\tnone\n";
    let (_root, table) = scratch_table(
        "secret_writers",
        &live_base("secret_writers"),
        &[("0.tsv", stale)],
    );
    let wrong = differences(&counted(), &table);
    assert!(
        wrong
            .iter()
            .any(|l| l.contains("stale") && l.contains("0.tsv")),
        "{}",
        wrong.join("\n")
    );
}

/// A row held only by a fragment still counts.
#[test]
fn secret_writers_reads_a_required_row_from_a_fragment() {
    let (base, moved) = without_first_row(&live_base("secret_writers"));
    let (_root, table) = scratch_table("secret_writers", &base, &[("0.tsv", &moved)]);
    let wrong = differences(&counted(), &table);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A row with a class outside the list fails.
#[test]
fn secret_writers_refuses_an_unlisted_class() {
    let bad = "src/x.rs\tf\tpersist:edit_config\t1\tfine\twhy\n";
    let (_root, table) = scratch_table(
        "secret_writers",
        &live_base("secret_writers"),
        &[("0.tsv", bad)],
    );
    let wrong = differences(&counted(), &table).join("\n");
    assert!(wrong.contains("no class or no reason"), "{wrong}");
}
