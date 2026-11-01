// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The delivery-record raise inventory and the plain-error refusal
//! classification, compared exactly against their reviewed tables, plus the
//! guards that reject what the recogniser cannot see.

use std::collections::BTreeSet;

use super::delivery_framing::CLASSES;
use super::packaged::crate_root;
use super::plain_refusals::{ASSOCIATED, Collect, Derived, TWELVE, monitored_tokens};
use super::scan::walk;

/// The crate's targets: the lib, the main bin and every `src/bin` bin.
pub(super) const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Plain-error refusal gaps, each closed by its follow-up, which deletes the
/// slug here when it flips the last `pending:<slug>` row.
const PENDING: [&str; 2] = ["inv2-credential-miss", "unbindable-confirmation"];

/// Every `crate::Error` variant that is not one of the twelve: covered by
/// the refusal scan in `delivery_framing.rs` (`Forbidden`, `GatewayRefused`,
/// `ResponseFirewallRefused`), or not a gateway decision.
const OTHER_VARIANTS: [&str; 23] = [
    "Forbidden",
    "ResponseFirewallRefused",
    "AuditUnavailable",
    "ConfigValidation",
    "ConfigWatcher",
    "CapabilityHashMismatch",
    "BackendTimeout",
    "Transport",
    "TransportPermanent",
    "TransportConnect",
    "OAuth",
    "AuthorizationIncomplete",
    "AuthorizationCancelled",
    "AuthorizationPending",
    "Tls",
    "JsonRpc",
    "GatewayRefused",
    "JsonRpcRetryable",
    "Io",
    "Json",
    "Http",
    "Shutdown",
    "Internal",
];

pub(super) fn collect(root: &std::path::Path, roots: &[&str]) -> Collect {
    let mut collect = Collect::default();
    walk(root, roots, &mut collect).expect("the crate walks");
    collect
}

fn crate_collect() -> (Collect, Derived) {
    let collect = collect(crate_root(), &ROOTS);
    let derived = collect.derive();
    (collect, derived)
}

fn rows(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .collect()
}

fn pinned(text: &str, columns: usize) -> Vec<String> {
    let mut pinned: Vec<String> = rows(text)
        .iter()
        .map(|l| l.split('\t').take(columns).collect::<Vec<_>>().join("\t"))
        .collect();
    pinned.sort();
    pinned
}

const REGENERATE: &str = "regenerate: cargo test --lib plain_refusals -- --nocapture, copy the \
                          printed table into the .tsv, and have the diff reviewed";

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(ToString::to_string).collect()
}

#[test]
fn every_raise_is_inventoried() {
    let (_, derived) = crate_collect();
    let have: Vec<String> = derived
        .raises
        .iter()
        .map(|(key, n)| format!("{key}\t{n}"))
        .collect();
    let want = pinned(include_str!("delivery_raises.tsv"), 4);
    if have != want {
        println!("BEGIN delivery_raises.tsv\n{}\nEND", have.join("\n"));
    }
    assert_eq!(have, want, "raise sites changed; {REGENERATE}");
}

#[test]
fn the_raise_set_is_every_effect_writer() {
    let (_, derived) = crate_collect();
    assert_eq!(
        derived.effect_writers,
        names(&[
            "composite_ended",
            "echo_refusal_delivered",
            "outlet",
            "raise",
            "refused",
            "refused_while_vouched",
            "withheld"
        ]),
        "a delivery_facts function now writes the effect: add it to the raise set"
    );
}

#[test]
fn refused_before_step_is_the_refusal_state_writer() {
    let (_, derived) = crate_collect();
    assert_eq!(
        derived.step_writers,
        names(&["refused_before_step", "step"]),
        "a delivery_facts function now stores LastStep::Refused"
    );
}

#[test]
fn no_raise_is_imported_aliased_or_globbed() {
    let (collect, derived) = crate_collect();
    let found = collect.raise_imports(&derived);
    assert!(
        found.is_empty(),
        "write raises as delivery_facts::<name>: {found:?}"
    );
}

#[test]
fn no_monitored_variant_is_imported_aliased_or_globbed() {
    let (collect, derived) = crate_collect();
    let mut found: Vec<String> = collect
        .aliases
        .iter()
        .map(|(file, text)| format!("{file}: {text}"))
        .collect();
    found.extend(collect.helper_renames(&derived.helpers));
    found.extend(
        collect
            .error_impls
            .iter()
            .map(|f| format!("{f}: impl Error")),
    );
    assert!(
        found.is_empty(),
        "the refusal scan reads Error::<V> and helper names as written: {found:?}"
    );
}

#[test]
fn no_raise_has_a_pass_through_wrapper() {
    let (collect, _) = crate_collect();
    assert!(
        collect.wrappers.is_empty(),
        "a function handing its argument to a raise hides its callers' raises: {:?}",
        collect.wrappers
    );
}

#[test]
fn no_macro_definition_names_a_monitored_constructor() {
    let (collect, derived) = crate_collect();
    let found: Vec<String> = collect
        .macro_defs
        .iter()
        .filter_map(|(file, name, tokens)| {
            let hit = monitored_tokens(tokens, &derived.helpers);
            (!hit.is_empty()).then(|| format!("{file}: {name}! {hit:?}"))
        })
        .collect();
    assert!(
        found.is_empty(),
        "a macro definition can expand to refusals no row sees: {found:?}"
    );
}

/// Cargo's lib and bin targets under `root`: src/lib.rs, each `[[bin]]`
/// path, and (unless `autobins = false`) `src/bin/*.rs` and
/// `src/bin/<name>/main.rs`.
pub(super) fn crate_targets(root: &std::path::Path) -> BTreeSet<String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml reads");
    let mut targets = BTreeSet::new();
    if root.join("src/lib.rs").exists() {
        targets.insert("src/lib.rs".to_string());
    }
    let mut in_bin = false;
    let mut autobins = true;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "path" if in_bin => {
                targets.insert(value.to_string());
            }
            "autobins" => autobins = value != "false",
            _ => {}
        }
    }
    if autobins && let Ok(entries) = std::fs::read_dir(root.join("src/bin")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
                targets.insert(format!("src/bin/{name}"));
            } else if path.join("main.rs").is_file() {
                targets.insert(format!("src/bin/{name}/main.rs"));
            }
        }
    }
    targets
}

#[test]
fn roots_are_the_crate_targets() {
    assert_eq!(
        crate_targets(crate_root()),
        names(&ROOTS),
        "a crate target is outside the raise and refusal walk"
    );
}

/// The six columns of a plain-refusal row.
struct Row<'a> {
    file: &'a str,
    func: &'a str,
    needle: &'a str,
    class: &'a str,
    cite: &'a str,
}

fn row(line: &str) -> Row<'_> {
    let mut columns = line.split('\t');
    let mut next = || columns.next().unwrap_or("");
    let (file, func, needle, _ordinal, class, cite) =
        (next(), next(), next(), next(), next(), next());
    Row {
        file,
        func,
        needle,
        class,
        cite,
    }
}

#[test]
fn every_plain_refusal_construction_is_classified() {
    let (_, derived) = crate_collect();
    let text = include_str!("delivery_plain_refusals.tsv");
    let want = pinned(text, 4);
    if derived.plain != want {
        println!(
            "BEGIN delivery_plain_refusals.tsv\n{}\nEND\n{} rows",
            derived.plain.join("\n"),
            derived.plain.len()
        );
    }
    assert_eq!(
        derived.plain, want,
        "plain refusal constructions changed; classify each new one; {REGENERATE}"
    );
    let raise_fns: BTreeSet<String> = derived
        .raises
        .keys()
        .map(|key| {
            let mut columns = key.split('\t');
            format!(
                "{}::{}",
                columns.next().unwrap_or(""),
                columns.next().unwrap_or("")
            )
        })
        .collect();
    for line in rows(text) {
        let r = row(line);
        let pending = r
            .class
            .strip_prefix("pending:")
            .is_some_and(|slug| PENDING.contains(&slug));
        assert!(
            CLASSES.contains(&r.class) || pending,
            "unclassified: {line}"
        );
        assert!(!r.cite.trim().is_empty(), "no cite: {line}");
        if r.class == "recorded" {
            assert!(
                raise_fns.contains(r.cite),
                "a recorded row cites the raise it relies on as file::fn: {line}"
            );
        }
        if r.needle.ends_with(" wrapped") {
            assert_eq!(
                r.class, "recorded",
                "a wrapped construction is recorded: {line}"
            );
            assert_eq!(
                r.cite,
                format!("{}::{}", r.file, r.func),
                "a wrapped row cites its own enclosing raise: {line}"
            );
        }
    }
    for slug in PENDING {
        assert!(
            text.contains(&format!("\tpending:{slug}\t")),
            "pending:{slug} has no rows left; delete it from PENDING"
        );
    }
}

/// The bare `Error::BackendNotFound(..)` constructions in
/// `list_tools_single_server`, in source order, each marked when it is the
/// credential miss (inside the `let .. = self.tool_credential_for(..) else`).
fn credential_miss_ordinal(source: &str) -> usize {
    use syn::visit::Visit;
    struct Find {
        in_miss: bool,
        in_raise: bool,
        seen: usize,
        miss: Option<usize>,
    }
    impl<'ast> Visit<'ast> for Find {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            let miss = local.init.as_ref().is_some_and(|init| {
                init.diverge.is_some() && quote_text(&init.expr).contains("tool_credential_for")
            });
            let saved = {
                let now = self.in_miss || miss;
                std::mem::replace(&mut self.in_miss, now)
            };
            syn::visit::visit_local(self, local);
            self.in_miss = saved;
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            let raise = matches!(&*call.func, syn::Expr::Path(p)
                if p.path.segments.iter().any(|s| s.ident == super::plain_refusals::FACTS));
            if let syn::Expr::Path(p) = &*call.func
                && !self.in_raise
                && p.path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .ends_with(&["Error".to_string(), "BackendNotFound".to_string()])
            {
                self.seen += 1;
                if self.in_miss {
                    self.miss.get_or_insert(self.seen);
                }
            }
            let saved = {
                let now = self.in_raise || raise;
                std::mem::replace(&mut self.in_raise, now)
            };
            syn::visit::visit_expr_call(self, call);
            self.in_raise = saved;
        }
    }
    fn quote_text(expr: &syn::Expr) -> String {
        struct Idents<'a>(&'a mut String);
        impl<'ast> Visit<'ast> for Idents<'_> {
            fn visit_ident(&mut self, ident: &'ast syn::Ident) {
                self.0.push_str(&ident.to_string());
                self.0.push(' ');
            }
        }
        let mut text = String::new();
        Idents(&mut text).visit_expr(expr);
        text
    }
    let parsed = syn::parse_file(source).expect("search.rs parses");
    let mut find = Find {
        in_miss: false,
        in_raise: false,
        seen: 0,
        miss: None,
    };
    for item in &parsed.items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        for inner in &block.items {
            if let syn::ImplItem::Fn(func) = inner
                && func.sig.ident == "list_tools_single_server"
            {
                find.visit_impl_item_fn(func);
            }
        }
    }
    find.miss
        .expect("the credential-miss BackendNotFound is in list_tools_single_server")
}

#[test]
fn the_inv2_credential_miss_is_pending() {
    let source = std::fs::read_to_string(crate_root().join("src/gateway/meta_mcp/search.rs"))
        .expect("search.rs reads");
    let ordinal = credential_miss_ordinal(&source);
    let key = format!(
        "src/gateway/meta_mcp/search.rs\tlist_tools_single_server\tError::BackendNotFound(..)\t{ordinal}\t"
    );
    let line = rows(include_str!("delivery_plain_refusals.tsv"))
        .into_iter()
        .find(|l| l.starts_with(&key))
        .unwrap_or_else(|| panic!("no row for the credential miss: {key}"));
    assert_eq!(row(line).class, "pending:inv2-credential-miss", "{line}");
}

fn error_enum(source: &str) -> syn::ItemEnum {
    syn::parse_file(source)
        .expect("src/error.rs parses")
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Enum(e) if e.ident == "Error" => Some(e),
            _ => None,
        })
        .expect("enum Error")
}

#[test]
fn the_error_variant_list_is_placed() {
    let source = std::fs::read_to_string(crate_root().join("src/error.rs")).expect("reads");
    let have: BTreeSet<String> = error_enum(&source)
        .variants
        .iter()
        .map(|v| v.ident.to_string())
        .collect();
    let want: BTreeSet<String> = TWELVE
        .iter()
        .chain(&OTHER_VARIANTS)
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        have, want,
        "place each new Error variant in TWELVE or OTHER_VARIANTS"
    );
}

/// The `impl Error` functions in `source` whose body builds one of the twelve.
pub(super) fn associated_constructors(source: &str) -> BTreeSet<String> {
    use syn::visit::Visit;
    struct Builds(bool);
    impl<'ast> Visit<'ast> for Builds {
        // Expressions only: a match pattern naming a variant builds nothing.
        fn visit_expr(&mut self, expr: &'ast syn::Expr) {
            let path = match expr {
                syn::Expr::Path(p) => Some(&p.path),
                syn::Expr::Struct(s) => Some(&s.path),
                _ => None,
            };
            if let Some(path) = path {
                let mut segments = path.segments.iter().rev();
                let variant = segments
                    .next()
                    .is_some_and(|s| TWELVE.iter().any(|v| s.ident == v));
                let owner = segments
                    .next()
                    .is_some_and(|s| s.ident == "Self" || s.ident == "Error");
                self.0 |= variant && owner;
            }
            syn::visit::visit_expr(self, expr);
        }
    }
    let parsed = syn::parse_file(source).expect("parses");
    let mut found = BTreeSet::new();
    for item in &parsed.items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        let own = block.trait_.is_none()
            && matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident("Error"));
        if !own {
            continue;
        }
        for inner in &block.items {
            if let syn::ImplItem::Fn(func) = inner {
                let mut builds = Builds(false);
                builds.visit_block(&func.block);
                if builds.0 {
                    found.insert(func.sig.ident.to_string());
                }
            }
        }
    }
    found
}

#[test]
fn the_associated_constructors_are_listed() {
    let source = std::fs::read_to_string(crate_root().join("src/error.rs")).expect("reads");
    assert_eq!(
        associated_constructors(&source),
        names(&ASSOCIATED),
        "an impl Error constructor builds one of the twelve: add it to ASSOCIATED"
    );
}
