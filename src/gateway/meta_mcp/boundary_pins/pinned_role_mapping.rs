// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A request is judged by the role mapping of the generation pinned on it
//! when it arrived (ADR-023), never by the live config: a reload published
//! after the request arrived must not change the role it is judged by. This
//! pin is the family's table: every production function in the crate is a
//! row, so a new live read fails here instead of becoming a ticket.
//!
//! Syntax scan, per function: a function that reads a `live_config` field and
//! a `role_mapping` field fails, unless [`ALLOW`] lists it. A read counts in
//! a body, in a macro's arguments (`.name` in its tokens) and in a trait's
//! default method (`Trait::method`). That is a coarse rule, not a data-flow
//! check: a mapping read routed through a helper in another function is
//! missed, as an alias is missed in the other pins.
//!
//! One judge must read the live mapping for good: the judge of a delivery
//! with no request behind it, `auth_live::current_caller`, which stream
//! rechecks reach through `current_client` and the view judge and the UI
//! stream call directly. It judges each delivery by the generation current
//! then, so a role removed by a reload stops a stream already open. Today it reaches the
//! mapping through `key_server_credential`, which the request path shares, so
//! that function's one row covers both callers until the request path moves
//! to the pinned generation. The change that moves it deletes that row, or
//! rewrites it as the delivery judge's if this function is left reading the
//! live mapping for the judge alone.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Production functions that may read the live role mapping: (file,
/// function, why). Each row must match a function that reads both, so a row
/// cannot outlive its site.
const ALLOW: &[(&str, &str, &str)] = &[(
    "src/gateway/auth_live.rs",
    "key_server_credential",
    "pending: the admin flag set at authentication reads the live mapping for \
     the request path and the delivery judge alike; the change that moves the \
     request path to the pinned generation deletes this row, or rewrites it \
     as the delivery judge's if this function keeps reading for the judge alone",
)];

/// The two fields, read as `.name` in a macro's arguments. Those are tokens,
/// not expressions, so the walk never reports them as field reads.
fn macro_reads(mac: &syn::Macro) -> impl Iterator<Item = &'static str> {
    let text = mac.tokens.to_string();
    ["live_config", "role_mapping"]
        .into_iter()
        .filter(move |name| {
            text.contains(&format!(". {name}")) || text.contains(&format!(".{name}"))
        })
}

/// The functions that read each field, per (file, function).
#[derive(Default)]
struct Reads {
    live: std::collections::BTreeSet<(String, String)>,
    mapping: std::collections::BTreeSet<(String, String)>,
}

impl Reads {
    fn note(&mut self, key: (String, String), name: &str) {
        if name == "live_config" {
            self.live.insert(key);
        } else if name == "role_mapping" {
            self.mapping.insert(key);
        }
    }
}

impl Sink for Reads {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let Some(func) = &at.func else {
            return;
        };
        let key = (at.file.clone(), func.clone());
        match expr {
            syn::Expr::Field(syn::ExprField {
                member: syn::Member::Named(name),
                ..
            }) => self.note(key, &name.to_string()),
            syn::Expr::Macro(mac) => macro_reads(&mac.mac).for_each(|n| self.note(key.clone(), n)),
            _ => {}
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if let (Some(func), syn::Stmt::Macro(mac)) = (&at.func, stmt) {
            let key = (at.file.clone(), func.clone());
            macro_reads(&mac.mac).for_each(|n| self.note(key.clone(), n));
        }
    }

    /// A trait's default method bodies: the walk names no function there, so
    /// each is read here as `Trait::method`.
    fn item(&mut self, at: &Place, item: &syn::Item) {
        let syn::Item::Trait(tr) = item else {
            return;
        };
        for trait_item in &tr.items {
            let syn::TraitItem::Fn(func) = trait_item else {
                continue;
            };
            let Some(body) = &func.default else {
                continue;
            };
            if super::scan::test_only(&func.attrs) {
                continue;
            }
            let key = (at.file.clone(), format!("{}::{}", tr.ident, func.sig.ident));
            let mut names = Names::default();
            syn::visit::Visit::visit_block(&mut names, body);
            for name in names.0 {
                self.note(key.clone(), &name);
            }
        }
    }
}

/// The field names a body reads, macro arguments included.
#[derive(Default)]
struct Names(Vec<String>);

impl<'ast> syn::visit::Visit<'ast> for Names {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.0.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.0.extend(macro_reads(mac).map(str::to_owned));
    }
}

/// The functions under `root` that read both fields and `allow` does not
/// list, and the `allow` rows that match no such function.
fn verdict(
    root: &std::path::Path,
    roots: &[&str],
    allow: &[(&str, &str, &str)],
) -> (Reads, Vec<String>, Vec<String>) {
    let mut reads = Reads::default();
    walk(root, roots, &mut reads).expect("the walk reads every module");
    let both: Vec<(String, String)> = reads.live.intersection(&reads.mapping).cloned().collect();
    let unlisted = both
        .iter()
        .filter(|(file, func)| !allow.iter().any(|(f, n, _)| f == file && n == func))
        .map(|(file, func)| format!("{file}:{func}"))
        .collect();
    let stale = allow
        .iter()
        .filter(|(f, n, _)| !both.iter().any(|(file, func)| file == f && func == n))
        .map(|(f, n, _)| format!("{f}:{n}"))
        .collect();
    (reads, unlisted, stale)
}

/// No production function judges a role by the live config, except as listed.
#[test]
fn role_checks_read_the_pinned_mapping() {
    let (reads, unlisted, stale) = verdict(crate_root(), &ROOTS, ALLOW);
    assert!(
        reads
            .mapping
            .iter()
            .any(|(file, _)| file.starts_with("src/gateway/ui/")),
        "premise: the scan sees the UI's role-mapping reads"
    );
    assert!(
        reads
            .mapping
            .iter()
            .any(|(file, _)| !file.starts_with("src/gateway/ui/")),
        "premise: the scan sees role-mapping reads outside the UI"
    );
    assert!(
        unlisted.is_empty(),
        "a function judges a role by the live config, not the request's pinned generation:\n{}",
        unlisted.join("\n")
    );
    assert!(
        stale.is_empty(),
        "an allowed live read no longer exists; delete its row:\n{}",
        stale.join("\n")
    );
}

/// The guard on a fixture crate: a plain read, a read in a macro's arguments
/// and one in a trait's default method are found; a listed read passes; a
/// row with no read behind it is stale; a test-only read is not production.
#[test]
fn the_guard_finds_every_shape_of_live_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("src")).expect("src");
    std::fs::write(
        dir.path().join("src/lib.rs"),
        r#"
fn plain(s: &S) -> bool { s.live_config.get().control_plane.role_mapping.x() }
fn in_macro(s: &S) { tracing::info!("{:?}", s.live_config.get().control_plane.role_mapping); }
trait Judge { fn judge(&self, s: &S) -> bool { s.live_config.get().control_plane.role_mapping.x() } }
fn listed(s: &S) -> bool { s.live_config.get().control_plane.role_mapping.x() }
fn pinned(g: &G) -> bool { g.config().control_plane.role_mapping.x() }
#[cfg(test)]
fn in_test(s: &S) -> bool { s.live_config.get().control_plane.role_mapping.x() }
"#,
    )
    .expect("fixture");
    let allow = [
        ("src/lib.rs", "listed", "fixture"),
        ("src/lib.rs", "gone", "fixture"),
    ];
    let (_, unlisted, stale) = verdict(dir.path(), &["src/lib.rs"], &allow);
    assert_eq!(
        unlisted,
        [
            "src/lib.rs:Judge::judge",
            "src/lib.rs:in_macro",
            "src/lib.rs:plain"
        ]
    );
    assert_eq!(stale, ["src/lib.rs:gone"]);
}
