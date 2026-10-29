// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B guard pins over the real tree (test plan v2 §3): T1b2,
//! T1e and T2b. Each is green on the tip; its strength is the named mutant.

use std::collections::BTreeSet;
use std::path::Path;

use super::scan::{Owner, Place, Sink, test_only, walk};

/// Every target the second clippy pass checks (`--lib --bins`).
const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

fn crate_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The lint names an `allow`/`expect` attribute names, through any depth of
/// `cfg_attr` nesting (`cfg_attr(a, cfg_attr(b, allow(warnings)))`).
fn lint_names(attr: &syn::Attribute) -> Vec<String> {
    lints_in(&attr.meta)
}

fn lints_in(meta: &syn::Meta) -> Vec<String> {
    type Metas = syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>;
    let syn::Meta::List(list) = meta else {
        return Vec::new();
    };
    let args = list
        .parse_args_with(Metas::parse_terminated)
        .map(|args| args.into_iter().collect::<Vec<_>>())
        .unwrap_or_default();
    if list.path.is_ident("allow") || list.path.is_ident("expect") {
        args.iter()
            .filter(|m| matches!(m, syn::Meta::Path(_)))
            .map(|m| {
                m.path()
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::")
            })
            .collect()
    } else if list.path.is_ident("cfg_attr") {
        args.iter().skip(1).flat_map(lints_in).collect()
    } else {
        Vec::new()
    }
}

#[derive(Default)]
pub(super) struct Broad(pub(super) Vec<String>);

impl Sink for Broad {
    fn attribute(&mut self, at: &Place, _owner: Owner, attr: &syn::Attribute) {
        for lint in lint_names(attr) {
            if ["warnings", "clippy::all", "clippy::style"].contains(&lint.as_str()) {
                self.0.push(format!("{} {:?}: {lint}", at.file, at.func));
            }
        }
    }
}

/// T1b2: no production `allow`/`expect` of `warnings`, `clippy::all` or
/// `clippy::style` (the group `disallowed_methods` belongs to), conditional
/// or not: any of them would silence the registry ban with no class.
/// Mutant T1b2-m1: `#![allow(clippy::style)]` added to `gateway/ui/mod.rs`.
#[test]
fn t1b2_no_production_code_suppresses_the_lint_group_the_ban_lives_in() {
    let mut broad = Broad::default();
    walk(crate_root(), &ROOTS, &mut broad).expect("the walk reads every module");
    assert!(
        broad.0.is_empty(),
        "broad suppression in production:\n{}",
        broad.0.join("\n")
    );
}

/// Where the router's `Envelope` (`pub(super)` in `backend_handlers`) can be
/// named. `task_service/store_disk.rs` has an unrelated `Envelope`.
const ENVELOPE_HOME: &str = "src/gateway/router/backend_handlers";

fn names_envelope(path: &syn::Path) -> bool {
    path.segments.last().is_some_and(|s| s.ident == "Envelope")
}

#[derive(Default)]
struct Envelopes {
    literals: BTreeSet<String>,
    /// `use .. Envelope as X`, `type X = Envelope` and `impl Envelope` (a
    /// `Self { .. }` there): constructions T2b's literal scan cannot see.
    aliases: Vec<String>,
    route_takes_envelope: Option<bool>,
}

fn renames_envelope(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Rename(r) => r.ident == "Envelope",
        syn::UseTree::Path(p) => renames_envelope(&p.tree),
        syn::UseTree::Group(g) => g.items.iter().any(renames_envelope),
        _ => false,
    }
}

impl Sink for Envelopes {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if let syn::Expr::Struct(lit) = expr
            && names_envelope(&lit.path)
            && at.file.starts_with(ENVELOPE_HOME)
        {
            self.literals.insert(at.func.clone().unwrap_or_default());
        }
    }

    fn item(&mut self, at: &Place, item: &syn::Item) {
        if !at.file.starts_with(ENVELOPE_HOME) {
            return;
        }
        match item {
            syn::Item::Use(u) if renames_envelope(&u.tree) => {
                self.aliases.push(format!("{}: use .. as", at.file));
            }
            syn::Item::Type(t) if matches!(&*t.ty, syn::Type::Path(p) if names_envelope(&p.path)) =>
            {
                self.aliases.push(format!("{}: type {}", at.file, t.ident));
            }
            syn::Item::Impl(imp) if matches!(&*imp.self_ty, syn::Type::Path(p) if names_envelope(&p.path)) =>
            {
                self.aliases.push(format!("{}: impl Envelope", at.file));
            }
            syn::Item::Fn(func) if func.sig.ident == "route" => {
                let takes = func.sig.inputs.iter().any(|input| {
                    matches!(input, syn::FnArg::Typed(arg) if matches!(&*arg.ty,
                        syn::Type::Reference(r) if matches!(&*r.elem,
                            syn::Type::Path(p) if names_envelope(&p.path))))
                });
                self.route_takes_envelope = Some(takes);
            }
            _ => {}
        }
    }
}

/// T2b, the router's order, structurally: in `backend_handlers`, where the
/// router's `Envelope` can be named, it is built only in `read_envelope`,
/// never through an alias or an `impl Envelope`, and `route` takes
/// `&Envelope`, so `route` cannot run before `read_envelope`. Mutant M20b:
/// an `Envelope` literal built in the handler.
#[test]
fn t2b_only_read_envelope_builds_the_envelope_route_consumes() {
    let mut found = Envelopes::default();
    walk(crate_root(), &ROOTS, &mut found).expect("the walk reads every module");
    assert_eq!(
        found.literals,
        BTreeSet::from(["read_envelope".to_string()]),
        "Envelope literal outside read_envelope"
    );
    assert!(
        found.aliases.is_empty(),
        "Envelope built through an alias: {:?}",
        found.aliases
    );
    assert_eq!(
        found.route_takes_envelope,
        Some(true),
        "route takes &Envelope"
    );
}

/// Derive names, including derives under any depth of `cfg_attr`.
fn derives_in(attrs: &[syn::Attribute]) -> BTreeSet<String> {
    type Metas = syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>;
    fn walk_meta(meta: &syn::Meta, out: &mut BTreeSet<String>) {
        let syn::Meta::List(list) = meta else { return };
        let Ok(args) = list.parse_args_with(Metas::parse_terminated) else {
            return;
        };
        if list.path.is_ident("derive") {
            for arg in &args {
                if let Some(last) = arg.path().segments.last() {
                    out.insert(last.ident.to_string());
                }
            }
        } else if list.path.is_ident("cfg_attr") {
            for arg in args.iter().skip(1) {
                walk_meta(arg, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    for attr in attrs {
        walk_meta(&attr.meta, &mut out);
    }
    out
}

fn is_registry(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "BackendRegistry"))
}

/// `BackendRegistry`'s production surface, gathered crate-wide: an `impl`
/// may live in any module and name the type by any path.
#[derive(Default)]
pub(super) struct Surface {
    methods: BTreeSet<String>,
    traits: BTreeSet<String>,
    pub(super) derives: BTreeSet<String>,
    pub(super) public_fields: Vec<String>,
}

impl Sink for Surface {
    fn item(&mut self, _at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Struct(s) if s.ident == "BackendRegistry" => {
                self.derives.extend(derives_in(&s.attrs));
                for field in &s.fields {
                    if !matches!(field.vis, syn::Visibility::Inherited) {
                        self.public_fields.push(
                            field
                                .ident
                                .as_ref()
                                .map(ToString::to_string)
                                .unwrap_or_default(),
                        );
                    }
                }
            }
            syn::Item::Impl(imp) if is_registry(&imp.self_ty) => match &imp.trait_ {
                Some((_, path, _)) => {
                    if let Some(last) = path.segments.last() {
                        self.traits.insert(last.ident.to_string());
                    }
                }
                None => {
                    for inner in &imp.items {
                        if let syn::ImplItem::Fn(f) = inner
                            && !matches!(f.vis, syn::Visibility::Inherited)
                        {
                            let flag = if test_only(&f.attrs) { " (test)" } else { "" };
                            self.methods.insert(format!("{}{flag}", f.sig.ident));
                        }
                    }
                }
            },
            _ => {}
        }
    }
}

/// T1e: `BackendRegistry`'s surface, pinned crate-wide. Its non-private
/// inherent methods with their test-only flag, its trait impls and derives
/// (`cfg_attr` derives included), and the invariant that every field is
/// private: a new reader the ban does not list, or a `pub` field a read
/// could go through, is red. Mutants: M19h (a new `pub fn`), T1e-m3 (`pub
/// backends:`), T1e-m4 (`is_stopping` loses `#[cfg(test)]`); derive
/// extraction is proven on SCAN-18.
#[test]
fn t1e_the_backend_registry_surface_is_pinned() {
    let mut surface = Surface::default();
    walk(crate_root(), &ROOTS, &mut surface).expect("the walk reads every module");
    let want: BTreeSet<String> = [
        "new",
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
        // A constructor, as `new` is: it installs the secret resolver the
        // registry stamps on each backend, and reads no backend.
        "with_secret_resolver",
        "get",
        "all",
        "statuses",
        "remove",
        "is_stopping (test)",
        "stop_all",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(
        surface.methods, want,
        "method set changed: a new reader must join the ban (MIK-8387)"
    );
    assert_eq!(
        surface.traits,
        BTreeSet::from(["Default".to_string()]),
        "trait impls changed"
    );
    assert!(
        surface.derives.is_empty(),
        "derives changed: {:?}",
        surface.derives
    );
    assert!(
        surface.public_fields.is_empty(),
        "field is not private: {:?}",
        surface.public_fields
    );
}

#[derive(Default)]
struct BackendForRefs {
    refs: BTreeSet<(String, String)>,
    definitions: usize,
}

impl Sink for BackendForRefs {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        // A call's callee is itself a path expression, so this one arm sees
        // calls and function-item references alike.
        if let syn::Expr::Path(path) = expr
            && path
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "backend_for")
        {
            self.refs
                .insert((at.file.clone(), at.func.clone().unwrap_or_default()));
        }
    }

    fn item(&mut self, _at: &Place, item: &syn::Item) {
        if let syn::Item::Fn(func) = item
            && func.sig.ident == "backend_for"
        {
            self.definitions += 1;
        }
    }
}

/// T2c: every production reference to the router choke point, by file and
/// enclosing fn, function items included, and one definition of it. A new
/// reader, such as a helper called from `read_envelope` before S4, is a new
/// key. Mutants: M20 (a call in `read_envelope`), M20c (a helper calling it).
#[test]
fn t2c_every_reference_to_the_router_choke_point_is_pinned() {
    let mut found = BackendForRefs::default();
    walk(crate_root(), &ROOTS, &mut found).expect("the walk reads every module");
    assert_eq!(found.definitions, 1, "second definition of backend_for");
    let want: BTreeSet<(String, String)> = [
        ("src/gateway/router/authorization.rs", "backend_tool_names"),
        ("src/gateway/router/authorization.rs", "decide_tool_target"),
        (
            "src/gateway/router/backend_handlers/direct_caller.rs",
            "route",
        ),
    ]
    .into_iter()
    .map(|(f, n)| (f.to_string(), n.to_string()))
    .collect();
    assert_eq!(found.refs, want, "unpinned reference to backend_for");
}
