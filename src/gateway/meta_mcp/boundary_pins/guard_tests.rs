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

/// The lint names an `allow`/`expect` attribute (or a `cfg_attr` carrying
/// one) names.
fn lint_names(attr: &syn::Attribute) -> Vec<String> {
    type Metas = syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>;
    let path = |meta: &syn::Meta| {
        meta.path()
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    };
    let lints = |meta: &syn::Meta| -> Vec<String> {
        match meta {
            syn::Meta::List(list)
                if list.path.is_ident("allow") || list.path.is_ident("expect") =>
            {
                list.parse_args_with(Metas::parse_terminated)
                    .map(|args| {
                        args.iter()
                            .filter(|m| matches!(m, syn::Meta::Path(_)))
                            .map(path)
                            .collect()
                    })
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        }
    };
    if attr.path().is_ident("cfg_attr") {
        attr.parse_args_with(Metas::parse_terminated)
            .map(|args| args.iter().skip(1).flat_map(lints).collect())
            .unwrap_or_default()
    } else {
        lints(&attr.meta)
    }
}

#[derive(Default)]
struct Broad(Vec<String>);

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

#[derive(Default)]
struct Envelopes {
    literals: BTreeSet<String>,
    route_takes_envelope: Option<bool>,
}

impl Sink for Envelopes {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if let syn::Expr::Struct(lit) = expr
            && lit
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "Envelope")
            && at.file.ends_with("backend_handlers/direct_caller.rs")
        {
            self.literals.insert(at.func.clone().unwrap_or_default());
        }
    }

    fn item(&mut self, at: &Place, item: &syn::Item) {
        if let syn::Item::Fn(func) = item
            && func.sig.ident == "route"
            && at.file.ends_with("backend_handlers/direct_caller.rs")
        {
            let takes = func.sig.inputs.iter().any(|input| {
                matches!(input, syn::FnArg::Typed(arg) if matches!(&*arg.ty,
                    syn::Type::Reference(r) if matches!(&*r.elem,
                        syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Envelope"))))
            });
            self.route_takes_envelope = Some(takes);
        }
    }
}

/// T2b, the router's order, structurally: `Envelope { .. }` is built only
/// in `read_envelope`, and `route` takes `&Envelope`, so `route` cannot run
/// before `read_envelope`. Mutant M20b: an `Envelope` literal built in the
/// handler.
#[test]
fn t2b_only_read_envelope_builds_the_envelope_route_consumes() {
    let mut found = Envelopes::default();
    walk(crate_root(), &ROOTS, &mut found).expect("the walk reads every module");
    assert_eq!(
        found.literals,
        BTreeSet::from(["read_envelope".to_string()]),
        "Envelope literal outside read_envelope"
    );
    assert_eq!(
        found.route_takes_envelope,
        Some(true),
        "route takes &Envelope"
    );
}

/// T1e: `BackendRegistry`'s surface, pinned. Its non-private inherent
/// methods with their test-only flag, its trait impls and derives, and the
/// invariant that every field is private: a new reader the ban does not
/// list, or a `pub` field a read could go through, is red. Mutants: M19h (a
/// new `pub fn`), T1e-m3 (`pub backends:`), T1e-m4 (`is_stopping` loses
/// `#[cfg(test)]`); derive extraction is proven on SCAN-18.
#[test]
fn t1e_the_backend_registry_surface_is_pinned() {
    let source =
        std::fs::read_to_string(crate_root().join("src/backend/registry.rs")).expect("registry.rs");
    let file = syn::parse_file(&source).expect("registry.rs parses");
    let is_registry =
        |ty: &syn::Type| matches!(ty, syn::Type::Path(p) if p.path.is_ident("BackendRegistry"));
    let (mut methods, mut traits, mut derives, mut public_fields) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        Vec::new(),
    );
    for item in &file.items {
        match item {
            syn::Item::Struct(s) if s.ident == "BackendRegistry" => {
                for attr in s.attrs.iter().filter(|a| a.path().is_ident("derive")) {
                    let _ = attr.parse_nested_meta(|meta| {
                        derives.insert(
                            meta.path
                                .segments
                                .last()
                                .map(|s| s.ident.to_string())
                                .unwrap_or_default(),
                        );
                        Ok(())
                    });
                }
                for field in &s.fields {
                    if !matches!(field.vis, syn::Visibility::Inherited) {
                        public_fields.push(
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
                    traits.insert(
                        path.segments
                            .last()
                            .map(|s| s.ident.to_string())
                            .unwrap_or_default(),
                    );
                }
                None => {
                    for inner in &imp.items {
                        if let syn::ImplItem::Fn(f) = inner
                            && !matches!(f.vis, syn::Visibility::Inherited)
                        {
                            let flag = if test_only(&f.attrs) { " (test)" } else { "" };
                            methods.insert(format!("{}{flag}", f.sig.ident));
                        }
                    }
                }
            },
            _ => {}
        }
    }
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
        "resolve_unwarmed",
        "with_membership",
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
        methods, want,
        "method set changed: a new reader must join the ban (MIK-8387)"
    );
    assert_eq!(
        traits,
        BTreeSet::from(["Default".to_string()]),
        "trait impls changed"
    );
    assert!(derives.is_empty(), "derives changed: {derives:?}");
    assert!(
        public_fields.is_empty(),
        "field is not private: {public_fields:?}"
    );
}
