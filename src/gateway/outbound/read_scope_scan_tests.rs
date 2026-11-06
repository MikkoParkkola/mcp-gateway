// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each judge entry point opens with the `judging` gate (every function the
//! judge exposes that takes a firewall, found by parsing it), and the
//! frame-level check asks the same gate, so the verdict decides whether to judge in one
//! place. That only the judge reaches the read history is pinned by the
//! production-node scan in `meta_mcp::boundary_pins::read_history_access`.

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const JUDGE: &str = "gateway/outbound/judge.rs";

/// Functions of the judge that take a firewall but are not entry points to
/// the verdict, each with why it needs no gate.
const NOT_ENTRIES: [(&str, &str); 2] = [
    ("judging", "the gate itself"),
    (
        "attribute",
        "labels a raw value's tenants for an outbox record; never reaches the read history",
    ),
];

/// Whether `ty` is `&Firewall`.
fn is_firewall_ref(ty: &syn::Type) -> bool {
    let syn::Type::Reference(reference) = ty else {
        return false;
    };
    let syn::Type::Path(path) = &*reference.elem else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|s| s.ident == "Firewall")
}

/// Names one module brings into its own scope that a bare identifier
/// pattern would match instead of binding: every `use` leaf and rename, and
/// every `const` and `static`. A `use` does not reach into child modules, so
/// each module's set is its own ([`entries`] swaps it per module).
fn taken_names(items: &[syn::Item]) -> std::collections::HashSet<String> {
    fn tree(t: &syn::UseTree, out: &mut std::collections::HashSet<String>) {
        match t {
            syn::UseTree::Path(p) => tree(&p.tree, out),
            syn::UseTree::Name(n) => {
                out.insert(n.ident.to_string());
            }
            syn::UseTree::Rename(r) => {
                out.insert(r.rename.to_string());
            }
            syn::UseTree::Group(g) => g.items.iter().for_each(|i| tree(i, out)),
            syn::UseTree::Glob(_) => {
                out.insert("*".to_owned());
            }
        }
    }
    let mut out = std::collections::HashSet::new();
    for item in items {
        match item {
            syn::Item::Use(u) => tree(&u.tree, &mut out),
            syn::Item::Const(c) => {
                out.insert(c.ident.to_string());
            }
            syn::Item::Static(s) => {
                out.insert(s.ident.to_string());
            }
            _ => {}
        }
    }
    out
}

/// Whether `pat` matches every value of its type: a binding or `_`, alone
/// or in a tuple. A name counts as a binding only if it is lowercase and is
/// no name the judge brings into scope (`taken`): `Some((guard, Off))` with
/// `Off` imported, or with `use ..::Off as off`, narrows instead of binding,
/// and would send every judged call to the unjudged `else`. A glob import
/// in `taken` (`*`) refuses every bare name, since any could be imported.
fn irrefutable(pat: &syn::Pat, taken: &std::collections::HashSet<String>) -> bool {
    match pat {
        syn::Pat::Ident(binding) => {
            let name = binding.ident.to_string();
            binding.subpat.is_none()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && !taken.contains(&name)
                && !taken.contains("*")
        }
        syn::Pat::Wild(_) => true,
        syn::Pat::Tuple(tuple) => tuple.elems.iter().all(|p| irrefutable(p, taken)),
        _ => false,
    }
}

/// Whether `stmt` is `let Some(<irrefutable>) = judging(firewall) else { .. };`.
fn is_judging_gate(stmt: &syn::Stmt, taken: &std::collections::HashSet<String>) -> bool {
    let syn::Stmt::Local(local) = stmt else {
        return false;
    };
    // Any attribute could compile the gate out (`#[cfg(any())]`).
    if !local.attrs.is_empty() {
        return false;
    }
    // The gate binds `Some(..)` whatever the guard and mode are: an inverted
    // `let None = ..` runs the body exactly when the verdict is off, and a
    // narrowing payload skips judging whenever it is on.
    let syn::Pat::TupleStruct(bound) = &local.pat else {
        return false;
    };
    if !bound.path.is_ident("Some")
        || bound.elems.len() != 1
        || !bound.elems.iter().all(|p| irrefutable(p, taken))
    {
        return false;
    }
    let Some(init) = &local.init else {
        return false;
    };
    let syn::Expr::Call(call) = &*init.expr else {
        return false;
    };
    let syn::Expr::Path(func) = &*call.func else {
        return false;
    };
    let gate = func
        .path
        .segments
        .last()
        .is_some_and(|s| s.ident == "judging");
    let on_firewall = matches!(
        call.args.first(),
        Some(syn::Expr::Path(arg)) if arg.path.is_ident("firewall")
    );
    gate && on_firewall && init.diverge.is_some()
}

/// What the walk of the judge found.
#[derive(Default)]
struct Entries {
    /// Exposed functions taking a `&Firewall` that open with the gate.
    gated: Vec<String>,
    /// Exposed functions taking a `&Firewall` that do not.
    ungated: Vec<String>,
    /// Items the walk cannot see into, so an entry could hide there: an
    /// out-of-line module, an item macro (also inside an `impl` or a
    /// trait), an exposed `use`.
    unsupported: Vec<String>,
    /// Names the judge brings into scope ([`taken_names`]).
    taken: std::collections::HashSet<String>,
}

impl Entries {
    /// One function: `exposed` is whether it is reachable from outside the
    /// judge; `exempt` whether it is a top-level free function named in
    /// [`NOT_ENTRIES`].
    fn check(&mut self, sig: &syn::Signature, exposed: bool, exempt: bool, block: &syn::Block) {
        let takes_firewall = sig
            .inputs
            .iter()
            .any(|input| matches!(input, syn::FnArg::Typed(arg) if is_firewall_ref(&arg.ty)));
        if !exposed || !takes_firewall || exempt {
            return;
        }
        let name = sig.ident.to_string();
        if block
            .stmts
            .first()
            .is_some_and(|stmt| is_judging_gate(stmt, &self.taken))
        {
            self.gated.push(name);
        } else {
            self.ungated.push(name);
        }
    }
}

/// Walk the judge's items: free functions, every method of every `impl`
/// block (a trait impl's methods count as exposed), default-bodied methods
/// of exposed traits, and nested inline modules. [`NOT_ENTRIES`] exempts
/// only top-level free functions, by name.
fn entries(items: &[syn::Item], top: bool, found: &mut Entries) {
    let exposed = |vis: &syn::Visibility| !matches!(vis, syn::Visibility::Inherited);
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                let exempt = top && NOT_ENTRIES.iter().any(|(n, _)| *n == name);
                found.check(&f.sig, exposed(&f.vis), exempt, &f.block);
            }
            syn::Item::Impl(block) => {
                for inner in &block.items {
                    match inner {
                        syn::ImplItem::Fn(m) => {
                            let open = block.trait_.is_some() || exposed(&m.vis);
                            found.check(&m.sig, open, false, &m.block);
                        }
                        syn::ImplItem::Macro(_) => {
                            found.unsupported.push("a macro in an impl".to_owned());
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Trait(t) => {
                for inner in &t.items {
                    match inner {
                        syn::TraitItem::Fn(m) => {
                            if let Some(body) = &m.default {
                                found.check(&m.sig, exposed(&t.vis), false, body);
                            }
                        }
                        syn::TraitItem::Macro(_) => {
                            found.unsupported.push("a macro in a trait".to_owned());
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Mod(module) => match &module.content {
                Some((_, inner)) => {
                    let outer = std::mem::replace(&mut found.taken, taken_names(inner));
                    entries(inner, false, found);
                    found.taken = outer;
                }
                None => found.unsupported.push(format!("mod {};", module.ident)),
            },
            syn::Item::Macro(mac) => found.unsupported.push(format!(
                "item macro {:?}",
                mac.mac.path.segments.last().map(|s| s.ident.to_string())
            )),
            syn::Item::Use(u) if exposed(&u.vis) => {
                found.unsupported.push("an exposed `use`".to_owned());
            }
            _ => {}
        }
    }
}

/// Every function of the judge reachable from outside it (`pub` of any
/// scope, a trait impl's method, or an exposed trait's default method) that
/// takes a `&Firewall` opens with the `judging` gate, so a new entry point
/// added later fails here unless it is gated or is one of the top-level free
/// functions named in [`NOT_ENTRIES`] with its reason. An item the walk
/// cannot see into fails it too, so a future one is a decision, not a gap.
#[test]
fn every_judge_entry_opens_with_the_judging_gate() {
    let source = std::fs::read_to_string(format!("{SRC}/{JUDGE}")).expect("read judge");
    let file = syn::parse_file(&source).expect("the judge parses");
    let mut found = Entries {
        taken: taken_names(&file.items),
        ..Entries::default()
    };
    entries(&file.items, true, &mut found);
    assert!(
        found.unsupported.is_empty(),
        "the judge has items this check cannot see into: {:?}",
        found.unsupported
    );
    assert!(
        found.ungated.is_empty(),
        "these take a firewall and are reachable from outside the judge, but do not open \
         with `let Some(..) = judging(firewall) else ..`: {:?}",
        found.ungated
    );
    for entry in ["delivered", "admit", "admit_stream_item"] {
        assert!(
            found.gated.iter().any(|g| g == entry),
            "positive control: {entry} was checked ({:?})",
            found.gated
        );
    }
    let outbound =
        std::fs::read_to_string(format!("{SRC}/gateway/outbound/mod.rs")).expect("read outbound");
    let start = outbound
        .find("pub(crate) fn judges(")
        .expect("premise: judges is in outbound");
    let end = outbound[start..].find("\n}\n").expect("judges ends") + start;
    assert!(
        outbound[start..end].contains("judge::judging("),
        "outbound::judges asks judge::judging"
    );
}

/// The checker accepts the real gate (as a free function, a method and a
/// function two modules down) and skips private functions, and refuses each
/// ungated shape: an inverted gate, a narrowing gate (a variant by path or
/// through a lowercase `use` alias), a gate under an attribute that can
/// compile it out, an ungated inherent, trait-impl and default trait method,
/// an ungated nested function, and an exempt name used anywhere but at the
/// top level. Items it cannot see into, macros in `impl` and trait bodies
/// included, are reported.
#[test]
fn the_gate_check_refuses_each_ungated_shape() {
    let source = r"
        pub(crate) fn gated(firewall: &Firewall) {
            let Some((guard, mode)) = judging(firewall) else { return; };
        }
        pub(crate) fn inverted(firewall: &Firewall) {
            let None = judging(firewall) else { return; };
        }
        pub(crate) fn narrowing(firewall: &Firewall) {
            let Some((guard, CrossTenantReads::Off)) = judging(firewall) else { return; };
        }
        use CrossTenantReads::Off as off;
        pub(crate) fn aliased(firewall: &Firewall) {
            let Some((guard, off)) = judging(firewall) else { return; };
        }
        pub(crate) fn disabled(firewall: &Firewall) {
            #[cfg(any())]
            let Some((guard, mode)) = judging(firewall) else { return; };
        }
        impl Generated {
            make_entry!();
        }
        pub(crate) trait Made {
            make_entry!();
        }
        impl Judge {
            pub(crate) fn gated_method(&self, firewall: &Firewall) {
                let Some((_, mode)) = judging(firewall) else { return; };
            }
            pub(crate) fn method(&self, firewall: &Firewall) {}
            pub(crate) fn attribute(&self, firewall: &Firewall) {}
            fn private_method(&self, firewall: &Firewall) {}
        }
        impl Entry for Judge {
            fn entry(firewall: &Firewall) {}
        }
        pub(crate) trait Defaulted {
            fn defaulted(firewall: &Firewall) {}
        }
        mod nested {
            pub(crate) fn inner(firewall: &Firewall) {}
            pub(crate) fn judging(firewall: &Firewall) {}
            mod deeper {
                pub(crate) fn deep_gated(firewall: &Firewall) {
                    let Some(both) = judging(firewall) else { return; };
                }
            }
        }
        mod elsewhere;
        some_macro! {}
        pub(crate) use inner::hidden;
        fn private(firewall: &Firewall) {}
        pub(crate) fn attribute(firewall: &Firewall) {}
    ";
    let file = syn::parse_file(source).expect("the fixture parses");
    let mut found = Entries {
        taken: taken_names(&file.items),
        ..Entries::default()
    };
    entries(&file.items, true, &mut found);
    found.gated.sort();
    found.ungated.sort();
    assert_eq!(found.gated, ["deep_gated", "gated", "gated_method"]);
    assert_eq!(
        found.ungated,
        [
            "aliased",
            "attribute",
            "defaulted",
            "disabled",
            "entry",
            "inner",
            "inverted",
            "judging",
            "method",
            "narrowing"
        ],
        "each exposed ungated shape is caught; the top-level `attribute` is exempt, \
         the method and nested fn sharing an exempt name are not"
    );
    found.unsupported.sort();
    assert_eq!(
        found.unsupported,
        [
            "a macro in a trait",
            "a macro in an impl",
            "an exposed `use`",
            "item macro Some(\"some_macro\")",
            "mod elsewhere;",
        ],
        "each item the walk cannot see into is reported"
    );
}
