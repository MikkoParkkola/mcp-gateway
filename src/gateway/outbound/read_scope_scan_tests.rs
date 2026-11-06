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

/// Whether `stmt` is `let Some(..) = judging(firewall) else { .. };`.
fn is_judging_gate(stmt: &syn::Stmt) -> bool {
    let syn::Stmt::Local(local) = stmt else {
        return false;
    };
    // The gate binds `Some(..)`: an inverted `let None = judging(..) else`
    // would run the body exactly when the verdict is off.
    let syn::Pat::TupleStruct(bound) = &local.pat else {
        return false;
    };
    if !bound.path.is_ident("Some") {
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

/// The judge's exposed functions that take a `&Firewall` and are not named
/// in [`NOT_ENTRIES`], split into those that open with the gate and those
/// that do not. Free functions, methods in `impl` blocks (a trait impl's
/// methods count as exposed) and functions in nested inline modules.
fn entries(items: &[syn::Item]) -> (Vec<String>, Vec<String>) {
    fn check(
        (sig, exposed, block): (&syn::Signature, bool, &syn::Block),
        found: &mut (Vec<String>, Vec<String>),
    ) {
        let name = sig.ident.to_string();
        let takes_firewall = sig
            .inputs
            .iter()
            .any(|input| matches!(input, syn::FnArg::Typed(arg) if is_firewall_ref(&arg.ty)));
        if !exposed || !takes_firewall || NOT_ENTRIES.iter().any(|(n, _)| *n == name) {
            return;
        }
        if block.stmts.first().is_some_and(is_judging_gate) {
            found.0.push(name);
        } else {
            found.1.push(name);
        }
    }
    let exposed = |vis: &syn::Visibility| !matches!(vis, syn::Visibility::Inherited);
    let mut found = (Vec::new(), Vec::new());
    for item in items {
        match item {
            syn::Item::Fn(f) => check((&f.sig, exposed(&f.vis), &f.block), &mut found),
            syn::Item::Impl(block) => {
                for inner in &block.items {
                    if let syn::ImplItem::Fn(m) = inner {
                        let open = block.trait_.is_some() || exposed(&m.vis);
                        check((&m.sig, open, &m.block), &mut found);
                    }
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    let (gated, ungated) = entries(inner);
                    found.0.extend(gated);
                    found.1.extend(ungated);
                }
            }
            _ => {}
        }
    }
    found
}

/// Every function of the judge reachable from outside it (`pub` of any
/// scope, or a trait impl's method) that takes a `&Firewall` opens with the
/// `judging` gate, so a new entry point added later fails here unless it is
/// gated or named in [`NOT_ENTRIES`] with its reason.
#[test]
fn every_judge_entry_opens_with_the_judging_gate() {
    let source = std::fs::read_to_string(format!("{SRC}/{JUDGE}")).expect("read judge");
    let file = syn::parse_file(&source).expect("the judge parses");
    let (gated, ungated) = entries(&file.items);
    assert!(
        ungated.is_empty(),
        "these take a firewall and are reachable from outside the judge, but do not open \
         with `let Some(..) = judging(firewall) else ..`: {ungated:?}"
    );
    for entry in ["delivered", "admit", "admit_stream_item"] {
        assert!(
            gated.iter().any(|g| g == entry),
            "positive control: {entry} was checked ({gated:?})"
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

/// The checker refuses an inverted gate, an ungated method in an `impl`
/// block, an ungated trait-impl method and an ungated function in a nested
/// module, and accepts the real gate.
#[test]
fn the_gate_check_refuses_each_ungated_shape() {
    let source = r#"
        pub(crate) fn gated(firewall: &Firewall) {
            let Some((guard, mode)) = judging(firewall) else { return; };
        }
        pub(crate) fn inverted(firewall: &Firewall) {
            let None = judging(firewall) else { return; };
        }
        impl Judge {
            pub(crate) fn method(&self, firewall: &Firewall) {}
        }
        impl Entry for Judge {
            fn entry(firewall: &Firewall) {}
        }
        mod nested {
            pub(crate) fn inner(firewall: &Firewall) {}
        }
        fn private(firewall: &Firewall) {}
    "#;
    let file = syn::parse_file(source).expect("the fixture parses");
    let (gated, mut ungated) = entries(&file.items);
    ungated.sort();
    assert_eq!(gated, ["gated"], "only the real gate passes");
    assert_eq!(
        ungated,
        ["entry", "inner", "inverted", "method"],
        "each exposed ungated shape is caught; the private fn is not an entry"
    );
}
