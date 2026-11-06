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

/// Every function of the judge reachable from outside it (`pub` of any
/// scope) that takes a `&Firewall` opens with the `judging` gate, so a new
/// entry point added later fails here unless it is gated or named in
/// [`NOT_ENTRIES`] with its reason.
#[test]
fn every_judge_entry_opens_with_the_judging_gate() {
    let source = std::fs::read_to_string(format!("{SRC}/{JUDGE}")).expect("read judge");
    let file = syn::parse_file(&source).expect("the judge parses");
    let mut gated = Vec::new();
    for item in &file.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        let name = function.sig.ident.to_string();
        let takes_firewall = function
            .sig
            .inputs
            .iter()
            .any(|input| matches!(input, syn::FnArg::Typed(arg) if is_firewall_ref(&arg.ty)));
        if matches!(function.vis, syn::Visibility::Inherited)
            || !takes_firewall
            || NOT_ENTRIES.iter().any(|(n, _)| *n == name)
        {
            continue;
        }
        assert!(
            function.block.stmts.first().is_some_and(is_judging_gate),
            "{name} takes a firewall and is reachable from outside the judge, but does not \
             open with `let Some(..) = judging(firewall) else ..`"
        );
        gated.push(name);
    }
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
