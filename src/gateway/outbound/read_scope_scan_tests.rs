// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each judge entry point opens with the `judging` gate (every function or
//! method the judge exposes, found by parsing it, bar two named ones), and the
//! frame-level check asks the same gate, so the verdict decides whether to judge in one
//! place. That only the judge reaches the read history is pinned by the
//! production-node scan in `meta_mcp::boundary_pins::read_history_access`.

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const JUDGE: &str = "gateway/outbound/judge.rs";

/// The judge's exposed top-level functions that are not entry points to the
/// verdict, each with why it needs no gate. Every other exposed function or
/// method of the judge is an entry, whatever its parameters, so a new way
/// in (generic, by trait, through another type) cannot be missed by how it
/// is spelled.
const NOT_ENTRIES: [(&str, &str); 2] = [
    ("judging", "the gate itself"),
    (
        "attribute",
        "labels a raw value's tenants for an outbox record; never reaches the read history",
    ),
];

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
    /// Exposed functions that open with the gate.
    gated: Vec<String>,
    /// Exposed functions that do not.
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
        if !exposed || exempt {
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
/// scope, a trait impl's method, or an exposed trait's default method),
/// whatever its parameters, opens with the `judging` gate, so a new entry point
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
    let read = |file: &str| std::fs::read_to_string(format!("{SRC}/{file}")).expect("read source");
    let outbound = read("gateway/outbound/mod.rs");
    assert_eq!(
        judges_check(&outbound),
        Ok(()),
        "outbound::judges asks judge::judging"
    );
    let (lib, gateway) = (read("lib.rs"), read("gateway/mod.rs"));
    assert_eq!(
        chain_check(&[
            (&lib, "gateway"),
            (&gateway, "outbound"),
            (&outbound, "judge")
        ]),
        Ok(()),
        "the module declarations on the way to the judge carry only doc and cfg attributes"
    );
}

/// The checker accepts the real gate, bare `judging` (raw or not) on a
/// `firewall` parameter, and refuses each other shape: an inverted or a
/// narrowing gate (by path, through a `use` alias, raw), another path to a
/// `judging`, a `firewall` that is not a parameter, a parameter or a body
/// item that shadows `judging`, a gate under an attribute. Any item kind
/// other than `use`, `const` with a literal or path value and `fn`, any
/// attribute but `doc`, and any macro is reported unsupported; one inline
/// `#[cfg(test)]` module is skipped.
#[test]
fn the_gate_check_refuses_each_ungated_shape() {
    let source = r"
        pub(crate) fn gated(firewall: &Firewall) {
            let Some((guard, mode)) = judging(firewall) else { return; };
        }
        pub(crate) fn gated_raw(firewall: &Firewall) {
            let Some((guard, mode)) = r#judging(firewall) else { return; };
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
        pub(crate) fn raw_alias(firewall: &Firewall) {
            let Some((guard, r#off)) = judging(firewall) else { return; };
        }
        pub(crate) fn generic<F: AsRef<Firewall>>(firewall: &F) {}
        pub(crate) fn foreign(firewall: &Firewall) {
            let Some(both) = bypass::judging(firewall) else { return; };
        }
        pub(crate) fn crate_path(firewall: &Firewall) {
            let Some(both) = crate::gateway::outbound::judge::judging(firewall) else { return; };
        }
        const firewall: &Firewall = FW;
        pub(crate) fn param_less() {
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn shadowed_param(judging: Pick, firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn local_item(firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
            fn judging(_: &Firewall) -> Option<()> { Some(()) }
        }
        pub(crate) fn disabled(firewall: &Firewall) {
            #[cfg(any())]
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn attribute(firewall: &Firewall) {}
        fn private(firewall: &Firewall) {}
        impl Judge {
            pub(crate) fn method(&self, firewall: &Firewall) {}
        }
        pub(crate) trait Made {}
        #[derive(Default)]
        struct Generated;
        const _: () = {};
        static FW2: u8 = 0;
        some_macro! {}
        mod elsewhere;
        mod nested {
            pub(crate) fn inner(firewall: &Firewall) {}
        }
        #[cfg(test)]
        mod tests {
            pub(crate) fn ungated_test(firewall: &Firewall) {}
        }
        #[inline]
        pub(crate) fn hinted(firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
        }
        pub(crate) fn with_macro(firewall: &Firewall) {
            let Some(both) = judging(firewall) else { return; };
            debug_assert!(true);
        }
        pub(crate) use inner::hidden;
    ";
    let file = syn::parse_file(source).expect("the fixture parses");
    let mut found = Entries {
        taken: taken_names(&file.items),
        ..Entries::default()
    };
    entries(&file.items, true, &mut found);
    found.gated.sort();
    found.ungated.sort();
    found.unsupported.sort();
    assert_eq!(found.gated, ["gated", "gated_raw"]);
    assert_eq!(
        found.ungated,
        [
            "aliased",
            "crate_path",
            "disabled",
            "foreign",
            "generic",
            "inverted",
            "local_item",
            "narrowing",
            "param_less",
            "raw_alias",
            "shadowed_param",
        ],
        "each exposed ungated shape is caught; the top-level `attribute` is exempt"
    );
    assert_eq!(
        found.unsupported,
        [
            "a macro in with_macro",
            "an attribute on hinted",
            "an exposed `use`",
            "const _",
            "impl Judge",
            "item macro some_macro",
            "mod elsewhere;",
            "mod nested",
            "static FW2",
            "struct Generated",
            "trait Made",
        ],
        "each item the check does not accept is reported; the cfg(test) module is skipped"
    );
}

/// Whether `source` holds `outbound::judges` in its one accepted shape.
/// Red-row stub: today's text test, to be replaced by the syntax check.
fn judges_check(source: &str) -> Result<(), String> {
    let start = source.find("pub(crate) fn judges(").ok_or("no judges")?;
    let end = source[start..]
        .find("\n}\n")
        .map_or(source.len(), |e| e + start);
    if source[start..end].contains("judge::judging(") {
        Ok(())
    } else {
        Err("judges does not ask judge::judging".to_owned())
    }
}

/// Whether each `mod <name>;` declaration in `chain` (file text, module
/// name) carries only `doc` and `cfg(..)` attributes. Red-row stub.
fn chain_check(chain: &[(&str, &str)]) -> Result<(), String> {
    let _ = chain;
    Ok(())
}

const REAL_JUDGES: &str = r#"
/// Whether `guard` judges frames at all.
pub(crate) fn judges(guard: Option<&Guard>) -> bool {
    #[cfg(feature = "firewall")]
    {
        guard.is_some_and(|g| judge::judging(g).is_some())
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = guard;
        false
    }
}
"#;

/// `judges()` is accepted only in its one real shape, signature and whole
/// body: a comment naming the gate, a dead call, another path or argument,
/// a missing or extra attribute, an early return, a local module, a generic
/// parameter or a cfg'd parameter are each refused. A module declaration on
/// the way to the judge carrying a non-cfg attribute is refused too.
#[test]
fn the_judges_check_refuses_each_other_shape() {
    assert_eq!(
        judges_check(REAL_JUDGES),
        Ok(()),
        "the real shape is accepted"
    );
    let tail = "guard.is_some_and(|g| judge::judging(g).is_some())";
    let open = "-> bool {\n";
    let fw = "#[cfg(feature = \"firewall\")]\n";
    for (name, from, to) in [
        (
            "comment_only",
            tail,
            "// judge::judging(g)\n        guard.is_some()",
        ),
        (
            "dead_call",
            tail,
            "let _ = guard.map(judge::judging);\n        true",
        ),
        (
            "self_path",
            tail,
            "guard.is_some_and(|g| self::judge::judging(g).is_some())",
        ),
        (
            "other_arg",
            tail,
            "guard.is_some_and(|g| judge::judging(other).is_some())",
        ),
        (
            "is_none",
            tail,
            "guard.is_some_and(|g| judge::judging(g).is_none())",
        ),
        ("no_cfg_block", fw, ""),
        (
            "extra_attr",
            fw,
            "#[cfg(feature = \"firewall\")]\n    #[allow(unused)]\n",
        ),
        ("early_return", open, "-> bool {\n    return false;\n"),
        (
            "local_mod",
            open,
            "-> bool {\n    mod judge { pub fn judging<T>(_: T) -> Option<()> { Some(()) } }\n",
        ),
        ("generic_judge", "fn judges(", "fn judges<judge: Pick>("),
        (
            "cfg_param",
            "fn judges(guard",
            "fn judges(#[cfg(test)] guard",
        ),
    ] {
        assert_eq!(
            REAL_JUDGES.matches(from).count(),
            1,
            "{name}: one site to change"
        );
        let mutated = REAL_JUDGES.replacen(from, to, 1);
        assert!(
            judges_check(&mutated).is_err(),
            "{name} is refused:\n{mutated}"
        );
    }
    let chain = [
        ("#[doc(hidden)]\npub mod gateway;\n", "gateway"),
        ("pub(crate) mod outbound;\n", "outbound"),
        ("#[cfg(feature = \"firewall\")]\nmod judge;\n", "judge"),
    ];
    assert_eq!(chain_check(&chain), Ok(()), "the real chain is accepted");
    let mut swapped = chain;
    swapped[2].0 = "#[cfg(feature = \"firewall\")]\n#[some_macro]\nmod judge;\n";
    assert!(
        chain_check(&swapped).is_err(),
        "an attribute macro on `mod judge;` is refused"
    );
}
