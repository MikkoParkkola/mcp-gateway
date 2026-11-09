// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each judge entry point opens with the `judging` gate (every function the
//! judge exposes, found by parsing it, bar two named ones), the judge holds no
//! item the check cannot see through, and the frame-level check asks the same
//! gate in its one shape, so the verdict decides whether to judge in one
//! place. The judge's read token keeps one shape and is built only in its one
//! read chain (`token_check`). Everything is read as syntax, never as text.
//! That only the judge reaches the read history is pinned by the
//! production-node scan in `meta_mcp::boundary_pins::read_history_access`.

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const JUDGE: &str = "gateway/outbound/judge.rs";

/// An identifier as written, with any `r#` removed: `r#off` is `off`.
fn plain(ident: &syn::Ident) -> String {
    use syn::ext::IdentExt;
    ident.unraw().to_string()
}

/// The judge's exposed functions that are not entry points to the verdict,
/// each with why it needs no gate. Every other exposed function of the judge
/// is an entry, whatever its parameters; a way in through another item kind
/// (a method, a trait, another module) is reported unsupported.
const NOT_ENTRIES: [(&str, &str); 2] = [
    ("judging", "the gate itself"),
    (
        "attribute",
        "labels a raw value's tenants for an outbox record; never reaches the read history",
    ),
];

/// Names one module brings into its own scope that a bare identifier
/// pattern would match instead of binding: every `use` leaf and rename, and
/// every `const` and `static`, unrawed.
fn taken_names(items: &[syn::Item]) -> std::collections::HashSet<String> {
    fn tree(t: &syn::UseTree, out: &mut std::collections::HashSet<String>) {
        match t {
            syn::UseTree::Path(p) => tree(&p.tree, out),
            syn::UseTree::Name(n) => {
                out.insert(plain(&n.ident));
            }
            syn::UseTree::Rename(r) => {
                out.insert(plain(&r.rename));
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
                out.insert(plain(&c.ident));
            }
            syn::Item::Static(s) => {
                out.insert(plain(&s.ident));
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
            let name = plain(&binding.ident);
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

/// Whether `stmt` is `let Some(<irrefutable>) = judging(firewall) else { .. };`
/// with the callee the bare name `judging` (the judge's own: Rust allows no
/// second top-level `judging` beside it, and a glob never shadows a local
/// item) and `firewall` one of the entry's `params`.
fn is_judging_gate(
    stmt: &syn::Stmt,
    taken: &std::collections::HashSet<String>,
    params: &[String],
) -> bool {
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
    let bare = |path: &syn::Path, name: &str| {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments[0].arguments.is_none()
            && plain(&path.segments[0].ident) == name
    };
    if !bare(&bound.path, "Some")
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
    let gate = func.qself.is_none() && bare(&func.path, "judging");
    let on_firewall = call.args.len() == 1
        && matches!(
            call.args.first(),
            Some(syn::Expr::Path(arg)) if arg.qself.is_none() && bare(&arg.path, "firewall")
        )
        && params.iter().any(|p| p == "firewall");
    gate && on_firewall && init.diverge.is_some()
}

/// What the check of the judge found.
#[derive(Default)]
struct Entries {
    /// Exposed functions that open with the gate.
    gated: Vec<String>,
    /// Exposed functions that do not.
    ungated: Vec<String>,
    /// What the check does not accept, so an entry could hide there: any item
    /// but a private `use`, a `const` with a literal or path value and a `fn`;
    /// any attribute but `doc`; any macro.
    unsupported: Vec<String>,
    /// Names the judge brings into scope ([`taken_names`]).
    taken: std::collections::HashSet<String>,
}

/// Whether `ty` is a type an exposed `const` may have: a primitive number,
/// `bool`, `char` or `&str`. A function pointer would export an ungated way
/// in under a name no entry check sees.
/// A primitive name the file imports (`use ..::Ptr as usize;`), or any name
/// under a glob import, may stand for anything, so it is not plain.
fn plain_value(ty: &syn::Type, taken: &std::collections::HashSet<String>) -> bool {
    const PRIMITIVES: [&str; 16] = [
        "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
        "f32", "f64", "bool", "char",
    ];
    match ty {
        syn::Type::Path(p) => {
            p.qself.is_none()
                && p.path.segments.len() == 1
                && p.path.segments[0].arguments.is_none()
                && PRIMITIVES.contains(&plain(&p.path.segments[0].ident).as_str())
                && !taken.contains(&plain(&p.path.segments[0].ident))
                && !taken.contains("*")
        }
        syn::Type::Reference(r) => {
            r.mutability.is_none()
                && matches!(&*r.elem, syn::Type::Path(p) if p.qself.is_none()
                    && p.path.is_ident("str"))
                && !taken.contains("str")
                && !taken.contains("*")
        }
        _ => false,
    }
}

/// Whether every attribute is a doc comment.
fn doc_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|a| a.path().is_ident("doc"))
}

/// Whether `attrs` is exactly `#[cfg(test)]`.
fn cfg_test_only(attrs: &[syn::Attribute]) -> bool {
    matches!(attrs, [only] if only.path().is_ident("cfg")
        && only.parse_args::<syn::Path>().is_ok_and(|p| p.is_ident("test")))
}

/// The names a signature's parameters bind, unrawed.
fn param_names(sig: &syn::Signature) -> Vec<String> {
    struct Names(Vec<String>);
    impl<'ast> syn::visit::Visit<'ast> for Names {
        fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
            self.0.push(plain(&pat.ident));
            syn::visit::visit_pat_ident(self, pat);
        }
    }
    let mut names = Names(Vec::new());
    for input in &sig.inputs {
        if let syn::FnArg::Typed(typed) = input {
            syn::visit::Visit::visit_pat(&mut names, &typed.pat);
        }
    }
    names.0
}

/// The macros and the items inside a function body, at any depth.
#[derive(Default)]
struct Inside {
    macros: usize,
    items: usize,
}

impl<'ast> syn::visit::Visit<'ast> for Inside {
    fn visit_macro(&mut self, _: &'ast syn::Macro) {
        self.macros += 1;
    }
    fn visit_item(&mut self, item: &'ast syn::Item) {
        self.items += 1;
        // Into it too: a macro in a nested item is still a macro. Today every
        // item holding an item is refused anyway (see the const arm in
        // `entries`), so this only picks the reason; it guards the verdict
        // if that rule is relaxed.
        syn::visit::visit_item(self, item);
    }
}

impl Entries {
    /// One top-level function. An exposed one that is not in [`NOT_ENTRIES`]
    /// is an entry: it must open with the gate, bind no parameter named
    /// `judging`, and declare no item in its body (a block item is visible
    /// in the whole block, before the gate too).
    fn check(&mut self, f: &syn::ItemFn) {
        let name = plain(&f.sig.ident);
        if !doc_only(&f.attrs) {
            self.unsupported.push(format!("an attribute on {name}"));
            return;
        }
        let mut inside = Inside::default();
        // The whole item: a macro in a signature (`fn f(_: ty!())`) counts too.
        syn::visit::Visit::visit_item_fn(&mut inside, f);
        if inside.macros > 0 {
            self.unsupported.push(format!("a macro in {name}"));
            return;
        }
        let exposed = !matches!(f.vis, syn::Visibility::Inherited);
        if !exposed || NOT_ENTRIES.iter().any(|(n, _)| *n == name) {
            if inside.items > 0 {
                self.unsupported.push(format!("an item inside {name}"));
            }
            return;
        }
        let params = param_names(&f.sig);
        let opens = f
            .block
            .stmts
            .first()
            .is_some_and(|stmt| is_judging_gate(stmt, &self.taken, &params));
        if opens && inside.items == 0 && !params.iter().any(|p| p == "judging") {
            self.gated.push(name);
        } else {
            self.ungated.push(name);
        }
    }
}

/// Check the judge's items against the one shape it may have: private `use`
/// items, `const` items with a literal or path value and `fn` items, with doc
/// comments only, and one inline `#[cfg(test)]` module, skipped. Anything
/// else is reported, so a new kind of item is a decision, not a gap.
fn entries(file: &syn::File, found: &mut Entries) {
    if !doc_only(&file.attrs) {
        found.unsupported.push("an inner attribute".to_owned());
    }
    let mut test_modules = 0;
    let mut token_seen = false;
    for item in &file.items {
        let name = |ident: &syn::Ident| plain(ident);
        let refused = match item {
            // Test-only code is not in a product build: the read history's
            // own tests take their token from here.
            syn::Item::Fn(f) if cfg_test_fn(&f.attrs) => None,
            syn::Item::Fn(f) => {
                found.check(f);
                None
            }
            syn::Item::Use(u) if !matches!(u.vis, syn::Visibility::Inherited) => {
                Some("an exposed `use`".to_owned())
            }
            syn::Item::Use(u) => {
                (!doc_only(&u.attrs)).then(|| "an attribute on a `use`".to_owned())
            }
            syn::Item::Const(c) => {
                let mut inside = Inside::default();
                syn::visit::Visit::visit_item_const(&mut inside, c);
                // A const holding any item is refused outright. While this
                // rule stands, the recursion into nested items in `Inside`
                // only changes the reason a shape is refused, never whether:
                // relax it and that recursion becomes load-bearing again.
                (!doc_only(&c.attrs)
                    || inside.macros > 0
                    || inside.items > 0
                    || !matches!(*c.expr, syn::Expr::Lit(_) | syn::Expr::Path(_))
                    || (!matches!(c.vis, syn::Visibility::Inherited)
                        && !plain_value(&c.ty, &found.taken)))
                .then(|| format!("const {}", name(&c.ident)))
            }
            syn::Item::Mod(m) if m.content.is_some() && cfg_test_only(&m.attrs) => {
                test_modules += 1;
                None
            }
            syn::Item::Mod(m) if m.content.is_some() => Some(format!("mod {}", name(&m.ident))),
            syn::Item::Mod(m) => Some(format!("mod {};", name(&m.ident))),
            syn::Item::Impl(i) => Some(match &*i.self_ty {
                syn::Type::Path(t) => t
                    .path
                    .segments
                    .last()
                    .map_or("impl".to_owned(), |s| format!("impl {}", name(&s.ident))),
                _ => "impl".to_owned(),
            }),
            syn::Item::Trait(t) => Some(format!("trait {}", name(&t.ident))),
            // The read token, in its one shape, once.
            syn::Item::Struct(s) if token_struct(s) && !token_seen => {
                token_seen = true;
                None
            }
            syn::Item::Struct(s) => Some(format!("struct {}", name(&s.ident))),
            syn::Item::Enum(e) => Some(format!("enum {}", name(&e.ident))),
            syn::Item::Static(s) => Some(format!("static {}", name(&s.ident))),
            syn::Item::Macro(m) => Some(format!(
                "item macro {}",
                m.mac
                    .path
                    .segments
                    .last()
                    .map_or(String::new(), |s| name(&s.ident))
            )),
            _ => Some("an unsupported item".to_owned()),
        };
        found.unsupported.extend(refused);
    }
    if test_modules > 1 {
        found
            .unsupported
            .push("more than one test module".to_owned());
    }
}

/// Every exposed function of the judge, whatever its parameters, opens with
/// the `judging` gate, unless it is named in [`NOT_ENTRIES`] with its reason;
/// the judge holds nothing the check cannot see through; `outbound::judges`
/// asks the gate in its one shape; and no attribute on the module
/// declarations leading to the judge can swap the source the check reads.
#[test]
fn every_judge_entry_opens_with_the_judging_gate() {
    let source = std::fs::read_to_string(format!("{SRC}/{JUDGE}")).expect("read judge");
    let file = syn::parse_file(&source).expect("the judge parses");
    let mut found = Entries {
        taken: taken_names(&file.items),
        ..Entries::default()
    };
    entries(&file, &mut found);
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
    assert_eq!(
        token_findings(&file),
        Vec::<String>::new(),
        "the judge builds the read token only in its one read chain"
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

/// Whether `expr` is the plain path `segs`, every segment unrawed.
fn path_is(expr: &syn::Expr, segs: &[&str]) -> bool {
    matches!(expr, syn::Expr::Path(p) if p.qself.is_none()
    && p.attrs.is_empty()
    && p.path.leading_colon.is_none()
    && p.path.segments.len() == segs.len()
    && p.path.segments.iter().zip(segs).all(|(s, want)| {
        s.arguments.is_none() && plain(&s.ident) == *want
    }))
}

/// `Some(true)` for exactly `#[cfg(feature = "firewall")]`, `Some(false)`
/// for exactly `#[cfg(not(feature = "firewall"))]`, else `None`.
fn firewall_cfg(attrs: &[syn::Attribute]) -> Option<bool> {
    let [only] = attrs else { return None };
    if !only.path().is_ident("cfg") {
        return None;
    }
    let is_feature = |meta: &syn::Meta| {
        matches!(meta, syn::Meta::NameValue(nv) if nv.path.is_ident("feature")
            && matches!(&nv.value, syn::Expr::Lit(lit) if lit.attrs.is_empty()
                && matches!(&lit.lit, syn::Lit::Str(s) if s.value() == "firewall")))
    };
    let meta: syn::Meta = only.parse_args().ok()?;
    if is_feature(&meta) {
        return Some(true);
    }
    if let syn::Meta::List(list) = &meta
        && list.path.is_ident("not")
        && list
            .parse_args::<syn::Meta>()
            .is_ok_and(|inner| is_feature(&inner))
    {
        return Some(false);
    }
    None
}

/// Whether `tail` is `guard.is_some_and(|P| judge::judging(P).is_some())`.
fn asks_the_gate(tail: &syn::Expr) -> bool {
    let syn::Expr::MethodCall(outer) = tail else {
        return false;
    };
    if !path_is(&outer.receiver, &["guard"])
        || plain(&outer.method) != "is_some_and"
        || outer.turbofish.is_some()
        || outer.args.len() != 1
    {
        return false;
    }
    let Some(syn::Expr::Closure(closure)) = outer.args.first() else {
        return false;
    };
    if closure.inputs.len() != 1 || !matches!(closure.output, syn::ReturnType::Default) {
        return false;
    }
    let syn::Pat::Ident(param) = &closure.inputs[0] else {
        return false;
    };
    let p = plain(&param.ident);
    let syn::Expr::MethodCall(some) = &*closure.body else {
        return false;
    };
    let syn::Expr::Call(call) = &*some.receiver else {
        return false;
    };
    param.subpat.is_none()
        && plain(&some.method) == "is_some"
        && some.args.is_empty()
        && some.turbofish.is_none()
        && path_is(&call.func, &["judge", "judging"])
        && call.args.len() == 1
        && path_is(&call.args[0], &[p.as_str()])
}

/// Whether `ty` is exactly `Option<&Guard>`: a guard of another type could
/// answer `is_some_and` without asking the gate.
fn option_of_guard_ref(ty: &syn::Type) -> bool {
    let syn::Type::Path(option) = ty else {
        return false;
    };
    let [segment] = option.path.segments.iter().collect::<Vec<_>>()[..] else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return false;
    };
    option.qself.is_none()
        && plain(&segment.ident) == "Option"
        && args.args.len() == 1
        && matches!(&args.args[0], syn::GenericArgument::Type(syn::Type::Reference(r))
            if r.mutability.is_none()
                && r.lifetime.is_none()
                && matches!(&*r.elem, syn::Type::Path(g) if g.qself.is_none() && g.path.is_ident("Guard")))
}

/// Whether `source` holds `outbound::judges` in its one accepted shape: doc
/// comments only, no generics, one parameter `guard`, and a body of exactly
/// the firewall block asking the gate and the no-firewall block answering
/// `false`.
fn judges_check(source: &str) -> Result<(), String> {
    let file = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut found = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(f) if plain(&f.sig.ident) == "judges" => Some(f),
        _ => None,
    });
    let f = found.next().ok_or("no top-level fn judges")?;
    if found.next().is_some() {
        return Err("two fn judges".to_owned());
    }
    let sig = &f.sig;
    let one_guard = sig.inputs.len() == 1
        && matches!(&sig.inputs[0], syn::FnArg::Typed(t) if t.attrs.is_empty()
            && matches!(&*t.pat, syn::Pat::Ident(p) if plain(&p.ident) == "guard"
                && p.subpat.is_none() && p.by_ref.is_none() && p.mutability.is_none())
            && option_of_guard_ref(&t.ty));
    if !doc_only(&f.attrs)
        || !sig.generics.params.is_empty()
        || sig.generics.where_clause.is_some()
        || !one_guard
    {
        return Err("judges has another signature".to_owned());
    }
    let [
        syn::Stmt::Expr(syn::Expr::Block(on), None),
        syn::Stmt::Expr(syn::Expr::Block(off), None),
    ] = f.block.stmts.as_slice()
    else {
        return Err("judges has another body".to_owned());
    };
    let on_ok = firewall_cfg(&on.attrs) == Some(true)
        && on.label.is_none()
        && matches!(on.block.stmts.as_slice(), [syn::Stmt::Expr(tail, None)] if asks_the_gate(tail));
    let off_ok = firewall_cfg(&off.attrs) == Some(false)
        && off.label.is_none()
        && matches!(off.block.stmts.as_slice(), [
            syn::Stmt::Local(local),
            syn::Stmt::Expr(syn::Expr::Lit(no), None),
        ] if local.attrs.is_empty()
            && matches!(local.pat, syn::Pat::Wild(_))
            && local.init.as_ref().is_some_and(|i| i.diverge.is_none() && path_is(&i.expr, &["guard"]))
            && no.attrs.is_empty()
            && matches!(no.lit, syn::Lit::Bool(ref b) if !b.value));
    if on_ok && off_ok {
        Ok(())
    } else {
        Err("judges does not ask judge::judging in its one shape".to_owned())
    }
}

/// Whether each `mod <name>;` declaration in `chain` (file text, module
/// name) is there once and carries only `doc` and `cfg(..)` attributes, so
/// no attribute macro can replace the module the scans read.
fn chain_check(chain: &[(&str, &str)]) -> Result<(), String> {
    for (text, module) in chain {
        let file = syn::parse_file(text).map_err(|e| e.to_string())?;
        let decls: Vec<&syn::ItemMod> = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(m) if plain(&m.ident) == *module => Some(m),
                _ => None,
            })
            .collect();
        let [decl] = decls.as_slice() else {
            return Err(format!("mod {module} is not declared once"));
        };
        if decl.content.is_some()
            || !decl.attrs.iter().all(|a| {
                a.path().is_ident("doc") || firewall_cfg(std::slice::from_ref(a)) == Some(true)
            })
        {
            return Err(format!("mod {module} carries another attribute"));
        }
    }
    Ok(())
}

/// The checkers' own rows: each shape they must accept, and each they must
/// refuse.
#[path = "read_scope_scan_rows_tests.rs"]
mod rows;

#[path = "read_scope_token_check_tests.rs"]
mod token_check;
use token_check::{cfg_test_fn, token_findings, token_struct};

#[path = "read_scope_token_rows_tests.rs"]
mod token_rows;
