// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The read token's shape in the judge: one token type of one shape, built
//! only as an argument of the one read chain, on the real firewall, in
//! `assess`, outside async code. The compiler keeps every other module from
//! building a token; this keeps the judge itself from handing one out.

use super::{cfg_test_only, doc_only, path_is, plain};

/// Whether `s` is the one admitted token type:
/// `pub(crate) struct ReadsToken(std::cell::Cell<()>);` with doc comments only.
pub(super) fn token_struct(s: &syn::ItemStruct) -> bool {
    let crate_visible = matches!(&s.vis, syn::Visibility::Restricted(r)
        if r.in_token.is_none() && r.path.is_ident("crate"));
    let syn::Fields::Unnamed(fields) = &s.fields else {
        return false;
    };
    plain(&s.ident) == "ReadsToken"
        && doc_only(&s.attrs)
        && crate_visible
        && s.generics.params.is_empty()
        && s.generics.where_clause.is_none()
        && fields.unnamed.len() == 1
        && fields.unnamed.iter().all(|f| {
            f.attrs.is_empty() && matches!(f.vis, syn::Visibility::Inherited) && is_cell_unit(&f.ty)
        })
}

/// `std::cell::Cell<()>`, written in full.
fn is_cell_unit(ty: &syn::Type) -> bool {
    let syn::Type::Path(p) = ty else {
        return false;
    };
    let names: Vec<String> = p.path.segments.iter().map(|s| plain(&s.ident)).collect();
    p.qself.is_none()
        && p.path.leading_colon.is_none()
        && names == ["std", "cell", "Cell"]
        && matches!(&p.path.segments[2].arguments,
            syn::PathArguments::AngleBracketed(a) if a.args.len() == 1
                && matches!(&a.args[0], syn::GenericArgument::Type(syn::Type::Tuple(t))
                    if t.elems.is_empty()))
}

/// Whether a fn is test-only: `#[cfg(test)]` plus doc comments.
pub(super) fn cfg_test_fn(attrs: &[syn::Attribute]) -> bool {
    let rest: Vec<syn::Attribute> = attrs
        .iter()
        .filter(|a| !a.path().is_ident("doc"))
        .cloned()
        .collect();
    cfg_test_only(&rest)
}

/// The judge's production items: the cfg(test) module and test-only fns out.
fn production(file: &syn::File) -> impl Iterator<Item = &syn::Item> {
    file.items.iter().filter(|item| match item {
        syn::Item::Mod(m) => !cfg_test_only(&m.attrs),
        syn::Item::Fn(f) => !cfg_test_fn(&f.attrs),
        _ => true,
    })
}

/// Every way the judge binds the name `Firewall`: each `use` leaf or rename
/// as its full path, a glob as `*`, any other item named `Firewall` as
/// `item`. The only accepted list is the real import.
fn firewall_bindings(file: &syn::File) -> Vec<String> {
    let mut out = Vec::new();
    for item in production(file) {
        match item {
            syn::Item::Use(u) => {
                for (path, local) in use_bindings(&u.tree) {
                    match local {
                        Some(name) if name == "Firewall" => out.push(path.join("::")),
                        Some(_) => {}
                        None => out.push("*".to_owned()),
                    }
                }
            }
            syn::Item::Struct(s) if plain(&s.ident) == "Firewall" => out.push("item".to_owned()),
            syn::Item::Enum(e) if plain(&e.ident) == "Firewall" => out.push("item".to_owned()),
            syn::Item::Type(t) if plain(&t.ident) == "Firewall" => out.push("item".to_owned()),
            syn::Item::Const(c) if plain(&c.ident) == "Firewall" => out.push("item".to_owned()),
            syn::Item::Fn(f) if plain(&f.sig.ident) == "Firewall" => out.push("item".to_owned()),
            _ => {}
        }
    }
    out
}

/// `&ReadsToken(Cell::new(()))`, exactly.
fn is_token_arg(expr: &syn::Expr) -> bool {
    let syn::Expr::Reference(r) = expr else {
        return false;
    };
    let syn::Expr::Call(token) = &*r.expr else {
        return false;
    };
    r.mutability.is_none()
        && path_is(&token.func, &["ReadsToken"])
        && token.args.len() == 1
        && matches!(&token.args[0], syn::Expr::Call(cell)
            if path_is(&cell.func, &["Cell", "new"])
                && cell.args.len() == 1
                && matches!(&cell.args[0], syn::Expr::Tuple(t) if t.elems.is_empty()))
}

/// The receiver name of `P.reads(&token).reserve(&token, ..)`, if `expr` is
/// that chain.
fn chain_receiver(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::MethodCall(reserve) = expr else {
        return None;
    };
    let syn::Expr::MethodCall(reads) = &*reserve.receiver else {
        return None;
    };
    let syn::Expr::Path(p) = &*reads.receiver else {
        return None;
    };
    (plain(&reserve.method) == "reserve"
        && plain(&reads.method) == "reads"
        && reads.args.len() == 1
        && is_token_arg(&reads.args[0])
        && reserve.args.first().is_some_and(is_token_arg)
        && p.qself.is_none()
        && p.path.segments.len() == 1)
        .then(|| plain(&p.path.segments[0].ident))
}

/// One fn's token facts: every path naming `ReadsToken`, each chain with its
/// receiver and whether it sits in async code, and every name a pattern binds.
#[derive(Default)]
struct Uses {
    mentions: usize,
    chains: Vec<(String, bool)>,
    bound: Vec<String>,
    in_async: usize,
}

impl<'ast> syn::visit::Visit<'ast> for Uses {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path
            .segments
            .last()
            .is_some_and(|s| plain(&s.ident) == "ReadsToken")
        {
            self.mentions += 1;
        }
        syn::visit::visit_path(self, path);
    }
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if let Some(receiver) = chain_receiver(expr) {
            self.chains.push((receiver, self.in_async > 0));
        }
        let entered = matches!(expr, syn::Expr::Async(_))
            || matches!(expr, syn::Expr::Closure(c) if c.asyncness.is_some());
        self.in_async += usize::from(entered);
        syn::visit::visit_expr(self, expr);
        self.in_async -= usize::from(entered);
    }
    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        self.bound.push(plain(&pat.ident));
        syn::visit::visit_pat_ident(self, pat);
    }
}

/// The bindings a `use` tree makes, raw identifiers unrawed, through the
/// shared `syn_scan_support::bindings` walk.
fn use_bindings(tree: &syn::UseTree) -> Vec<(Vec<String>, Option<String>)> {
    let unraw = |s: &str| s.strip_prefix("r#").unwrap_or(s).to_owned();
    let mut out = Vec::new();
    crate::gateway::syn_scan_support::bindings(tree, &mut Vec::new(), &mut out);
    out.into_iter()
        .map(|(path, local)| {
            (
                path.iter().map(|s| unraw(s)).collect(),
                local.map(|l| unraw(&l)),
            )
        })
        .collect()
}

/// Whether a `use` tree brings `ReadsToken` in under any name, a glob over it
/// included: `use self::ReadsToken::{self as X}` names it mid-path.
fn use_names_token(tree: &syn::UseTree) -> bool {
    use_bindings(tree)
        .iter()
        .any(|(path, _)| path.last().is_some_and(|l| l == "ReadsToken"))
}

/// Whether `assess`'s parameter `name` is typed `&Firewall`.
fn firewall_param(sig: &syn::Signature, name: &str) -> bool {
    sig.inputs.iter().any(|input| {
        matches!(input, syn::FnArg::Typed(t)
            if matches!(&*t.pat, syn::Pat::Ident(i) if plain(&i.ident) == name)
                && matches!(&*t.ty, syn::Type::Reference(r) if r.mutability.is_none()
                    && matches!(&*r.elem, syn::Type::Path(p) if p.qself.is_none()
                        && p.path.is_ident("Firewall"))))
    })
}

/// What the judge does with the read token that it must not: empty when the
/// token is built only in the one read chain, on the real firewall, in a
/// plain `assess`, and `Firewall` is bound only by its import.
pub(crate) fn token_findings(file: &syn::File) -> Vec<String> {
    use syn::visit::Visit;
    let mut out = Vec::new();
    if firewall_bindings(file) != ["crate::security::firewall::Firewall"] {
        out.push("Firewall bound other than by its import".to_owned());
    }
    let mut chains = 0;
    for item in production(file) {
        let syn::Item::Fn(f) = item else {
            // Outside a fn, the token may appear only as its own declaration:
            // a `use` naming it (an alias builds tokens under another name), a
            // const or static holding its constructor, any other mention.
            match item {
                syn::Item::Struct(s) if token_struct(s) => {}
                syn::Item::Use(u) if use_names_token(&u.tree) => {
                    out.push("an alias of ReadsToken".to_owned());
                }
                other => {
                    let mut uses = Uses::default();
                    uses.visit_item(other);
                    if uses.mentions > 0 {
                        out.push("a token outside the read chain outside a fn".to_owned());
                    }
                }
            }
            continue;
        };
        let name = plain(&f.sig.ident);
        let mut sig = Uses::default();
        sig.visit_signature(&f.sig);
        let mut body = Uses::default();
        body.visit_block(&f.block);
        chains += body.chains.len();
        if sig.mentions + body.mentions > 2 * body.chains.len() {
            out.push(format!("a token outside the read chain in {name}"));
        }
        for (receiver, in_async) in &body.chains {
            if name != "assess" {
                out.push(format!("a read chain outside assess in {name}"));
                continue;
            }
            // A generic parameter could rename `Firewall` to any type.
            if !f.sig.generics.params.is_empty() {
                out.push("a generic assess".to_owned());
            }
            if !firewall_param(&f.sig, receiver) {
                out.push("a read chain on other than a Firewall parameter in assess".to_owned());
            }
            if body.bound.iter().any(|b| b == receiver) {
                out.push(format!("a binding shadows {receiver} in assess"));
            }
            if *in_async || f.sig.asyncness.is_some() {
                out.push("a read chain in async code in assess".to_owned());
            }
        }
    }
    match chains {
        0 => out.push("no read chain".to_owned()),
        1 => {}
        _ => out.push("more than one read chain".to_owned()),
    }
    out.sort();
    out.dedup();
    out
}
