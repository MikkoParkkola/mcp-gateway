// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What each scanned file says about names the discovery output scan relies
//! on: renamed output macros, the shared escape's import, its escape helpers
//! and its `Shown` parameters.

use std::collections::{BTreeMap, BTreeSet};

use syn::ext::IdentExt;
use syn::visit::Visit;

use super::{ASSERT_COND, ASSERT_PAIR, FORMAT_FIRST, FileNames, TRACING, WRITE_MACROS, path_text};

/// Whether a function body is exactly one call of the shared escape: an
/// escape helper such as `shown_path`, accepted where it is called.
fn is_helper(block: &syn::Block) -> bool {
    let [syn::Stmt::Expr(syn::Expr::Call(call), None)] = block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Path(func) = &*call.func else {
        return false;
    };
    matches!(
        path_text(&func.path).as_str(),
        "shown" | "crate::cli_support::shown" | "mcp_gateway::cli_support::shown"
    )
}

/// The parameters of `sig` typed `Shown` (or `&Shown`) that no binding in
/// `body` shadows: a `let`, closure or pattern of the same name makes the
/// name ambiguous, so it needs a row again.
fn shown_params(
    sig: &syn::Signature,
    body: &syn::Block,
    out: &mut BTreeMap<String, BTreeSet<String>>,
) {
    struct Bound(BTreeSet<String>);
    impl<'ast> Visit<'ast> for Bound {
        fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
            self.0.insert(pat.ident.unraw().to_string());
            syn::visit::visit_pat_ident(self, pat);
        }
    }
    let mut bound = Bound(BTreeSet::new());
    bound.visit_block(body);
    for input in &sig.inputs {
        let syn::FnArg::Typed(arg) = input else {
            continue;
        };
        let mut ty = &*arg.ty;
        while let syn::Type::Reference(r) = ty {
            ty = &r.elem;
        }
        if let (syn::Pat::Ident(name), syn::Type::Path(path)) = (&*arg.pat, ty)
            && path
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "Shown")
            && !bound.0.contains(&name.ident.unraw().to_string())
        {
            out.entry(sig.ident.to_string())
                .or_default()
                .insert(name.ident.to_string());
        }
    }
}

/// The names a file's `use` declarations bring in that the scan relies on.
pub(super) fn file_names(file: &syn::File) -> FileNames {
    fn uses(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<(String, String)>) {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                uses(&p.tree, prefix, out);
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let full = [prefix.as_slice(), &[n.ident.to_string()]]
                    .concat()
                    .join("::");
                out.push((full, n.ident.to_string()));
            }
            syn::UseTree::Rename(r) => {
                let full = [prefix.as_slice(), &[r.ident.to_string()]]
                    .concat()
                    .join("::");
                out.push((full, r.rename.to_string()));
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    uses(item, prefix, out);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }
    // Free functions by name, inline modules included: a helper name that
    // another function in the file reuses is ambiguous, so not a helper.
    struct Defined(BTreeMap<String, usize>);
    impl<'ast> Visit<'ast> for Defined {
        fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
            *self.0.entry(f.sig.ident.unraw().to_string()).or_default() += 1;
            syn::visit::visit_item_fn(self, f);
        }
    }
    let mut defined = Defined(BTreeMap::new());
    defined.visit_file(file);
    let defined = defined.0;
    let mut names = FileNames::default();
    let watched = |n: &str| {
        [
            FORMAT_FIRST,
            WRITE_MACROS,
            TRACING,
            ASSERT_COND,
            ASSERT_PAIR,
        ]
        .iter()
        .any(|set| set.contains(&n))
            || n == "dbg"
    };
    for item in &file.items {
        match item {
            syn::Item::Use(u) => {
                let mut found = Vec::new();
                uses(&u.tree, &mut Vec::new(), &mut found);
                for (full, local) in found {
                    let original = full.rsplit("::").next().unwrap_or_default().to_owned();
                    if (full == "crate::cli_support::shown"
                        || full == "mcp_gateway::cli_support::shown")
                        && local == "shown"
                    {
                        names.shown_imported = true;
                    }
                    if local != original && watched(&original) {
                        names.aliases.insert(local, original);
                    }
                }
            }
            syn::Item::Fn(f) => {
                if f.sig.ident == "shown" {
                    names.shown_defined = true;
                }
                if is_helper(&f.block) && defined.get(&f.sig.ident.to_string()) == Some(&1) {
                    names.helpers.insert(f.sig.ident.to_string());
                }
                shown_params(&f.sig, &f.block, &mut names.shown_params);
            }
            syn::Item::Impl(block) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(method) = member {
                        shown_params(&method.sig, &method.block, &mut names.shown_params);
                    }
                }
            }
            _ => {}
        }
    }
    names
}
