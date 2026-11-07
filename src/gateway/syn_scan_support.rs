// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Syntax helpers shared by the source scans: the boundary pins under
//! `meta_mcp::boundary_pins` and the admin-standing reader scan. One copy of
//! each, so the scans read `use` trees and `matches!` bodies the same way.

/// Each name `tree` binds: (the full path, the local name), or `None` for a
/// glob over the path.
pub(crate) fn bindings(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, Option<String>)>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            bindings(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "self" => {
            out.push((prefix.clone(), prefix.last().cloned()));
        }
        syn::UseTree::Name(name) => {
            let mut full = prefix.clone();
            full.push(name.ident.to_string());
            out.push((full, Some(name.ident.to_string())));
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            if rename.ident != "self" {
                full.push(rename.ident.to_string());
            }
            out.push((full, Some(rename.rename.to_string())));
        }
        syn::UseTree::Glob(_) => out.push((prefix.clone(), None)),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                bindings(tree, prefix, out);
            }
        }
    }
}

/// `matches!(expr, pat)` or `matches!(expr, pat if guard)`: its expression,
/// pattern and guard, for a macro whose last path segment is `matches`. A
/// guard that does not parse is `None` and the pattern is still returned, as
/// is anything after the guard skipped: a caller that reads only the pattern
/// sees what it always saw.
pub(crate) fn matches_parts(mac: &syn::Macro) -> Option<(syn::Expr, syn::Pat, Option<syn::Expr>)> {
    if mac
        .path
        .segments
        .last()
        .is_none_or(|s| s.ident != "matches")
    {
        return None;
    }
    let parser = |input: syn::parse::ParseStream| {
        let expr = input.parse::<syn::Expr>()?;
        input.parse::<syn::Token![,]>()?;
        let pat = syn::Pat::parse_multi_with_leading_vert(input)?;
        let guard = if input.parse::<Option<syn::Token![if]>>()?.is_some() {
            input.parse::<syn::Expr>().ok()
        } else {
            None
        };
        input.step(|cursor| {
            let mut rest = *cursor;
            while let Some((_, next)) = rest.token_tree() {
                rest = next;
            }
            Ok(((), rest))
        })?;
        Ok((expr, pat, guard))
    };
    mac.parse_body_with(parser).ok()
}
