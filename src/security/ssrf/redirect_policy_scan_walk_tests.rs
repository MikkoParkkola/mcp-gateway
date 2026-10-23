// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8660: the redirect-policy scan's crate walk: which files are production
//! (reached from `lib.rs` / `main.rs` through no `#[cfg(test)]` module), and the
//! per-file entry points. Split from `redirect_policy_scan_tests.rs` for the
//! 800-line ceiling; the visitors it drives live there.

use std::path::PathBuf;

use super::*;

fn module_dir_for_file(root: &Path, rel: &str) -> Option<PathBuf> {
    let abs = root.join(rel);
    let parent = abs.parent()?.to_path_buf();
    let name = abs.file_name()?.to_str()?;
    if name == "lib.rs" || name == "main.rs" || name == "mod.rs" {
        Some(parent)
    } else if let Some(stem) = name.strip_suffix(".rs") {
        Some(parent.join(stem))
    } else {
        Some(parent)
    }
}

fn rel_for_abs(root: &Path, abs: &Path) -> Option<String> {
    let rel = abs.strip_prefix(root).ok()?;
    let text = rel.to_str()?;
    Some(text.replace('\\', "/"))
}

fn resolve_child_mod(
    root: &Path,
    current_rel: &str,
    mod_name: &str,
    path_attr: Option<&str>,
) -> Option<String> {
    let current_abs = root.join(current_rel);
    let declaring = current_abs.parent()?.to_path_buf();
    if let Some(p) = path_attr {
        let child = declaring.join(p);
        if child.is_file() {
            return rel_for_abs(root, &child);
        }
        return None;
    }
    let dir = module_dir_for_file(root, current_rel)?;
    let first = dir.join(format!("{mod_name}.rs"));
    if first.is_file() {
        return rel_for_abs(root, &first);
    }
    let second = dir.join(mod_name).join("mod.rs");
    if second.is_file() {
        return rel_for_abs(root, &second);
    }
    None
}

fn collect_child_mods_from_items(
    items: &[syn::Item],
    test_only_ancestor: bool,
    current_rel: &str,
    root: &Path,
    out: &mut Vec<String>,
) {
    for item in items {
        if let syn::Item::Mod(m) = item {
            let test_only = test_only_ancestor || is_cfg_test(&m.attrs);
            if let Some((_, inner)) = &m.content {
                if !test_only {
                    collect_child_mods_from_items(inner, test_only, current_rel, root, out);
                }
            } else {
                if test_only {
                    continue;
                }
                let name = m.ident.to_string();
                let path_attr = path_attr_value(&m.attrs);
                if let Some(child) =
                    resolve_child_mod(root, current_rel, &name, path_attr.as_deref())
                    && !child.starts_with(OAUTH_PREFIX)
                {
                    out.push(child);
                }
            }
        }
    }
}

pub(super) fn scan_crate(root: &Path) -> Vec<Entry> {
    let mut seen = HashSet::new();
    let mut queue = Vec::new();
    for start in ["src/lib.rs", "src/main.rs"] {
        if root.join(start).is_file() {
            queue.push(start.to_string());
        }
    }
    // The module walk is unchanged; parsing is split from checking so the
    // factory names are known crate-wide before any chain is judged.
    let mut parsed: Vec<(String, syn::File)> = Vec::new();
    while let Some(rel) = queue.pop() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        if rel.starts_with(OAUTH_PREFIX) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(root.join(&rel)) else {
            continue;
        };
        let Ok(file) = syn::parse_file(&content) else {
            continue;
        };
        let test_only = is_cfg_test(&file.attrs);
        let mut kids = Vec::new();
        collect_child_mods_from_items(&file.items, test_only, &rel, root, &mut kids);
        for k in kids {
            if !seen.contains(&k) {
                queue.push(k);
            }
        }
        if !test_only {
            parsed.push((rel, file));
        }
    }
    let mut factories = HashSet::new();
    for (_, file) in &parsed {
        collect_factories_from_items(&file.items, false, &mut factories);
    }
    let mut entries = Vec::new();
    for (rel, file) in &parsed {
        let mut found = Vec::new();
        scan_items(rel, &file.items, false, &factories, &mut found);
        entries.extend(found);
    }
    entries.sort();
    entries.dedup();
    entries
}

pub(super) fn scan_source(rel: &str, src: &str) -> Vec<Entry> {
    if rel.starts_with(OAUTH_PREFIX) {
        return Vec::new();
    }
    let Ok(file) = syn::parse_file(src) else {
        return Vec::new();
    };
    scan_file_ast(rel, &file)
}

fn scan_file_ast(rel: &str, file: &syn::File) -> Vec<Entry> {
    if rel.starts_with(OAUTH_PREFIX) {
        return Vec::new();
    }
    if is_cfg_test(&file.attrs) {
        return Vec::new();
    }
    let mut factories = HashSet::new();
    collect_factories_from_items(&file.items, false, &mut factories);
    let mut out = Vec::new();
    scan_items(rel, &file.items, false, &factories, &mut out);
    out.sort();
    out.dedup();
    out
}

/// Every free fn or method in production code whose return type mentions
/// `ClientBuilder`: a call to one starts a builder chain.
fn collect_factories_from_items(
    items: &[syn::Item],
    test_only_ancestor: bool,
    out: &mut HashSet<String>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                if test_only_ancestor || is_cfg_test(&f.attrs) {
                    continue;
                }
                if return_type_mentions_client_builder(&f.sig.output) {
                    out.insert(f.sig.ident.to_string());
                }
            }
            syn::Item::Mod(m) => {
                if test_only_ancestor || is_cfg_test(&m.attrs) {
                    continue;
                }
                if let Some((_, inner)) = &m.content {
                    collect_factories_from_items(inner, false, out);
                }
            }
            syn::Item::Impl(imp) => {
                if test_only_ancestor || is_cfg_test(&imp.attrs) {
                    continue;
                }
                for inner in &imp.items {
                    if let syn::ImplItem::Fn(meth) = inner
                        && !is_cfg_test(&meth.attrs)
                        && return_type_mentions_client_builder(&meth.sig.output)
                    {
                        out.insert(meth.sig.ident.to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

fn scan_items(
    rel: &str,
    items: &[syn::Item],
    test_only_ancestor: bool,
    factories: &HashSet<String>,
    out: &mut Vec<Entry>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                if test_only_ancestor || is_cfg_test(&f.attrs) {
                    continue;
                }
                push_fn_entries(rel, &f.sig, &f.block, factories, out);
            }
            syn::Item::Mod(m) => {
                if test_only_ancestor || is_cfg_test(&m.attrs) {
                    continue;
                }
                if let Some((_, inner)) = &m.content {
                    scan_items(rel, inner, false, factories, out);
                }
            }
            syn::Item::Impl(imp) => {
                if test_only_ancestor || is_cfg_test(&imp.attrs) {
                    continue;
                }
                for inner in &imp.items {
                    if let syn::ImplItem::Fn(meth) = inner {
                        if is_cfg_test(&meth.attrs) {
                            continue;
                        }
                        push_fn_entries(rel, &meth.sig, &meth.block, factories, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn push_fn_entries(
    rel: &str,
    sig: &syn::Signature,
    block: &syn::Block,
    factories: &HashSet<String>,
    out: &mut Vec<Entry>,
) {
    let mut v = FnVisitor::new(rel, sig, factories);
    v.visit_block(block);
    if v.hits.implicit {
        out.push(Entry {
            rule: RULE_IMPLICIT,
            file: rel.to_string(),
            func: v.func.clone(),
        });
    }
    if v.hits.hop {
        out.push(Entry {
            rule: RULE_HOP,
            file: rel.to_string(),
            func: v.func.clone(),
        });
    }
    if v.hits.delegation {
        out.push(Entry {
            rule: RULE_DELEGATION,
            file: rel.to_string(),
            func: v.func.clone(),
        });
    }
}
