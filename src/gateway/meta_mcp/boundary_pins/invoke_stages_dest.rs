// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the `In` move-destructure and group-by-type helpers.

use syn::visit::Visit;

use super::invoke_stages_allow::GROUPS;
use super::invoke_stages_rules::FoundFunc;

fn tail_is(path: &syn::Path, name: &str) -> bool {
    path.segments.last().is_some_and(|seg| seg.ident == name)
}

fn is_group(name: &str) -> bool {
    GROUPS.iter().any(|(group, _)| *group == name)
}

fn is_in_param(ty: &syn::Type, in_type: &str) -> bool {
    if let syn::Type::Path(plain) = ty
        && plain.qself.is_none()
        && tail_is(&plain.path, in_type)
    {
        true
    } else {
        false
    }
}

fn is_plain_path(expr: &syn::Expr, name: &str) -> bool {
    if let syn::Expr::Path(plain) = expr
        && plain.qself.is_none()
        && plain.path.segments.len() == 1
        && let Some(seg) = plain.path.segments.first()
    {
        seg.ident == name
    } else {
        false
    }
}

struct InputUses<'a> {
    name: &'a str,
    fields: usize,
    others: usize,
}

impl Visit<'_> for InputUses<'_> {
    fn visit_expr_field(&mut self, field: &syn::ExprField) {
        if is_plain_path(&field.base, self.name) {
            self.fields += 1;
            return;
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        if is_plain_path(&call.receiver, self.name) {
            self.fields += 1;
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &syn::ExprPath) {
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && let Some(seg) = path.path.segments.first()
            && seg.ident == self.name
        {
            self.others += 1;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

fn first_is_in_let(found: &FoundFunc<'_>, name: &str, in_type: &str) -> bool {
    let Some(syn::Stmt::Local(local)) = found.block.stmts.first() else {
        return false;
    };
    if let syn::Pat::Struct(pat) = &local.pat
        && tail_is(&pat.path, in_type)
        && let Some(init) = local.init.as_ref()
        && is_plain_path(&init.expr, name)
    {
        true
    } else {
        false
    }
}

/// R1: the stage's `In` parameter is move-destructured in full, once.
pub(super) fn check_input_destructured(found: &FoundFunc<'_>, in_type: &str) -> Vec<String> {
    let mut ins = Vec::new();
    for input in &found.sig.inputs {
        if let syn::FnArg::Typed(typed) = input
            && is_in_param(&typed.ty, in_type)
        {
            ins.push(typed);
        }
    }
    if ins.is_empty() {
        return vec![format!("R1: the {in_type} input is never destructured")];
    }
    let mut out = Vec::new();
    for typed in ins {
        match typed.pat.as_ref() {
            syn::Pat::Struct(pat) if tail_is(&pat.path, in_type) => {}
            syn::Pat::Wild(_) => {
                out.push(format!(
                    "R1: the {in_type} input is never destructured (`_` discards it)"
                ));
            }
            syn::Pat::Ident(bound)
                if bound.ident.to_string().starts_with('_')
                    || bound.subpat.is_some()
                    || bound.by_ref.is_some() =>
            {
                let name = bound.ident.to_string();
                out.push(format!(
                    "R1: the {in_type} input `{name}` is never destructured"
                ));
            }
            syn::Pat::Ident(bound) => {
                let name = bound.ident.to_string();
                if !first_is_in_let(found, &name, in_type) {
                    out.push(format!(
                        "R1: the {in_type} input `{name}` is never destructured"
                    ));
                    continue;
                }
                let mut seen = InputUses {
                    name: &name,
                    fields: 0,
                    others: 0,
                };
                seen.visit_block(found.block);
                if seen.fields > 0 {
                    out.push(format!(
                        "R1: field access on `{name}` outside its destructure"
                    ));
                } else if seen.others > 1 {
                    out.push(format!("R1: `{name}` is passed on outside its destructure"));
                }
            }
            _ => {
                out.push(format!("R1: the {in_type} input is never destructured"));
            }
        }
    }
    out
}

fn type_tail(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(plain) => plain.path.segments.last().map(|seg| seg.ident.to_string()),
        syn::Type::Reference(borrow) => type_tail(borrow.elem.as_ref()),
        _ => None,
    }
}

fn struct_group_fields(items: &[syn::Item], in_type: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for item in items {
        if let syn::Item::Struct(defined) = item
            && defined.ident == in_type
            && let syn::Fields::Named(named) = &defined.fields
        {
            for field in &named.named {
                let Some(ident) = field.ident.as_ref() else {
                    continue;
                };
                if let Some(tail) = type_tail(&field.ty)
                    && is_group(&tail)
                {
                    out.push((ident.to_string(), tail));
                }
            }
        }
        if let syn::Item::Mod(module) = item
            && let Some((_, nested)) = &module.content
        {
            out.extend(struct_group_fields(nested, in_type));
        }
    }
    out
}

/// The `In` struct's group-typed fields, by declared type rather than name.
pub(super) fn group_fields_by_type(file: &syn::File, in_type: &str) -> Vec<(String, String)> {
    struct_group_fields(&file.items, in_type)
}
