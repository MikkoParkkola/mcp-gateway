// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the R0-R5, R8 and R10 stage checkers.

use std::collections::HashSet;

use syn::visit::Visit;

use super::invoke_stages_allow::{ExtraKind, GROUPS};
use super::invoke_stages_dest::{
    check_input_destructured, group_fields_by_type, is_group, is_in_param, tail_is,
};

/// A stage function found by name, whether a free item or an `impl` method.
pub(super) struct FoundFunc<'a> {
    pub(super) sig: &'a syn::Signature,
    pub(super) block: &'a syn::Block,
    pub(super) attrs: &'a [syn::Attribute],
}

fn check_items<'a>(items: &'a [syn::Item], name: &str) -> Option<FoundFunc<'a>> {
    for item in items {
        if let syn::Item::Fn(func) = item
            && func.sig.ident == name
        {
            return Some(FoundFunc {
                sig: &func.sig,
                block: &func.block,
                attrs: &func.attrs,
            });
        }
        if let syn::Item::Impl(block) = item {
            for inner in &block.items {
                if let syn::ImplItem::Fn(method) = inner
                    && method.sig.ident == name
                {
                    return Some(FoundFunc {
                        sig: &method.sig,
                        block: &method.block,
                        attrs: &method.attrs,
                    });
                }
            }
        }
        if let syn::Item::Mod(module) = item
            && let Some((_, nested)) = &module.content
            && let Some(found) = check_items(nested, name)
        {
            return Some(found);
        }
    }
    None
}

/// Find `name` anywhere in the file, `impl` bodies and inline modules included.
pub(super) fn find_function<'a>(file: &'a syn::File, name: &str) -> Option<FoundFunc<'a>> {
    check_items(&file.items, name)
}

/// R0: the file exists and parses, and the stage function is in it.
pub(super) fn check_r0(
    stage_file: &str,
    stage_func: &str,
    file_content: Option<&str>,
    parsed: Option<&syn::File>,
) -> Vec<String> {
    if file_content.is_none() {
        return vec![format!("R0: stage file missing: {stage_file}")];
    }
    if let Some(file) = parsed {
        if find_function(file, stage_func).is_none() {
            return vec![format!(
                "R0: stage function missing: {stage_func} in {stage_file}"
            )];
        }
        return Vec::new();
    }
    vec![format!("R0: stage file does not parse: {stage_file}")]
}

fn is_target(path: &syn::Path, in_type: &str) -> bool {
    if let Some(tail) = path.segments.last() {
        let tail = tail.ident.to_string();
        tail == in_type || is_group(&tail)
    } else {
        false
    }
}

struct Structs<'a> {
    in_type: &'a str,
    hits: Vec<&'a syn::PatStruct>,
}

impl<'ast> Visit<'ast> for Structs<'ast> {
    fn visit_pat_struct(&mut self, pat: &'ast syn::PatStruct) {
        if is_target(&pat.path, self.in_type) {
            self.hits.push(pat);
        }
        syn::visit::visit_pat_struct(self, pat);
    }
}

fn target_structs<'a>(found: &'a FoundFunc<'a>, in_type: &'a str) -> Vec<&'a syn::PatStruct> {
    let mut seen = Structs {
        in_type,
        hits: Vec::new(),
    };
    for input in &found.sig.inputs {
        seen.visit_fn_arg(input);
    }
    seen.visit_block(found.block);
    seen.hits
}

/// R1: the `In` is move-destructured in full, with no `..` in it or any group.
pub(super) fn check_r1(found: &FoundFunc<'_>, in_type: &str) -> Vec<String> {
    let mut out = check_input_destructured(found, in_type);
    for pat in target_structs(found, in_type) {
        if pat.rest.is_some() {
            let tail = pat
                .path
                .segments
                .last()
                .map_or(String::new(), |seg| seg.ident.to_string());
            out.push(format!("R1: `..` in the {tail} destructure"));
        }
    }
    out
}

struct Wilds<'a> {
    in_type: &'a str,
    depth: usize,
    found: bool,
}

impl Wilds<'_> {
    fn inside(&mut self, pat: &syn::PatStruct, visit: impl FnOnce(&mut Self)) {
        let target = is_target(&pat.path, self.in_type);
        if target {
            self.depth += 1;
        }
        visit(self);
        if target {
            self.depth -= 1;
        }
    }
}

impl<'ast> Visit<'ast> for Wilds<'ast> {
    fn visit_pat_struct(&mut self, pat: &'ast syn::PatStruct) {
        self.inside(pat, |seen| {
            syn::visit::visit_pat_struct(seen, pat);
        });
    }

    fn visit_pat_wild(&mut self, pat: &'ast syn::PatWild) {
        if self.depth > 0 {
            self.found = true;
        }
        syn::visit::visit_pat_wild(self, pat);
    }
}

/// R2: no `_` inside the `In` or group destructures.
pub(super) fn check_r2(found: &FoundFunc<'_>, in_type: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pat in target_structs(found, in_type) {
        let mut seen = Wilds {
            in_type,
            depth: 0,
            found: false,
        };
        seen.visit_pat_struct(pat);
        if seen.found {
            out.push(format!("R2: `_` in the {in_type} destructure"));
        }
    }
    out
}

struct Blanks<'a> {
    in_type: &'a str,
    depth: usize,
    hits: Vec<String>,
}

impl<'ast> Visit<'ast> for Blanks<'ast> {
    fn visit_pat_struct(&mut self, pat: &'ast syn::PatStruct) {
        let target = is_target(&pat.path, self.in_type);
        if target {
            self.depth += 1;
        }
        syn::visit::visit_pat_struct(self, pat);
        if target {
            self.depth -= 1;
        }
    }

    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        if self.depth > 0 {
            let name = pat.ident.to_string();
            if name.starts_with('_') && name != "_" {
                self.hits.push(name);
            }
        }
        syn::visit::visit_pat_ident(self, pat);
    }
}

/// R3: no `_`-led binding inside the `In` or group destructures.
pub(super) fn check_r3(found: &FoundFunc<'_>, in_type: &str) -> Vec<String> {
    let mut seen = Blanks {
        in_type,
        depth: 0,
        hits: Vec::new(),
    };
    for input in &found.sig.inputs {
        seen.visit_fn_arg(input);
    }
    seen.visit_block(found.block);
    seen.hits
        .into_iter()
        .map(|name| {
            format!(
                "R3: `_{}` binding in the {in_type} destructure",
                name.trim_start_matches('_')
            )
        })
        .collect()
}

fn member_name(member: &syn::Member) -> Option<String> {
    if let syn::Member::Named(ident) = member {
        Some(ident.to_string())
    } else {
        None
    }
}

fn group_fields(group: &str) -> &'static [&'static str] {
    for (name, fields) in GROUPS {
        if *name == group {
            return fields;
        }
    }
    &[]
}

struct Lets<'a> {
    inits: Vec<(&'a syn::Pat, Option<&'a syn::Expr>)>,
}

impl<'ast> Visit<'ast> for Lets<'ast> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let init = local.init.as_ref().map(|init| init.expr.as_ref());
        self.inits.push((&local.pat, init));
        syn::visit::visit_local(self, local);
    }
}

/// R4: every group-typed `In` field is itself destructured in full.
pub(super) fn check_r4(found: &FoundFunc<'_>, file: &syn::File, in_type: &str) -> Vec<String> {
    let mut out = Vec::new();
    let targets = target_structs(found, in_type);
    for pat in &targets {
        let tail = pat
            .path
            .segments
            .last()
            .map_or(String::new(), |seg| seg.ident.to_string());
        if !is_group(&tail) {
            continue;
        }
        let want = group_fields(&tail);
        let mut have = HashSet::new();
        for field in &pat.fields {
            if let Some(name) = member_name(&field.member) {
                have.insert(name);
            }
        }
        for field in want {
            if !have.contains(*field) {
                out.push(format!("R4: the {tail} destructure skips `{field}`"));
            }
        }
        for name in &have {
            if !want.contains(&name.as_str()) {
                out.push(format!("R4: the {tail} destructure names unknown `{name}`"));
            }
        }
    }
    let typed = group_fields_by_type(file, in_type);
    if typed.is_empty() {
        return out;
    }
    let mut lets = Lets { inits: Vec::new() };
    lets.visit_block(found.block);
    for pat in &targets {
        let tail = pat
            .path
            .segments
            .last()
            .map_or(String::new(), |seg| seg.ident.to_string());
        if tail != in_type {
            continue;
        }
        for (name, group) in &typed {
            let mut field_pat: Option<&syn::Pat> = None;
            for field in &pat.fields {
                if member_name(&field.member).as_deref() == Some(name.as_str()) {
                    field_pat = Some(field.pat.as_ref());
                }
            }
            let Some(bound) = field_pat else {
                out.push(format!("R4: the `{name}` group is never destructured"));
                continue;
            };
            if let syn::Pat::Struct(inner) = bound
                && tail_is(&inner.path, group)
            {
                continue;
            }
            let binding = if let syn::Pat::Ident(named) = bound {
                named.ident.to_string()
            } else {
                String::new()
            };
            let mut settled = false;
            if !binding.is_empty() {
                for (pat, init) in &lets.inits {
                    if let syn::Pat::Struct(plain) = pat
                        && tail_is(&plain.path, group)
                        && let Some(syn::Expr::Path(rhs)) = init
                        && rhs.path.segments.len() == 1
                        && rhs
                            .path
                            .segments
                            .first()
                            .is_some_and(|seg| seg.ident == binding)
                    {
                        settled = true;
                    }
                }
            }
            if !settled {
                out.push(format!("R4: the `{name}` group is never destructured"));
            }
        }
    }
    out
}

fn is_witness(ty: &syn::Type) -> bool {
    if let syn::Type::Reference(borrow) = ty
        && borrow.mutability.is_some()
        && let syn::Type::Path(plain) = borrow.elem.as_ref()
        && tail_is(&plain.path, "Witnessed")
    {
        true
    } else {
        false
    }
}

fn is_reservation(ty: &syn::Type) -> bool {
    if let syn::Type::Reference(borrow) = ty
        && borrow.mutability.is_some()
        && let syn::Type::Path(outer) = borrow.elem.as_ref()
        && tail_is(&outer.path, "Option")
        && let Some(seg) = outer.path.segments.last()
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
        && args.args.len() == 1
        && let Some(syn::GenericArgument::Type(syn::Type::Path(inner))) = args.args.first()
        && tail_is(&inner.path, "IdempotencyReservation")
    {
        true
    } else {
        false
    }
}

/// R5: `self` plus exactly one by-value `In` plus only the allowed `&mut` extras.
pub(super) fn check_r5(
    found: &FoundFunc<'_>,
    in_type: &str,
    allowed_extra: &[ExtraKind],
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(receiver) = found.sig.receiver() {
        let plain = receiver.reference.is_some()
            && receiver.mutability.is_none()
            && receiver.colon_token.is_none();
        if !plain {
            out.push(String::from("R5: the receiver is not `&self`"));
        }
    }
    let mut ins = 0usize;
    let mut witnesses = 0usize;
    let mut reservations = 0usize;
    for input in &found.sig.inputs {
        if matches!(input, syn::FnArg::Receiver(_)) {
            continue;
        }
        let syn::FnArg::Typed(typed) = input else {
            continue;
        };
        if is_in_param(&typed.ty, in_type) {
            ins += 1;
        } else if is_witness(&typed.ty) {
            witnesses += 1;
        } else if is_reservation(&typed.ty) {
            reservations += 1;
        } else {
            out.push(format!("R5: unexpected parameter for {in_type}"));
        }
    }
    if ins != 1 {
        out.push(format!(
            "R5: want exactly one {in_type} parameter, found {ins}"
        ));
    }
    let mut want_witness = 0usize;
    let mut want_reservation = 0usize;
    for kind in allowed_extra {
        match kind {
            ExtraKind::Witness => want_witness += 1,
            ExtraKind::Reservation => want_reservation += 1,
        }
    }
    if witnesses != want_witness || reservations != want_reservation {
        out.push(String::from(
            "R5: the `&mut` extras are not the allowed ones",
        ));
    }
    out
}

fn is_self(expr: &syn::Expr) -> bool {
    if let syn::Expr::Path(plain) = expr
        && plain.qself.is_none()
        && plain.path.segments.len() == 1
        && plain
            .path
            .segments
            .first()
            .is_some_and(|seg| seg.ident == "self")
    {
        true
    } else {
        false
    }
}

struct Selves {
    hits: usize,
}

impl<'ast> Visit<'ast> for Selves {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if is_self(&field.base) {
            return;
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if is_self(&call.receiver) {
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && path
                .path
                .segments
                .first()
                .is_some_and(|seg| seg.ident == "self")
        {
            self.hits += 1;
        }
        syn::visit::visit_expr_path(self, path);
    }
}

/// R8: `self` only ever as the receiver of a field or method read.
pub(super) fn check_r8(found: &FoundFunc<'_>) -> Vec<String> {
    let mut seen = Selves { hits: 0 };
    seen.visit_block(found.block);
    if seen.hits == 0 {
        Vec::new()
    } else {
        vec![format!(
            "R8: {hits} bare use(s) of `self`",
            hits = seen.hits
        )]
    }
}

fn carries_forbid(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if !attr.path().is_ident("forbid") {
            continue;
        }
        let tokens = match &attr.meta {
            syn::Meta::List(list) => list.tokens.to_string(),
            _ => continue,
        };
        for part in tokens.split(',') {
            // The lint tail after any `::` decides, so `clippy::x` never matches.
            let trimmed = part.trim();
            let tail = trimmed
                .rsplit_once("::")
                .map_or(trimmed, |(_, tail)| tail.trim());
            if tail == "unused_variables" {
                return true;
            }
        }
    }
    false
}

struct Idents {
    names: HashSet<String>,
}

impl<'ast> Visit<'ast> for Idents {
    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        self.names.insert(pat.ident.to_string());
        syn::visit::visit_pat_ident(self, pat);
    }
}

fn input_bindings(found: &FoundFunc<'_>, in_type: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for input in &found.sig.inputs {
        if let syn::FnArg::Typed(typed) = input
            && is_in_param(&typed.ty, in_type)
            && let syn::Pat::Ident(bound) = typed.pat.as_ref()
        {
            names.insert(bound.ident.to_string());
        }
    }
    for pat in target_structs(found, in_type) {
        let mut seen = Idents {
            names: HashSet::new(),
        };
        seen.visit_pat_struct(pat);
        names.extend(seen.names);
    }
    names
}

struct Discards<'a> {
    inputs: &'a HashSet<String>,
    hits: usize,
}

fn is_input_path(expr: &syn::Expr, inputs: &HashSet<String>) -> bool {
    if let syn::Expr::Path(plain) = expr
        && plain.qself.is_none()
        && plain.path.segments.len() == 1
        && let Some(seg) = plain.path.segments.first()
    {
        inputs.contains(&seg.ident.to_string())
    } else {
        false
    }
}

impl Visit<'_> for Discards<'_> {
    fn visit_local(&mut self, local: &syn::Local) {
        if let Some(init) = local.init.as_ref() {
            let discarded = match &local.pat {
                syn::Pat::Wild(_) => is_input_path(&init.expr, self.inputs),
                syn::Pat::Ident(bound) => {
                    let name = bound.ident.to_string();
                    name.starts_with('_') && name != "_" && is_input_path(&init.expr, self.inputs)
                }
                _ => false,
            };
            if discarded {
                self.hits += 1;
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &syn::ExprCall) {
        if let syn::Expr::Path(callee) = call.func.as_ref()
            && callee.qself.is_none()
            && callee
                .path
                .segments
                .last()
                .is_some_and(|seg| seg.ident == "drop")
            && call.args.len() == 1
            && let Some(arg) = call.args.first()
            && is_input_path(arg, self.inputs)
        {
            self.hits += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// R10: the stage forbids `unused_variables` and never discards an input binding.
pub(super) fn check_r10(found: &FoundFunc<'_>, in_type: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !carries_forbid(found.attrs) {
        out.push(String::from("R10: missing `#[forbid(unused_variables)]`"));
    }
    let inputs = input_bindings(found, in_type);
    let mut seen = Discards {
        inputs: &inputs,
        hits: 0,
    };
    seen.visit_block(found.block);
    for _ in 0..seen.hits {
        out.push(String::from("R10: a discard-only use of an input binding"));
    }
    out
}
