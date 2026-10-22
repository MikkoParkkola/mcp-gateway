// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `shipped_reads` source visitor: string literals, string bindings and
//! the macro bodies `syn` leaves unparsed. Split out to keep its parent under
//! the file-size limit; used only through `super`.

use std::path::PathBuf;

use syn::visit::Visit;

/// Every string literal of a file, and those that are arguments of a call to
/// the packaged-aware helper (a literal read through the helper is covered; a
/// second, direct use of the same text is not). String bindings and their
/// identifier uses answer the same covered/direct question one step removed.
#[derive(Default)]
pub(super) struct Literals {
    pub(super) all: Vec<String>,
    pub(super) covered: Vec<String>,
    /// The file's directory, against which `include_*!` paths resolve.
    pub(super) dir: PathBuf,
    /// `name → literal` for bindings initialised with one string literal; the
    /// first binding of a name wins (no scope analysis).
    pub(super) bindings: std::collections::HashMap<String, String>,
    /// Every path-expression use of a bound name ...
    pub(super) uses: std::collections::HashMap<String, usize>,
    /// ... and how many of those are direct arguments of a helper call.
    pub(super) helper_uses: std::collections::HashMap<String, usize>,
}

fn is_helper_call(call: &syn::ExprCall) -> bool {
    matches!(&*call.func, syn::Expr::Path(p)
        if p.path.segments.last().is_some_and(|s| s.ident == "repo_file" || s.ident == "read_or_skip"))
}

/// The literal, if `expr` is one string literal.
fn as_lit_str(expr: &syn::Expr) -> Option<String> {
    if let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(s),
        ..
    }) = expr
    {
        Some(s.value())
    } else {
        None
    }
}

impl<'ast> Visit<'ast> for Literals {
    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.all.push(lit.value());
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if let Some(lit) = as_lit_str(&item.expr) {
            self.bindings.entry(item.ident.to_string()).or_insert(lit);
        }
        syn::visit::visit_item_const(self, item);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let syn::Pat::Ident(named) = &local.pat
            && let Some(init) = &local.init
            && let Some(lit) = as_lit_str(&init.expr)
        {
            self.bindings.entry(named.ident.to_string()).or_insert(lit);
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(ident) = path.path.get_ident() {
            let name = ident.to_string();
            if self.bindings.contains_key(&name) {
                *self.uses.entry(name).or_default() += 1;
            }
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if is_helper_call(call) {
            let mut inner = Literals {
                dir: self.dir.clone(),
                ..Default::default()
            };
            for arg in &call.args {
                // A binding passed straight to the helper covers its literal;
                // anything nested (a call, a method, a reference) does not.
                if let syn::Expr::Path(p) = arg
                    && let Some(ident) = p.path.get_ident()
                {
                    *self.helper_uses.entry(ident.to_string()).or_default() += 1;
                }
                inner.visit_expr(arg);
            }
            self.covered.extend(inner.all);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // `syn` leaves macro token streams unparsed, so these literals are
        // invisible unless read here. Any other macro is not seen.
        if mac.path.is_ident("include_str") || mac.path.is_ident("include_bytes") {
            if let Ok(args) = mac.parse_body_with(
                syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated,
            ) {
                for lit in &args {
                    self.all.push(resolve_include(&self.dir, &lit.value()));
                }
            }
        } else if mac.path.is_ident("concat")
            && let Ok(args) = mac.parse_body_with(
                syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated,
            )
        {
            self.all.push(args.iter().map(syn::LitStr::value).collect());
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// An `include_str!`/`include_bytes!` path, resolved against the source
/// file's directory and normalised lexically (`.` dropped, one component
/// popped per `..`, clamped at the crate root).
fn resolve_include(dir: &std::path::Path, lit: &str) -> String {
    let joined = dir
        .join(lit.replace('\\', "/"))
        .to_string_lossy()
        .replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for comp in joined.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    parts.join("/")
}
