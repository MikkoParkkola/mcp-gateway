// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production place that reads an email, or writes one into a macro
//! (a log line, `format!`, `json!`), is a reviewed row; the forms that would
//! put a verified identity's raw email into output are refused outright.
//!
//! Counted, by (file, owner, kind):
//! - `read`: a `.email()` call or a `.email` field access, on any receiver;
//! - `macro`: a macro invocation whose tokens name `email`.
//!
//! Refused: a derived or hand-written `Serialize` for a raw identity or token
//! type; a derived `Debug` for a raw identity type or the ID-token claims; and
//! `#[instrument]` without `skip` on a fn that takes a raw identity or token.
//! This is syntax, not data flow: runtime capture rows check the output.

use super::identity_sources::{Scan, item_name, last_ident, name};
use super::packaged::crate_root;
use super::scan::{Place, Sink, item_attrs, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Types holding a verified identity's raw email: never serialized as such.
const RAW: [&str; 2] = ["VerifiedIdentity", "TemporaryToken"];
/// Types whose derived `Debug` would print the raw email.
const NO_DERIVED_DEBUG: [&str; 2] = ["VerifiedIdentity", "IdTokenClaims"];

/// Scan one production file, `file` relative to the crate root.
pub(super) fn scan_file(file: &str, parsed: &syn::File, scan: &mut Scan) {
    let mut visitor = Visitor {
        file,
        owner: Vec::new(),
        scan,
    };
    for item in &parsed.items {
        visitor.item(item);
    }
}

struct Visitor<'a> {
    file: &'a str,
    owner: Vec<String>,
    scan: &'a mut Scan,
}

impl Visitor<'_> {
    fn owner(&self) -> String {
        if self.owner.is_empty() {
            "<module>".to_owned()
        } else {
            self.owner.join("::")
        }
    }

    fn count(&mut self, kind: &str) {
        let key = (self.file.to_owned(), self.owner(), kind.to_owned());
        let n = self
            .scan
            .rows
            .get(&key)
            .map_or(0, |v| v.parse::<usize>().unwrap_or(0));
        self.scan.rows.insert(key, (n + 1).to_string());
    }

    fn refuse(&mut self, what: &str) {
        self.scan
            .refused
            .push(format!("{}: {} ({what})", self.file, self.owner()));
    }

    fn item(&mut self, item: &syn::Item) {
        if test_only(item_attrs(item)) {
            return;
        }
        match item {
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    self.owner.push(name(&m.ident));
                    for inner in items {
                        self.item(inner);
                    }
                    self.owner.pop();
                }
                return;
            }
            syn::Item::Impl(block) => return self.impl_block(block),
            syn::Item::Struct(s) => self.derives(&name(&s.ident), &s.attrs),
            syn::Item::Enum(e) => self.derives(&name(&e.ident), &e.attrs),
            syn::Item::Fn(f) => self.instrument(&f.attrs, &f.sig),
            _ => {}
        }
        self.owner.push(item_name(item));
        syn::visit::visit_item(self, item);
        self.owner.pop();
    }

    fn impl_block(&mut self, block: &syn::ItemImpl) {
        if test_only(&block.attrs) {
            return;
        }
        let ty = last_ident(&block.self_ty).unwrap_or_default();
        let serializes = block.trait_.as_ref().is_some_and(|(_, path, _)| {
            path.segments
                .last()
                .is_some_and(|s| name(&s.ident) == "Serialize")
        });
        if serializes && RAW.contains(&ty.as_str()) {
            self.refuse(&format!("hand-written Serialize for the raw type `{ty}`"));
        }
        for inner in &block.items {
            let syn::ImplItem::Fn(f) = inner else {
                continue;
            };
            if test_only(&f.attrs) {
                continue;
            }
            self.instrument(&f.attrs, &f.sig);
            self.owner.push(format!("{ty}::{}", name(&f.sig.ident)));
            syn::visit::visit_impl_item_fn(self, f);
            self.owner.pop();
        }
    }
}

impl Visitor<'_> {
    /// Refuse a derived `Serialize` on a raw type and a derived `Debug` on a
    /// type whose `Debug` would print the raw email, under any `cfg_attr`.
    fn derives(&mut self, ty: &str, attrs: &[syn::Attribute]) {
        let derived = super::scan::derives_in(attrs);
        if RAW.contains(&ty) && derived.contains("Serialize") {
            self.refuse(&format!("derived Serialize for the raw type `{ty}`"));
        }
        if NO_DERIVED_DEBUG.contains(&ty) && derived.contains("Debug") {
            self.refuse(&format!("derived Debug for `{ty}` prints the raw email"));
        }
    }

    /// Refuse `#[instrument]` without `skip` on a fn taking a raw type: the
    /// span would record the argument's `Debug`.
    fn instrument(&mut self, attrs: &[syn::Attribute], sig: &syn::Signature) {
        let Some(attr) = attrs.iter().find(|a| {
            a.path()
                .segments
                .last()
                .is_some_and(|s| name(&s.ident) == "instrument")
        }) else {
            return;
        };
        // `skip(..)` or `skip_all` inside the attribute's arguments.
        if let syn::Meta::List(list) = &attr.meta
            && list.tokens.to_string().contains("skip")
        {
            return;
        }
        let takes_raw = sig.inputs.iter().any(|arg| match arg {
            syn::FnArg::Typed(t) => mentions_raw(&t.ty),
            syn::FnArg::Receiver(_) => false,
        });
        if takes_raw {
            self.refuse(&format!(
                "#[instrument] without skip on `{}`, which takes a raw identity",
                name(&sig.ident)
            ));
        }
    }
}

/// Whether `ty` names a raw type anywhere (a reference, an `Option`, a
/// generic argument).
fn mentions_raw(ty: &syn::Type) -> bool {
    struct Find(bool);
    impl<'ast> syn::visit::Visit<'ast> for Find {
        fn visit_path_segment(&mut self, seg: &'ast syn::PathSegment) {
            self.0 |= RAW.contains(&name(&seg.ident).as_str());
            syn::visit::visit_path_segment(self, seg);
        }
    }
    let mut find = Find(false);
    syn::visit::Visit::visit_type(&mut find, ty);
    find.0
}

/// Whether a macro's tokens name `email` at any depth.
fn names_email(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|t| match t {
        proc_macro2::TokenTree::Ident(i) => syn::ext::IdentExt::unraw(&i) == "email",
        proc_macro2::TokenTree::Group(g) => names_email(g.stream()),
        _ => false,
    })
}

impl<'ast> syn::visit::Visit<'ast> for Visitor<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        self.item(item);
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(l) => &l.attrs,
            syn::Stmt::Macro(m) => &m.attrs,
            syn::Stmt::Expr(e, _) => super::scan::expr_attrs(e),
            syn::Stmt::Item(_) => &[],
        };
        if !test_only(attrs) {
            syn::visit::visit_stmt(self, stmt);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if name(&call.method) == "email" && call.args.is_empty() {
            self.count("read");
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if matches!(&field.member, syn::Member::Named(n) if name(n) == "email") {
            self.count("read");
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if names_email(mac.tokens.clone()) {
            self.count("macro");
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// Hands each production file the shared walk reaches to [`scan_file`].
struct Files(Scan);

impl Sink for Files {
    fn file(&mut self, at: &Place, file: &syn::File) {
        scan_file(&at.file, file, &mut self.0);
    }
}

/// The scan of every production file of this crate.
pub(super) fn crate_scan() -> Scan {
    let mut files = Files(Scan::default());
    walk(crate_root(), &ROOTS, &mut files).expect("the walk reads every module");
    files.0
}

#[path = "email_sinks_tests.rs"]
mod tests;
