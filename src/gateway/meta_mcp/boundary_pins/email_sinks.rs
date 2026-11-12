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

/// Scan one production file, `file` relative to the crate root, whose text
/// is `source`. Each owner with a `read` row also gets a `body` row: the
/// SHA-256 of its source lines, so a reviewed reader's body cannot change
/// (say, to forward the email to a logging helper) while its count holds.
pub(super) fn scan_file(file: &str, source: &str, parsed: &syn::File, scan: &mut Scan) {
    let mut visitor = Visitor {
        file,
        owner: Vec::new(),
        spans: std::collections::BTreeMap::new(),
        scan,
    };
    for item in &parsed.items {
        visitor.item(item);
    }
    let lines: Vec<&str> = source.lines().collect();
    let readers: Vec<String> = visitor
        .scan
        .rows
        .keys()
        .filter(|(f, _, kind)| f == file && kind == "read")
        .map(|(_, owner, _)| owner.clone())
        .collect();
    for owner in readers {
        let Some(&(first, last)) = visitor.spans.get(&owner) else {
            continue;
        };
        let body = lines
            .get(first.saturating_sub(1)..last.min(lines.len()))
            .unwrap_or_default()
            .join("\n");
        visitor.scan.rows.insert(
            (file.to_owned(), owner, "body".to_owned()),
            crate::hashing::sha256_hex(body.as_bytes()),
        );
    }
}

struct Visitor<'a> {
    file: &'a str,
    owner: Vec<String>,
    /// Each owner's first and last source line.
    spans: std::collections::BTreeMap<String, (usize, usize)>,
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
        self.mark(syn::spanned::Spanned::span(item));
        syn::visit::visit_item(self, item);
        self.owner.pop();
    }

    /// Record the current owner's source lines (the first sighting wins).
    fn mark(&mut self, span: proc_macro2::Span) {
        let owner = self.owner();
        self.spans
            .entry(owner)
            .or_insert((span.start().line, span.end().line));
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
            self.mark(syn::spanned::Spanned::span(f));
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
        let skipped = skipped_args(&attr.meta);
        let unskipped: Vec<String> = sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(t) if mentions_raw(&t.ty) => Some(t),
                _ => None,
            })
            .map(|t| match &*t.pat {
                syn::Pat::Ident(p) => name(&p.ident),
                _ => "_".to_owned(),
            })
            .filter(|arg| !skipped.covers(arg))
            .collect();
        if !unskipped.is_empty() {
            self.refuse(&format!(
                "#[instrument] on `{}` records the raw identity argument(s) {unskipped:?}; skip them",
                name(&sig.ident)
            ));
        }
    }
}

/// What an `#[instrument]` attribute leaves out of its span.
enum Skipped {
    All,
    Named(Vec<String>),
}

impl Skipped {
    fn covers(&self, arg: &str) -> bool {
        match self {
            Self::All => true,
            Self::Named(names) => names.iter().any(|n| n == arg),
        }
    }
}

/// The arguments an `#[instrument(..)]` skips: `skip_all`, or the names
/// inside its `skip(..)` group. A bare `#[instrument]` skips nothing.
fn skipped_args(meta: &syn::Meta) -> Skipped {
    let syn::Meta::List(list) = meta else {
        return Skipped::Named(Vec::new());
    };
    // Split the top-level options on commas; an option is a skip directive
    // only if it is exactly `skip_all`, or `skip` followed by its group. A
    // `name = value` option (`parent = skip_all`) is neither.
    let mut options: Vec<Vec<proc_macro2::TokenTree>> = vec![Vec::new()];
    for token in list.tokens.clone() {
        match &token {
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => options.push(Vec::new()),
            _ => options.last_mut().expect("one option at least").push(token),
        }
    }
    let mut names = Vec::new();
    for option in &options {
        match option.as_slice() {
            [proc_macro2::TokenTree::Ident(i)] if i == "skip_all" => return Skipped::All,
            [
                proc_macro2::TokenTree::Ident(i),
                proc_macro2::TokenTree::Group(group),
            ] if i == "skip" => {
                names.extend(group.stream().into_iter().filter_map(|t| match t {
                    proc_macro2::TokenTree::Ident(i) => {
                        Some(syn::ext::IdentExt::unraw(&i).to_string())
                    }
                    _ => None,
                }));
            }
            _ => {}
        }
    }
    Skipped::Named(names)
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
        let path = crate_root().join(&at.file);
        let source =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        scan_file(&at.file, &source, file, &mut self.0);
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
