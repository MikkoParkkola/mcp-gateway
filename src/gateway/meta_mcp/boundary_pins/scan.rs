// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The pin scanner (design §4.2). It walks the crate from every checked root
//! along `mod` declarations, skips test-only code by cfg evaluation (never by
//! filename), and hands each production node to a [`Sink`].

use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// A cfg predicate's value with `test` false and every other atom unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cfg {
    True,
    False,
    Unknown,
}

/// Evaluate one cfg predicate (`test`, `not(..)`, `all(..)`, `any(..)`, or
/// any other atom). `all()` is true and `any()` false, as Rust defines them.
pub(super) fn eval(meta: &syn::Meta) -> Cfg {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => Cfg::False,
        syn::Meta::List(list) => {
            let args: Vec<syn::Meta> = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .map(|p| p.into_iter().collect())
                .unwrap_or_default();
            let values: Vec<Cfg> = args.iter().map(eval).collect();
            if list.path.is_ident("not") {
                match values.as_slice() {
                    [Cfg::True] => Cfg::False,
                    [Cfg::False] => Cfg::True,
                    _ => Cfg::Unknown,
                }
            } else if list.path.is_ident("all") {
                if values.contains(&Cfg::False) {
                    Cfg::False
                } else if values.iter().all(|v| *v == Cfg::True) {
                    Cfg::True
                } else {
                    Cfg::Unknown
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Cfg::True) {
                    Cfg::True
                } else if values.iter().all(|v| *v == Cfg::False) {
                    Cfg::False
                } else {
                    Cfg::Unknown
                }
            } else {
                Cfg::Unknown
            }
        }
        _ => Cfg::Unknown,
    }
}

/// Whether `attrs` carry a `#[cfg(..)]` that is definitely false outside
/// tests: the node exists only in test builds.
pub(super) fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| eval(&meta) == Cfg::False)
    })
}

/// What the walk reports: every production node, with where it sits.
pub(super) trait Sink {
    /// An attribute on a production node; `owner` names the node kind.
    fn attribute(&mut self, _at: &Place, _owner: Owner, _attr: &syn::Attribute) {}
    /// A production expression.
    fn expr(&mut self, _at: &Place, _expr: &syn::Expr) {}
    /// A production item.
    fn item(&mut self, _at: &Place, _item: &syn::Item) {}
    /// A production statement.
    fn stmt(&mut self, _at: &Place, _stmt: &syn::Stmt) {}
    /// A production file, with its inner attributes.
    fn file(&mut self, _at: &Place, _file: &syn::File) {}
}

/// The kind of node an attribute is attached to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Owner {
    /// A module's inner attribute (`#![..]`), the file's included.
    Module,
    Item,
    Statement,
    Expression,
}

/// Where a node sits: its file (relative to the crate root) and the fn it is
/// inside, if any.
#[derive(Clone, Debug, Default)]
pub(super) struct Place {
    pub(super) file: String,
    pub(super) func: Option<String>,
}

/// The attributes written on an expression.
pub(super) fn expr_attrs(expr: &syn::Expr) -> &[syn::Attribute] {
    use syn::Expr as E;
    match expr {
        E::Array(e) => &e.attrs,
        E::Assign(e) => &e.attrs,
        E::Async(e) => &e.attrs,
        E::Await(e) => &e.attrs,
        E::Binary(e) => &e.attrs,
        E::Block(e) => &e.attrs,
        E::Break(e) => &e.attrs,
        E::Call(e) => &e.attrs,
        E::Cast(e) => &e.attrs,
        E::Closure(e) => &e.attrs,
        E::Const(e) => &e.attrs,
        E::Continue(e) => &e.attrs,
        E::Field(e) => &e.attrs,
        E::ForLoop(e) => &e.attrs,
        E::Group(e) => &e.attrs,
        E::If(e) => &e.attrs,
        E::Index(e) => &e.attrs,
        E::Infer(e) => &e.attrs,
        E::Let(e) => &e.attrs,
        E::Lit(e) => &e.attrs,
        E::Loop(e) => &e.attrs,
        E::Macro(e) => &e.attrs,
        E::Match(e) => &e.attrs,
        E::MethodCall(e) => &e.attrs,
        E::Paren(e) => &e.attrs,
        E::Path(e) => &e.attrs,
        E::Range(e) => &e.attrs,
        E::RawAddr(e) => &e.attrs,
        E::Reference(e) => &e.attrs,
        E::Repeat(e) => &e.attrs,
        E::Return(e) => &e.attrs,
        E::Struct(e) => &e.attrs,
        E::Try(e) => &e.attrs,
        E::TryBlock(e) => &e.attrs,
        E::Tuple(e) => &e.attrs,
        E::Unary(e) => &e.attrs,
        E::Unsafe(e) => &e.attrs,
        E::While(e) => &e.attrs,
        E::Yield(e) => &e.attrs,
        _ => &[],
    }
}

/// The attributes written on an item.
pub(super) fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    use syn::Item as I;
    match item {
        I::Const(i) => &i.attrs,
        I::Enum(i) => &i.attrs,
        I::ExternCrate(i) => &i.attrs,
        I::Fn(i) => &i.attrs,
        I::ForeignMod(i) => &i.attrs,
        I::Impl(i) => &i.attrs,
        I::Macro(i) => &i.attrs,
        I::Mod(i) => &i.attrs,
        I::Static(i) => &i.attrs,
        I::Struct(i) => &i.attrs,
        I::Trait(i) => &i.attrs,
        I::TraitAlias(i) => &i.attrs,
        I::Type(i) => &i.attrs,
        I::Union(i) => &i.attrs,
        I::Use(i) => &i.attrs,
        _ => &[],
    }
}

/// Walk the crate at `crate_root` from each of `roots` (paths relative to
/// it, such as `src/lib.rs`), reporting every production node to `sink`.
/// A declared module whose file cannot be found or parsed is an error, so a
/// walk can never silently cover less than the compiler does.
pub(super) fn walk(
    crate_root: &Path,
    roots: &[&str],
    sink: &mut dyn Sink,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    // A module the lib and a bin both declare is one file: walked once.
    let mut visited = std::collections::HashSet::new();
    for root in roots {
        let path = crate_root.join(root);
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let mut walker = Walker {
            crate_root,
            child_dir: dir.clone(),
            path_base: dir,
            place: Place::default(),
            owner: Owner::Module,
            stmt_top: false,
            sink: &mut *sink,
            errors: &mut errors,
            visited: &mut visited,
        };
        walker.file(&path);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

struct Walker<'a> {
    crate_root: &'a Path,
    /// Where an out-of-line `mod x;` with no `#[path]` looks for `x.rs`.
    child_dir: PathBuf,
    /// What a `#[path]` on a module declaration is relative to.
    path_base: PathBuf,
    place: Place,
    owner: Owner,
    /// The next expression is a statement's own expression.
    stmt_top: bool,
    sink: &'a mut dyn Sink,
    errors: &'a mut Vec<String>,
    visited: &'a mut std::collections::HashSet<PathBuf>,
}

impl Walker<'_> {
    fn file(&mut self, path: &Path) {
        let key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !self.visited.insert(key) {
            return;
        }
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(e) => return self.errors.push(format!("{}: {e}", path.display())),
        };
        let parsed = match syn::parse_file(&source) {
            Ok(parsed) => parsed,
            Err(e) => return self.errors.push(format!("{}: {e}", path.display())),
        };
        // A file whose own inner attributes say `#![cfg(test)]` is test-only.
        if test_only(&parsed.attrs) {
            return;
        }
        let saved = self.place.clone();
        // A `#[path = "../x.rs"]` include names the file by where it lives,
        // not by the route the declaring module took to it.
        let mut real = PathBuf::new();
        for part in path.components() {
            match part {
                std::path::Component::ParentDir => {
                    real.pop();
                }
                std::path::Component::CurDir => {}
                part => real.push(part),
            }
        }
        self.place = Place {
            file: real
                .strip_prefix(self.crate_root)
                .unwrap_or(&real)
                .to_string_lossy()
                // The pinned data keys files with `/`; Windows paths use `\`.
                .replace('\\', "/"),
            func: None,
        };
        self.owner = Owner::Module;
        self.sink.file(&self.place, &parsed);
        self.visit_file(&parsed);
        self.place = saved;
    }

    /// Load the out-of-line module `name` (with its `#[path]`, if any).
    fn module_file(&mut self, name: &str, attrs: &[syn::Attribute]) {
        let explicit = attrs
            .iter()
            .find(|a| a.path().is_ident("path"))
            .and_then(|a| match &a.meta {
                syn::Meta::NameValue(nv) => match &nv.value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) => Some(s.value()),
                    _ => None,
                },
                _ => None,
            });
        let flat = self.child_dir.join(format!("{name}.rs"));
        let (target, owns_dir) = if let Some(rel) = explicit {
            (self.path_base.join(rel), true)
        } else if flat.exists() {
            (flat, false)
        } else {
            (self.child_dir.join(name).join("mod.rs"), true)
        };
        let parent = target.parent().map(Path::to_path_buf).unwrap_or_default();
        // A `mod.rs` or `#[path]` file owns its directory; `x.rs` owns `x/`.
        let child_dir = if owns_dir || target.file_name().is_some_and(|f| f == "mod.rs") {
            parent.clone()
        } else {
            parent.join(name)
        };
        let saved = (
            std::mem::replace(&mut self.child_dir, child_dir),
            std::mem::replace(&mut self.path_base, parent),
        );
        self.file(&target);
        (self.child_dir, self.path_base) = saved;
    }
}

impl<'ast> Visit<'ast> for Walker<'_> {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        self.sink.attribute(&self.place, self.owner, attr);
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if test_only(item_attrs(item)) {
            return;
        }
        self.sink.item(&self.place, item);
        let saved = self.owner;
        self.owner = Owner::Item;
        syn::visit::visit_item(self, item);
        self.owner = saved;
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        for attr in &module.attrs {
            self.visit_attribute(attr);
        }
        // `mod r#override;` lives in `override.rs`.
        let name = syn::ext::IdentExt::unraw(&module.ident).to_string();
        // Shapes the walk does not resolve fail loudly rather than skip a
        // module: a `#[path]` behind `cfg_attr`, or one on an inline module.
        let conditional_path = module.attrs.iter().any(|a| {
            a.path().is_ident("cfg_attr")
                && a.parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|args| args.iter().skip(1).any(|m| m.path().is_ident("path")))
        });
        let inline_path =
            module.content.is_some() && module.attrs.iter().any(|a| a.path().is_ident("path"));
        if conditional_path || inline_path {
            self.errors.push(format!(
                "{}: module `{name}` uses a path shape the pin walk does not resolve",
                self.place.file
            ));
            return;
        }
        match &module.content {
            None => self.module_file(&name, &module.attrs),
            Some((_, items)) => {
                let inner = self.child_dir.join(&name);
                let saved = (
                    std::mem::replace(&mut self.child_dir, inner.clone()),
                    std::mem::replace(&mut self.path_base, inner),
                );
                for item in items {
                    self.visit_item(item);
                }
                (self.child_dir, self.path_base) = saved;
            }
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // `include!` splices a file the walk cannot see as a module.
        if mac.path.is_ident("include") {
            self.errors.push(format!(
                "{}: include! in production code is not walked",
                self.place.file
            ));
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_item_fn(&mut self, func: &'ast syn::ItemFn) {
        let saved = self.place.func.replace(func.sig.ident.to_string());
        syn::visit::visit_item_fn(self, func);
        self.place.func = saved;
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if test_only(attrs) {
            return;
        }
        let saved = self.owner;
        self.owner = Owner::Item;
        syn::visit::visit_impl_item(self, item);
        self.owner = saved;
    }

    fn visit_impl_item_fn(&mut self, func: &'ast syn::ImplItemFn) {
        let saved = self.place.func.replace(func.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, func);
        self.place.func = saved;
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(local) => &local.attrs,
            syn::Stmt::Macro(mac) => &mac.attrs,
            syn::Stmt::Expr(expr, _) => expr_attrs(expr),
            syn::Stmt::Item(_) => &[],
        };
        if test_only(attrs) {
            return;
        }
        self.sink.stmt(&self.place, stmt);
        let saved = self.owner;
        self.owner = Owner::Statement;
        self.stmt_top = matches!(stmt, syn::Stmt::Expr(..));
        syn::visit::visit_stmt(self, stmt);
        self.stmt_top = false;
        self.owner = saved;
    }

    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if test_only(expr_attrs(expr)) {
            return;
        }
        let top = std::mem::take(&mut self.stmt_top);
        self.sink.expr(&self.place, expr);
        let saved = self.owner;
        self.owner = if top {
            Owner::Statement
        } else {
            Owner::Expression
        };
        syn::visit::visit_expr(self, expr);
        self.owner = saved;
    }
}
