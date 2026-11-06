// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every way production code creates a caller identity is a reviewed row in
//! `identity_sources.tsv`, keyed by (file, owner, kind): each call of a
//! checked constructor or the certificate parser and each struct literal of
//! the three identity types, with its count; each macro that names one of
//! them; and each of the three files that define them, with a hash of its
//! exact bytes. A new site, a changed count or
//! fingerprint, a stale row or a row with no reason fails.
//!
//! Refused outright, whatever the table says: renaming one of the types by
//! `use .. as` or `type`, a qualified path (`<GrantSubject>::new`), a child
//! module or `include!` in a defining module, and any macro outside a fixed
//! list in a defining module or in an impl of one of the types.
//!
//! Outside the defining modules the compiler is the guard for fields: they are
//! private, and privacy is checked after macro expansion. Inside them the
//! file hash is, so any edit there is a reviewed row.

use std::collections::BTreeMap;

use super::fragments::{Table, shown};
use super::packaged::crate_root;
use super::scan::{Place, Sink, expr_attrs, item_attrs, test_only, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// (file, owner, kind) -> count, or the file hash for kind `file`.
pub(super) type Rows = BTreeMap<(String, String, String), String>;

/// What one scan found: the rows, and the forms refused outright.
#[derive(Default, Debug)]
pub(super) struct Scan {
    pub(super) rows: Rows,
    pub(super) refused: Vec<String>,
}

/// Each identity type with the constructors that create one.
const TYPES: [(&str, &[&str]); 3] = [
    ("VerifiedIdentity", &["checked"]),
    ("GrantSubject", &["new"]),
    ("CertIdentity", &["from_der", "parse"]),
];

/// The modules that define the types: their fields are visible here only.
const LEAVES: [&str; 3] = [
    "src/key_server/oidc/verified.rs",
    "src/identity_grants/subject.rs",
    "src/mtls/identity/cert.rs",
];

/// The only macros allowed in a defining module or an impl of one of the
/// types: none of them can reach a field through an expansion written
/// elsewhere.
const MACROS: [&str; 15] = [
    "format",
    "write",
    "writeln",
    "vec",
    "debug_assert",
    "assert",
    "assert_eq",
    "matches",
    "concat",
    "stringify",
    "debug",
    "info",
    "warn",
    "error",
    "trace",
];

fn is_type(name: &str) -> bool {
    TYPES.iter().any(|(t, _)| *t == name)
}

/// Scan one production file, `file` relative to the crate root.
pub(super) fn scan_file(file: &str, parsed: &syn::File, scan: &mut Scan) {
    let mut visitor = Visitor {
        file,
        leaf: LEAVES.contains(&file),
        owner: Vec::new(),
        impl_ty: None,
        scan,
    };
    for item in &parsed.items {
        visitor.item(item);
    }
}

struct Visitor<'a> {
    file: &'a str,
    leaf: bool,
    owner: Vec<String>,
    impl_ty: Option<String>,
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
        let at = format!("{}: {what} in `{}`", self.file, self.owner());
        self.scan.refused.push(at);
    }

    /// The identity type a path's first segment names: the type itself, or
    /// `Self` inside an impl of one.
    fn named_type(&self, segment: &syn::PathSegment) -> Option<String> {
        let name = segment.ident.to_string();
        if is_type(&name) {
            return Some(name);
        }
        (name == "Self")
            .then(|| self.impl_ty.clone())
            .flatten()
            .filter(|t| is_type(t))
    }

    fn item(&mut self, item: &syn::Item) {
        use syn::Item as I;
        if test_only(item_attrs(item)) {
            return;
        }
        match item {
            I::Mod(m) => {
                if self.leaf {
                    self.refuse(&format!("child module `{}` of a defining module", m.ident));
                }
                if let Some((_, items)) = &m.content {
                    self.owner.push(m.ident.to_string());
                    for inner in items {
                        self.item(inner);
                    }
                    self.owner.pop();
                }
                return;
            }
            I::Use(u) => self.use_tree(&u.tree),
            I::Type(t) => {
                if last_ident(&t.ty).is_some_and(|n| is_type(&n)) {
                    self.refuse(&format!("type alias `{}` of an identity type", t.ident));
                }
            }
            I::Impl(block) => return self.impl_block(block),
            _ => {}
        }
        let name = item_name(item);

        self.owner.push(name);
        syn::visit::visit_item(self, item);
        self.owner.pop();
    }

    fn impl_block(&mut self, block: &syn::ItemImpl) {
        let saved = self
            .impl_ty
            .replace(last_ident(&block.self_ty).unwrap_or_default());
        let ty = self.impl_ty.clone().unwrap_or_default();
        for inner in &block.items {
            let (attrs, name) = match inner {
                syn::ImplItem::Const(i) => (&i.attrs, i.ident.to_string()),
                syn::ImplItem::Fn(i) => (&i.attrs, i.sig.ident.to_string()),
                syn::ImplItem::Type(i) => (&i.attrs, i.ident.to_string()),
                syn::ImplItem::Macro(i) => (&i.attrs, format!("{}!", path_text(&i.mac.path))),
                _ => continue,
            };
            if test_only(attrs) || test_only(&block.attrs) {
                continue;
            }
            let owner = format!("{ty}::{name}");

            self.owner.push(owner);
            syn::visit::visit_impl_item(self, inner);
            self.owner.pop();
        }
        self.impl_ty = saved;
    }

    fn use_tree(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(p) => self.use_tree(&p.tree),
            syn::UseTree::Group(g) => g.items.iter().for_each(|t| self.use_tree(t)),
            syn::UseTree::Rename(r) if is_type(&r.ident.to_string()) => {
                self.refuse(&format!("`{}` imported as `{}`", r.ident, r.rename));
            }
            _ => {}
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for Visitor<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        self.item(item);
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(l) => &l.attrs,
            syn::Stmt::Macro(m) => &m.attrs,
            syn::Stmt::Expr(e, _) => expr_attrs(e),
            syn::Stmt::Item(_) => &[],
        };
        if !test_only(attrs) {
            syn::visit::visit_stmt(self, stmt);
        }
    }

    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if !test_only(expr_attrs(expr)) {
            syn::visit::visit_expr(self, expr);
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(q) = &path.qself {
            let named = last_ident(&q.ty).is_some_and(|n| {
                is_type(&n) || (n == "Self" && self.impl_ty.as_deref().is_some_and(is_type))
            });
            if named {
                self.refuse("a qualified path to an identity type");
            }
        }
        let segs: Vec<&syn::PathSegment> = path.path.segments.iter().collect();
        if let [.., ty, ctor] = segs[..]
            && path.qself.is_none()
            && let Some(ty) = self.named_type(ty)
        {
            let ctor = ctor.ident.to_string();
            let listed = TYPES
                .iter()
                .any(|(t, ctors)| *t == ty && ctors.contains(&ctor.as_str()));
            if listed {
                self.count(&ctor);
            }
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_struct(&mut self, lit: &'ast syn::ExprStruct) {
        if lit
            .path
            .segments
            .last()
            .and_then(|s| self.named_type(s))
            .is_some()
        {
            self.count("literal");
        }
        syn::visit::visit_expr_struct(self, lit);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let near_fields = self.leaf || self.impl_ty.as_deref().is_some_and(is_type);
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if near_fields && !MACROS.contains(&name.as_str()) {
            self.refuse(&format!(
                "macro `{}!` near identity fields",
                path_text(&mac.path)
            ));
        }
        let in_impl = self.impl_ty.as_deref().is_some_and(is_type);
        if names_identity(mac, in_impl) {
            self.count("macro");
        }
    }
}

/// Hands each production file the shared walk reaches to [`scan_file`].
struct Files(Scan);

impl Sink for Files {
    fn file(&mut self, at: &Place, file: &syn::File) {
        scan_file(&at.file, file, &mut self.0);
        if LEAVES.contains(&at.file.as_str()) {
            let path = crate_root().join(&at.file);
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let key = (at.file.clone(), "<file>".to_owned(), "file".to_owned());
            self.0.rows.insert(key, file_fingerprint(&bytes));
        }
    }
}

/// The scan of every production file of this crate.
pub(super) fn crate_scan() -> Scan {
    let mut files = Files(Scan::default());
    walk(crate_root(), &ROOTS, &mut files).expect("the walk reads every module");
    files.0
}

/// The last identifier of a type written as a path (`a::B<C>` -> `B`).
fn last_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        syn::Type::Group(g) => last_ident(&g.elem),
        syn::Type::Paren(p) => last_ident(&p.elem),
        _ => None,
    }
}

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// The owner name an item gives the code inside it.
fn item_name(item: &syn::Item) -> String {
    use syn::Item as I;
    match item {
        I::Const(i) => i.ident.to_string(),
        I::Enum(i) => i.ident.to_string(),
        I::ExternCrate(i) => i.ident.to_string(),
        I::Fn(i) => i.sig.ident.to_string(),
        I::Macro(i) => i.ident.as_ref().map_or_else(
            || format!("{}!", path_text(&i.mac.path)),
            ToString::to_string,
        ),
        I::Static(i) => i.ident.to_string(),
        I::Struct(i) => i.ident.to_string(),
        I::Trait(i) => i.ident.to_string(),
        I::TraitAlias(i) => i.ident.to_string(),
        I::Type(i) => i.ident.to_string(),
        I::Union(i) => i.ident.to_string(),
        _ => "<item>".to_owned(),
    }
}

/// Whether a macro's tokens name an identity type, or `Self` inside an impl
/// of one. Tokens inside groups are searched too.
fn names_identity(mac: &syn::Macro, in_impl: bool) -> bool {
    let buffer = syn::buffer::TokenBuffer::new2(mac.tokens.clone());
    let mut stack = vec![buffer.begin()];
    while let Some(mut cursor) = stack.pop() {
        while !cursor.eof() {
            if let Some((ident, next)) = cursor.ident() {
                let name = ident.to_string();
                if is_type(&name) || (in_impl && name == "Self") {
                    return true;
                }
                cursor = next;
            } else if let Some((inside, _, _, next)) = cursor.any_group() {
                stack.push(inside);
                cursor = next;
            } else if let Some((_, next)) = cursor.token_tree() {
                cursor = next;
            } else {
                break;
            }
        }
    }
    false
}

/// The fingerprint of a defining module: a hash of its exact bytes, so any
/// edit to the file, whitespace and test sections included, is a reviewed row.
pub(super) fn file_fingerprint(bytes: &[u8]) -> String {
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes))
}

/// (file, owner, kind) -> (value, the table file listing it).
type Listed = BTreeMap<(String, String, String), (String, String)>;

/// The reviewed rows (file, owner, kind, value, reason), and the malformed ones.
fn listed(table: &Table) -> (Listed, Vec<String>) {
    let mut rows = Listed::new();
    let mut bad = Vec::new();
    for (path, line) in table.rows() {
        let at = shown(path);
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, owner, kind, value, reason] = cols[..] else {
            bad.push(format!("not five columns in {at}: {line}"));
            continue;
        };
        if reason.trim().is_empty() {
            bad.push(format!("no reason in {at}: {line}"));
        }
        let key = (file.to_owned(), owner.to_owned(), kind.to_owned());
        if let Some((_, earlier)) = rows.insert(key, (value.to_owned(), at.clone())) {
            bad.push(format!(
                "repeated key in {earlier} and {at}: {file}\t{owner}\t{kind}"
            ));
        }
    }
    (rows, bad)
}

/// What differs between a scan and the reviewed table: refused forms,
/// malformed rows, changed values, unlisted sites and stale rows.
pub(super) fn differences(found: &Scan, table: &Table) -> Vec<String> {
    let (want, bad) = listed(table);
    let mut wrong: Vec<String> = found.refused.clone();
    wrong.extend(bad);
    let mut add = Vec::new();
    for (key, value) in &found.rows {
        match want.get(key) {
            Some((listed, _)) if listed == value => {}
            Some((listed, at)) => wrong.push(format!(
                "{listed} -> {value}, review and edit this row in {at}: {}\t{}\t{}",
                key.0, key.1, key.2
            )),
            None => add.push(format!(
                "{}\t{}\t{}\t{value}\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for (key, (_, at)) in want.iter().filter(|(k, _)| !found.rows.contains_key(*k)) {
        wrong.push(format!(
            "stale, remove from {at}: {}\t{}\t{}",
            key.0, key.1, key.2
        ));
    }
    if !add.is_empty() {
        wrong.push(format!(
            "rows to add ({}; put these in your fragment identity_sources.d/<ticket>.tsv):",
            add.len()
        ));
        wrong.extend(add);
    }
    wrong
}

#[path = "identity_sources_tests.rs"]
mod tests;
