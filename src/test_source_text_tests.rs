// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `production_text`: each `#[cfg(test)]` item shape is blanked by its own
//! extent, and nothing after it is lost.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::test_source_text::{production_text, sanitize};

/// `(source, kept, blanked)`: after blanking, every `kept` text remains and
/// no `blanked` text does.
const CASES: &[(&str, &[&str], &[&str])] = &[
    (
        "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn product() {}\n",
        &["fn product()"],
        &["fn t()"],
    ),
    (
        "#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod x;\nfn product() {}\n",
        &["fn product()"],
        &["mod x"],
    ),
    (
        "struct S {\n    #[cfg(test)]\n    probe: u8,\n    live: u8,\n}\nimpl S {}\n",
        &["live: u8", "impl S"],
        &["probe"],
    ),
    (
        "struct S {\n    live: u8,\n    #[cfg(test)]\n    probe: u8\n}\nimpl S {}\n",
        &["live: u8", "}\nimpl S"],
        &["probe"],
    ),
    (
        "enum E {\n    #[cfg(test)]\n    Probe,\n    Live,\n}\n",
        &["Live"],
        &["Probe"],
    ),
    (
        "fn f(x: u8) -> u8 {\n    match x {\n        #[cfg(test)]\n        0 => { probe() }\n        _ => live(),\n    }\n}\n",
        &["_ => live()"],
        &["probe"],
    ),
    (
        "#[cfg(test)]\nconst TABLE: [u8; 4] = [0; 4];\nfn product() {}\n",
        &["fn product()"],
        &["TABLE"],
    ),
    (
        "#[cfg(test)]\nconst S: Shape = Shape { a: 1 };\nfn product() {}\n",
        &["fn product()"],
        &["Shape {"],
    ),
    (
        "#[cfg(test)]\nuse crate::{probe, other};\nfn product() {}\n",
        &["fn product()"],
        &["probe"],
    ),
    (
        "fn now(&self) -> u64 {\n    #[cfg(test)]\n    if let Some(t) = probe() {\n        return t;\n    } else {\n        idle();\n    }\n    self.live()\n}\n",
        &["self.live()"],
        &["probe", "idle"],
    ),
    (
        "fn now(&self) -> u8 {\n    #[cfg(test)]\n    { probe() }.touch()?;\n    self.live()\n}\n",
        &["self.live()"],
        &["probe", "touch"],
    ),
    (
        "fn f(x: u8) -> u8 {\n    match x {\n        #[cfg(test)]\n        0 => { probe() }\n        ..=5 => live(),\n        _ => 0,\n    }\n}\n",
        &["..=5 => live()"],
        &["probe"],
    ),
    (
        "fn f() -> std::ops::RangeTo<u8> {\n    #[cfg(test)]\n    { probe() }\n    ..5\n}\n",
        &["..5"],
        &["probe"],
    ),
    (
        "fn f() {\n    #[cfg(test)]\n    {}\n    \"x\".chars().for_each(|_| live());\n}\n",
        &["for_each(|_| live())"],
        &[],
    ),
    (
        "fn f() {\n    #[cfg(test)]\n    { probe() }\n    elseé.live();\n}\n",
        &["elseé.live()"],
        &["probe"],
    ),
    (
        "// A comment naming #[cfg(test)] marks nothing.\nfn product() {}\n",
        &["fn product()"],
        &[],
    ),
    (
        "const NOTE: &str = \"#[cfg(test)] in a string\";\nfn product() {}\n",
        &["fn product()", "in a string"],
        &[],
    ),
    (
        "#[cfg(test)]\nfn probe() { let s = \"}\"; }\nfn product() {}\n",
        &["fn product()"],
        &["probe"],
    ),
];

#[test]
fn each_test_item_shape_is_blanked_by_its_own_extent() {
    for (source, kept, blanked) in CASES {
        let out = production_text(source);
        assert_eq!(out.len(), source.len(), "positions kept: {source}");
        assert_eq!(
            out.lines().count(),
            source.lines().count(),
            "lines kept: {source}"
        );
        for k in *kept {
            assert!(out.contains(k), "{k:?} lost from {source:?}: {out:?}");
        }
        for b in *blanked {
            assert!(!out.contains(b), "{b:?} kept in {source:?}: {out:?}");
        }
    }
}

/// An item whose block never closes stays (a scan sees more, never less),
/// and an earlier, well-formed test item is still blanked.
#[test]
fn an_unclosed_item_stays_and_earlier_items_are_still_blanked() {
    let source = "#[cfg(test)]\nfn probe() {}\nfn product() {}\n#[cfg(test)]\nfn broken() {\n";
    let out = production_text(source);
    assert!(!out.contains("probe"));
    assert!(out.contains("fn product()"));
    assert!(out.contains("fn broken()"));
}

/// The case a review named: a test-only last field of `LiveConfig` must not
/// take the `impl LiveConfig` after it.
#[test]
fn a_test_only_field_keeps_the_impl_after_it() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config_reload/mod.rs"),
    )
    .unwrap();
    let out = production_text(&source);
    assert!(out.contains("impl LiveConfig {"));
    assert!(!out.contains("publishes: std::sync::atomic::AtomicU64"));
}

/// The tree-wide net for the rule "a scan sees more, never less": in every
/// source file under `src/` and `tests/` that the helper changes, each
/// identifier outside a `#[cfg(test)]` item, as a full Rust parse reads it,
/// still appears at least as often in the helper's output. A parse decides
/// what is test code here, independently of the helper's bracket walk, so a
/// shape the walk ends too late (production text blanked) fails by name.
/// Leftover test text only raises the output's counts and passes.
#[test]
fn no_production_identifier_is_blanked_anywhere_in_the_tree() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    let mut checked = 0;
    let mut lost = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let out = production_text(&text);
        if out == text {
            continue;
        }
        let file = syn::parse_file(&text)
            .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
        let mut parsed = ProductionIdents::default();
        syn::visit::Visit::visit_file(&mut parsed, &file);
        let code = sanitize(&out);
        let kept = words(&code);
        for (ident, want) in parsed.counts {
            let have = kept.get(ident.as_str()).copied().unwrap_or(0);
            if have < want {
                let name = path.strip_prefix(root).unwrap_or(&path).display();
                lost.push(format!(
                    "{name}: `{ident}` {want} in production, {have} kept"
                ));
            }
        }
        checked += 1;
    }
    assert!(checked > 100, "only {checked} files have test items");
    assert!(
        lost.is_empty(),
        "production text blanked:\n{}",
        lost.join("\n")
    );
}

/// The checker's own skip stays narrow: a `///` comment in a macro body
/// counts no `doc`, while `doc` as a name in macro code still counts.
#[test]
fn a_doc_comment_in_a_macro_body_is_not_counted_but_a_doc_name_is() {
    let file =
        syn::parse_file("m! {\n    /// note\n    static A: u8;\n}\nm! { let doc = 1; }\n").unwrap();
    let mut parsed = ProductionIdents::default();
    syn::visit::Visit::visit_file(&mut parsed, &file);
    assert_eq!(parsed.counts.get("doc"), Some(&1));
    assert_eq!(parsed.counts.get("note"), None);
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Identifier counts in code: runs of word characters that do not start
/// with a digit (a number's suffix is not an identifier).
fn words(code: &str) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for run in code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if run.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            *counts.entry(run).or_insert(0) += 1;
        }
    }
    counts
}

/// Counts identifiers outside `#[cfg(test)]` items, as `syn` reads them.
#[derive(Default)]
struct ProductionIdents {
    counts: BTreeMap<String, usize>,
}

impl ProductionIdents {
    fn count(&mut self, ident: &syn::Ident) {
        let name = ident.to_string();
        let name = name.strip_prefix("r#").unwrap_or(&name).to_string();
        *self.counts.entry(name).or_insert(0) += 1;
    }

    fn count_tokens(&mut self, mut cursor: syn::buffer::Cursor) {
        while !cursor.eof() {
            if let Some((ident, next)) = cursor.ident() {
                self.count(&ident);
                cursor = next;
            } else if let Some((lifetime, next)) = cursor.lifetime() {
                self.count(&lifetime.ident);
                cursor = next;
            } else if let Some(next) = doc_attribute_end(cursor) {
                cursor = next;
            } else if let Some((inner, _, _, next)) = cursor.any_group() {
                self.count_tokens(inner);
                cursor = next;
            } else if let Some((_, next)) = cursor.token_tree() {
                cursor = next;
            } else {
                break;
            }
        }
    }
}

/// Past a `#[doc = ...]` in macro tokens: a `///` comment to the parser, a
/// comment (blanked) in the text, as `visit_attribute` treats it outside macros.
fn doc_attribute_end(cursor: syn::buffer::Cursor) -> Option<syn::buffer::Cursor> {
    let (hash, next) = cursor.punct()?;
    let (inner, _, _, after) = next.any_group()?;
    let (ident, rest) = inner.ident()?;
    let is_doc = hash.as_char() == '#'
        && ident == "doc"
        && rest.punct().is_some_and(|(p, _)| p.as_char() == '=');
    is_doc.then_some(after)
}

/// An outer `#[cfg(test)]`, exactly the mark the helper looks for.
fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        matches!(a.style, syn::AttrStyle::Outer)
            && a.path().is_ident("cfg")
            && matches!(&a.meta, syn::Meta::List(l) if l.tokens.to_string() == "test")
    })
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    use syn::Item;
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

fn expr_attrs(expr: &syn::Expr) -> &[syn::Attribute] {
    use syn::Expr;
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Break(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Cast(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Const(e) => &e.attrs,
        Expr::Continue(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::Group(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Index(e) => &e.attrs,
        Expr::Infer(e) => &e.attrs,
        Expr::Let(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Range(e) => &e.attrs,
        Expr::RawAddr(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Repeat(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::TryBlock(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        Expr::Yield(e) => &e.attrs,
        _ => &[],
    }
}

impl<'ast> syn::visit::Visit<'ast> for ProductionIdents {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.count(ident);
    }

    /// A doc comment is an attribute to the parser and a comment in the text.
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if !attr.path().is_ident("doc") {
            syn::visit::visit_attribute(self, attr);
        }
    }

    /// A macro body is tokens, not items: one that holds a test-only mark is
    /// left uncounted rather than judged by a second copy of the helper's rule.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        syn::visit::visit_path(self, &mac.path);
        let body = mac.tokens.to_string().replace(' ', "");
        if !body.contains("#[cfg(test)]") {
            let tokens = syn::buffer::TokenBuffer::new2(mac.tokens.clone());
            self.count_tokens(tokens.begin());
        }
    }

    fn visit_fn_arg(&mut self, node: &'ast syn::FnArg) {
        let attrs = match node {
            syn::FnArg::Receiver(r) => &r.attrs,
            syn::FnArg::Typed(t) => &t.attrs,
        };
        if !test_only(attrs) {
            syn::visit::visit_fn_arg(self, node);
        }
    }

    fn visit_generic_param(&mut self, node: &'ast syn::GenericParam) {
        let attrs = match node {
            syn::GenericParam::Lifetime(p) => &p.attrs,
            syn::GenericParam::Type(p) => &p.attrs,
            syn::GenericParam::Const(p) => &p.attrs,
        };
        if !test_only(attrs) {
            syn::visit::visit_generic_param(self, node);
        }
    }

    fn visit_item(&mut self, node: &'ast syn::Item) {
        if !test_only(item_attrs(node)) {
            syn::visit::visit_item(self, node);
        }
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        let attrs = match node {
            syn::ImplItem::Const(i) => &i.attrs[..],
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if !test_only(attrs) {
            syn::visit::visit_impl_item(self, node);
        }
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        let attrs = match node {
            syn::TraitItem::Const(i) => &i.attrs[..],
            syn::TraitItem::Fn(i) => &i.attrs,
            syn::TraitItem::Type(i) => &i.attrs,
            syn::TraitItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        if !test_only(attrs) {
            syn::visit::visit_trait_item(self, node);
        }
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        if !test_only(&node.attrs) {
            syn::visit::visit_field(self, node);
        }
    }

    fn visit_variant(&mut self, node: &'ast syn::Variant) {
        if !test_only(&node.attrs) {
            syn::visit::visit_variant(self, node);
        }
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        if !test_only(&node.attrs) {
            syn::visit::visit_arm(self, node);
        }
    }

    /// `S { id }` holds `id` as both field and value; the text has it once.
    fn visit_field_value(&mut self, node: &'ast syn::FieldValue) {
        if test_only(&node.attrs) {
            return;
        }
        if node.colon_token.is_none() {
            self.visit_expr(&node.expr);
        } else {
            syn::visit::visit_field_value(self, node);
        }
    }

    /// The same shorthand in a pattern, `S { id, .. }`.
    fn visit_field_pat(&mut self, node: &'ast syn::FieldPat) {
        if node.colon_token.is_none() {
            self.visit_pat(&node.pat);
        } else {
            syn::visit::visit_field_pat(self, node);
        }
    }

    /// `&self` carries a `Self` type the parser supplies; the text has none.
    fn visit_receiver(&mut self, node: &'ast syn::Receiver) {
        if node.colon_token.is_some() {
            syn::visit::visit_receiver(self, node);
        } else if let Some((_, Some(lifetime))) = &node.reference {
            self.visit_lifetime(lifetime);
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if !test_only(&node.attrs) {
            syn::visit::visit_local(self, node);
        }
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        if !test_only(&node.attrs) {
            syn::visit::visit_stmt_macro(self, node);
        }
    }

    fn visit_expr(&mut self, node: &'ast syn::Expr) {
        if !test_only(expr_attrs(node)) {
            syn::visit::visit_expr(self, node);
        }
    }
}
