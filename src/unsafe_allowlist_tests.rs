// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-016: `unsafe` lives in exactly the scoped modules named here. A new
//! site fails this test until an ADR names it (ADR-028 rule 10 adds the
//! Windows credential module when it lands).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Product and test-helper files allowed to hold `unsafe`.
const ALLOWED: &[&str] = &["src/win_acl.rs", "src/gateway/server/tests/alloc_meter.rs"];

/// Integration tests with their own `unsafe` exemption (environment mutation
/// in single-threaded test binaries), recorded so a new one is a decision.
const TEST_EXEMPT: &[&str] = &[
    "tests/agent_key_env_tests.rs",
    "tests/capability_default_directories.rs",
    "tests/capability_egress_env_proxy.rs",
    "tests/capability_egress_proxy_opt_in.rs",
    "tests/common/era_probe_cap.rs",
    "tests/hardened_backend_env_proxy.rs",
    "tests/loopback_backend_env_proxy.rs",
    "tests/redact_memory_peak.rs",
    "tests/secret_injection_tests.rs",
];

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

/// Finds any use of `unsafe` or opt-in to it in one parsed file.
#[derive(Default)]
struct UnsafeFinder {
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for UnsafeFinder {
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.found = true;
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_signature(&mut self, node: &'ast syn::Signature) {
        self.found |= node.unsafety.is_some();
        syn::visit::visit_signature(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        self.found |= node.unsafety.is_some();
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        self.found |= node.unsafety.is_some();
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        // `extern` blocks declare foreign items that only `unsafe` can call.
        self.found = true;
        syn::visit::visit_item_foreign_mod(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // A macro body is opaque tokens to the parser: `unsafe` written there
        // is found by keyword, never by a string that merely spells it.
        let buffer = syn::buffer::TokenBuffer::new2(node.tokens.clone());
        self.found |= has_unsafe_keyword(buffer.begin());
        syn::visit::visit_macro(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        // `#[unsafe(no_mangle)]`, and `unsafe_code` anywhere in an `allow`,
        // `expect`, `cfg_attr` or combined lint list.
        let lint_list = match &node.meta {
            syn::Meta::List(list)
                if list.path.is_ident("allow")
                    || list.path.is_ident("expect")
                    || list.path.is_ident("cfg_attr") =>
            {
                list.tokens.to_string().contains("unsafe_code")
            }
            _ => false,
        };
        self.found |= node.path().is_ident("unsafe") || lint_list;
        syn::visit::visit_attribute(self, node);
    }
}

/// Whether the tokens from `cursor` hold the `unsafe` keyword, or
/// `unsafe_code`, at any depth.
fn has_unsafe_keyword(mut cursor: syn::buffer::Cursor<'_>) -> bool {
    while !cursor.eof() {
        if let Some((ident, next)) = cursor.ident() {
            if ident == "unsafe" || ident == "unsafe_code" {
                return true;
            }
            cursor = next;
        } else if let Some((inside, _, _, next)) = cursor.any_group() {
            if has_unsafe_keyword(inside) {
                return true;
            }
            cursor = next;
        } else if let Some((_, next)) = cursor.token_tree() {
            cursor = next;
        } else {
            break;
        }
    }
    false
}

/// Whether the Rust source in `text` uses or opts into `unsafe`. A file that
/// does not parse fails the test by name rather than passing unread.
fn uses_unsafe(path: &Path, text: &str) -> bool {
    let file = syn::parse_file(text)
        .unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
    let mut finder = UnsafeFinder::default();
    syn::visit::Visit::visit_file(&mut finder, &file);
    finder.found
}

fn sites(root: &Path, dirs: &[&str]) -> BTreeSet<String> {
    let mut files = Vec::new();
    for dir in dirs {
        let path = root.join(dir);
        if path.is_file() {
            files.push(path);
        } else {
            rust_files(&path, &mut files);
        }
    }
    files
        .into_iter()
        .filter(|path| std::fs::read_to_string(path).is_ok_and(|text| uses_unsafe(path, &text)))
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn a18_unsafe_appears_only_in_the_scoped_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = sites(root, &["src", "benches", "examples", "build.rs"]);
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|path| (*path).to_owned()).collect();
    assert_eq!(
        found, allowed,
        "unsafe outside ADR-016/ADR-028's list, or a listed module without it"
    );
}

#[test]
fn a18_test_exemptions_are_the_recorded_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let found = sites(root, &["tests"]);
    let exempt: BTreeSet<String> = TEST_EXEMPT.iter().map(|path| (*path).to_owned()).collect();
    assert_eq!(found, exempt, "a new unsafe site in tests/");
}

#[test]
fn the_scan_sees_every_form_of_unsafe() {
    let path = Path::new("fixture.rs");
    for source in [
        "fn f() { unsafe { g() } }",
        "unsafe fn f() {}",
        "unsafe impl Send for T {}",
        "unsafe trait T {}",
        "unsafe extern \"C\" { fn g(); }",
        "#[unsafe(no_mangle)] fn f() {}",
        "#![allow(unsafe_code)]",
        "#[expect(unsafe_code)] fn f() {}",
        "#[allow(dead_code, unsafe_code)] fn f() {}",
        "#[cfg_attr(test, allow(unsafe_code))] fn f() {}",
        "m! { unsafe { g() } }",
        "macro_rules! m { () => { unsafe { g() } }; }",
        "fn f() { m!(#[allow(unsafe_code)] x); }",
    ] {
        assert!(uses_unsafe(path, source), "missed: {source}");
    }
    for source in [
        "fn f() { let s = \"unsafe { }\"; }",
        "// unsafe { }\nfn f() {}",
        "#[allow(dead_code)] fn f() {}",
        "fn f() { println!(\"unsafe {}\", 1); }",
    ] {
        assert!(!uses_unsafe(path, source), "false hit: {source}");
    }
}
