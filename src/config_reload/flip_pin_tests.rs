// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The multi-user flip check exists once and is called only where listed: a
//! key list that changes whether the gateway is multi-user is judged by one
//! predicate on every path, never a copy that could drift.

use std::path::Path;

use crate::test_source_files::rust_files;

/// Each production call of the flip check, by file: the reload's
/// `Generation::prepare`, and the web UI key create's compute.
const CALLERS: &[(&str, usize)] = &[
    ("src/config_reload/generation.rs", 1),
    ("src/gateway/ui/keys_create.rs", 1),
    ("src/gateway/ui/keys_revoke.rs", 1),
];

fn production_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            if relative.split('/').any(|part| {
                part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
            }) {
                return None;
            }
            let text = std::fs::read_to_string(&path).ok()?;
            let code =
                crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
            Some((relative, code))
        })
        .collect()
}

#[test]
fn the_flip_check_is_called_only_where_listed() {
    let mut found: Vec<(String, usize)> = production_sources()
        .into_iter()
        .filter_map(|(file, code)| {
            let count = code.matches("refuse_multi_user_flip(").count()
                - code.matches("fn refuse_multi_user_flip(").count();
            (count > 0).then_some((file, count))
        })
        .collect();
    found.sort();
    let want: Vec<(String, usize)> = CALLERS
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(found, want, "a new caller of the flip check: list it here");
}

#[test]
fn the_flip_comparison_exists_once() {
    let copies: Vec<String> = production_sources()
        .into_iter()
        .filter(|(_, code)| code.contains("implies_multi_user(oidc) !="))
        .map(|(file, _)| file)
        .collect();
    assert_eq!(copies, ["src/config_reload/generation.rs"], "{copies:?}");
}
