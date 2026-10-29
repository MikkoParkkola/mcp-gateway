// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `Error` doc tests list every variant. The `compile_fail` one shows the
//! enum is non-exhaustive only while none is missing: a variant left out
//! would fail it for that reason instead, and it would still pass.

use std::collections::BTreeSet;

const SOURCE: &str = include_str!("error.rs");

/// The variant names of `pub enum Error`, read from its source.
fn enum_variants() -> BTreeSet<String> {
    let body = SOURCE
        .split("\npub enum Error {\n")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("the enum and its closing brace");
    body.lines()
        .filter_map(|line| {
            let item = line.strip_prefix("    ")?;
            let name: String = item
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect();
            name.starts_with(|c: char| c.is_ascii_uppercase())
                .then_some(name)
        })
        .collect()
}

/// The `Error::Name` arms of the doc test that opens with `fence`.
fn doc_test_arms(fence: &str) -> (BTreeSet<String>, String) {
    let block = SOURCE
        .split(fence)
        .nth(1)
        .and_then(|rest| rest.split("/// ```").next())
        .expect("the doc test");
    let arms = block
        .split("Error::")
        .skip(1)
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect()
        })
        .collect();
    (arms, block.to_owned())
}

#[test]
fn the_error_doc_tests_list_every_variant() {
    let variants = enum_variants();
    assert!(variants.len() > 30, "parsed {} variants", variants.len());
    let (failing, _) = doc_test_arms("/// ```compile_fail,E0004\n");
    assert_eq!(failing, variants, "the compile_fail doc test's arms");
    let (passing, block) =
        doc_test_arms("/// The same arms with a wildcard compile:\n///\n/// ```\n");
    assert_eq!(passing, variants, "the wildcard doc test's arms");
    assert!(block.contains("_ => false"), "the wildcard arm: {block}");
}
