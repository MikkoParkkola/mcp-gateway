// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Error` is non-exhaustive, and its doc tests show what that means for a
//! caller. The `compile_fail` doc test lists every variant with no wildcard
//! arm; it proves the point only while it names every variant and differs
//! from its compiling twin by nothing but that arm. Otherwise a missing
//! variant or a mistyped pattern would fail it instead, and it would pass.

use std::collections::BTreeSet;

const SOURCE: &str = include_str!("error.rs");
const FAILING: &str = "/// ```compile_fail,E0004\n";
const PASSING: &str = "/// The same arms with a wildcard compile:\n///\n/// ```\n";

/// A full identifier at the start of `text`.
fn ident(text: &str) -> String {
    text.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// The variant names of `pub enum Error`, read from its source.
fn enum_variants() -> BTreeSet<String> {
    let body = SOURCE
        .split("\npub enum Error {\n")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("the enum and its closing brace");
    body.lines()
        .filter_map(|line| {
            let name = ident(line.strip_prefix("    ")?);
            name.starts_with(|c: char| c.is_ascii_uppercase())
                .then_some(name)
        })
        .collect()
}

/// The code lines of the doc test that opens with `fence`, `///` removed.
fn doc_test_lines(fence: &str) -> Vec<String> {
    SOURCE
        .split(fence)
        .nth(1)
        .and_then(|rest| rest.split("/// ```").next())
        .expect("the doc test")
        .lines()
        .map(|line| line.trim_start_matches("///").trim().to_owned())
        .collect()
}

/// The arm lines of a doc test: every line naming a variant.
fn arms(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| line.contains("Error::"))
        .cloned()
        .collect()
}

#[test]
fn error_is_non_exhaustive() {
    assert!(
        SOURCE.contains("#[derive(Error, Debug)]\n#[non_exhaustive]\npub enum Error {\n"),
        "`#[non_exhaustive]` must apply to `pub enum Error`"
    );
}

#[test]
fn the_error_doc_tests_list_every_variant() {
    let failing = doc_test_lines(FAILING);
    let passing = doc_test_lines(PASSING);
    for line in failing.iter().chain(&passing) {
        assert!(!line.starts_with("//"), "no commented-out arm: {line}");
    }
    let named: BTreeSet<String> = arms(&failing)
        .iter()
        .filter_map(|line| line.split("Error::").nth(1).map(ident))
        .collect();
    let variants = enum_variants();
    assert!(variants.len() > 30, "parsed {} variants", variants.len());
    assert_eq!(named, variants, "the compile_fail doc test's arms");
    assert_eq!(
        arms(&passing),
        arms(&failing),
        "the twin's arms are the compile_fail arms, line for line"
    );
    let extra: Vec<&String> = passing.iter().filter(|l| !failing.contains(l)).collect();
    assert_eq!(
        extra,
        [&"_ => false,".to_owned()],
        "the twin differs only by the wildcard arm"
    );
}
