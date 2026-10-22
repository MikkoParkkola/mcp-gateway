// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8639 bounds: seam, alias-name, reuse, directive and expansion edges.
//!
//! Red on the skeleton unless marked ACCEPTED: its `limit()` is `None`, and
//! shapes the backend accepts fail at the refusal itself. Rows marked
//! ACCEPTED pass on the skeleton by design and pin the boundary kept green.

#[path = "common/yaml.rs"]
mod yaml;

use std::fmt::Write as _;

/// The probe string hostile inputs carry; it must never reach error text.
const SENTINEL: &str = "MIK8425-SENTINEL-7f3a";

/// The size gate the guard enforces on every text-taking seam.
const MAX_YAML_BYTES: usize = 16 * 1024 * 1024;

/// Parse `input` as a tree, assert it is refused value-free, return the error.
fn refused(input: &str, what: &str) -> yaml::Error {
    let Err(err) = yaml::from_str::<yaml::Value>(input) else {
        panic!("{what}: accepted, must be refused")
    };
    assert!(
        !err.to_string().contains(SENTINEL),
        "{what}: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "{what}: Debug leaks the sentinel"
    );
    err
}

/// Parse `input` through the loose seam, assert refused value-free.
fn refused_loose(input: &str, what: &str) -> yaml::Error {
    let Err(err) = yaml::from_str_loose(input) else {
        panic!("{what}: accepted, must be refused")
    };
    assert!(
        !err.to_string().contains(SENTINEL),
        "{what}: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "{what}: Debug leaks the sentinel"
    );
    err
}

/// Valid input of exactly `len` bytes: a small mapping plus one long comment.
fn sized_input(len: usize) -> String {
    let head = format!("a: {SENTINEL}\n");
    let mut input = String::with_capacity(len);
    input.push_str(&head);
    input.push('#');
    input.push_str(&"x".repeat(len - head.len() - 2));
    input.push('\n');
    input
}

/// One anchor plus `aliases` references to it.
fn aliased_input(aliases: usize) -> String {
    let mut input = format!("note: {SENTINEL}\nbase: &a 1\n");
    for index in 0..aliases {
        writeln!(input, "u{index}: *a").expect("writing to a String cannot fail");
    }
    input
}

/// Flow depth input with the sentinel scalar innermost.
fn deep_flow(depth: usize) -> String {
    format!("{}{SENTINEL}{}", "[".repeat(depth), "]".repeat(depth))
}

#[test]
fn alias_name_outside_grammar_refused() {
    let input = String::from("big: &x 1\nlater: {*x: 2}\n");
    let offset = input.find('*').unwrap();
    let err = refused(&input, "alias-name");
    assert_eq!(err.limit(), Some(&yaml::Limit::AnchorName { offset }));
    let expected = format!(
        "YAML refused: anchor or alias name outside [A-Za-z0-9_-] at byte {offset}; refused: parsers disagree"
    );
    assert_eq!(err.to_string(), expected);
}

#[test]
fn anchor_reuse_then_new_anchor_refused() {
    let input = String::from("x: &a 1\ny: &a 2\nz: &b 3\nw: *a\n");
    let offset = input.match_indices("&a").nth(1).unwrap().0;
    let err = refused(&input, "reuse-new");
    assert_eq!(err.limit(), Some(&yaml::Limit::AnchorReuse { offset }));
    assert_eq!(
        err.to_string(),
        format!("YAML refused: anchor name reused at byte {offset}")
    );
}

#[test]
fn loose_size_over_limit_refused() {
    let input = sized_input(MAX_YAML_BYTES + 1);
    assert_eq!(input.len(), MAX_YAML_BYTES + 1);
    let err = refused_loose(&input, "loose-size");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Size {
            len: input.len(),
            max: MAX_YAML_BYTES
        })
    );
    assert_eq!(
        err.to_string(),
        format!(
            "YAML refused: {} bytes, over the 16777216-byte limit",
            input.len()
        )
    );
}

#[test]
fn loose_depth_129_refused() {
    let input = deep_flow(129);
    let err = refused_loose(&input, "loose-depth");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
}

#[test]
fn loose_aliases_over_limit_refused() {
    let err = refused_loose(&aliased_input(65), "loose-aliases");
    assert_eq!(err.limit(), Some(&yaml::Limit::Aliases { max: 64 }));
    assert_eq!(err.to_string(), "YAML refused: more than 64 aliases");
}

#[test]
fn figment_size_over_limit_refused() {
    let input = sized_input(MAX_YAML_BYTES + 1);
    let expected = format!(
        "YAML refused: {} bytes, over the 16777216-byte limit",
        input.len()
    );
    let Err(err) = yaml::figment_data(&input) else {
        panic!("figment-size: accepted, must be refused")
    };
    assert_eq!(err.to_string(), expected);
    assert!(
        !err.to_string().contains(SENTINEL),
        "figment-size: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "figment-size: Debug leaks the sentinel"
    );
}

#[test]
fn figment_depth_129_refused() {
    let input = deep_flow(129);
    let expected = "YAML refused: nesting deeper than 128 levels at line 1";
    let Err(err) = yaml::figment_data(&input) else {
        panic!("figment-depth: accepted, must be refused")
    };
    assert_eq!(err.to_string(), expected);
    assert!(
        !err.to_string().contains(SENTINEL),
        "figment-depth: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "figment-depth: Debug leaks the sentinel"
    );
}

#[test]
fn figment_aliases_over_limit_refused() {
    let input = aliased_input(65);
    let expected = "YAML refused: more than 64 aliases";
    let Err(err) = yaml::figment_data(&input) else {
        panic!("figment-aliases: accepted, must be refused")
    };
    assert_eq!(err.to_string(), expected);
    assert!(
        !err.to_string().contains(SENTINEL),
        "figment-aliases: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "figment-aliases: Debug leaks the sentinel"
    );
}

#[test]
fn documents_size_over_limit_refused() {
    let input = sized_input(MAX_YAML_BYTES + 1);
    let mut stream = yaml::documents(&input);
    let first = stream.next().unwrap();
    let err = first.unwrap_err();
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Size {
            len: input.len(),
            max: MAX_YAML_BYTES
        })
    );
    assert_eq!(
        err.to_string(),
        format!(
            "YAML refused: {} bytes, over the 16777216-byte limit",
            input.len()
        )
    );
    assert!(stream.next().is_none(), "one refusal, nothing yielded");
}

#[test]
fn documents_depth_129_refused() {
    let input = deep_flow(129);
    let mut stream = yaml::documents(&input);
    let err = stream.next().unwrap().unwrap_err();
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
    assert!(stream.next().is_none(), "one refusal, nothing yielded");
}

#[test]
fn documents_aliases_over_limit_refused() {
    let input = aliased_input(65);
    let mut stream = yaml::documents(&input);
    let err = stream.next().unwrap().unwrap_err();
    assert_eq!(err.limit(), Some(&yaml::Limit::Aliases { max: 64 }));
    assert_eq!(err.to_string(), "YAML refused: more than 64 aliases");
    assert!(stream.next().is_none(), "one refusal, nothing yielded");
}

/// Scalar of `len` bytes anchored once and aliased 64 times.
fn anchored_scalar_fanout(len: usize) -> String {
    let mut input = format!("a: &a {}\n", "x".repeat(len));
    for index in 0..64 {
        writeln!(input, "b{index}: *a").expect("writing to a String cannot fail");
    }
    input
}

#[test]
fn expansion_exactly_64mib_refused() {
    let input = anchored_scalar_fanout(1_048_512);
    let (result, _work) = yaml::guard_work(&input);
    let err = result.unwrap_err();
    assert_eq!(err.limit(), Some(&yaml::Limit::Expansion));
    assert_eq!(
        err.to_string(),
        "YAML refused: alias expansion over the limit"
    );
}

#[test]
fn expansion_just_under_64mib_accepted() {
    // ACCEPTED on the skeleton by design: 64 bytes under the expansion cap.
    let input = anchored_scalar_fanout(1_048_511);
    let (result, _work) = yaml::guard_work(&input);
    assert!(result.is_ok(), "64 MiB minus 64 bytes must be accepted");
}

// Saturation is not reachable through &str under the 16 MiB size and 64-alias
// caps (max about 2^56); no row pins it. It stays unreachable by construction,
// not only by those caps: the guard checks the 64 MiB cap BEFORE every add
// (refusing at the first add that would reach it) and uses checked or
// saturating adds.

#[test]
fn expansion_resets_each_document_accepted() {
    // ACCEPTED on the skeleton by design: each document stays under the cap
    // while the stream total is over; the alias count is exactly 64.
    let big = "x".repeat(2_097_087);
    let mut first = format!("a: &a {big}\n");
    for index in 0..32 {
        writeln!(first, "b{index}: *a").expect("writing to a String cannot fail");
    }
    let mut second = format!("a: &a {big}\n");
    for index in 0..32 {
        writeln!(second, "c{index}: *a").expect("writing to a String cannot fail");
    }
    let input = format!("{first}---\n{second}");
    let (result, _work) = yaml::guard_work(&input);
    assert!(result.is_ok(), "per-document reset must be accepted");
}

#[test]
fn reserved_directive_params_over_limit_refused() {
    let input = String::from("%FOO a b c d e f g h i j k l m n o p q\n---\na: 1\n");
    let err = refused(&input, "reserved-params");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 1, column: 1 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: directive too large at line 1 column 1"
    );
}

#[test]
fn tag_directive_prefix_over_limit_refused() {
    let input = format!("%TAG !e! {}\n---\na: 1\n", "x".repeat(1100));
    let err = refused(&input, "tag-prefix");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 1, column: 1 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: directive too large at line 1 column 1"
    );
}

#[test]
fn many_documents_accepted() {
    // ACCEPTED on the skeleton by design: no document count cap.
    let mut input = String::new();
    for index in 0..1100 {
        if index % 2 == 0 {
            input.push_str("---\n");
        } else {
            input.push_str("---\na: 1\n");
        }
    }
    let results: Vec<_> = yaml::documents(&input).collect();
    let expected = serde_yaml::Deserializer::from_str(&input).count();
    assert_eq!(expected, 1100, "fixture must hold 1100 documents");
    assert_eq!(results.len(), expected, "all documents must be yielded");
    assert!(
        results.iter().all(std::result::Result::is_ok),
        "1100 documents must be accepted"
    );
}

#[test]
fn anchor_reuse_after_multibyte_reports_byte_offset() {
    let input = String::from("note: \"ä€😀\"\nx: &a 1\ny: &a 2\n");
    let offset = input.rfind("&a").unwrap();
    let err = refused(&input, "reuse-utf8");
    assert_eq!(err.limit(), Some(&yaml::Limit::AnchorReuse { offset }));
    assert_eq!(
        err.to_string(),
        format!("YAML refused: anchor name reused at byte {offset}")
    );
}

#[test]
fn tag_directives_after_multibyte_reports_byte_offset() {
    let mut input = String::from("# ä€😀\n");
    for index in 0..65 {
        writeln!(input, "%TAG !t{index}! tag:x:").expect("writing to a String cannot fail");
    }
    input.push_str("---\na: 1\n");
    let offset = input.match_indices("%TAG").nth(64).unwrap().0;
    let err = refused(&input, "tag-utf8");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::TagDirectives { max: 64, offset })
    );
    assert_eq!(
        err.to_string(),
        format!("YAML refused: more than 64 %TAG directives at byte {offset}")
    );
}

#[test]
fn quoted_continuation_at_parent_indent_refused_with_fix_hint() {
    let input = format!("fs:\n  description: \"first line {SENTINEL}\n  more: text\"\n");
    let err = refused(&input, "quoted-continuation");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 3, column: 3 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: quoted text is not closed, or continues with too little \
         indentation, at line 3 column 3; close the quote, or indent the \
         continuation lines, or use a block scalar (| or >)"
    );
    let accepted = format!("fs:\n  description: \"first line {SENTINEL}\n    more: text\"\n");
    assert!(
        yaml::from_str::<yaml::Value>(&accepted).is_ok(),
        "a continuation indented past its key must be accepted"
    );
}

#[test]
fn unterminated_quote_refused_with_fix_hint() {
    let input = format!("name: \"unterminated {SENTINEL}\n");
    let err = refused(&input, "unterminated-quote");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 2, column: 1 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: quoted text is not closed, or continues with too little \
         indentation, at line 2 column 1; close the quote, or indent the \
         continuation lines, or use a block scalar (| or >)"
    );
}
