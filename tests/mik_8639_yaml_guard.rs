// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8639 red rows: the YAML guard refuses hostile text with a typed,
//! value-free refusal, fast.
//!
//! Every refused row parses through `from_str`, asserts the exact `Limit`
//! variant, prints the wall time (informational only; the guard_work counter pins
//! the cost), and asserts Display and Debug free of
//! the sentinel the input carries in a scalar. Red on the skeleton: its
//! `limit()` is `None`, and shapes the backend accepts fail at the refusal
//! itself. Rows marked ACCEPTED pass on the skeleton by design and pin the
//! no-false-refusal boundary the implementation must keep.

#[path = "common/yaml.rs"]
mod yaml;

use std::time::Instant;

use serde::Deserialize;

/// The probe string every hostile input carries in a scalar; it must never
/// reach an error's Display or Debug.
const SENTINEL: &str = "MIK8425-SENTINEL-7f3a";

/// The size gate the guard enforces on every text-taking seam.
const MAX_YAML_BYTES: usize = 16 * 1024 * 1024;

/// Parse `input` as `T`, assert it is refused and value-free, and return
/// the error for the row's `limit()` assertion.
fn refused_as<T: serde::de::DeserializeOwned>(input: &str, what: &str) -> yaml::Error {
    let start = Instant::now();
    let result = yaml::from_str::<T>(input);
    let elapsed = start.elapsed();
    // Wall time is informational only (repo rule: no wall-clock bound under
    // 5 s in tests); the guard_work counter rows pin the cost.
    eprintln!("mik-8639 {what}: {} ms", elapsed.as_millis());
    let err = match result {
        Ok(_) => panic!("{what}: accepted, must be refused"),
        Err(err) => err,
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

/// Parse `input` as a tree, assert it is refused and value-free.
fn refused(input: &str, what: &str) -> yaml::Error {
    refused_as::<yaml::Value>(input, what)
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

#[test]
fn size_over_limit_refused() {
    let input = sized_input(MAX_YAML_BYTES + 1);
    assert_eq!(input.len(), MAX_YAML_BYTES + 1);
    let err = refused(&input, "size-over");
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
fn size_at_limit_accepted() {
    // ACCEPTED on the skeleton by design: pins the exact size boundary.
    let input = sized_input(MAX_YAML_BYTES);
    assert_eq!(input.len(), MAX_YAML_BYTES);
    assert!(
        yaml::from_str::<yaml::Value>(&input).is_ok(),
        "exactly 16 MiB of a valid shape must be accepted"
    );
}

/// `n` nested block mappings ending in the sentinel scalar.
fn block_map(n: usize) -> String {
    let mut input = String::new();
    for level in 0..n {
        input.push_str(&"  ".repeat(level));
        input.push_str("a:\n");
    }
    input.push_str(&"  ".repeat(n));
    input.push_str(SENTINEL);
    input.push('\n');
    input
}

/// `n` nested block sequences ending in the sentinel scalar.
fn block_seq(n: usize) -> String {
    let mut input = String::new();
    for level in 0..n {
        input.push_str(&"  ".repeat(level));
        input.push_str("-\n");
    }
    input.push_str(&"  ".repeat(n));
    input.push_str(SENTINEL);
    input.push('\n');
    input
}

#[test]
fn flow_sequence_depth_129_refused() {
    let input = format!("{}{SENTINEL}{}", "[".repeat(129), "]".repeat(129));
    let err = refused(&input, "flow-seq-129");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
}

#[test]
fn flow_sequence_depth_128_accepted() {
    // ACCEPTED on the skeleton by design: the same shape at 128.
    let ok = format!("{}{SENTINEL}{}", "[".repeat(128), "]".repeat(128));
    assert!(
        yaml::from_str::<yaml::Value>(&ok).is_ok(),
        "flow-seq-128 must be accepted"
    );
}

#[test]
fn flow_mapping_depth_129_refused() {
    let nested = format!("{}{SENTINEL}{}", "{a: ".repeat(129), "}".repeat(129));
    let err = refused(&nested, "flow-map-129");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
}

#[test]
fn flow_mapping_depth_128_accepted() {
    // ACCEPTED on the skeleton by design: the same shape at 128.
    let ok = format!("{}{SENTINEL}{}", "{a: ".repeat(128), "}".repeat(128));
    assert!(
        yaml::from_str::<yaml::Value>(&ok).is_ok(),
        "flow-map-128 must be accepted"
    );
}

#[test]
fn block_mapping_depth_129_refused() {
    let err = refused(&block_map(129), "block-map-129");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 129 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 129"
    );
}

#[test]
fn block_mapping_depth_128_accepted() {
    // ACCEPTED on the skeleton by design: the same shape at 128.
    assert!(
        yaml::from_str::<yaml::Value>(&block_map(128)).is_ok(),
        "block-map-128 must be accepted"
    );
}

#[test]
fn block_sequence_depth_129_refused() {
    let err = refused(&block_seq(129), "block-seq-129");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 129 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 129"
    );
}

#[test]
fn block_sequence_depth_128_accepted() {
    // ACCEPTED on the skeleton by design: the same shape at 128.
    assert!(
        yaml::from_str::<yaml::Value>(&block_seq(128)).is_ok(),
        "block-seq-128 must be accepted"
    );
}

#[test]
fn compact_dashes_depth_129_refused() {
    let input = format!("{}{SENTINEL}", "- ".repeat(129));
    let err = refused(&input, "dashes-129");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
}

#[test]
fn compact_dashes_depth_128_accepted() {
    // ACCEPTED on the skeleton by design: the same shape at 128.
    let ok = format!("{}{SENTINEL}", "- ".repeat(128));
    assert!(
        yaml::from_str::<yaml::Value>(&ok).is_ok(),
        "dashes-128 must be accepted"
    );
}

#[test]
fn implicit_flow_map_depth_129_refused() {
    // 64 implicit pairs (128 levels) plus one inner sequence: depth 129.
    let input = format!("{}[{SENTINEL}]{}", "[a: ".repeat(64), "]".repeat(64));
    let err = refused(&input, "implicit-map-129");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
}

#[test]
fn implicit_flow_map_depth_128_accepted() {
    // ACCEPTED on the skeleton by design: 64 pairs alone are depth 128.
    let ok = format!("{}{SENTINEL}{}", "[a: ".repeat(64), "]".repeat(64));
    assert!(
        yaml::from_str::<yaml::Value>(&ok).is_ok(),
        "implicit-map-128 must be accepted"
    );
}

#[test]
fn compact_json_depth_129_refused() {
    let input = format!("{}\"{SENTINEL}\"{}", "{\"a\":".repeat(129), "}".repeat(129));
    let err = refused(&input, "json-129");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
}

#[test]
fn compact_json_depth_128_accepted() {
    // ACCEPTED on the skeleton by design: the same shape at 128.
    let ok = format!("{}\"{SENTINEL}\"{}", "{\"a\":".repeat(128), "}".repeat(128));
    assert!(
        yaml::from_str::<yaml::Value>(&ok).is_ok(),
        "json-128 must be accepted"
    );
}

#[test]
fn flow_depth_10000_is_depth_not_syntax() {
    let input = format!("{}{SENTINEL}{}", "[".repeat(10_000), "]".repeat(10_000));
    let err = refused(&input, "flow-10k");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 1 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 1"
    );
}

/// A typed reader that never looks at the deep field (DEPTH.2).
#[derive(Deserialize)]
struct T {
    name: String,
}

#[test]
fn unread_field_10000_deep_refused() {
    let input = format!(
        "name: {SENTINEL}\nprobe: {}1{}\n",
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    let err = refused_as::<T>(&input, "struct-10k");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 2 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 2"
    );
}

#[test]
fn tagged_scalar_with_deep_tail_refused() {
    let input = format!(
        "bad: !!bool nope\nnote: {SENTINEL}\ntail: {}1{}\n",
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    let err = refused(&input, "bool-tail");
    assert_eq!(err.limit(), Some(&yaml::Limit::Depth { line: 3 }));
    assert_eq!(
        err.to_string(),
        "YAML refused: nesting deeper than 128 levels at line 3"
    );
}

/// One anchor plus `aliases` references to it.
fn aliased_input(aliases: usize) -> String {
    let mut input = format!("note: {SENTINEL}\nbase: &a 1\n");
    for index in 0..aliases {
        input.push_str(&format!("u{index}: *a\n"));
    }
    input
}

#[test]
fn aliases_over_limit_refused() {
    let err = refused(&aliased_input(65), "aliases-65");
    assert_eq!(err.limit(), Some(&yaml::Limit::Aliases { max: 64 }));
    assert_eq!(err.to_string(), "YAML refused: more than 64 aliases");
}

#[test]
fn aliases_at_limit_accepted() {
    // ACCEPTED on the skeleton by design: 64 aliases stay under the cap.
    assert!(
        yaml::from_str::<yaml::Value>(&aliased_input(64)).is_ok(),
        "64 aliases must be accepted"
    );
}

#[test]
fn aliases_counted_stream_wide() {
    let mut input = format!("note: {SENTINEL}\nbase: &a 1\nuse: *a\n---\n");
    for _ in 1..65 {
        input.push_str("base: &a 1\nuse: *a\n---\n");
    }
    let err = refused(&input, "aliases-stream");
    assert_eq!(err.limit(), Some(&yaml::Limit::Aliases { max: 64 }));
    assert_eq!(err.to_string(), "YAML refused: more than 64 aliases");
}

/// `count` `%TAG` directives joined by `newline`, then a small document.
fn tag_flood(count: usize, newline: &str) -> String {
    let mut input = String::new();
    for index in 0..count {
        input.push_str(&format!("%TAG !t{index}! tag:x:{newline}"));
    }
    input.push_str("---");
    input.push_str(newline);
    input.push_str(&format!("note: {SENTINEL}{newline}"));
    input
}

#[test]
fn tag_directives_lf_over_limit_refused() {
    let input = tag_flood(65, "\n");
    // The byte where the 65th directive starts.
    let offset = input.match_indices("%TAG").nth(64).unwrap().0;
    let err = refused(&input, "tag-lf");
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
fn tag_directives_cr_over_limit_refused() {
    let input = tag_flood(65, "\r");
    // The byte where the 65th directive starts.
    let offset = input.match_indices("%TAG").nth(64).unwrap().0;
    let err = refused(&input, "tag-cr");
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
fn tag_directives_crlf_over_limit_refused() {
    let input = tag_flood(65, "\r\n");
    // The byte where the 65th directive starts.
    let offset = input.match_indices("%TAG").nth(64).unwrap().0;
    let err = refused(&input, "tag-crlf");
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
fn tag_directives_at_limit_accepted() {
    // ACCEPTED on the skeleton by design: 64 directives stay under the cap.
    assert!(
        yaml::from_str::<yaml::Value>(&tag_flood(64, "\n")).is_ok(),
        "64 directives must be accepted"
    );
}

#[test]
fn raw_nel_refused() {
    let input = format!("# hello\u{85}world\n%TAG !e! tag:evil:\n---\nnote: {SENTINEL}\n");
    let offset = input.find('\u{85}').unwrap();
    let err = refused(&input, "nel");
    assert_eq!(err.limit(), Some(&yaml::Limit::LineBreak { offset }));
    let expected = format!(
        "YAML refused: U+0085, U+2028 or U+2029 line break at byte {offset}; refused: parsers disagree"
    );
    assert_eq!(err.to_string(), expected);
}

#[test]
fn raw_line_separator_refused() {
    let input = format!("# hello\u{2028}world\n%TAG !e! tag:evil:\n---\nnote: {SENTINEL}\n");
    let offset = input.find('\u{2028}').unwrap();
    let err = refused(&input, "ls");
    assert_eq!(err.limit(), Some(&yaml::Limit::LineBreak { offset }));
    let expected = format!(
        "YAML refused: U+0085, U+2028 or U+2029 line break at byte {offset}; refused: parsers disagree"
    );
    assert_eq!(err.to_string(), expected);
}

#[test]
fn raw_paragraph_separator_refused() {
    let input = format!("# hello\u{2029}world\n%TAG !e! tag:evil:\n---\nnote: {SENTINEL}\n");
    let offset = input.find('\u{2029}').unwrap();
    let err = refused(&input, "ps");
    assert_eq!(err.limit(), Some(&yaml::Limit::LineBreak { offset }));
    let expected = format!(
        "YAML refused: U+0085, U+2028 or U+2029 line break at byte {offset}; refused: parsers disagree"
    );
    assert_eq!(err.to_string(), expected);
}

#[test]
fn anchor_name_outside_grammar_refused() {
    let input = format!("{{&x: {SENTINEL}}}");
    // Offset of the `&` starting the offending anchor token.
    let offset = input.find('&').unwrap();
    let err = refused(&input, "anchor-name");
    assert_eq!(err.limit(), Some(&yaml::Limit::AnchorName { offset }));
    let expected = format!(
        "YAML refused: anchor or alias name outside [A-Za-z0-9_-] at byte {offset}; refused: parsers disagree"
    );
    assert_eq!(err.to_string(), expected);
}

#[test]
fn anchor_reuse_refused() {
    let input = format!("x: &a {SENTINEL}\ny: &a 2\n");
    // Offset of the second `&`: the reuse, not the first definition.
    let offset = input.rfind("&a").unwrap();
    let err = refused(&input, "anchor-reuse");
    assert_eq!(err.limit(), Some(&yaml::Limit::AnchorReuse { offset }));
    assert_eq!(
        err.to_string(),
        format!("YAML refused: anchor name reused at byte {offset}")
    );
}

#[test]
fn anchor_reuse_across_documents_accepted() {
    // ACCEPTED on the skeleton by design: the reuse rule resets per document.
    // documents() is the seam: from_str is single-document by design (a second
    // document is refused there with or without the guard).
    for (what, input) in [
        ("dashes", "x: &a 1\n---\ny: &a 2\n"),
        ("dots", "x: &a 1\n...\n---\ny: &a 2\n"),
    ] {
        let results: Vec<_> = yaml::documents(input).collect();
        assert!(!results.is_empty(), "{what}: expected documents");
        assert_eq!(results.len(), 2, "{what}: expected exactly 2 documents");
        assert!(
            results.iter().all(|read| read.is_ok()),
            "{what}: reuse across documents must be accepted"
        );
    }
}

#[test]
fn alias_to_open_anchor_refused() {
    let input = format!("a: &a [{SENTINEL}, *a]");
    let err = refused(&input, "open-direct");
    assert_eq!(err.limit(), Some(&yaml::Limit::Expansion));
    assert_eq!(
        err.to_string(),
        "YAML refused: alias expansion over the limit"
    );
}

#[test]
fn alias_to_open_anchor_through_nested_anchor_refused() {
    let input = format!("a: &a [{SENTINEL}, &b [*a]]");
    let err = refused(&input, "open-nested");
    assert_eq!(err.limit(), Some(&yaml::Limit::Expansion));
    assert_eq!(
        err.to_string(),
        "YAML refused: alias expansion over the limit"
    );
}

#[test]
fn expansion_large_scalar_fanout_refused() {
    let big = "x".repeat(8 * 1024 * 1024);
    let mut input = format!("note: {SENTINEL}\nbig: &a {big}\n");
    for index in 0..64 {
        input.push_str(&format!("u{index}: *a\n"));
    }
    let start = Instant::now();
    let (result, work) = yaml::guard_work(&input);
    eprintln!("mik-8639 expand-scalar: {} ms", start.elapsed().as_millis());
    assert!(
        work <= 2 * input.len() as u64,
        "expand-scalar: work {work} over twice the input length {}",
        input.len()
    );
    let err = result.unwrap_err();
    assert_eq!(err.limit(), Some(&yaml::Limit::Expansion));
    assert_eq!(
        err.to_string(),
        "YAML refused: alias expansion over the limit"
    );
    assert!(
        !err.to_string().contains(SENTINEL),
        "expand-scalar: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "expand-scalar: Debug leaks the sentinel"
    );
}

#[test]
fn expansion_anchored_nulls_refused() {
    let mut input = String::from("- &a\n");
    for _ in 0..400_000 {
        input.push_str("  - ~\n");
    }
    for _ in 0..64 {
        input.push_str("- *a\n");
    }
    input.push_str(&format!("- {SENTINEL}\n"));
    let start = Instant::now();
    let (result, work) = yaml::guard_work(&input);
    eprintln!("mik-8639 expand-nulls: {} ms", start.elapsed().as_millis());
    assert!(
        work <= 2 * input.len() as u64,
        "expand-nulls: work {work} over twice the input length {}",
        input.len()
    );
    let err = result.unwrap_err();
    assert_eq!(err.limit(), Some(&yaml::Limit::Expansion));
    assert_eq!(
        err.to_string(),
        "YAML refused: alias expansion over the limit"
    );
    assert!(
        !err.to_string().contains(SENTINEL),
        "expand-nulls: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "expand-nulls: Debug leaks the sentinel"
    );
}

#[test]
fn expansion_nested_fanout_refused() {
    let big = "x".repeat(1024 * 1024);
    let mut input = format!("note: {SENTINEL}\nl0: &a {big}\n");
    input.push_str(&format!("l1: &b [{}]\n", ["*a"; 10].join(", ")));
    input.push_str(&format!("l2: &c [{}]\n", ["*b"; 10].join(", ")));
    input.push_str(&format!("l3: [{}]\n", ["*c"; 10].join(", ")));
    let start = Instant::now();
    let (result, work) = yaml::guard_work(&input);
    eprintln!("mik-8639 expand-fanout: {} ms", start.elapsed().as_millis());
    assert!(
        work <= 2 * input.len() as u64,
        "expand-fanout: work {work} over twice the input length {}",
        input.len()
    );
    let err = result.unwrap_err();
    assert_eq!(err.limit(), Some(&yaml::Limit::Expansion));
    assert_eq!(
        err.to_string(),
        "YAML refused: alias expansion over the limit"
    );
    assert!(
        !err.to_string().contains(SENTINEL),
        "expand-fanout: Display leaks the sentinel"
    );
    assert!(
        !format!("{err:?}").contains(SENTINEL),
        "expand-fanout: Debug leaks the sentinel"
    );
}

#[test]
fn syntax_reports_bracket_position() {
    let input = format!("a: {SENTINEL}\n---\nb: [1, 2\n");
    let err = refused(&input, "syntax");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 3, column: 4 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: unclosed bracket at line 3 column 4"
    );
    // documents() refuses the whole stream: exactly one error, nothing else.
    let results: Vec<_> = yaml::documents(&input).collect();
    assert_eq!(results.len(), 1, "one refusal, nothing yielded");
    assert!(results[0].is_err(), "the single item must be the refusal");
}

// Custom, InputIo, InputDecoding and InputByteLimitExceeded need I/O sources
// and are not reachable from &str. DirectiveByteLimitExceeded (granit's
// 1024-byte directive budget) and TooManyReservedDirectiveParams (16
// reserved-directive params) are reachable from &str and have rows in
// mik_8639_yaml_guard_bounds.rs, so only the three kinds below have rows here.

#[test]
fn syntax_unexpected_character_is_value_free() {
    let input = format!("a: 1\n@{SENTINEL}\n");
    let err = refused(&input, "unexpected-char");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 2, column: 1 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: unexpected character at line 2 column 1"
    );
}

#[test]
fn syntax_unclosed_bracket_is_value_free() {
    let input = format!("b: [{SENTINEL}\n");
    let err = refused(&input, "unclosed");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 1, column: 4 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: unclosed bracket at line 1 column 4"
    );
}

#[test]
fn syntax_mismatched_bracket_is_value_free() {
    let input = format!("b: [{SENTINEL}}}\n");
    // Reported at the opening bracket's mark, columns one-based.
    let err = refused(&input, "mismatched");
    assert_eq!(
        err.limit(),
        Some(&yaml::Limit::Syntax { line: 1, column: 4 })
    );
    assert_eq!(
        err.to_string(),
        "YAML refused: mismatched bracket at line 1 column 4"
    );
}

#[test]
fn guard_work_scales_linearly_on_wide_documents() {
    let unit = "- a: 1\n  b: [x, y]\n";
    let one = unit.repeat(55_188);
    let sixteen = unit.repeat(883_008);
    assert_eq!(sixteen.len(), 16 * one.len());
    let (first, work_one) = yaml::guard_work(&one);
    let (second, work_sixteen) = yaml::guard_work(&sixteen);
    assert!(
        first.is_ok() && second.is_ok(),
        "wide valid documents must pass the guard"
    );
    assert!(
        work_one > 0 && work_sixteen > 0,
        "work must count visited events and tokens, got {work_one} and {work_sixteen}"
    );
    for (work, len, what) in [
        (work_one, one.len(), "1 MiB"),
        (work_sixteen, sixteen.len(), "16 MiB"),
    ] {
        assert!(
            work as f64 / len as f64 <= 2.0,
            "{what}: work per byte over the constant"
        );
    }
    assert!(
        work_sixteen >= 12 * work_one && work_sixteen <= 20 * work_one,
        "work must scale about 16x, got {work_sixteen} vs {work_one}"
    );
    let comment = format!("#{}\n", "x".repeat(1024 * 1024 - 2));
    assert_eq!(comment.len(), 1024 * 1024);
    let (comment_ok, comment_work) = yaml::guard_work(&comment);
    assert!(comment_ok.is_ok(), "comment-only input must pass the guard");
    assert!(
        comment_work < 64,
        "comment-only work must stay under 64, got {comment_work}"
    );
}
