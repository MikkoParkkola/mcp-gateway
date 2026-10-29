// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The nesting-depth rows of the YAML guard: each shape refused at depth 129
//! and accepted at 128, and a deep flow refused for its depth, not its syntax.
//! Moved from the parent test file for the file-size ceiling.

use super::*;

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
