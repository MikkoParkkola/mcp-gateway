// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The syntax-error rows of the YAML guard: a refusal names the position and
//! carries no value from the input. Moved from the parent test file for the
//! file-size ceiling.

use super::*;

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
