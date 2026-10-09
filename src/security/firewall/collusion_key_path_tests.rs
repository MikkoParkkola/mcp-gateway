// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8209` K1: the per-key-path join rule, row by row.

use serde_json::json;

use super::key_path_joins;

#[test]
fn content_items_join_their_text_path_only() {
    let value = json!({"content": [
        {"type": "text", "text": "ab"},
        {"type": "text", "text": "cd"},
    ]});
    assert_eq!(key_path_joins(&value), vec!["abcd", "texttext"]);
}

#[test]
fn a_missing_key_or_non_string_value_ends_a_run() {
    let value = json!({"parts": [
        {"part": "a"}, {"part": "b"}, {"other": "x"},
        {"part": "c"}, {"part": 7}, {"part": "d"}, {"part": "e"},
    ]});
    assert_eq!(key_path_joins(&value), vec!["ab", "de"]);
}

#[test]
fn an_array_of_strings_is_left_to_the_all_values_form() {
    assert!(key_path_joins(&json!({"list": ["a", "b", "c"]})).is_empty());
    assert!(key_path_joins(&json!(["a", "b"])).is_empty());
}

#[test]
fn nested_objects_are_paths_and_nested_arrays_are_their_own() {
    let value = json!({"rows": [
        {"cell": {"v": "a"}, "inner": [{"w": "x"}, {"w": "y"}]},
        {"cell": {"v": "b"}, "inner": [{"w": "z"}, {"w": "q"}]},
    ]});
    // The outer array joins `cell.v`; each inner array joins only itself.
    assert_eq!(key_path_joins(&value), vec!["ab", "xy", "zq"]);
}

#[test]
fn keys_order_as_key_sequences_and_the_gateway_slot_is_skipped() {
    let value = json!({
        "_context_integrity": {"items": [{"a": "1"}, {"a": "2"}]},
        "items": [
            {"a.b": "p", "a": {"b": "r"}},
            {"a.b": "q", "a": {"b": "s"}},
        ],
    });
    // ["a", "b"] sorts before ["a.b"].
    assert_eq!(key_path_joins(&value), vec!["rs", "pq"]);
}
