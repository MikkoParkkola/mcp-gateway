// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8667: the persisted usage file (`usage.json`) keeps full tool names and
//! its bytes (DUPC-10.PR10.3, PR10.4).

use super::*;

/// A saved file of one row, as this build writes it. One row only: the counts
/// live in a map, so a file of several rows has no fixed row order.
const ONE_ROW: &str =
    "[\n  {\n    \"server\": \"brave\",\n    \"tool\": \"search\",\n    \"count\": 3\n  }\n]";

#[test]
fn a_tool_name_with_a_colon_survives_a_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("usage.json");
    let ranker = SearchRanker::new();
    ranker.record_use("s", "a:b");
    ranker.save(&path).unwrap();

    let reloaded = SearchRanker::new();
    reloaded.load(&path).unwrap();
    assert_eq!(
        reloaded.usage_count("s", "a:b"),
        1,
        "the count moved off a:b"
    );
    assert_eq!(
        reloaded.usage_count("s", "a"),
        0,
        "the name was cut at its colon"
    );
}

#[test]
fn a_saved_usage_file_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("usage.json");
    std::fs::write(&path, ONE_ROW).unwrap();
    let ranker = SearchRanker::new();
    ranker.load(&path).unwrap();
    ranker.save(&path).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), ONE_ROW);
}

/// A row an older build already cut at the second colon (`s:a:b` saved as
/// tool `a`) is not repaired: its count stays on the name it holds.
#[test]
fn a_row_cut_by_an_older_build_keeps_its_count_on_the_cut_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("usage.json");
    std::fs::write(&path, r#"[{"server":"s","tool":"a","count":5}]"#).unwrap();
    let ranker = SearchRanker::new();
    ranker.load(&path).unwrap();
    assert_eq!(ranker.usage_count("s", "a"), 5);
    assert_eq!(ranker.usage_count("s", "a:b"), 0);
    // A save after the load writes the row back as it was read.
    ranker.save(&path).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[\n  {\n    \"server\": \"s\",\n    \"tool\": \"a\",\n    \"count\": 5\n  }\n]"
    );
}

/// Two tools that differ only past the colon keep separate counts through a
/// save and load (red before the fix: both were saved as `a`, and the load
/// kept only one of them).
#[test]
fn a_and_a_colon_b_keep_separate_counts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("usage.json");
    let ranker = SearchRanker::new();
    ranker.record_use("s", "a");
    ranker.record_use("s", "a");
    ranker.record_use("s", "a:b");
    ranker.save(&path).unwrap();

    let reloaded = SearchRanker::new();
    reloaded.load(&path).unwrap();
    assert_eq!(
        (
            reloaded.usage_count("s", "a"),
            reloaded.usage_count("s", "a:b")
        ),
        (2, 1)
    );
}
