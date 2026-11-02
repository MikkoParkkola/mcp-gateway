// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The pin-table loader, on temporary crate-shaped trees: a base table plus
//! an optional `<name>.d/` directory of fragments beside it.

use std::path::Path;

use super::super::packaged::crate_root;
use super::{DIR, pin_table, try_pin_table_at};

/// A crate-shaped temporary root holding table `t`: the base text and the
/// fragment files, each `(name, bytes)` under `t.d/`.
fn crate_with(base: &str, fragments: &[(&str, &[u8])]) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("a temp crate");
    let dir = root.path().join(DIR);
    std::fs::create_dir_all(&dir).expect("the table directory");
    std::fs::write(dir.join("t.tsv"), base).expect("the base table");
    if !fragments.is_empty() {
        std::fs::create_dir_all(dir.join("t.d")).expect("the fragment directory");
    }
    for (name, bytes) in fragments {
        std::fs::write(dir.join("t.d").join(name), bytes).expect("a fragment");
    }
    root
}

/// The row lines of table `t` under `root`.
fn lines(root: &Path) -> Vec<String> {
    try_pin_table_at(root, "t")
        .expect("the table loads")
        .rows()
        .iter()
        .map(|(_, line)| line.clone())
        .collect()
}

/// The load error for table `t` under `root`.
fn error(root: &Path) -> String {
    match try_pin_table_at(root, "t") {
        Ok(table) => panic!("the table loaded with {} rows", table.rows().len()),
        Err(e) => e,
    }
}

#[test]
fn a_fragment_row_is_read() {
    let root = crate_with("a\n", &[("1.tsv", b"b\n")]);
    let table = try_pin_table_at(root.path(), "t").expect("the table loads");
    let rows: Vec<(String, String)> = table
        .rows()
        .iter()
        .map(|(file, line)| {
            (
                file.file_name().unwrap().to_string_lossy().into_owned(),
                line.clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("t.tsv".to_owned(), "a".to_owned()),
            ("1.tsv".to_owned(), "b".to_owned())
        ]
    );
}

#[test]
fn a_missing_directory_is_no_fragments() {
    let root = crate_with("a\n", &[]);
    assert_eq!(lines(root.path()), ["a"]);
}

#[test]
fn an_empty_directory_is_no_fragments() {
    let root = crate_with("a\n", &[]);
    std::fs::create_dir_all(root.path().join(DIR).join("t.d"))
        .expect("an empty fragment directory");
    assert_eq!(lines(root.path()), ["a"]);
}

#[test]
fn fragments_are_read_in_name_order() {
    let root = crate_with(
        "a\n",
        &[
            ("2.tsv", b"two\n"),
            ("10.tsv", b"ten\n"),
            ("1.tsv", b"one\n"),
        ],
    );
    assert_eq!(lines(root.path()), ["a", "one", "ten", "two"]);
}

#[test]
fn a_fragment_without_a_final_newline_does_not_join_rows() {
    let root = crate_with("a\n", &[("1.tsv", b"x"), ("2.tsv", b"y\n")]);
    assert_eq!(lines(root.path()), ["a", "x", "y"]);
}

#[test]
fn a_non_tsv_entry_is_ignored() {
    let root = crate_with(
        "a\n",
        &[
            (".DS_Store", b"junk"),
            ("1.tsv.orig", b"old\n"),
            ("x.swp", b"swap"),
        ],
    );
    assert_eq!(lines(root.path()), ["a"]);
}

#[test]
fn a_free_form_fragment_name_fails() {
    let root = crate_with("a\n", &[("notes.tsv", b"b\n")]);
    assert!(error(root.path()).contains("notes.tsv"));
}

/// A fragment whose extension is not lower-case `.tsv` fails, naming it,
/// instead of being skipped and never loaded.
#[test]
fn a_wrong_case_extension_fails() {
    for name in ["1.TSV", "1.Tsv"] {
        let root = crate_with("a\n", &[(name, b"b\n")]);
        assert!(error(root.path()).contains(name), "{name} was skipped");
    }
}

#[test]
fn a_non_ascii_digit_fragment_name_fails() {
    let root = crate_with("a\n", &[("\u{663}.tsv", b"b\n")]);
    assert!(error(root.path()).contains("\u{663}.tsv"));
}

#[test]
fn a_dashed_numeric_name_is_accepted() {
    let root = crate_with("a\n", &[("12-3.tsv", b"b\n")]);
    assert_eq!(lines(root.path()), ["a", "b"]);
}

#[test]
fn malformed_dashed_names_fail() {
    for name in ["12-.tsv", "-3.tsv", "12-3-4.tsv"] {
        let root = crate_with("a\n", &[(name, b"b\n")]);
        assert!(error(root.path()).contains(name), "{name} was accepted");
    }
}

#[test]
fn a_missing_base_fails() {
    let root = tempfile::tempdir().expect("a temp crate");
    assert!(error(root.path()).contains("t.tsv"));
}

#[test]
fn a_directory_named_like_a_fragment_fails() {
    let root = crate_with("a\n", &[]);
    std::fs::create_dir_all(root.path().join(DIR).join("t.d").join("1.tsv")).expect("a directory");
    assert!(error(root.path()).contains("1.tsv"));
}

#[test]
fn a_non_utf8_fragment_fails() {
    let root = crate_with("a\n", &[("2.tsv", &[0xff, 0xfe, b'\n'])]);
    assert!(error(root.path()).contains("2.tsv"));
}

#[test]
fn a_fragment_dir_that_is_a_file_fails() {
    let root = crate_with("a\n", &[]);
    std::fs::write(root.path().join(DIR).join("t.d"), "not a directory").expect("a file");
    assert!(error(root.path()).contains("t.d"));
}

#[test]
fn comments_and_blank_lines_are_dropped_in_every_file() {
    let root = crate_with("a\n", &[("1.tsv", b"# a comment\n\nrow\n")]);
    assert_eq!(lines(root.path()), ["a", "row"]);
}

#[test]
fn text_is_the_row_lines_only() {
    let root = crate_with("# header\na\n", &[("1.tsv", b"# pending:x note\nb\n")]);
    let text = try_pin_table_at(root.path(), "t")
        .expect("the table loads")
        .text();
    assert_eq!(text, "a\nb");
}

/// The reader modules in this PR, and the tables they read.
const READERS: [&str; 4] = [
    "allow_pins.rs",
    "creation_sites.rs",
    "presend_exits.rs",
    "fragments.rs",
];
const TABLES: [&str; 4] = [
    "allows",
    "scoped_backends_classes",
    "creation_sites",
    "presend_exits",
];

/// The source of reader module `file`.
fn reader_source(file: &str) -> String {
    let path = crate_root().join(DIR).join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// No pin test embeds its table: every one reads through the loader, so a
/// fragment cannot be missed by a check that still holds a compiled-in copy.
#[test]
fn no_pin_test_embeds_a_table() {
    for file in READERS {
        let source = reader_source(file);
        for table in TABLES {
            let embedded = format!("include_str!(\"{table}.tsv\")");
            assert!(
                !source.contains(&embedded),
                "{file} still embeds {table}.tsv"
            );
        }
    }
}

/// No failure message tells anyone to paste a whole table back into a base
/// file, which would recreate the shared-file edits fragments remove.
#[test]
fn no_reader_asks_to_paste_the_table() {
    for file in READERS {
        let source = reader_source(file);
        for banned in [
            "copy the printed table",
            "full inventory:",
            "full table:",
            "BEGIN ",
        ] {
            assert!(!source.contains(banned), "{file} still prints {banned:?}");
        }
    }
}

/// Neither keyed table repeats a key in its base file, so the duplicate-key
/// check cannot turn the switch-over red.
#[test]
fn the_base_tables_hold_no_duplicate_keys() {
    for (table, key_columns) in [("creation_sites", 3), ("presend_exits", 2)] {
        let rows = pin_table(table);
        let mut seen = std::collections::BTreeSet::new();
        for (_, line) in rows.rows() {
            let key: Vec<&str> = line.split('\t').take(key_columns).collect();
            assert!(seen.insert(key.join("\t")), "{table} repeats a key: {line}");
        }
    }
}
