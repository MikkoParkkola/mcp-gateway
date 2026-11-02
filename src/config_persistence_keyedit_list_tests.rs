// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whole-list rows: a list of strings set at a path, written as one inline
//! list. An absent list is inserted with its key, a one-line inline list is
//! replaced in place, and a block list is rewritten inline at the same place,
//! changing only that key's lines.

use super::super::GiveUp;
use super::*;

fn list(dotted: &str, items: &[&str]) -> (FieldPath, Change) {
    (
        path(dotted),
        Change::List(items.iter().map(|s| (*s).to_owned()).collect()),
    )
}

fn api_key_list(i: usize, field: &str, items: &[&str]) -> (FieldPath, Change) {
    (
        FieldPath(vec![
            Segment::Key("auth".into()),
            Segment::Key("api_keys".into()),
            Segment::Index(i),
            Segment::Key(field.into()),
        ]),
        Change::List(items.iter().map(|s| (*s).to_owned()).collect()),
    )
}

fn api_key_set(i: usize, field: &str, value: &str) -> (FieldPath, Change) {
    (
        FieldPath(vec![
            Segment::Key("auth".into()),
            Segment::Key("api_keys".into()),
            Segment::Index(i),
            Segment::Key(field.into()),
        ]),
        Change::Set(Scalar::Str(value.into())),
    )
}

fn strings(text: &str, dotted: &str) -> Vec<String> {
    let doc: crate::yaml::Value = crate::yaml::from_str(text).expect("the edited file loads");
    let mut node = &doc;
    for key in dotted.split('.') {
        node = &node[key];
    }
    node.as_sequence()
        .expect("a list")
        .iter()
        .map(|v| v.as_str().expect("a string").to_owned())
        .collect()
}

const INLINE: &str = "\
# head comment
auth:
  enabled: true
  scope: [\"alpha\", \"beta\"] # keep me
other: 1
";

const BLOCK: &str = "\
# head comment
auth:
  enabled: true # flag
  scope:
    - alpha
    - beta
  after: 2
other: 1\r
";

#[test]
fn a_longer_list_replaces_an_inline_one_in_place() {
    let out = edited(INLINE, &[list("auth.scope", &["alpha", "beta", "gamma"])]);
    assert_eq!(strings(&out, "auth.scope"), ["alpha", "beta", "gamma"]);
    assert_eq!(
        out,
        INLINE.replace("[\"alpha\", \"beta\"]", "[\"alpha\", \"beta\", \"gamma\"]"),
        "only the list's own bytes changed"
    );
}

#[test]
fn a_shorter_an_equal_and_an_empty_list_replace_it() {
    for items in [&["alpha"][..], &["one", "two"][..], &[][..]] {
        let out = edited(INLINE, &[list("auth.scope", items)]);
        assert_eq!(strings(&out, "auth.scope"), items);
    }
    assert!(edited(INLINE, &[list("auth.scope", &[])]).contains("  scope: [] # keep me\n"));
}

#[test]
fn an_absent_list_is_inserted_with_its_key() {
    let out = edited(INLINE, &[list("auth.allow", &["x", "y"])]);
    assert_eq!(strings(&out, "auth.allow"), ["x", "y"]);
    assert_eq!(strings(&out, "auth.scope"), ["alpha", "beta"]);
}

/// The lead's condition: rewriting a block list inline changes only that
/// key's lines; every other line, comment and line ending is identical.
#[test]
fn a_block_list_is_rewritten_inline_changing_only_its_lines() {
    let out = edited(BLOCK, &[list("auth.scope", &["gamma"])]);
    assert_eq!(strings(&out, "auth.scope"), ["gamma"]);
    let expected = "\
# head comment
auth:
  enabled: true # flag
  scope: [\"gamma\"]
  after: 2
other: 1\r
";
    assert_eq!(out, expected, "a line outside the list changed");
}

/// The lead's condition: a comment inside the block list refuses, naming its
/// line (1-based, in the original).
#[test]
fn a_comment_inside_a_block_list_refuses_naming_its_line() {
    let original = "auth:\n  scope:\n    - alpha\n    # why beta\n    - beta\n";
    assert_refused_by(original, &[list("auth.scope", &["x"])], "line 4");
    let trailing = "auth:\n  scope:\n    - alpha # first\n    - beta\n";
    assert_refused_by(trailing, &[list("auth.scope", &["x"])], "line 3");
}

#[test]
fn several_lists_on_a_new_key_in_a_file_with_no_api_keys() {
    let original = "auth:\n  enabled: true # keys below\n";
    let out = edited(
        original,
        &[
            api_key_set(0, "name", "ops"),
            api_key_set(0, "key_sha256", "sha256:aa"),
            api_key_list(0, "backends", &["alpha", "beta"]),
            api_key_list(0, "allowed_tools", &["read_*", "list"]),
            api_key_list(0, "denied_tools", &["drop"]),
        ],
    );
    let doc: crate::yaml::Value = crate::yaml::from_str(&out).expect("loads");
    let key = &doc["auth"]["api_keys"][0];
    assert_eq!(key["backends"][1].as_str(), Some("beta"));
    assert_eq!(key["allowed_tools"][0].as_str(), Some("read_*"));
    assert_eq!(key["denied_tools"][0].as_str(), Some("drop"));
    assert!(out.starts_with(original), "the original lines were kept");
}

/// Items that change meaning if written bare stay strings when written inline.
#[test]
fn every_item_is_quoted_so_its_meaning_holds() {
    let items = ["a, b", "]", "x: y", "# no", "- dash", "", "yes", "1"];
    let out = edited(INLINE, &[list("auth.scope", &items)]);
    assert_eq!(strings(&out, "auth.scope"), items);
}

#[test]
fn shapes_the_proofs_cannot_cover_are_refused() {
    assert_refused_by(
        "auth:\n  scope: &s [\"a\"]\n",
        &[list("auth.scope", &["x"])],
        "anchor",
    );
    assert_refused_by(
        "auth:\n  scope:\n    - !tag a\n",
        &[list("auth.scope", &["x"])],
        "anchor",
    );
    assert_refused_by(
        "auth:\n  scope: [\"a\",\n    \"b\"]\n",
        &[list("auth.scope", &["x"])],
        "more than one line",
    );
    assert_refused_by(
        "auth:\n  scope:\n    - 5\n",
        &[list("auth.scope", &["x"])],
        "not a plain string",
    );
    assert_refused_by(
        "auth:\n  scope:\n    - a: 1\n",
        &[list("auth.scope", &["x"])],
        "not a plain string",
    );
}

#[test]
fn a_list_set_and_an_element_change_on_one_list_are_refused() {
    let element = (
        FieldPath(vec![
            Segment::Key("auth".into()),
            Segment::Key("scope".into()),
            Segment::Index(0),
        ]),
        Change::Set(Scalar::Str("z".into())),
    );
    assert_refused_by(INLINE, &[list("auth.scope", &["x"]), element], "same field");
}

/// The comment refusal is the shared deletion step's, so an existing caller,
/// removing a key whose line carries a comment, names its line too.
#[test]
fn removing_a_commented_key_names_the_comments_line() {
    let original = "auth:\n  enabled: true\n  legacy: 1 # drop me later\n";
    assert_refused_by(original, &[(path("auth.legacy"), Change::Remove)], "line 3");
}

/// A comment standing alone between two block items, and one on the list's
/// own key line, both refuse naming their line. `edit_in_place` returns the
/// edit and writes nothing, so a refusal leaves the file as it was.
#[test]
fn comments_between_items_or_on_the_key_line_refuse_naming_their_line() {
    let between = "auth:\n  scope:\n    - alpha\n\n    # standalone note\n    - beta\n  after: 2\n";
    assert_refused_by(between, &[list("auth.scope", &["x"])], "line 5");
    let on_key = "auth:\n  scope: # note\n    - alpha\n    - beta\n";
    assert_refused_by(on_key, &[list("auth.scope", &["x"])], "line 2");
}

#[test]
fn a_block_list_on_its_elements_dash_line_keeps_the_dash_line() {
    let original = "auth:\n  api_keys:\n    - backends:\n        - a\n      name: x\n";
    let out = edited(original, &[api_key_list(0, "backends", &["b"])]);
    assert_eq!(
        out,
        "auth:\n  api_keys:\n    - backends: [\"b\"]\n      name: x\n"
    );
}

#[test]
fn a_list_that_is_the_whole_crlf_file_with_and_without_a_final_newline() {
    let out = edited("scope:\r\n  - a\r\n  - b", &[list("scope", &["x"])]);
    assert_eq!(out, "scope: [\"x\"]");
    let out = edited("scope:\r\n  - a\r\n", &[list("scope", &["x"])]);
    assert_eq!(out, "scope: [\"x\"]\r\n");
}

#[test]
fn empty_values_take_the_list_and_keep_their_comment() {
    for value in ["~ ", "null ", "[] ", ""] {
        let original = format!("auth:\n  scope: {value}# c\n");
        let out = edited(&original, &[list("auth.scope", &["x"])]);
        assert_eq!(out, "auth:\n  scope: [\"x\"] # c\n", "from `{value}`");
    }
}

#[test]
fn decorated_or_multi_line_empty_values_are_refused() {
    for original in [
        "auth:\n  scope: &a []\n",
        "auth:\n  scope: &a ~\n",
        "auth:\n  scope: &a null\n",
        "auth:\n  scope: &s\n    - a\n",
        "auth:\n  base: &b x\n  scope:\n    - *b\n",
    ] {
        assert_refused_by(original, &[list("auth.scope", &["x"])], "anchor");
    }
    assert_refused_by(
        "auth:\n  scope: [\n  ]\n",
        &[list("auth.scope", &["x"])],
        "more than one line",
    );
}

#[test]
fn other_shapes_and_items_are_refused_naming_why() {
    let set =
        |original: &str, by: &str| assert_refused_by(original, &[list("auth.scope", &["x"])], by);
    set("auth:\n  scope: x\n", "a scalar, not a list");
    set("auth:\n  scope:\n    a: 1\n", "a mapping, not a list");
    set("auth:\n  scope:\n    - true\n", "not a plain string");
    set("auth:\n  scope:\n    - ~\n", "not a plain string");
    set(
        "auth:\n  scope:\n    - |\n      text\n",
        "not a plain string",
    );
    let at_index = (
        FieldPath(vec![
            Segment::Key("auth".into()),
            Segment::Key("scope".into()),
            Segment::Index(0),
        ]),
        Change::List(vec!["x".into()]),
    );
    assert_refused_by(BLOCK, &[at_index], "not at a list position");
}

#[test]
fn quoted_items_are_replaced_and_rewritten() {
    let original = "auth:\n  scope:\n    - \"5\"\n    - 'q'\n";
    let out = edited(original, &[list("auth.scope", &["y"])]);
    assert_eq!(out, "auth:\n  scope: [\"y\"]\n");
}

#[test]
fn hard_items_round_trip_and_the_output_edits_again() {
    let items = ["a\"b", "c\\d", "e\nf"];
    let out = edited(INLINE, &[list("auth.scope", &items)]);
    assert_eq!(strings(&out, "auth.scope"), items);
    assert!(out.contains("  scope: [\"a\\\"b\", "), "exact text: {out}");
    let again = edited(&out, &[list("auth.scope", &["z"])]);
    assert_eq!(again, INLINE.replace("[\"alpha\", \"beta\"]", "[\"z\"]"));
}

#[test]
fn two_block_rewrites_and_a_key_removal_pass_the_deletion_proof() {
    let original = "\
auth:
  scope:
    - a
    - b
  legacy: 1
  allow:
    - c
other: 1
";
    let out = edited(
        original,
        &[
            list("auth.scope", &["x"]),
            (path("auth.legacy"), Change::Remove),
            list("auth.allow", &[]),
        ],
    );
    assert_eq!(out, "auth:\n  scope: [\"x\"]\n  allow: []\nother: 1\n");
}

#[test]
fn a_refused_comment_names_its_original_line_after_an_insertion_above() {
    let original = "a:\n  x: 1\nauth:\n  scope:\n    - p\n    # c\n    - q\n";
    assert_refused_by(
        original,
        &[
            (path("a.y"), Change::Set(Scalar::Int(2))),
            list("auth.scope", &["x"]),
        ],
        "line 6",
    );
}

#[test]
fn an_unchanged_list_writes_nothing() {
    assert_eq!(
        edited(BLOCK, &[list("auth.scope", &["alpha", "beta"])]),
        BLOCK
    );
    assert_eq!(
        edited(INLINE, &[list("auth.scope", &["alpha", "beta"])]),
        INLINE
    );
}

#[test]
fn two_new_elements_by_element_changes_are_still_refused() {
    let element = |i: usize| {
        (
            FieldPath(vec![
                Segment::Key("auth".into()),
                Segment::Key("scope".into()),
                Segment::Index(i),
            ]),
            Change::Set(Scalar::Str("z".into())),
        )
    };
    assert_refused_by(
        BLOCK,
        &[element(2), element(3)],
        "only one new list element",
    );
}

/// Refused with the machine-readable code `code`, whatever the text says.
#[track_caller]
fn assert_code(original: &str, changes: &[(FieldPath, Change)], code: GiveUp) {
    match edit_in_place(original, changes) {
        Err(ComputeRefusal::Unprovable { code: got, .. }) if got == code => {}
        other => panic!("expected Unprovable with {code:?}, got {other:?}"),
    }
}

#[test]
fn refusals_carry_their_codes() {
    let set = [list("auth.scope", &["x"])];
    assert_code("auth:\n  scope: &s [\"a\"]\n", &set, GiveUp::Anchor);
    assert_code("auth:\n  scope:\n    - !tag a\n", &set, GiveUp::Anchor);
    assert_code("auth:\n  scope: [\"a\",\n    \"b\"]\n", &set, GiveUp::Flow);
    assert_code("auth:\n  &k scope: [\"a\"]\n", &set, GiveUp::NotPlainKey);
    assert_code("auth:\n  scope:\n    - a # c\n", &set, GiveUp::Comment);
}

/// The key must be written plain: an anchor or a tag before it refuses,
/// though the parser's key span leaves the decoration out.
#[test]
fn a_decorated_key_is_refused() {
    for original in [
        "auth:\n  &k scope: [\"a\"]\n",
        "auth:\n  !!str scope: [\"a\"]\n",
    ] {
        assert_refused_by(original, &[list("auth.scope", &["x"])], "not written plain");
    }
}

/// The deletion proof judges every save now: an explicit `? key` entry's
/// removal keeps a comment indented less than its key, as before.
#[test]
fn removing_an_explicit_key_keeps_a_comment_outside_it() {
    let original = "? scope\n: old\n # keep\nother: 1\n";
    let out = edited(original, &[(path("scope"), Change::Remove)]);
    assert_eq!(out, " # keep\nother: 1\n");
}

/// The planner and the deletion agree on trailing blank lines: after a block
/// list rewritten inline, and after a block scalar whose key is removed.
#[test]
fn trailing_blank_lines_are_judged_alike_by_the_planner_and_the_deletion() {
    let out = edited(
        "auth:\n  scope:\n    - a\n\n  after: 1\n",
        &[list("auth.scope", &["x"])],
    );
    assert_eq!(strings(&out, "auth.scope"), ["x"]);
    assert!(out.starts_with("auth:\n  scope: [\"x\"]\n"), "{out}");
    assert!(out.ends_with("  after: 1\n"), "{out}");
    let out = edited(
        "a:\n  text: |\n    hi\n\n  b: 1\n",
        &[(path("a.text"), Change::Remove)],
    );
    assert!(!out.contains("hi"), "{out}");
    assert!(out.ends_with("  b: 1\n"), "{out}");
}
