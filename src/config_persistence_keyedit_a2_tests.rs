// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! a2 rows: inserting and removing keys, sequences, numbers and the empty
//! file, each under both proofs.

use super::super::{FiniteF64, GiveUp};
use super::*;

fn at(segments: &[Segment]) -> FieldPath {
    FieldPath(segments.to_vec())
}

fn key(k: &str) -> Segment {
    Segment::Key(k.to_owned())
}

fn remove(dotted: &str) -> (FieldPath, Change) {
    (path(dotted), Change::Remove)
}

#[track_caller]
fn assert_gives_up(original: &str, changes: &[(FieldPath, Change)], want: GiveUp) {
    match edit_in_place(original, changes) {
        Err(ComputeRefusal::Unprovable { code, .. }) if code == want => {}
        other => panic!("expected a {} give-up, got {other:?}", want.as_str()),
    }
}

/// The same edit under each line-ending shape: the inserted or removed line
/// takes the ending of the line before it, every other byte stays.
#[track_caller]
fn assert_in_every_ending(lf_original: &str, changes: &[(FieldPath, Change)], lf_want: &str) {
    assert_eq!(edited(lf_original, changes), lf_want, "LF");
    let crlf = |s: &str| s.replace('\n', "\r\n");
    assert_eq!(edited(&crlf(lf_original), changes), crlf(lf_want), "CRLF");
    let trimmed = lf_original.strip_suffix('\n').expect("LF fixture");
    let want_trimmed = lf_want.strip_suffix('\n').expect("LF fixture");
    assert_eq!(edited(trimmed, changes), want_trimmed, "no final newline");
}

// A1, A2: insertion and removal keep every other byte.

#[test]
fn an_inserted_key_keeps_every_other_byte() {
    assert_in_every_ending(
        "server:\n  port: 8080 # the listener\nauth:\n  enabled: false\n",
        &[set_str("server.host", "0.0.0.0")],
        "server:\n  port: 8080 # the listener\n  host: \"0.0.0.0\"\nauth:\n  enabled: false\n",
    );
    assert_in_every_ending(
        "auth:\n  enabled: false # off\n",
        &[set_int("auth.limit", 3)],
        "auth:\n  enabled: false # off\n  limit: 3\n",
    );
}

#[test]
fn an_inserted_key_in_a_mixed_ending_file_takes_its_neighbours_ending() {
    assert_eq!(
        edited("a:\r\n  b: 1\r\nc: 2\n", &[set_int("a.d", 4)]),
        "a:\r\n  b: 1\r\n  d: 4\r\nc: 2\n"
    );
}

#[test]
fn a_removed_key_keeps_every_other_byte() {
    assert_in_every_ending(
        "server:\n  port: 8080 # the listener\n  host: x\nauth:\n  enabled: false\n",
        &[remove("server.host")],
        "server:\n  port: 8080 # the listener\nauth:\n  enabled: false\n",
    );
    assert_in_every_ending("a:\n  b: 1\n  c: 2\n", &[remove("a.c")], "a:\n  b: 1\n");
}

#[test]
fn removing_a_missing_key_is_a_no_op() {
    assert_eq!(edited("a:\n  b: 1\n", &[remove("a.z")]), "a:\n  b: 1\n");
}

// A3, A4, A5: parents, composed on one evolving document.

#[test]
fn a_missing_parent_chain_is_created_once_for_two_fields() {
    assert_eq!(
        edited(
            "server:\n  port: 1\n",
            &[
                set_int("cost_governance.budgets.daily_usd", 5),
                set_int("cost_governance.budgets.monthly_usd", 50),
            ],
        ),
        "server:\n  port: 1\ncost_governance:\n  budgets:\n    daily_usd: 5\n    monthly_usd: 50\n"
    );
}

#[test]
fn removing_the_last_old_child_while_inserting_a_sibling_keeps_the_parent() {
    assert_eq!(
        edited(
            "a:\n  old: 1\nz: 0\n",
            &[remove("a.old"), set_int("a.new", 2)]
        ),
        "a:\n  new: 2\nz: 0\n"
    );
}

#[test]
fn a_parent_left_empty_is_removed() {
    assert_eq!(
        edited("a:\n  b:\n    c: 1\nd: 2\n", &[remove("a.b.c")]),
        "d: 2\n"
    );
}

// A6: removal never deletes operator text.

#[test]
fn removing_a_commented_key_gives_up() {
    assert_gives_up(
        "a:\n  b: 1 # keep\n  c: 2\n",
        &[remove("a.b")],
        GiveUp::Comment,
    );
    // The parent `a` would go too, and it holds a full-line comment.
    assert_gives_up(
        "a:\n  # note\n  b: 1\nd: 2\n",
        &[remove("a.b")],
        GiveUp::Comment,
    );
}

// A7 to A11: block sequences of block mappings (alerts).

const ALERTS: &str =
    "alerts:\n  - name: a # first\n    threshold: 1\n  - name: b\n    threshold: 2\n";

fn alert(i: usize, field: &str) -> FieldPath {
    at(&[key("alerts"), Segment::Index(i), key(field)])
}

#[test]
fn an_alert_field_in_an_existing_element_is_edited() {
    let change = (alert(1, "threshold"), Change::Set(Scalar::Int(3)));
    assert_eq!(
        edited(ALERTS, &[change]),
        "alerts:\n  - name: a # first\n    threshold: 1\n  - name: b\n    threshold: 3\n"
    );
}

#[test]
fn two_fields_of_one_new_alert_form_one_element() {
    let changes = [
        (alert(1, "name"), Change::Set(Scalar::Str("b".into()))),
        (alert(1, "threshold"), Change::Set(Scalar::Int(5))),
    ];
    assert_eq!(
        edited("alerts:\n  - name: a\n", &changes),
        "alerts:\n  - name: a\n  - name: \"b\"\n    threshold: 5\n"
    );
}

#[test]
fn a_missing_alerts_list_is_created_with_its_first_element() {
    let change = || (alert(0, "name"), Change::Set(Scalar::Str("a".into())));
    assert_eq!(
        edited("server:\n  port: 1\n", &[change()]),
        "server:\n  port: 1\nalerts:\n  - name: \"a\"\n"
    );
    // `alerts:` written alone takes its first element under it.
    assert_eq!(
        edited("alerts:\nserver:\n  port: 1\n", &[change()]),
        "alerts:\n  - name: \"a\"\nserver:\n  port: 1\n"
    );
}

#[test]
fn sequence_shapes_give_up_with_their_codes() {
    let set_name = |i| (alert(i, "name"), Change::Set(Scalar::Str("x".into())));
    assert_gives_up("alerts: ~\n", &[set_name(0)], GiveUp::NullSequence);
    assert_gives_up("alerts: null\n", &[set_name(0)], GiveUp::NullSequence);
    assert_gives_up("alerts: []\n", &[set_name(0)], GiveUp::NullSequence);
    // `name` sits on the element's dash line.
    assert_gives_up(
        ALERTS,
        &[(alert(0, "name"), Change::Remove)],
        GiveUp::DashLine,
    );
    // Two different new positions, and a gap past the end.
    assert_gives_up(ALERTS, &[set_name(2), set_name(3)], GiveUp::SequenceShape);
    assert_gives_up(ALERTS, &[set_name(4)], GiveUp::SequenceShape);
    assert_gives_up("alerts: [{name: a}]\n", &[set_name(0)], GiveUp::Flow);
}

#[test]
fn a_remove_inside_a_new_element_is_a_no_op() {
    let changes = [
        (alert(1, "name"), Change::Set(Scalar::Str("b".into()))),
        (alert(1, "threshold"), Change::Remove),
    ];
    assert_eq!(
        edited("alerts:\n  - name: a\n", &changes),
        "alerts:\n  - name: a\n  - name: \"b\"\n"
    );
}

// A12, A13: slots inside list items, and the one display form.

#[test]
fn a_secret_in_a_list_item_fills_its_own_slot() {
    let file = "alerts:\n  - name: a\n    webhook: old\n";
    let field = alert(0, "webhook");
    let template = edit_in_place(file, &[(field.clone(), Change::Secret(field.slot()))])
        .expect("a provable edit");
    let refs = BTreeMap::from([(field.slot(), "keychain:hook".to_owned())]);
    let filled = String::from_utf8(template.fill(&refs).expect("fills")).expect("utf-8");
    assert_eq!(
        filled,
        "alerts:\n  - name: a\n    webhook: \"keychain:hook\"\n"
    );
}

#[test]
fn slot_display_is_one_to_one_for_plain_keys() {
    assert_eq!(alert(0, "webhook").slot().display(), "alerts[0].webhook");
    assert_eq!(
        slot("backends.my-srv.env.TOKEN").display(),
        "backends.my-srv.env.TOKEN"
    );
    assert_ne!(
        alert(1, "x").slot().display(),
        alert(0, "x").slot().display()
    );
    assert_ne!(
        at(&[key("a"), Segment::Index(1)]).slot().display(),
        at(&[key("a"), key("1")]).slot().display()
    );
}

// A14: numbers.

#[test]
fn a_number_round_trips_as_a_float() {
    let num = |v: f64| Change::Set(Scalar::Num(FiniteF64::new(v).expect("finite")));
    for (value, written) in [
        (2.0, "2.0"),
        (0.1, "0.1"),
        (1e300, "1.0e300"),
        (-0.5, "-0.5"),
    ] {
        assert_eq!(
            edited("a:\n  x: 1\n", &[(path("a.x"), num(value))]),
            format!("a:\n  x: {written}\n")
        );
    }
    assert!(FiniteF64::new(f64::NAN).is_none());
    assert!(FiniteF64::new(f64::INFINITY).is_none());
}

// A15, A16: keys and parents the editor gives up on.

#[test]
fn a_non_plain_backend_name_gives_up() {
    for name in ["a.b", "a:b", "a#b", "a[0]", "\"a\"", "-a", "a b"] {
        let file = "backends:\n  x:\n    description: d\n";
        let change = (
            keys(&["backends", name, "description"]),
            Change::Set(Scalar::Int(1)),
        );
        assert_gives_up(file, &[change], GiveUp::NotPlainKey);
    }
}

#[test]
fn insertion_gives_up_on_flow_anchor_and_inline_empty_parents() {
    assert_gives_up("a: {b: 1}\n", &[set_int("a.c", 2)], GiveUp::Flow);
    assert_gives_up("a: &x\n  b: 1\n", &[set_int("a.c", 2)], GiveUp::Anchor);
    assert_gives_up("a: {}\n", &[set_int("a.c", 2)], GiveUp::InlineEmpty);
}

// A17: an empty file is an empty root mapping.

#[test]
fn an_empty_document_edits_as_an_empty_root() {
    assert_eq!(edited("", &[set_int("a.b", 1)]), "a:\n  b: 1\n");
}

// A18: a hand table in place of a property test (no property-testing
// library): key order, nesting depth, and a comment beside each edit.

/// One table row: the original file, the changes, the edited file.
type Case = (&'static str, Vec<(FieldPath, Change)>, &'static str);

#[test]
fn edits_keep_untouched_bytes_across_order_depth_and_comments() {
    let new_v = || (path("s.new"), Change::Set(Scalar::Str("v".into())));
    let cases: Vec<Case> = vec![
        // Unsorted keys: an insert goes last, nothing is reordered.
        (
            "z: 1\na: 2\nm: 3\n",
            vec![set_int("b", 4)],
            "z: 1\na: 2\nm: 3\nb: 4\n",
        ),
        // Four levels deep, beside an inline comment.
        (
            "a:\n  b:\n    c:\n      d: 1 # deep\n",
            vec![set_int("a.b.c.e", 2)],
            "a:\n  b:\n    c:\n      d: 1 # deep\n      e: 2\n",
        ),
        // A new chain under a deep parent ends after that parent's subtree.
        (
            "a:\n  b:\n    c:\n      d: 1 # deep\n",
            vec![set_int("a.b.x.y", 3)],
            "a:\n  b:\n    c:\n      d: 1 # deep\n    x:\n      y: 3\n",
        ),
        // Full-line and inline comments around a value edit.
        (
            "# top\na: 1 # one\n# mid\nb: 2 # two\n",
            vec![set_int("b", 5)],
            "# top\na: 1 # one\n# mid\nb: 5 # two\n",
        ),
        // An insert lands before a comment that follows its parent.
        (
            "a:\n  b: 1 # keep\n# after\nc: 2\n",
            vec![set_int("a.x", 1)],
            "a:\n  b: 1 # keep\n  x: 1\n# after\nc: 2\n",
        ),
        // A removal beside commented lines takes only its own line.
        (
            "# head\na: 1\nb: 2 # two\n",
            vec![remove("a")],
            "# head\nb: 2 # two\n",
        ),
        // Set, insert and remove under one parent in one save.
        (
            "s:\n  k: 1 # k\n  old: 2\nt: 3\n",
            vec![set_int("s.k", 9), new_v(), remove("s.old")],
            "s:\n  k: 9 # k\n  new: \"v\"\nt: 3\n",
        ),
        // A file indented by four spaces keeps its indentation.
        (
            "a:\n    b: 1\n",
            vec![set_int("a.c", 2)],
            "a:\n    b: 1\n    c: 2\n",
        ),
    ];
    for (original, changes, want) in cases {
        assert_eq!(edited(original, &changes), want, "from {original:?}");
    }
}

// Review rows: an unterminated last line, the last root key, and a comment
// past a blank line.

#[test]
fn an_insert_then_a_set_on_an_unterminated_unicode_line_is_proven() {
    assert_eq!(
        edited("a: é", &[set_int("b", 1), set_str("a", "x")]),
        "a: \"x\"\nb: 1"
    );
}

#[test]
fn removing_the_last_root_key_leaves_an_empty_file() {
    assert_eq!(edited("a: 1\n", &[remove("a")]), "");
}

#[test]
fn a_comment_past_a_blank_line_under_a_removed_entry_gives_up() {
    assert_gives_up("a: 1\n\n  # note\nb: 2\n", &[remove("a")], GiveUp::Comment);
}

#[test]
fn a_set_then_a_removal_of_the_unterminated_last_line_is_proven() {
    assert_eq!(
        edited("a: 1\nb: 2", &[set_int("a", 5), remove("b")]),
        "a: 5"
    );
}

#[test]
fn a_parser_refused_field_gives_up_with_its_own_code() {
    assert_gives_up(
        "auth: {enabled: false}\n",
        &[set_int("auth.enabled", 1)],
        GiveUp::Flow,
    );
    assert_gives_up("a: &x 1\n", &[set_int("a", 2)], GiveUp::Anchor);
}

#[test]
fn removing_a_field_past_a_lists_end_is_a_no_op() {
    assert_eq!(
        edited(ALERTS, &[(alert(5, "name"), Change::Remove)]),
        ALERTS
    );
}

#[test]
fn a_comment_only_file_takes_an_insert() {
    assert_eq!(
        edited("# template\n", &[set_int("a.b", 1)]),
        "# template\na:\n  b: 1\n"
    );
}
