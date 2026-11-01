// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for `config_persistence_keyedit.rs`: in-place edits of existing
//! fields, the two proofs, and secret slots.

use std::collections::BTreeMap;

use super::{Change, ComputeRefusal, FieldPath, Scalar, Segment, SlotId, Template, edit_in_place};

/// A commented file of the shape the web UI edits.
const COMMENTED: &str = "\
# gateway config, edited by hand
server:
  port: 8080 # the listener

# budgets
cost_governance:
  budgets:
    daily_usd: 5
auth:
  enabled: false  # off for now
";

fn path(dotted: &str) -> FieldPath {
    keys(&dotted.split('.').collect::<Vec<_>>())
}

/// A path of mapping keys, taken as given (a key may hold a dot).
fn keys(segments: &[&str]) -> FieldPath {
    FieldPath(
        segments
            .iter()
            .map(|k| Segment::Key((*k).to_owned()))
            .collect(),
    )
}

/// The slot of the dotted key path `dotted`.
fn slot(dotted: &str) -> SlotId {
    path(dotted).slot()
}

fn set_int(dotted: &str, value: i64) -> (FieldPath, Change) {
    (path(dotted), Change::Set(Scalar::Int(value)))
}

fn set_str(dotted: &str, value: &str) -> (FieldPath, Change) {
    (path(dotted), Change::Set(Scalar::Str(value.to_owned())))
}

fn secret(dotted: &str) -> (FieldPath, Change) {
    (path(dotted), Change::Secret(slot(dotted)))
}

/// The edited text; the edit must be provable.
fn edited(original: &str, changes: &[(FieldPath, Change)]) -> String {
    let template = edit_in_place(original, changes).expect("a provable edit");
    String::from_utf8(template.bytes().to_vec()).expect("utf-8")
}

/// Refused, and by the check whose reason contains `by`: pins which later
/// check guards an input whose own check was removed as redundant.
#[track_caller]
fn assert_refused_by(original: &str, changes: &[(FieldPath, Change)], by: &str) {
    match edit_in_place(original, changes) {
        Err(ComputeRefusal::Unprovable { reason, .. }) if reason.contains(by) => {}
        other => panic!("expected Unprovable by `{by}`, got {other:?}"),
    }
}

#[track_caller]
fn assert_unprovable(original: &str, changes: &[(FieldPath, Change)]) {
    match edit_in_place(original, changes) {
        Err(ComputeRefusal::Unprovable { .. }) => {}
        other => panic!("expected Unprovable, got {other:?}"),
    }
}

// The falsifier: a commented file keeps every byte but the edited values.

#[test]
fn a_nested_field_edit_keeps_every_other_byte() {
    let got = edited(
        COMMENTED,
        &[
            set_int("cost_governance.budgets.daily_usd", 10),
            (path("auth.enabled"), Change::Set(Scalar::Bool(true))),
        ],
    );
    let want = COMMENTED
        .replace("daily_usd: 5", "daily_usd: 10")
        .replace("enabled: false  #", "enabled: true  #");
    assert_eq!(got, want);
}

#[test]
fn an_anchored_field_is_unprovable() {
    let file = "defaults:\n  limit: &lim 5\nother:\n  limit: *lim\n";
    assert_unprovable(file, &[set_int("defaults.limit", 6)]);
}

// Proof 1 compares values, which cannot see an alias: the parser's span
// refuses one. `other.limit` resolves to 5, so setting it to 5 by value
// would compare equal while dropping the alias.

#[test]
fn a_dropped_alias_is_refused() {
    let file = "defaults:\n  limit: &lim 5\nother:\n  limit: *lim\n";
    assert_unprovable(file, &[set_int("other.limit", 5)]);
}

#[test]
fn a_tag_on_the_edited_value_is_unprovable() {
    assert_unprovable("a:\n  b: !!int 5\n", &[set_int("a.b", 6)]);
}

// Proof 2: untouched lines keep their bytes, line endings included.

#[test]
fn kept_lines_keep_crlf() {
    let crlf = COMMENTED.replace('\n', "\r\n");
    let got = edited(&crlf, &[set_int("cost_governance.budgets.daily_usd", 10)]);
    assert_eq!(got, crlf.replace("daily_usd: 5", "daily_usd: 10"));
}

#[test]
fn kept_lines_keep_mixed_endings() {
    let file = "a:\r\n  b: 1\n  c: 2\r\n";
    assert_eq!(
        edited(file, &[set_int("a.b", 3)]),
        "a:\r\n  b: 3\n  c: 2\r\n"
    );
}

#[test]
fn a_file_without_a_final_newline_keeps_it() {
    assert_eq!(edited("a:\n  b: 1", &[set_int("a.b", 2)]), "a:\n  b: 2");
}

// Values and comments.

#[test]
fn a_string_is_written_double_quoted() {
    let got = edited(
        "server:\n  label: old\n",
        &[set_str("server.label", "new value")],
    );
    assert_eq!(got, "server:\n  label: \"new value\"\n");
}

#[test]
fn a_hash_inside_a_quoted_value_is_part_of_the_value() {
    let got = edited("a:\n  note: \"keep # this\"\n", &[set_str("a.note", "new")]);
    assert_eq!(got, "a:\n  note: \"new\"\n");
}

// Shapes it does not edit: nothing is written.

#[test]
fn a_duplicate_key_anywhere_is_unprovable() {
    assert_unprovable("x: 1\nx: 2\na:\n  b: 1\n", &[set_int("a.b", 2)]);
}

/// The parser reports the field, but inside a flow mapping: refused.
#[test]
fn a_field_inside_a_flow_mapping_is_unprovable() {
    assert_unprovable("auth: {enabled: false}\n", &[set_int("auth.enabled", 1)]);
}

#[test]
fn a_block_scalar_value_is_refused_by_the_line_end_guard() {
    assert_refused_by(
        "a:\n  b: |\n    text\n",
        &[set_str("a.b", "x")],
        "runs past the end of its line",
    );
}

#[test]
fn a_mapping_value_is_unprovable() {
    assert_unprovable(COMMENTED, &[set_str("auth", "x")]);
}

/// A missing key is inserted (a2); one under a plain value cannot be.
#[test]
fn a_key_under_a_plain_value_is_unprovable() {
    assert_unprovable(COMMENTED, &[set_int("auth.enabled.missing", 1)]);
}

#[test]
fn overlapping_changes_are_unprovable() {
    assert_unprovable(
        COMMENTED,
        &[set_int("server.port", 1), set_int("server.port", 2)],
    );
}

// Paths.

#[test]
fn a_runtime_backend_name_is_a_path_segment() {
    let file = "backends:\n  my-srv:\n    description: old\n";
    let change = (
        keys(&["backends", "my-srv", "description"]),
        Change::Set(Scalar::Str("new".into())),
    );
    assert_eq!(
        edited(file, &[change]),
        "backends:\n  my-srv:\n    description: \"new\"\n"
    );
}

/// A plain key YAML reads as a number, a bool or null is not the string key
/// the expected document would use.
#[test]
fn a_segment_yaml_reads_as_a_number_or_bool_is_unprovable() {
    for name in ["123", "true", "1e3"] {
        let file = format!("backends:\n  {name}:\n    description: x\n");
        let change = (
            keys(&["backends", name, "description"]),
            Change::Set(Scalar::Str("y".into())),
        );
        assert_unprovable(&file, &[change]);
    }
}

/// Reaches the flow check: the field is found, and replacing its flow
/// mapping with a scalar would pass the meaning proof.
#[test]
fn a_flow_mapping_as_the_edited_value_is_unprovable() {
    assert_unprovable("a: {b: 1}\n", &[set_int("a", 1)]);
}

/// Reaches the segment check: a literal `a.b` key, which a dotted slot name
/// could not tell apart from the path `a` then `b`.
#[test]
fn a_literal_dotted_key_is_unprovable() {
    let change = (keys(&["a.b"]), Change::Set(Scalar::Int(2)));
    assert_unprovable("a.b: 1\n", &[change]);
}

#[test]
fn an_empty_segment_is_refused() {
    let change = (keys(&["a", ""]), Change::Set(Scalar::Int(2)));
    assert_unprovable("a:\n  b: 1\n", &[change]);
}

// Secret slots.

const TWO_SECRETS: &str =
    "backends:\n  a:\n    env:\n      TOKEN: old-a\n  b:\n    env:\n      TOKEN: old-b\n";

#[test]
fn same_named_secrets_in_two_backends_get_distinct_slots() {
    let template = edit_in_place(
        TWO_SECRETS,
        &[
            secret("backends.a.env.TOKEN"),
            secret("backends.b.env.TOKEN"),
        ],
    )
    .expect("provable");
    let text = String::from_utf8(template.bytes().to_vec()).expect("utf-8");
    assert!(
        text.contains("TOKEN: \"__mcpgw_slot_backends.a.env.TOKEN__\""),
        "{text}"
    );
    assert!(
        text.contains("TOKEN: \"__mcpgw_slot_backends.b.env.TOKEN__\""),
        "{text}"
    );
}

/// The two placeholders swapped in the text: each field holds the other's
/// slot, so the meaning proof must refuse it.
#[test]
fn crossed_slots_fail_the_meaning_proof() {
    let changes = [
        secret("backends.a.env.TOKEN"),
        secret("backends.b.env.TOKEN"),
    ];
    let straight = String::from_utf8(
        edit_in_place(TWO_SECRETS, &changes)
            .expect("provable")
            .bytes()
            .to_vec(),
    )
    .expect("utf-8");
    assert!(super::meaning_holds(TWO_SECRETS, &changes, &straight));
    let crossed = straight
        .replace("backends.a.env.TOKEN__", "SWAP__")
        .replace("backends.b.env.TOKEN__", "backends.a.env.TOKEN__")
        .replace("SWAP__", "backends.b.env.TOKEN__");
    assert!(!super::meaning_holds(TWO_SECRETS, &changes, &crossed));
}

/// The ids swapped while the ranges stay in file order: each range holds
/// the other field's placeholder. With one shared placeholder this could not
/// be told apart; with one per path the constructor refuses it.
#[test]
fn crossed_slot_ranges_are_refused() {
    let text = "a: \"__mcpgw_slot_a__\"\nb: \"__mcpgw_slot_b__\"\n";
    let a = 3..21;
    let b = 25..43;
    assert_eq!(&text[a.clone()], "\"__mcpgw_slot_a__\"");
    assert_eq!(&text[b.clone()], "\"__mcpgw_slot_b__\"");
    let straight = Template::checked(
        text.into(),
        vec![(slot("a"), a.clone()), (slot("b"), b.clone())],
    );
    assert!(straight.is_ok());
    let crossed = Template::checked(text.into(), vec![(slot("b"), a), (slot("a"), b)]);
    assert_eq!(crossed, Err(ComputeRefusal::SlotMismatch));
}

#[test]
fn fill_writes_each_reference_under_its_own_field() {
    // Request order is the reverse of file order.
    let changes = [
        secret("backends.b.env.TOKEN"),
        secret("backends.a.env.TOKEN"),
    ];
    let template = edit_in_place(TWO_SECRETS, &changes).expect("provable");
    let refs = BTreeMap::from([
        (slot("backends.a.env.TOKEN"), "keychain:for-a".to_owned()),
        (slot("backends.b.env.TOKEN"), "keychain:for-b".to_owned()),
    ]);
    let filled = String::from_utf8(template.fill(&refs).expect("filled")).expect("utf-8");
    let doc: crate::yaml::Value = crate::yaml::from_str(&filled).expect("parses");
    assert_eq!(
        doc["backends"]["a"]["env"]["TOKEN"].as_str(),
        Some("keychain:for-a")
    );
    assert_eq!(
        doc["backends"]["b"]["env"]["TOKEN"].as_str(),
        Some("keychain:for-b")
    );
}

#[test]
fn a_reference_with_quotes_and_a_newline_round_trips() {
    let template = edit_in_place("a:\n  t: old\n", &[secret("a.t")]).expect("provable");
    let reference = "file:C:\\dir \"q\"\tx\ny";
    let refs = BTreeMap::from([(slot("a.t"), reference.to_owned())]);
    let filled = String::from_utf8(template.fill(&refs).expect("filled")).expect("utf-8");
    let doc: crate::yaml::Value = crate::yaml::from_str(&filled).expect("parses");
    assert_eq!(doc["a"]["t"].as_str(), Some(reference));
}

#[test]
fn fill_refuses_a_missing_or_an_extra_reference() {
    let template = edit_in_place("a:\n  t: old\n", &[secret("a.t")]).expect("provable");
    assert_eq!(
        template.clone().fill(&BTreeMap::new()),
        Err(ComputeRefusal::SlotMismatch)
    );
    let extra = BTreeMap::from([
        (slot("a.t"), "keychain:x".to_owned()),
        (slot("a.u"), "keychain:y".to_owned()),
    ]);
    assert_eq!(template.fill(&extra), Err(ComputeRefusal::SlotMismatch));
}

#[test]
fn a_slot_named_for_another_field_is_refused() {
    let change = (path("a.t"), Change::Secret(slot("a.u")));
    assert_eq!(
        edit_in_place("a:\n  t: old\n  u: old\n", &[change]),
        Err(ComputeRefusal::SlotMismatch)
    );
}

/// A value that is only a comment is a null field, not a scalar: editing it
/// would delete the comment.
#[test]
fn a_comment_only_value_is_refused_by_the_meaning_proof() {
    assert_refused_by(
        "a:\n  t: # keep\n",
        &[set_int("a.t", 2)],
        "does not mean the original",
    );
}

/// A slot whose placeholder sits under another field: `fill` re-reads its
/// output and refuses a reference that did not land under its own path.
#[test]
fn fill_refuses_a_reference_not_under_its_own_field() {
    let text = "a: \"__mcpgw_slot_b__\"\nb: \"__mcpgw_slot_a__\"\n";
    let template = Template::checked(text.into(), vec![(slot("b"), 3..21), (slot("a"), 25..43)])
        .expect("each range holds its own id's placeholder");
    let refs = BTreeMap::from([
        (slot("a"), "keychain:for-a".to_owned()),
        (slot("b"), "keychain:for-b".to_owned()),
    ]);
    assert_eq!(template.fill(&refs), Err(ComputeRefusal::SlotMismatch));
}

/// YAML whitespace is a space or a tab only: a non-breaking space before a
/// comment belongs to the value, and the comment after it must survive.
#[test]
fn a_comment_after_a_non_breaking_space_survives() {
    let got = edited("a: old\u{a0} # keep\n", &[set_str("a", "new")]);
    assert_eq!(got, "a: \"new\" # keep\n");
}

/// A double-quoted value may go on over several lines, and a continuation
/// line may start with `#`: only a value that closes on its own line is
/// edited, so no old text survives as an apparent comment.
#[test]
fn a_quoted_value_continued_on_the_next_line_is_refused_by_the_line_end_guard() {
    assert_refused_by(
        "a:\n  t: \"p1\n    #rest\"\n",
        &[set_str("a.t", "new")],
        "runs past the end of its line",
    );
}

/// Text right after a closing quote is not valid YAML: the parser refuses
/// the config, so nothing is written (a red run on the pre-fix code shows
/// the parser, not a check of ours, refuses it).
#[test]
fn text_touching_a_quoted_value_is_refused_by_the_parser() {
    assert_unprovable("a:\n  t: \"old\"# keep\n", &[set_str("a.t", "new")]);
}

#[test]
fn a_comment_after_a_quoted_value_survives() {
    let got = edited("a:\n  t: \"old # x\"   # keep\n", &[set_str("a.t", "new")]);
    assert_eq!(got, "a:\n  t: \"new\"   # keep\n");
}

/// An explicit tag refuses; an untagged number and a quoted one both edit.
#[test]
fn only_an_explicit_tag_refuses() {
    let file = "a:\n  x: 5\n  y: \"5\"\n";
    let got = edited(file, &[set_int("a.x", 6), set_str("a.y", "7")]);
    assert_eq!(got, "a:\n  x: 6\n  y: \"7\"\n");
    assert_unprovable(
        "a:\n  b: !<tag:yaml.org,2002:int> 5\n",
        &[set_int("a.b", 6)],
    );
}

/// The parser's span is the value's own bytes, after any multi-byte text.
#[test]
fn unicode_before_the_value_keeps_every_byte() {
    let file = "# \u{fc}nic\u{f6}de \u{1f389}\na:\n  b: \"h\u{e9}llo\"  # \u{2713} ok\n";
    let got = edited(file, &[set_str("a.b", "x")]);
    assert_eq!(got, file.replace("\"h\u{e9}llo\"", "\"x\""));
}

/// A key with no value is a null field the parser synthesizes: refused.
#[test]
fn an_empty_value_is_refused_by_the_meaning_proof() {
    assert_refused_by(
        "a:\n  t:\n  u: 1\n",
        &[set_int("a.t", 2)],
        "does not mean the original",
    );
}

// Keys and mappings on the path: only plain keys of plain block mappings.

#[test]
fn a_quoted_key_on_the_path_is_unprovable() {
    assert_unprovable("\"a\":\n  b: 1\n", &[set_int("a.b", 2)]);
}

#[test]
fn an_anchored_key_is_unprovable() {
    assert_unprovable("&k a: 1\n", &[set_int("a", 2)]);
}

#[test]
fn a_tagged_key_is_unprovable() {
    assert_unprovable("!!str a: 1\n", &[set_int("a", 2)]);
}

#[test]
fn a_field_under_an_anchored_mapping_is_unprovable() {
    assert_unprovable("a: &m\n  b: 1\n", &[set_int("a.b", 2)]);
}

#[test]
fn a_field_under_a_tagged_mapping_is_unprovable() {
    assert_unprovable("a: !!map\n  b: 1\n", &[set_int("a.b", 2)]);
}

/// An empty block scalar: with no block check, the meaning proof is what
/// refuses it.
#[test]
fn an_empty_block_scalar_is_refused_by_the_meaning_proof() {
    assert_refused_by(
        "a:\n  b: |\nc: 1\n",
        &[set_int("a.b", 2)],
        "does not mean the original",
    );
}

/// Edits are placed by `\n` line, so a config breaking lines with a bare
/// `\r` holds several parser lines on one: the bytes proof refuses a
/// rebuilt line that lost its trailing `\r`, and two changes on one line.
#[test]
fn bare_carriage_return_lines_are_refused_by_the_bytes_proof() {
    assert_refused_by(
        "a: 1\rb: 2\r",
        &[set_int("a", 3)],
        "an untouched line changed",
    );
    assert_refused_by(
        "a: 1\rb: 2",
        &[set_int("a", 3), set_int("b", 4)],
        "an untouched line changed",
    );
}

/// A slot placeholder already present (here in a comment) would make the
/// slot's place ambiguous: refused, nothing written.
#[test]
fn a_placeholder_already_present_is_unprovable() {
    let text = "a:\n  t: old  # \"__mcpgw_slot_a.t__\"\n";
    assert_unprovable(text, &[secret("a.t")]);
}

#[test]
fn the_span_walk_refuses_a_second_document() {
    assert!(crate::yaml::mapping_values("a: 1\n---\nb: 2\n").is_err());
}

/// The walk's bookkeeping recovers after a sequence value and after a
/// collection used as a key: the next field is still found and edited.
#[test]
fn a_field_after_a_sequence_or_a_collection_key_is_editable() {
    let flow = "a: [1, 2]\nb: 3\n";
    assert_eq!(edited(flow, &[set_int("b", 4)]), "a: [1, 2]\nb: 4\n");
    let block = "a:\n  - 1\n  - x: 2\nb: 3\n";
    assert_eq!(
        edited(block, &[set_int("b", 4)]),
        "a:\n  - 1\n  - x: 2\nb: 4\n"
    );
    let keyed = "? [k]\n: v\nb: 3\n";
    assert_eq!(edited(keyed, &[set_int("b", 4)]), "? [k]\n: v\nb: 4\n");
}

/// An anchor nothing refers to: value equality cannot see it dropped, so
/// only the anchor check keeps the operator's text.
#[test]
fn an_unused_anchor_on_the_value_is_unprovable() {
    assert_unprovable("a: &x 5\n", &[set_int("a", 6)]);
}

#[path = "config_persistence_keyedit_a2_tests.rs"]
mod a2;
