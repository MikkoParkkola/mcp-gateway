// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Insert and drop of one list entry, in place. New lines follow the entry
//! ahead of the target position, so a note written above an entry keeps
//! belonging to it. A drop removes that entry's own lines only, and a list
//! it empties is left as `[]`. Each row compares the full resulting file.

use super::super::{Element, GiveUp, Member, value_text};
use super::*;

/// The path of `list` (dotted keys) followed by position `i`.
fn nth(list: &str, i: usize) -> FieldPath {
    let mut steps = path(list).0;
    steps.push(Segment::Index(i));
    FieldPath(steps)
}

fn insert(list: &str, i: usize, element: Element) -> (FieldPath, Change) {
    (nth(list, i), Change::Insert(element))
}

fn drop_at(list: &str, i: usize) -> (FieldPath, Change) {
    (nth(list, i), Change::Drop)
}

fn text(s: &str) -> Element {
    Element::Str(s.to_owned())
}

/// The warn-on-credentials rule every mapping row uses.
fn m() -> Element {
    let one = |s: &str| Member::Str(s.to_owned());
    Element::Map(vec![
        ("match".to_owned(), one("*")),
        (
            "scan".to_owned(),
            Member::Strings(vec!["credentials".to_owned()]),
        ),
        ("action".to_owned(), one("warn")),
    ])
}

/// [`m`] in block form, dash at column `dash`.
fn m_lines(dash: usize) -> String {
    let pad = " ".repeat(dash);
    format!("{pad}- match: \"*\"\n{pad}  scan: [\"credentials\"]\n{pad}  action: \"warn\"\n")
}

/// Code and reason of a refusal; a written edit fails the row.
#[track_caller]
fn refusal(original: &str, changes: &[(FieldPath, Change)]) -> (GiveUp, String) {
    match edit_in_place(original, changes) {
        Err(ComputeRefusal::Unprovable { code, reason }) => (code, reason),
        other => panic!("wanted Unprovable, got {other:?}"),
    }
}

#[track_caller]
fn code(original: &str, changes: &[(FieldPath, Change)]) -> GiveUp {
    refusal(original, changes).0
}

/// Two rules under `rules`, each with a note line above it.
const RULES: &str = "\
rules:
  # first
  - match: a
    action: block
  # second
  - {match: b, action: warn}
";

#[test]
fn e1_block_list_gains_a_string_at_its_end() {
    let original = "deny:\n  - a:b # one\n  - \"c\"\nlast: 1\n";
    assert_eq!(
        edited(original, &[insert("deny", 2, text("d:e"))]),
        "deny:\n  - a:b # one\n  - \"c\"\n  - \"d:e\"\nlast: 1\n"
    );
}

#[test]
fn e2_inline_list_gains_a_string_before_its_bracket() {
    assert_eq!(
        edited(
            "deny: [a:b, 'c' ] # note\n",
            &[insert("deny", 2, text("d:e"))]
        ),
        "deny: [a:b, 'c', \"d:e\" ] # note\n"
    );
}

#[test]
fn e3_first_string_into_absent_blank_bracketed_or_null_list() {
    for (original, want) in [
        ("deny:  ~ # none\n", "deny:  [\"d:e\"] # none\n"),
        ("deny: []\n", "deny: [\"d:e\"]\n"),
        ("x: 1\n", "x: 1\ndeny: [\"d:e\"]\n"),
        ("deny:  [] # none\n", "deny:  [\"d:e\"] # none\n"),
        ("deny: ~\n", "deny: [\"d:e\"]\n"),
        ("deny:\n", "deny: [\"d:e\"]\n"),
    ] {
        assert_eq!(
            edited(original, &[insert("deny", 0, text("d:e"))]),
            want,
            "{original:?}"
        );
    }
}

#[test]
fn e4_mapping_lands_below_the_previous_rule() {
    let want = RULES.replace(
        "    action: block\n",
        &format!("    action: block\n{}", m_lines(2)),
    );
    assert_eq!(edited(RULES, &[insert("rules", 1, m())]), want);
}

#[test]
fn e5_mapping_at_position_zero_sits_right_under_the_key() {
    let want = RULES.replacen("rules:\n", &format!("rules:\n{}", m_lines(2)), 1);
    assert_eq!(edited(RULES, &[insert("rules", 0, m())]), want);
}

#[test]
fn e6_mapping_appended_at_the_end() {
    assert_eq!(
        edited(RULES, &[insert("rules", 2, m())]),
        format!("{RULES}{}", m_lines(2))
    );
}

#[test]
fn e7_mapping_into_absent_blank_or_bracketed_list() {
    let block = m_lines(2);
    for (original, want) in [
        // Just the brackets are taken out; whitespace either side survives.
        ("rules:  [] # none\n", format!("rules:   # none\n{block}")),
        ("rules:\n", format!("rules:\n{block}")),
        ("rules: [] # none\n", format!("rules:  # none\n{block}")),
        ("x: 1\n", format!("x: 1\nrules:\n{block}")),
    ] {
        assert_eq!(
            edited(original, &[insert("rules", 0, m())]),
            want,
            "{original:?}"
        );
    }
    assert_eq!(
        code("rules: ~\n", &[insert("rules", 0, m())]),
        GiveUp::NullSequence
    );
}

#[test]
fn e8_block_string_drop() {
    assert_eq!(
        edited("deny:\n  - a:b\n  - \"c\"\n  - d\n", &[drop_at("deny", 1)]),
        "deny:\n  - a:b\n  - d\n"
    );
}

#[test]
fn e9_inline_string_drop_at_each_position() {
    let original = "deny: [a:b, 'c', d] # n\n";
    for (i, kept) in [(2, "a:b, 'c'"), (0, "'c', d"), (1, "a:b, d")] {
        assert_eq!(
            edited(original, &[drop_at("deny", i)]),
            format!("deny: [{kept}] # n\n"),
            "at {i}"
        );
    }
}

/// grok r3 (binding): a quoted item holding a comma counts as one item, and
/// the items around a drop keep their own quoting.
#[test]
fn e9b_quoted_comma_item_survives_inline_drops() {
    let original = "deny: [\"a,b\", c, 'd'] # n\n";
    for (i, kept) in [(1, "\"a,b\", 'd'"), (2, "\"a,b\", c"), (0, "c, 'd'")] {
        assert_eq!(
            edited(original, &[drop_at("deny", i)]),
            format!("deny: [{kept}] # n\n"),
            "at {i}"
        );
    }
}

#[test]
fn e10_dropping_the_sole_entry_writes_brackets() {
    assert_eq!(edited("deny: [a:b]\n", &[drop_at("deny", 0)]), "deny: []\n");
    assert_eq!(
        edited(
            "rules:\n  - match: a\n    action: warn\n",
            &[drop_at("rules", 0)]
        ),
        "rules: []\n"
    );
    assert_eq!(
        edited("deny:\n  - a:b\nx: 1\n", &[drop_at("deny", 0)]),
        "deny: []\nx: 1\n"
    );
}

/// grok r3 (binding): extra spaces and a note on the key line are untouched.
#[test]
fn e10b_sole_entry_drop_keeps_key_comment_and_spacing() {
    assert_eq!(
        edited("deny:   # keep\n  - a:b\nx: 1\n", &[drop_at("deny", 0)]),
        "deny: []   # keep\nx: 1\n"
    );
}

#[test]
fn e11_mapping_drop_takes_exactly_its_lines() {
    let first = "rules:\n  - match: a\n    action: warn\n";
    let second = "  - match: b\n    scan: [credentials]\n    action: block\n";
    let third = "  - {match: c, action: warn}\n";
    let original = format!("{first}{second}{third}");
    assert_eq!(
        edited(&original, &[drop_at("rules", 1)]),
        format!("{first}{third}")
    );
    assert_eq!(
        edited(&original, &[drop_at("rules", 2)]),
        format!("{first}{second}")
    );
}

#[test]
fn e12_written_then_rewritten_list_is_accepted() {
    let strings = [
        ("deny: [a:b]\n", "deny: [\"d:e\"]\n"),
        ("deny:\n  - a:b\nx: 1\n", "deny: [\"d:e\"]\nx: 1\n"),
    ];
    for (original, want) in strings {
        let emptied = edited(original, &[drop_at("deny", 0)]);
        assert_eq!(
            edited(&emptied, &[insert("deny", 0, text("d:e"))]),
            want,
            "{original:?}"
        );
    }
    let emptied = edited(
        "rules:\n  - match: a\n    action: warn\n",
        &[drop_at("rules", 0)],
    );
    // e7's rule on `rules: []`: the brackets go, the space after the colon
    // stays (the spec's row text shows `rules:` with no space; see the lane
    // note).
    assert_eq!(
        edited(&emptied, &[insert("rules", 0, m())]),
        format!("rules: \n{}", m_lines(2))
    );
}

#[test]
fn e13_drop_refuses_a_commented_line() {
    for (original, line) in [
        ("deny:\n  - a:b\n    # why\n  - c\n", "line 3"),
        ("deny:\n  - a:b # why\n  - c\n", "line 2"),
    ] {
        let (code, reason) = refusal(original, &[drop_at("deny", 0)]);
        assert_eq!(code, GiveUp::Comment, "{original:?}");
        assert!(reason.contains(line), "{original:?}: {reason}");
    }
}

#[test]
fn e14_flow_anchor_and_range_refusals() {
    let split = "deny: [a:b,\n  c]\n";
    let maps = "rules: [{match: a}]\n";
    let anchored = "deny: &d [a]\n";
    let cases: [(&str, (FieldPath, Change), GiveUp); 9] = [
        (split, insert("deny", 2, text("d:e")), GiveUp::Flow),
        (split, drop_at("deny", 0), GiveUp::Flow),
        (maps, insert("rules", 1, m()), GiveUp::Flow),
        (maps, drop_at("rules", 0), GiveUp::Flow),
        (anchored, drop_at("deny", 0), GiveUp::Anchor),
        (anchored, insert("deny", 1, text("d:e")), GiveUp::Anchor),
        (
            "deny:\n  - &x a\n  - b\n",
            drop_at("deny", 0),
            GiveUp::Anchor,
        ),
        (
            "deny: [a]\n",
            insert("deny", 2, text("d:e")),
            GiveUp::SequenceShape,
        ),
        ("deny: [a]\n", drop_at("deny", 1), GiveUp::SequenceShape),
    ];
    for (original, change, want) in cases {
        let label = format!("{original:?} {change:?}");
        assert_eq!(code(original, &[change]), want, "{label}");
    }
}

const FIREWALL: &str = "\
firewall:
  credential_redaction: false
  rules:
    - match: a
      action: block
";

#[test]
fn e15_element_edit_shares_no_list_with_another_change() {
    let mut action = nth("firewall.rules", 0);
    action.0.push(Segment::Key("action".to_owned()));
    let set_action = (action, Change::Set(Scalar::Str("warn".to_owned())));
    let crowded = [
        vec![insert("firewall.rules", 1, m()), set_action],
        vec![
            insert("firewall.rules", 0, m()),
            insert("firewall.rules", 1, text("x")),
        ],
        vec![
            insert("firewall.rules", 1, m()),
            drop_at("firewall.rules", 0),
        ],
    ];
    for changes in crowded {
        assert_eq!(
            code(FIREWALL, &changes),
            GiveUp::SequenceShape,
            "{changes:?}"
        );
    }
    // A change beside the list, not in it, applies with the insert.
    let switched = (
        path("firewall.credential_redaction"),
        Change::Set(Scalar::Bool(true)),
    );
    assert_eq!(
        edited(FIREWALL, &[insert("firewall.rules", 0, m()), switched]),
        format!(
            "firewall:\n  credential_redaction: true\n  rules:\n{}    - match: a\n      action: block\n",
            m_lines(4)
        )
    );
}

#[test]
fn e16_insert_shifts_rather_than_replaces() {
    let original = "rules:\n  - match: a\n    action: block\n  - match: b\n    action: warn\n";
    let parse = |s: &str| crate::yaml::from_str::<crate::yaml::Value>(s).expect("parses");
    assert_eq!(
        parse(&edited(original, &[insert("rules", 0, m())])),
        parse(
            "rules: [{match: '*', scan: [credentials], action: warn}, {match: a, action: block}, {match: b, action: warn}]\n"
        )
    );
}

/// An insert and a drop under CRLF endings, with no final newline, and after
/// a byte order mark: the changed lines differ, every other byte stays.
#[test]
fn e17_endings_and_mark_survive_insert_and_drop() {
    let lf = "deny:\n  - a:b\n  - c\n";
    let crlf = |s: &str| s.replace('\n', "\r\n");
    for (change, lf_want) in [
        (drop_at("deny", 0), "deny:\n  - c\n"),
        (
            insert("deny", 2, text("d:e")),
            "deny:\n  - a:b\n  - c\n  - \"d:e\"\n",
        ),
    ] {
        let changes = [change];
        assert_eq!(edited(&crlf(lf), &changes), crlf(lf_want), "CRLF");
        assert_eq!(
            edited(lf.trim_end_matches('\n'), &changes),
            lf_want.trim_end_matches('\n'),
            "no final newline"
        );
        assert_eq!(
            edited(&format!("\u{feff}{lf}"), &changes),
            format!("\u{feff}{lf_want}"),
            "byte order mark"
        );
    }
}

#[test]
fn e18_api_key_revocation_and_plain_remove_as_before() {
    let one_key = "auth:\n  api_keys:\n    - name: solo\n      key_sha256: \"sha256:0f\"\nx: 1\n";
    assert_eq!(
        edited(one_key, &[(nth("auth.api_keys", 0), Change::Remove)]),
        "x: 1\n"
    );
    let (code, reason) = refusal("deny:\n  - a\n", &[(nth("deny", 0), Change::Remove)]);
    assert_eq!(code, GiveUp::SequenceShape);
    assert!(reason.contains("auth.api_keys"), "{reason}");
}

#[test]
fn e19_patch_text_of_element_changes() {
    assert_eq!(value_text(&Change::Drop), None);
    assert_eq!(
        value_text(&Change::Insert(text("d:e"))).as_deref(),
        Some("\"d:e\"")
    );
    assert_eq!(
        value_text(&Change::Insert(m())).as_deref(),
        Some("{match: \"*\", scan: [\"credentials\"], action: \"warn\"}")
    );
}
