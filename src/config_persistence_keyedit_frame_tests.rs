// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A file whose one document sits in a YAML frame: a byte order mark,
//! directives and a `---` line before it, a `...` line after it. Every form
//! the loader accepts takes in-place edits, the frame's bytes stay as they
//! were, and every line number the editor reports is the file's own.

use super::revoke::{drop_lines, instructs, loads_auth, refused, revoke, revoked};
use super::*;
use crate::config_persistence::keyedit::GiveUp;

const BOM: &str = "\u{feff}";

/// The body every framed file below wraps: one scalar and two keys.
const BODY: &str = "\
server:
  port: 1
auth:
  api_keys:
    - name: a
      key_sha256: \"sha256:01\"
    - name: b
      key_sha256: \"sha256:02\"
";

/// `BODY` with key `b` revoked.
const WITHOUT_B: &str = "\
server:
  port: 1
auth:
  api_keys:
    - name: a
      key_sha256: \"sha256:01\"
";

/// `head`, the body, then `tail`.
fn framed(head: &str, tail: &str) -> String {
    format!("{head}{BODY}{tail}")
}

/// Revoking `b` and setting the port both succeed on `head` + body +
/// `tail`, and each leaves the frame byte for byte around the edited body.
#[track_caller]
fn frame_holds(head: &str, tail: &str) {
    let original = framed(head, tail);
    let (out, _) = revoked(&original, &[revoke(1)]);
    assert_eq!(out, format!("{head}{WITHOUT_B}{tail}"));
    let out = edited(&original, &[set_int("server.port", 2)]);
    assert_eq!(out, framed(head, tail).replace("port: 1", "port: 2"));
}

#[test]
fn p2_a_bom_file_takes_a_revocation_and_a_set() {
    frame_holds(BOM, "");
}

/// The BOM shares line 1 with the first key: removing that key keeps the
/// BOM at byte 0, and a new root key is written at column 0.
#[test]
fn p2b_a_bom_outlives_its_line_and_never_counts_as_indent() {
    let original = framed(BOM, "");
    let out = edited(&original, &[(path("server"), Change::Remove)]);
    assert_eq!(
        out,
        format!("{BOM}{}", &BODY["server:\n  port: 1\n".len()..])
    );
    let out = edited(&original, &[set_int("limit", 3)]);
    assert!(out.starts_with(BOM), "{out:?}");
    assert_eq!(out.matches(BOM).count(), 1, "{out:?}");
    assert!(out.lines().any(|line| line == "limit: 3"), "{out:?}");
}

/// A secret slot's range is read from the result's own bytes, which start
/// with the BOM: filling it writes the reference under its field.
#[test]
fn p2c_a_secret_slot_after_a_bom_is_filled_in_place() {
    let original = framed(BOM, "");
    let template = edit_in_place(&original, &[secret("server.token")]).expect("provable");
    let refs = BTreeMap::from([(slot("server.token"), "keychain:tok".to_owned())]);
    let filled = String::from_utf8(template.fill(&refs).expect("filled")).expect("utf-8");
    assert!(filled.starts_with(BOM), "{filled:?}");
    assert_eq!(filled.matches(BOM).count(), 1, "{filled:?}");
    let doc: crate::yaml::Value = crate::yaml::from_str(&filled).expect("parses");
    assert_eq!(doc["server"]["token"].as_str(), Some("keychain:tok"));
    assert_eq!(doc["server"]["port"].as_i64(), Some(1));
}

/// The diff preview's entry point reads an empty framed document as an
/// empty root, with a BOM as without one.
#[test]
fn p2d_the_preview_reads_an_empty_framed_document() {
    let changes = [set_int("limit", 3)];
    let plain = super::super::expected_text("---\n...\n", &changes).expect("an empty root");
    assert_eq!(plain, "limit: 3\n");
    let bom = super::super::expected_text(&format!("{BOM}---\n...\n"), &changes);
    assert_eq!(bom.as_deref(), Some(plain.as_str()));
}

/// A document-start line, bare, with a comment, and with a tab before it.
#[test]
fn p3_a_document_start_line_is_kept() {
    for head in ["---\n", "--- # note\n", "---\t# c\n"] {
        frame_holds(head, "");
    }
}

/// Directives and comments before `---`, and a BOM before `---`.
#[test]
fn p4_directives_and_a_bom_before_the_start_line_are_kept() {
    for head in [
        "%YAML 1.2\n---\n",
        "%TAG !g! !gateway-\n---\n",
        "# head\n\n---\n",
        "\u{feff}---\n",
        "\u{feff}--- # note\n",
    ] {
        frame_holds(head, "");
    }
}

/// A `...` tail, with a comment or comments after it, and a document
/// wrapped in both markers.
#[test]
fn p5_an_end_line_and_a_wrapped_document_are_kept() {
    for (head, tail) in [
        ("", "...\n"),
        ("", "... # end\n"),
        ("", "...\n# trailing\n\n"),
        ("---\n", "...\n"),
        ("%YAML 1.2\n---\n", "... # end\n"),
    ] {
        frame_holds(head, tail);
    }
}

/// CRLF frame lines around an LF body, and CRLF throughout.
#[test]
fn p5b_crlf_frame_lines_are_kept() {
    frame_holds("---\r\n", "...\r\n");
    let original = framed("---\n", "...\n").replace('\n', "\r\n");
    let (out, _) = revoked(&original, &[revoke(1)]);
    assert_eq!(out, format!("---\n{WITHOUT_B}...\n").replace('\n', "\r\n"));
}

/// A `...` last line without a final line ending takes an edit too; it may
/// gain the ending, nothing else.
#[test]
fn p5c_an_unterminated_end_line_is_kept() {
    let original = framed("", "...");
    let out = edited(&original, &[set_int("server.port", 2)]);
    let want = original.replace("port: 1", "port: 2");
    assert!(out == want || out == format!("{want}\n"), "{out:?}");
}

/// A new root key lands inside the body, before the `...` line, which stays
/// the last line.
#[test]
fn p6_a_new_root_key_lands_before_the_end_line() {
    for tail in ["...\n", "... # end\n# trailing\n"] {
        let out = edited(&framed("---\n", tail), &[set_int("limit", 3)]);
        assert!(out.ends_with(tail), "{out:?}");
        let body = &out[..out.len() - tail.len()];
        assert!(body.lines().any(|line| line == "limit: 3"), "{out:?}");
        assert!(out.starts_with("---\n"), "{out:?}");
    }
}

/// An empty framed document, bare or holding only a comment, takes a set:
/// the new key lands between the markers, which stay byte for byte.
#[test]
fn p9_an_empty_framed_document_takes_a_new_key() {
    for original in ["---\n...\n", "---\n# nothing yet\n...\n"] {
        let out = edited(original, &[set_int("limit", 3)]);
        assert!(
            out.starts_with("---\n") && out.ends_with("...\n"),
            "{out:?}"
        );
        assert!(out.lines().any(|line| line == "limit: 3"), "{out:?}");
        assert_eq!(out.len(), original.len() + "limit: 3\n".len(), "{out:?}");
    }
}

/// A file with no document before its `...` line, bare or after a comment,
/// takes a new key just above that line.
#[test]
fn p9c_a_headless_empty_document_takes_a_new_key() {
    for original in ["...\n", "# nothing yet\n...\n"] {
        let out = edited(original, &[set_int("limit", 3)]);
        assert_eq!(out, original.replace("...\n", "limit: 3\n...\n"));
    }
}

/// Revoking the only key empties the document: the markers stay around an
/// empty body, and the edit still proves.
#[test]
fn p9b_revoking_the_only_key_leaves_the_bare_frame() {
    let original = "--- # gateway\nauth:\n  api_keys:\n    - name: solo\n      \
                    key_sha256: \"sha256:5a\"\n... # end\n";
    let (out, _) = revoked(original, &[revoke(0)]);
    assert_eq!(out, "--- # gateway\n... # end\n");
}

/// Removing the first top-level key takes nothing from a two-line head.
#[test]
fn p10_removing_the_first_key_keeps_the_head() {
    let original = framed("%YAML 1.2\n---\n", "...\n");
    let out = edited(&original, &[(path("server"), Change::Remove)]);
    let rest = &BODY["server:\n  port: 1\n".len()..];
    assert_eq!(out, format!("%YAML 1.2\n---\n{rest}...\n"));
}

/// A start line that also holds part of the document (an anchor or a tag on
/// the root, or the whole document) never refuses the file whole. A key is
/// still revoked with that line kept byte for byte. A value under an
/// anchored or tagged root is refused on its own field, as it is in a file
/// with no start line; a whole document written on the start line is a
/// flow collection, refused on its field as a flow root is without one.
#[test]
fn p11_a_start_line_with_content_is_kept_or_refused() {
    for head in ["--- &root\n", "--- !!map\n"] {
        let (out, _) = revoked(&framed(head, ""), &[revoke(1)]);
        assert_eq!(out, format!("{head}{WITHOUT_B}"));
        let (code, why) = refused(&framed(head, ""), &[set_int("server.port", 2)]);
        assert_eq!(code, GiveUp::NotPlainKey, "{head:?}: {why}");
        let bare = framed(head.trim_start_matches("--- "), "");
        let (code, why) = refused(&bare, &[set_int("server.port", 2)]);
        assert_eq!(code, GiveUp::NotPlainKey, "{bare:?}: {why}");
    }
    for text in ["--- {server: {port: 1}}\n", "{server: {port: 1}}\n"] {
        let (code, why) = refused(text, &[set_int("server.port", 2)]);
        assert_eq!(code, GiveUp::Flow, "{text:?}: {why}");
    }
}

/// A plain key written on the start line itself is not YAML a reader
/// accepts as one document, so no edit may reach that line: setting the
/// key's value, and removing the only key, are both refused.
#[test]
fn p13_a_plain_key_on_the_start_line_takes_no_edit() {
    let cases = [
        ("--- port: 1\n", (path("port"), Change::Remove)),
        ("--- port: 1\n", set_int("port", 2)),
        ("--- server:\n  port: 1\n", set_int("server.port", 2)),
        ("--- server:\n  port: 1\n", (path("server"), Change::Remove)),
    ];
    for (text, change) in cases {
        let got = edit_in_place(text, &[change]);
        assert!(got.is_err(), "{text:?} took an edit: {got:?}");
    }
}

/// The proofs alone keep the frame: any frame line deleted outside the
/// plan is refused, and a key written after the end line is refused.
#[test]
fn p12_a_frame_line_cannot_vanish_or_be_written_past() {
    use super::super::shape;
    let original = "%YAML 1.2\n# head\n---\nport: 1\n... # end\n# tail\n";
    let before = shape::nodes(original).expect("nodes");
    for line in [0, 1, 2, 4, 5] {
        let mut lines = shape::Lines::new(original);
        lines.delete(line..line + 1);
        let after = lines.text();
        let planned =
            super::super::deleted_as_planned(original, &before, &[], &[], None, &lines, &after);
        assert!(planned.is_err(), "line {line} went unplanned: {after:?}");
    }
    let past_the_end = "port: 1\n...\nlimit: 3\n";
    assert!(!super::super::meaning_holds(
        "port: 1\n...",
        &[set_int("limit", 3)],
        past_the_end
    ));
}

/// Below a directive and a start line, the hand deletion offered for an
/// anchored entry counts from the top of the file as written; carried out
/// as offered, it leaves the head and the other key standing.
#[test]
fn p7_a_checked_deletion_names_true_line_numbers() {
    let text = "%YAML 1.2\n---\nauth:\n  api_keys:\n    - &pinned\n      name: deploy\n      \
                key_sha256: \"sha256:d1\"\n    - name: reader\n";
    let (cause, why) = refused(text, &[revoke(0)]);
    assert_eq!(cause, GiveUp::Anchor, "{why}");
    instructs(&why, "deploy");
    assert!(why.contains("lines 5 to 7"), "{why}");
    let followed = drop_lines(text, 4..7);
    assert!(
        followed.starts_with("%YAML 1.2\n---\nauth:\n"),
        "{followed:?}"
    );
    let left = loads_auth(&followed).api_keys;
    let names: Vec<_> = left.iter().map(|key| key.name.as_str()).collect();
    assert_eq!(names, ["reader"]);
}

/// The one-line form offered for a flow list counts true lines as well.
/// Its parts are checked one by one, not as one sentence.
#[test]
fn p7b_an_on_line_edit_names_the_true_line() {
    let text = "---\nauth:\n  api_keys: [{name: reader, key_sha256: \"sha256:r1\"}, \
                {name: deploy, key_sha256: \"sha256:d1\"}]\n...\n";
    let (cause, why) = refused(text, &[revoke(1)]);
    assert_eq!(cause, GiveUp::Flow, "{why}");
    for part in ["on line 3", "name: deploy", "one comma next to it"] {
        assert!(why.contains(part), "missing {part:?}: {why}");
    }
}

/// A comment inside a revoked entry is reported at the line it holds in the
/// file, which a start line above pushes down by one.
#[test]
fn p7c_a_dropped_comment_is_reported_at_its_true_line() {
    let text = "---\nauth:\n  api_keys:\n    - name: reader\n    - name: deploy\n      \
                # rotate monthly\n      key_sha256: \"sha256:d1\"\n...\n";
    let (left, comments) = revoked(text, &[revoke(1)]);
    assert_eq!(comments, [6]);
    assert_eq!(left, "---\nauth:\n  api_keys:\n    - name: reader\n...\n");
}

/// Past the frame nothing changes: each of these still refuses.
#[test]
fn p8_markers_past_the_frame_still_refuse() {
    let cases = [
        ("a second document", format!("{BODY}---\nother: 1\n")),
        ("an empty first document", format!("---\n---\n{BODY}")),
        (
            "content after the end line",
            format!("{BODY}...\nother: 1\n"),
        ),
        (
            "a directive in the body",
            "server:\n  port: 1\n%x: 1\n".to_owned(),
        ),
        (
            "a directive with no start line",
            format!("%YAML 1.2\n{BODY}"),
        ),
        (
            "a bare carriage return",
            format!("---\n{}", BODY.replacen('\n', "\r", 1)),
        ),
    ];
    for (what, text) in cases {
        let got = edit_in_place(&text, &[set_int("server.port", 2)]);
        assert!(
            matches!(got, Err(ComputeRefusal::Unprovable { .. })),
            "{what}: {got:?}"
        );
    }
}

// The frame reader on its own, as a caller with no parser in front of it
// reaches it: each shape past the frame is refused by the reader itself.

#[test]
fn p14_frame_refuses_content_after_the_end_line() {
    assert!(super::super::frame::frame("port: 1\n... x\n").is_none());
}

#[test]
fn p15_frame_refuses_a_directive_inside_the_document() {
    assert!(super::super::frame::frame("port: 1\n%x\n").is_none());
}

#[test]
fn p16_frame_refuses_a_directive_with_no_start_line() {
    assert!(super::super::frame::frame("%YAML 1.2\nport: 1\n").is_none());
}

/// A byte order mark is not content: a marked file holding only its frame
/// is empty to the emptiness test as well.
#[test]
fn p17_a_marked_file_of_only_frame_lines_has_no_content() {
    assert!(super::super::shape::no_content("\u{feff}---\n...\n"));
}
