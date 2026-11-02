// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Revocation rows: removing one `auth.api_keys` element in place. The
//! element's lines go, with the comments on them reported by original line
//! number; nothing outside the element changes, and a shape the proofs
//! cannot cover refuses with the revocation instructions.

use super::super::GiveUp;
use super::*;

fn key(i: usize) -> FieldPath {
    FieldPath(vec![
        Segment::Key("auth".into()),
        Segment::Key("api_keys".into()),
        Segment::Index(i),
    ])
}

fn revoke(i: usize) -> (FieldPath, Change) {
    (key(i), Change::Remove)
}

/// The edited text and the comment lines it dropped; the edit must prove.
#[track_caller]
fn revoked(original: &str, changes: &[(FieldPath, Change)]) -> (String, Vec<usize>) {
    let template = edit_in_place(original, changes).expect("a provable revocation");
    let text = String::from_utf8(template.bytes().to_vec()).expect("utf-8");
    (text, template.dropped_comments().to_vec())
}

/// The refusal's code and reason.
#[track_caller]
fn refused(original: &str, changes: &[(FieldPath, Change)]) -> (GiveUp, String) {
    match edit_in_place(original, changes) {
        Err(ComputeRefusal::Unprovable { code, reason }) => (code, reason),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

const THREE: &str = "\
auth:
  api_keys:
    - name: a
      key_sha256: \"sha256:01\"
    - name: b
      key_sha256: \"sha256:02\"
    - name: c
      key_sha256: \"sha256:03\"
";

// R1: the middle of three goes; the others keep every byte.
#[test]
fn r1_removing_the_middle_key_keeps_the_others() {
    let (out, dropped) = revoked(THREE, &[revoke(1)]);
    assert_eq!(
        out,
        "auth:\n  api_keys:\n    - name: a\n      key_sha256: \"sha256:01\"\n    \
         - name: c\n      key_sha256: \"sha256:03\"\n"
    );
    assert!(dropped.is_empty(), "{dropped:?}");
}

// R1b: an element written with its dash alone on a line.
#[test]
fn r1b_an_element_with_a_bare_dash_is_removed_whole() {
    let original = "auth:\n  api_keys:\n    - name: a\n    -\n      name: b\n    - name: c\n";
    let (out, _) = revoked(original, &[revoke(1)]);
    assert_eq!(out, "auth:\n  api_keys:\n    - name: a\n    - name: c\n");
}

// R1c: a comment on the dash line goes with the element and is reported.
#[test]
fn r1c_a_comment_on_the_dash_line_is_reported() {
    let original = "auth:\n  api_keys:\n    - name: a\n    - # leaked\n      name: b\n";
    let (out, dropped) = revoked(original, &[revoke(1)]);
    assert_eq!(out, "auth:\n  api_keys:\n    - name: a\n");
    assert_eq!(dropped, vec![4]);
}

/// init's auth block (src/commands/mod.rs `build_init_config`) with one key.
const INIT_WITH_KEY: &str = "\
# Admin credential, generated for this install.
auth:
  enabled: true
  bearer_token: \"init-token\"
  single_user: true
  public_paths:
    - \"/health\"
    - \"/mcp\"
  api_keys:
    - name: ops
      key_sha256: \"sha256:aa\"

# Auth is on, so every tool call is recorded
security:
  transparency_log:
    enabled: true
";

// R2: the only key on init's file: the list's key goes too, all else stays.
#[test]
fn r2_removing_the_only_key_on_inits_file_removes_the_list() {
    let (out, dropped) = revoked(INIT_WITH_KEY, &[revoke(0)]);
    let want = INIT_WITH_KEY.replace(
        "  api_keys:\n    - name: ops\n      key_sha256: \"sha256:aa\"\n",
        "",
    );
    assert_eq!(out, want);
    assert!(dropped.is_empty(), "{dropped:?}");
}

// R3: a comment inside the entry is dropped and reported; the one above its
// dash, at the dash's indent, is kept.
#[test]
fn r3_a_comment_inside_the_entry_is_reported_and_one_above_is_kept() {
    let original = "auth:\n  api_keys:\n    - name: a\n    # above b\n    - name: b\n      \
                    # inside b\n      key_sha256: \"sha256:02\"\n";
    let (out, dropped) = revoked(original, &[revoke(1)]);
    assert_eq!(out, "auth:\n  api_keys:\n    - name: a\n    # above b\n");
    assert_eq!(dropped, vec![6]);
}

// R3b: a key inserted above in the same save: the number is the original's.
#[test]
fn r3b_a_reported_line_is_the_original_line() {
    let original = "server:\n  port: 1\nauth:\n  api_keys:\n    - name: a\n      # gone\n";
    let host = (
        FieldPath(vec![
            Segment::Key("server".into()),
            Segment::Key("host".into()),
        ]),
        Change::Set(Scalar::Str("127.0.0.1".into())),
    );
    let (_, dropped) = revoked(original, &[host, revoke(0)]);
    assert_eq!(dropped, vec![6]);
}

// R3c: a `#` inside a quoted value or a block scalar is not a comment.
#[test]
fn r3c_a_hash_inside_a_value_is_not_reported() {
    let original = "auth:\n  api_keys:\n    - name: \"a # b\"\n      note: |\n        # not a comment\n    \
                    - name: c\n";
    let (_, dropped) = revoked(original, &[revoke(0)]);
    assert!(dropped.is_empty(), "{dropped:?}");
}

// R3d: two entries with the same comment text: the removed one's line.
#[test]
fn r3d_a_repeated_comment_is_reported_at_its_own_line() {
    let original = "auth:\n  api_keys:\n    -\n      # x\n      name: ops\n    -\n      # x\n      \
                    name: ci\n";
    let (out, dropped) = revoked(original, &[revoke(0)]);
    assert_eq!(
        out,
        "auth:\n  api_keys:\n    -\n      # x\n      name: ci\n"
    );
    assert_eq!(dropped, vec![4]);
}

// R8: a block scalar ending the entry does not take the next comment.
#[test]
fn r8_a_block_scalar_ending_the_entry_keeps_the_next_comment() {
    let original = "auth:\n  api_keys:\n    - key_sha256: \"sha256:aa\"\n      name: |-\n        ops\n    \
                    # next key\n    - name: ci\n";
    let (out, _) = revoked(original, &[revoke(0)]);
    assert_eq!(out, "auth:\n  api_keys:\n    # next key\n    - name: ci\n");
}

// R9: the list key's own comment goes with the emptied list, reported.
#[test]
fn r9_the_emptied_lists_key_comment_is_reported() {
    let original = "auth:\n  enabled: true\n  api_keys: # keep\n    - name: ops\n";
    let (out, dropped) = revoked(original, &[revoke(0)]);
    assert_eq!(out, "auth:\n  enabled: true\n");
    assert_eq!(dropped, vec![3]);
}

// R9b: a trailing comment under the last entry is part of the removal.
#[test]
fn r9b_a_trailing_comment_under_the_last_entry_is_reported() {
    let original = "auth:\n  enabled: true\n  api_keys:\n    - name: ops\n      # under ops\n";
    let (out, dropped) = revoked(original, &[revoke(0)]);
    assert_eq!(out, "auth:\n  enabled: true\n");
    assert_eq!(dropped, vec![5]);
}

// R9c: a trailing comment under an entry that is not the last goes with it:
// a deletion one line short would keep the meaning, so S5's equality is what
// refuses it.
#[test]
fn r9c_a_trailing_comment_under_a_middle_entry_is_removed_and_reported() {
    let original = "auth:\n  api_keys:\n    - name: a\n      # under a\n    - name: b\n";
    let (out, dropped) = revoked(original, &[revoke(0)]);
    assert_eq!(out, "auth:\n  api_keys:\n    - name: b\n");
    assert_eq!(dropped, vec![4]);
}

// R12: an emptied `auth` goes too, its line's comment reported.
#[test]
fn r12_an_emptied_auth_is_removed_and_its_comment_reported() {
    let original = "server:\n  port: 1\nauth: # keep\n  api_keys:\n    - name: ops\n";
    let (out, dropped) = revoked(original, &[revoke(0)]);
    assert_eq!(out, "server:\n  port: 1\n");
    assert_eq!(dropped, vec![3]);
}

/// The S9 instructions a refused revocation of `name` must carry.
#[track_caller]
fn instructs(reason: &str, name: &str) {
    assert!(reason.contains(name), "names the key: {reason}");
    assert!(reason.contains("expires_at"), "expiry first: {reason}");
    let expiry = reason.find("expires_at").expect("expiry");
    let delete = reason
        .find("delete")
        .or_else(|| reason.find("remove"))
        .expect("deletion");
    assert!(expiry < delete, "expiry comes before deletion: {reason}");
    assert!(reason.contains("reload"), "then reload: {reason}");
    assert!(
        reason.contains("restart"),
        "the multi-user restart note: {reason}"
    );
    assert!(!reason.contains("sha256:"), "never a value: {reason}");
}

// R4, R4b: an anchor on the element and an alias refuse, with the
// instructions, and write nothing.
#[test]
fn r4_a_decorated_element_refuses_with_the_instructions() {
    let anchored = "auth:\n  api_keys:\n    - &k\n      name: ops\n      key_sha256: \"sha256:aa\"\n    - name: ci\n";
    let (code, reason) = refused(anchored, &[revoke(0)]);
    assert_eq!(code, GiveUp::Anchor);
    instructs(&reason, "ops");
    assert!(reason.contains("lines 3 to 5"), "names its lines: {reason}");
    let aliased = "base: &k\n  name: ops\nauth:\n  api_keys:\n    - *k\n    - name: ci\n";
    let (code, _) = refused(aliased, &[revoke(0)]);
    assert_eq!(code, GiveUp::Anchor);
}

// R4e: an anchor anywhere inside the element refuses too (a surviving alias
// may name it).
#[test]
fn r4e_an_anchor_inside_the_element_refuses() {
    let original = "auth:\n  api_keys:\n    - name: ops\n      backends: &shared\n        - fs\n    \
                    - name: ci\n      backends: *shared\n";
    let (code, reason) = refused(original, &[revoke(0)]);
    assert_eq!(code, GiveUp::Anchor);
    instructs(&reason, "ops");
    assert!(reason.contains("lines 3 to 5"), "names its lines: {reason}");
    let alias = reason.find("alias").expect("the alias step");
    assert!(
        alias < reason.find("delete").expect("deletion"),
        "the alias is replaced before the deletion: {reason}"
    );
    // Following it: the alias takes the value it named, then the lines go.
    let by_hand = drop_lines(
        &original.replace("backends: *shared", "backends:\n        - fs"),
        2..5,
    );
    let doc: crate::yaml::Value = crate::yaml::from_str(&by_hand).expect("loads");
    let keys = doc["auth"]["api_keys"].as_sequence().expect("a list");
    assert_eq!(keys.len(), 1, "{by_hand}");
    assert_eq!(keys[0]["name"].as_str(), Some("ci"));
    assert_eq!(keys[0]["backends"][0].as_str(), Some("fs"));
}

/// `text` without its 0-based `lines`.
fn drop_lines(text: &str, lines: std::ops::Range<usize>) -> String {
    let mut out = String::new();
    for (_, line) in text.lines().enumerate().filter(|(i, _)| !lines.contains(i)) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

// R4g: an anchor on its own line between the dash and the entry: the
// deletion still names the dash through the entry's last line, and
// following it loads.
#[test]
fn r4g_a_decoration_on_its_own_line_keeps_the_whole_entry() {
    let original = "auth:\n  api_keys:\n    -\n      &k\n      name: ops\n      \
                    key_sha256: \"sha256:aa\"\n    - name: ci\n";
    let (code, reason) = refused(original, &[revoke(0)]);
    assert_eq!(code, GiveUp::Anchor);
    instructs(&reason, "ops");
    assert!(reason.contains("lines 3 to 6"), "the whole entry: {reason}");
    let doc: crate::yaml::Value =
        crate::yaml::from_str(&drop_lines(original, 2..6)).expect("loads");
    let keys = doc["auth"]["api_keys"].as_sequence().expect("a list");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["name"].as_str(), Some("ci"));
}

// R4h: a decorated sole key where `api_keys` is all of `auth`: the
// deletion names the `auth:` line too, and following it loads.
#[test]
fn r4h_deleting_the_only_key_by_hand_names_the_auth_line_it_empties() {
    let original = "server:\n  port: 1\nauth:\n  api_keys:\n    - &k\n      name: ops\n";
    let (code, reason) = refused(original, &[revoke(0)]);
    assert_eq!(code, GiveUp::Anchor);
    instructs(&reason, "ops");
    assert!(
        reason.contains("lines 5 to 6 and the `api_keys:` line 4 and the `auth:` line 3"),
        "{reason}"
    );
    let by_hand = drop_lines(original, 2..6);
    let doc: crate::yaml::Value = crate::yaml::from_str(&by_hand).expect("loads");
    assert!(doc.get("auth").is_none(), "{by_hand}");
}

// R4i: a flow element in a block list has its own lines: delete them,
// never "remove the entry on line N" (that leaves a bare dash).
#[test]
fn r4i_a_flow_element_in_a_block_list_deletes_its_own_lines() {
    let original =
        "auth:\n  api_keys:\n    - {name: ops, key_sha256: \"sha256:aa\"}\n    - name: ci\n";
    let (code, reason) = refused(original, &[revoke(0)]);
    assert_eq!(code, GiveUp::Flow);
    instructs(&reason, "ops");
    assert!(reason.contains("delete lines 3 to 3"), "{reason}");
    assert!(!reason.contains("on line"), "{reason}");
    let doc: crate::yaml::Value =
        crate::yaml::from_str(&drop_lines(original, 2..3)).expect("loads");
    let keys = doc["auth"]["api_keys"].as_sequence().expect("a list");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["name"].as_str(), Some("ci"));
}

// R4j: an anchor on the list itself: an alias elsewhere may name it, so
// the revocation refuses with the instructions, the alias step first.
#[test]
fn r4j_an_anchored_list_refuses_with_the_instructions() {
    let original = "auth:\n  api_keys: &keys\n    - name: ops\n    - name: ci\nmirror: *keys\n";
    let (code, reason) = refused(original, &[revoke(0)]);
    assert_eq!(code, GiveUp::Anchor);
    instructs(&reason, "ops");
    assert!(reason.contains("alias"), "{reason}");
}

// R4c, R4f: a flow list refuses with an entry-specific edit, never a
// whole-line deletion; applying either edit by hand loads as promised.
#[test]
fn r4c_a_flow_list_refuses_with_an_entry_specific_edit() {
    let original = "auth:\n  api_keys: [{name: ops, key_sha256: \"sha256:aa\"}, {name: ci, key_sha256: \"sha256:cc\"}]\n";
    let (code, reason) = refused(original, &[revoke(0)]);
    assert_eq!(code, GiveUp::Flow);
    instructs(&reason, "ops");
    assert!(reason.contains("line 2"), "names the shared line: {reason}");
    assert!(
        reason.contains("name: ops"),
        "names the exact field: {reason}"
    );
    assert!(
        !reason.contains("delete line"),
        "never a whole-line deletion: {reason}"
    );
    // Following the deletion: the other key survives.
    let by_hand = original.replace("{name: ops, key_sha256: \"sha256:aa\"}, ", "");
    let doc: crate::yaml::Value = crate::yaml::from_str(&by_hand).expect("loads");
    assert_eq!(doc["auth"]["api_keys"][0]["name"].as_str(), Some("ci"));
    assert_eq!(doc["auth"]["api_keys"].as_sequence().map(Vec::len), Some(1));
    // Following the expiry: the key stays, expired.
    let expired = original.replace(
        "{name: ops,",
        "{name: ops, expires_at: \"2020-01-01T00:00:00Z\",",
    );
    let doc: crate::yaml::Value = crate::yaml::from_str(&expired).expect("loads");
    assert_eq!(
        doc["auth"]["api_keys"][0]["expires_at"].as_str(),
        Some("2020-01-01T00:00:00Z")
    );
}

// R4d: a decorated last entry: the deletion names the `api_keys:` line too,
// and following it loads with no keys.
#[test]
fn r4d_deleting_the_last_entry_by_hand_names_the_list_line() {
    let original = "auth:\n  enabled: true\n  api_keys:\n    - &k\n      name: ops\n";
    let (_, reason) = refused(original, &[revoke(0)]);
    assert!(reason.contains("lines 4 to 5"), "the entry: {reason}");
    assert!(reason.contains("line 3"), "the api_keys line: {reason}");
    let mut by_hand = String::new();
    for (_, line) in original
        .lines()
        .enumerate()
        .filter(|(i, _)| ![2, 3, 4].contains(i))
    {
        by_hand.push_str(line);
        by_hand.push('\n');
    }
    let config: crate::config::AuthConfig = {
        let doc: crate::yaml::Value = crate::yaml::from_str(&by_hand).expect("loads");
        crate::yaml::from_value(doc["auth"].clone()).expect("auth loads")
    };
    assert!(config.api_keys.is_empty());
}

// R5: a removal plus a set in the same list gives up; in another section it
// is proven.
#[test]
fn r5_a_revocation_is_alone_in_its_list() {
    let set_other = (
        FieldPath(vec![
            Segment::Key("auth".into()),
            Segment::Key("api_keys".into()),
            Segment::Index(2),
            Segment::Key("name".into()),
        ]),
        Change::Set(Scalar::Str("z".into())),
    );
    let (code, _) = refused(THREE, &[revoke(1), set_other]);
    assert_eq!(code, GiveUp::SequenceShape);
    let elsewhere = (
        FieldPath(vec![
            Segment::Key("auth".into()),
            Segment::Key("enabled".into()),
        ]),
        Change::Set(Scalar::Bool(true)),
    );
    let (out, _) = revoked(THREE, &[revoke(1), elsewhere]);
    assert!(
        out.contains("enabled: true") && !out.contains("name: b"),
        "{out}"
    );
}

// R5c: a revocation plus a nested key removal is proven.
#[test]
fn r5c_a_revocation_and_a_nested_key_removal_prove_together() {
    let original = format!("server:\n  port: 1\n  host: a\n{THREE}");
    let port = (
        FieldPath(vec![
            Segment::Key("server".into()),
            Segment::Key("port".into()),
        ]),
        Change::Remove,
    );
    let (out, _) = revoked(&original, &[revoke(1), port]);
    assert!(out.starts_with("server:\n  host: a\nauth:\n"), "{out}");
    assert!(!out.contains("name: b"), "{out}");
}

// R1d: the last element of a file without a final newline.
#[test]
fn r1d_the_last_element_without_a_final_newline() {
    let original = THREE.trim_end_matches('\n');
    let (out, _) = revoked(original, &[revoke(2)]);
    assert_eq!(
        out,
        "auth:\n  api_keys:\n    - name: a\n      key_sha256: \"sha256:01\"\n    \
         - name: b\n      key_sha256: \"sha256:02\""
    );
}

// R5b: a revocation plus an unrelated key removal is proven.
#[test]
fn r5b_a_revocation_and_another_removal_prove_together() {
    let original = format!("environment: staging\n{THREE}");
    let environment = (
        FieldPath(vec![Segment::Key("environment".into())]),
        Change::Remove,
    );
    let (out, _) = revoked(&original, &[revoke(1), environment]);
    assert!(
        !out.contains("environment") && !out.contains("name: b"),
        "{out}"
    );
}

// R13: a key removal whose block scalar ends past a blank line proves
// beside a revocation: both removals end at their last non-space byte.
#[test]
fn r13_a_block_scalar_key_removed_beside_a_revocation_proves() {
    let original = format!("environment: |-\n  staging\n\n{THREE}");
    let environment = (
        FieldPath(vec![Segment::Key("environment".into())]),
        Change::Remove,
    );
    let (out, dropped) = revoked(&original, &[revoke(1), environment]);
    assert!(
        !out.contains("environment") && !out.contains("name: b"),
        "{out}"
    );
    assert!(dropped.is_empty(), "{dropped:?}");
}

// R10, R10b: removing an element outside `auth.api_keys` gives up.
#[test]
fn r10_only_auth_api_keys_elements_are_removed() {
    let alerts = FieldPath(vec![Segment::Key("alerts".into()), Segment::Index(0)]);
    let (code, _) = refused("alerts:\n  - name: a\n", &[(alerts, Change::Remove)]);
    assert_eq!(code, GiveUp::SequenceShape);
    let backends = FieldPath(vec![
        Segment::Key("auth".into()),
        Segment::Key("api_keys".into()),
        Segment::Index(0),
        Segment::Key("backends".into()),
        Segment::Index(0),
    ]);
    let original = "auth:\n  api_keys:\n    - name: ops\n      backends:\n        - fs\n";
    let (code, _) = refused(original, &[(backends, Change::Remove)]);
    assert_eq!(code, GiveUp::SequenceShape);
}
