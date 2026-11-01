// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Splice tests for comment- and layout-preserving config persistence.

use super::{edit_entry, inline_comment, remove_entry, splice};

const BLOCK: &str = "new:\n  command: echo\n";

#[test]
fn appends_inside_the_mapping_before_the_next_keys_comment() {
    let original = "# top\nbackends:\n    old:\n      command: x  # why\n\n# leads auth\nauth:\n  enabled: true\n";
    let edited = splice(original, BLOCK).expect("block style");
    assert_eq!(
        edited,
        "# top\nbackends:\n    old:\n      command: x  # why\n    new:\n      command: echo\n\n# leads auth\nauth:\n  enabled: true\n"
    );
}

#[test]
fn adds_a_mapping_when_there_is_none() {
    let edited = splice("# only a comment\nserver:\n  port: 1", BLOCK).expect("appends");
    assert_eq!(
        edited,
        // The file ends without a line break, and still does (MIK-8029).
        "# only a comment\nserver:\n  port: 1\nbackends:\n  new:\n    command: echo"
    );
    // A commented-out example is not the mapping.
    let edited = splice("# backends:\n#   x: {}\n", BLOCK).expect("appends");
    assert!(edited.ends_with("#   x: {}\nbackends:\n  new:\n    command: echo\n"));
}

#[test]
fn fills_an_empty_mapping_and_leaves_flow_style_alone() {
    let edited = splice("backends: {}  # none yet\nauth: {}\n", BLOCK).expect("empty");
    assert_eq!(
        edited,
        "backends: # none yet\n  new:\n    command: echo\nauth: {}\n"
    );
    assert_eq!(splice("backends: {a: {command: x}}\n", BLOCK), None);
}

#[test]
fn removes_one_entry_and_keeps_the_rest() {
    let original = "backends:\n  # a's note\n  a:\n    command: x\n\n  # leads b\n  b:\n    command: y\n# leads auth\nauth: {}\n";
    assert_eq!(
        remove_entry(original, "a").expect("a"),
        "backends:\n  # a's note\n\n  # leads b\n  b:\n    command: y\n# leads auth\nauth: {}\n"
    );
    assert_eq!(
        remove_entry(original, "b").expect("b"),
        "backends:\n  # a's note\n  a:\n    command: x\n\n  # leads b\n# leads auth\nauth: {}\n"
    );
    assert_eq!(remove_entry(original, "missing"), None);
}

#[test]
fn removing_the_last_entry_leaves_an_empty_mapping() {
    assert_eq!(
        remove_entry("backends:  # mine\n  a:\n    command: x\n", "a").expect("a"),
        "backends: {} # mine\n"
    );
    // Bare `backends:` would load as null, not the empty mapping.
    assert_eq!(
        remove_entry("backends:\n  a:\n    command: x\nauth: {}\n", "a").expect("a"),
        "backends: {}\nauth: {}\n"
    );
    // An anchor on the header cannot be kept on `{}`: no splice.
    assert_eq!(
        remove_entry("backends: &pool # keep\n  a:\n    command: x\n", "a"),
        None
    );
}

fn map(yaml: &str) -> crate::yaml::Mapping {
    crate::yaml::from_str(yaml).expect("mapping")
}

fn edited(original: &str, old: &str, new: &str) -> Option<String> {
    edit_entry(original, "svc", &map(old), &map(new))
}

#[test]
fn the_inline_comment_scanner_skips_quoted_hashes() {
    assert_eq!(inline_comment("a: \"x # y\"  # z"), Some("  # z"));
    assert_eq!(inline_comment("a: x#y"), None);
    assert_eq!(inline_comment("a: x\t# t"), Some("\t# t"));
    // An apostrophe inside a word opens no quote.
    assert_eq!(inline_comment("a: it's old  # kept"), Some("  # kept"));
    // Nor does a quote after a word, and escapes do not end a quote.
    assert_eq!(inline_comment("a: say \"hi  # kept"), Some("  # kept"));
    assert_eq!(
        inline_comment("a: \"x \\\" # y\"  # kept"),
        Some("  # kept")
    );
    assert_eq!(inline_comment("a: 'it''s # y'  # kept"), Some("  # kept"));
}

#[test]
fn a_hash_left_in_a_replaced_value_refuses() {
    let original = "backends:\n  svc:\n    description: \"a # b\"\n";
    let old = "description: \"a # b\"\n";
    assert_eq!(edited(original, old, "description: c\n"), None);
}

#[test]
fn a_tagged_value_with_a_hash_refuses() {
    let original = "backends:\n  svc:\n    env:\n      TOKEN: !!str \"old # secret\"\n";
    let old = "env:\n  TOKEN: \"old # secret\"\n";
    assert_eq!(edited(original, old, "env:\n  TOKEN: new\n"), None);
    let flow = "backends:\n  svc:\n    env: {TOKEN: !!str \"old # secret\"}\n";
    assert_eq!(edited(flow, old, "env:\n  TOKEN: new\n"), None);
    let sequence = "backends:\n  svc:\n    args: [!!str \"old # secret\"]\n";
    let old = "args: [\"old # secret\"]\n";
    assert_eq!(edited(sequence, old, "args: [new]\n"), None);
}

#[test]
fn a_real_comment_after_a_tag_or_alias_is_kept() {
    let tagged = "backends:\n  svc:\n    env:\n      TOKEN: !!str \"old\"  # keep\n";
    assert_eq!(
        edited(tagged, "env:\n  TOKEN: old\n", "env:\n  TOKEN: new\n"),
        Some("backends:\n  svc:\n    env:\n      TOKEN: new  # keep\n".to_owned())
    );
    // The alias resolves only in the whole document.
    let aliased = "x: &shared {A: one}\nbackends:\n  svc:\n    env: *shared  # keep\n";
    assert_eq!(
            edited(aliased, "env:\n  A: one\n", "env:\n  A: one\n  B: two\n"),
            Some(
                "x: &shared {A: one}\nbackends:\n  svc:\n    env:  # keep\n      A: one\n      B: two\n"
                    .to_owned()
            )
        );
}

#[test]
fn an_edit_touches_only_the_keys_that_changed() {
    let original = "backends:\n  svc:\n    command: \"x\"  # why\n    description: a\n";
    assert_eq!(
        edited(
            original,
            "command: x\ndescription: a\n",
            "command: x\ndescription: b\n"
        ),
        Some("backends:\n  svc:\n    command: \"x\"  # why\n    description: b\n".to_owned())
    );
}

#[test]
fn an_omitted_default_is_appended_inside_the_entry() {
    let original = "backends:\n  svc:\n    command: x\n  # leads other\n  other:\n    command: y\n";
    assert_eq!(
            edited(original, "command: x\nenabled: true\n", "command: x\nenabled: false\n"),
            Some(
                "backends:\n  svc:\n    command: x\n    enabled: false\n  # leads other\n  other:\n    command: y\n"
                    .to_owned()
            )
        );
}

#[test]
fn a_block_mapping_is_edited_key_by_key() {
    let original = "backends:\n  svc:\n    env:\n      # vault\n      A: one\n";
    assert_eq!(
        edited(original, "env:\n  A: one\n", "env:\n  A: one\n  B: two\n"),
        Some("backends:\n  svc:\n    env:\n      # vault\n      A: one\n      B: two\n".to_owned())
    );
}

#[test]
fn a_comment_inside_a_replaced_or_removed_value_refuses() {
    let original = "backends:\n  svc:\n    secrets:\n      # pinned\n      - a\n";
    assert_eq!(edited(original, "secrets: [a]\n", "secrets: [b]\n"), None);
    assert_eq!(edited(original, "secrets: [a]\n", "{}\n"), None);
    let flow = "backends:\n  svc:\n    env: {\n      # vault\n      A: one\n    }\n";
    assert_eq!(
        edited(flow, "env: {A: one}\n", "env: {A: one, B: two}\n"),
        None
    );
    assert_eq!(
        edited(
            "backends: {svc: {env: {}}}\n",
            "env: {}\n",
            "env: {B: two}\n"
        ),
        None
    );
}

#[test]
fn a_type_change_replaces_the_value_and_keeps_its_inline_comment() {
    let original = "backends:\n  svc:\n    timeout: 5s  # slow host\n";
    assert_eq!(
        edited(original, "timeout: 5s\n", "timeout:\n  secs: 9\n"),
        Some("backends:\n  svc:\n    timeout:  # slow host\n      secs: 9\n".to_owned())
    );
}

/// The web UI loaded `a` and `b`, another writer then removed `b`, and the
/// UI now adds `c`. Two differences on a commented file are refused: a
/// splice of both would put `b` back.
#[test]
fn a_web_ui_write_after_a_concurrent_removal_is_refused() {
    use crate::config::Config;
    use crate::config_persistence::{CommentLoss, Unwritten, write_config_with};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let current = "backends:\n  a:  # kept by hand\n    command: a\n";
    crate::gateway::test_helpers::write_owner_only(&path, current).expect("write");
    let stale: Config = crate::yaml::from_str(
        "backends:\n  a: {command: a}\n  b: {command: b}\n  c: {command: c}\n",
    )
    .expect("config");
    let held = crate::config_persistence::lock::lock_config_blocking(
        &path,
        std::time::Instant::now(),
        |_| {},
    )
    .expect("config lock")
    .held;
    let result = write_config_with(&path, &stale, CommentLoss::Refuse, &held);
    assert!(
        matches!(result, Err(Unwritten::CommentLoss(_))),
        "{result:?}"
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), current);
}

/// The one public writer: `Ok` when it keeps the comments, otherwise the
/// refusal as `Err`, naming the lines and leaving the file untouched.
#[test]
fn the_preserving_writer_reports_each_outcome() {
    use crate::config::Config;
    use crate::config_persistence::edit_config;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    // Owner-only, as the loader requires (CONFIG.2): a file it refuses to
    // load would be refused for that reason, not the one under test.
    let write = crate::gateway::test_helpers::write_owner_only;
    let flow = "backends: {a: {command: a}}  # kept by hand\n";
    write(&path, flow).expect("write");
    let two: Config =
        crate::yaml::from_str("backends:\n  a: {command: a}\n  b: {command: b}\n").expect("config");
    let refusal = edit_config(&path, crate::config_persistence::CommentLoss::Refuse, |c| {
        *c = two.clone();
        Ok(())
    })
    .map(drop)
    .expect_err("refused");
    assert!(
        refusal.starts_with("Not saved:") && refusal.contains("line 1"),
        "{refusal}"
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), flow);
    let block = "backends:\n  a:  # kept by hand\n    command: a\n";
    write(&path, block).expect("write");
    assert_eq!(
        edit_config(&path, crate::config_persistence::CommentLoss::Refuse, |c| {
            *c = two.clone();
            Ok(())
        })
        .map(drop),
        Ok(())
    );
    assert!(
        std::fs::read_to_string(&path)
            .expect("read")
            .contains("# kept by hand")
    );
}

/// YAML indentation is spaces only: a key that starts with a non-breaking
/// space sits at its spaces' depth, so a sibling after it is still in the
/// same mapping and the edit stays in place.
#[test]
fn a_key_starting_with_a_non_breaking_space_keeps_its_depth() {
    use crate::config::Config;
    let original = "backends:\n  svc:\n    command: x\n    env:\n      \u{a0}FOO: one  # keep\n      BAR: two\n";
    let before: Config = crate::yaml::from_str(original).expect("loads");
    let mut config = before.clone();
    config
        .backends
        .get_mut("svc")
        .expect("svc")
        .env
        .insert("BAR".into(), "three".into());
    let got = super::with_backend_edited(original, &before, &config, "svc")
        .expect("an in-place edit, not a refusal");
    assert_eq!(got, original.replace("BAR: two", "BAR: three"));
}

/// The gateway's own YAML writes a block list at its key's depth
/// (`allowed_tools:` then `- read_a` under it, not indented). Those items
/// belong to the key, so replacing or removing the list takes them too.
const LIST_AT_KEY_DEPTH: &str = "backends:\n  svc:\n    command: x\n    allowed_tools:\n    - read_a\n  other:\n    command: y\n";

#[test]
fn a_list_at_its_keys_depth_is_replaced_whole() {
    let old = "command: x\nallowed_tools: [read_a]\n";
    let new = "command: x\nallowed_tools: [read_a, write_b]\n";
    assert_eq!(
        edited(LIST_AT_KEY_DEPTH, old, new).as_deref(),
        Some(
            "backends:\n  svc:\n    command: x\n    allowed_tools:\n    - read_a\n    - write_b\n  \
             other:\n    command: y\n"
        )
    );
}

#[test]
fn a_list_at_its_keys_depth_is_removed_whole() {
    let old = "command: x\nallowed_tools: [read_a]\n";
    assert_eq!(
        edited(LIST_AT_KEY_DEPTH, old, "command: x\n").as_deref(),
        Some("backends:\n  svc:\n    command: x\n  other:\n    command: y\n")
    );
}

/// Control: a list indented under its key was already handled.
#[test]
fn an_indented_list_is_replaced_whole() {
    let original = "backends:\n  svc:\n    command: x\n    allowed_tools:\n      - read_a\n";
    let old = "command: x\nallowed_tools: [read_a]\n";
    let new = "command: x\nallowed_tools: [write_b]\n";
    let text = edited(original, old, new).expect("spliced");
    assert!(text.ends_with("allowed_tools:\n    - write_b\n"), "{text}");
    assert!(!text.contains("read_a"), "{text}");
}

/// Edge: a list at its key's depth followed by a sibling key. The sibling
/// ends the list's span, so replacing or removing the list keeps it.
#[test]
fn a_list_at_its_keys_depth_keeps_the_sibling_after_it() {
    let original = "backends:\n  svc:\n    allowed_tools:\n    - a\n    - b\n    enabled: true\n";
    let old = "allowed_tools: [a, b]\nenabled: true\n";
    assert_eq!(
        edited(original, old, "allowed_tools: [c]\nenabled: true\n").as_deref(),
        Some("backends:\n  svc:\n    allowed_tools:\n    - c\n    enabled: true\n")
    );
    assert_eq!(
        edited(original, old, "enabled: true\n").as_deref(),
        Some("backends:\n  svc:\n    enabled: true\n")
    );
}

/// Edge: inside a sequence of mappings, a key's same-depth list items belong
/// to it, but the next item of the enclosing sequence (`- name: y`, shallower
/// than the key) ends its span; and an item line's own span never takes the
/// sibling item at its depth.
#[test]
fn a_sibling_sequence_item_ends_the_span() {
    let lines = ["- name: x", "  allowed_tools:", "  - a", "- name: y"];
    assert_eq!(
        super::key_span(&lines, 1, lines.len()),
        3,
        "the key keeps `- a`"
    );
    assert_eq!(
        super::key_span(&lines, 0, lines.len()),
        3,
        "the item stops at `- name: y`"
    );
}
