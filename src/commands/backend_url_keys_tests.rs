// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::collections::BTreeSet;

use super::*;

/// Two backends, one on each older key, with comments around and inside them.
const TWO_BACKENDS: &str = "\
# my gateway
server:
  port: 39400
backends:
  # the files server
  fs:
    http_url: \"https://fs.example.com/mcp\"  # primary
    headers:
      X-Note: \"http_url: is not a key here\"
  rt:
    # realtime
    ws_url: \"wss://rt.example.com/mcp\"
    timeout: 30s
";

#[test]
fn both_aliases_across_two_backends_become_url_and_comments_stay() {
    let out = rewrite_url_aliases(TWO_BACKENDS, None);
    let expected = TWO_BACKENDS
        .replace("    http_url: \"https://fs", "    url: \"https://fs")
        .replace("    ws_url: \"wss://rt", "    url: \"wss://rt");
    assert_eq!(out.text, expected);
    assert_eq!(out.changed, vec![7, 12]);
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
}

#[test]
fn a_second_run_changes_nothing() {
    let first = rewrite_url_aliases(TWO_BACKENDS, None);
    let second = rewrite_url_aliases(&first.text, None);
    assert_eq!(second.text, first.text);
    assert!(second.changed.is_empty());
}

#[test]
fn only_the_named_backends_are_rewritten() {
    let only: BTreeSet<String> = ["rt".to_string()].into();
    let out = rewrite_url_aliases(TWO_BACKENDS, Some(&only));
    assert!(
        out.text.contains("    http_url: \"https://fs"),
        "{}",
        out.text
    );
    assert!(out.text.contains("    url: \"wss://rt"), "{}", out.text);
    assert_eq!(out.changed, vec![12]);
}

#[test]
fn a_key_that_is_not_a_backend_field_is_left_alone() {
    let text = "\
# http_url: in a comment
meta_mcp:
  http_url: \"not a backend\"
backends:
  fs:
    env:
      http_url: \"https://env.example.com\"
";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert!(out.changed.is_empty());
}

#[test]
fn a_backend_that_already_has_url_is_left_for_the_loader_to_refuse() {
    let text = "backends:\n  fs:\n    url: \"https://a.example.com\"\n    http_url: \"https://b.example.com\"\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert!(out.changed.is_empty());
}

#[test]
fn a_flow_style_backend_is_reported_not_edited() {
    let text = "backends:\n  fs: { http_url: \"https://a.example.com\" }\n  rt:\n    ws_url: \"wss://b.example.com\"\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.skipped, vec!["fs".to_string()]);
    assert!(out.text.contains("  fs: { http_url:"), "{}", out.text);
    assert!(out.text.contains("    url: \"wss://b"), "{}", out.text);
}

#[test]
fn a_cli_write_saves_a_new_backend_with_url() {
    use mcp_gateway::config::{BackendConfig, TransportConfig};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "# kept\nbackends:\n  old:\n    http_url: \"https://old.example.com/mcp\"\n",
    )
    .expect("write config");
    let mut config =
        mcp_gateway::config_persistence::load_existing_or_default(&path).expect("config loads");
    config.backends.insert(
        "new".to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "https://new.example.com/mcp".to_string(),
                streamable_http: None,
                protocol_version: None,
            },
            ..Default::default()
        },
    );
    super::super::config_write::write(
        &path,
        &config,
        super::super::config_write::CommentLoss::Refuse,
    )
    .expect("write succeeds");
    let text = std::fs::read_to_string(&path).expect("read back");
    assert!(
        text.contains("url: https://new.example.com/mcp")
            || text.contains("url: \"https://new.example.com/mcp\""),
        "{text}"
    );
    assert!(
        !text.contains("http_url: https://new") && !text.contains("http_url: \"https://new"),
        "{text}"
    );
    assert!(
        text.contains("http_url: \"https://old.example.com/mcp\""),
        "an existing backend was rewritten: {text}"
    );
    assert!(text.contains("# kept"), "{text}");
}

#[test]
fn a_cli_write_keeps_url_on_a_backend_that_already_had_it() {
    use mcp_gateway::config::BackendConfig;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "backends:\n  kept:\n    url: \"https://kept.example.com/mcp\"\n",
    )
    .expect("write config");
    let mut config =
        mcp_gateway::config_persistence::load_existing_or_default(&path).expect("config loads");
    config.backends.insert(
        "other".to_string(),
        BackendConfig {
            transport: mcp_gateway::config::TransportConfig::Stdio {
                command: "true".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..Default::default()
        },
    );
    super::super::config_write::write(
        &path,
        &config,
        super::super::config_write::CommentLoss::Refuse,
    )
    .expect("write succeeds");
    let text = std::fs::read_to_string(&path).expect("read back");
    assert!(
        !text.contains("http_url"),
        "url was turned back into http_url: {text}"
    );
    assert!(text.contains("url:"), "{text}");
}

#[test]
fn a_line_inside_a_multiline_quoted_value_is_never_renamed() {
    // The second line belongs to the quoted description; renaming it would
    // change the operator's text, so the backend is reported instead.
    let text = "backends:\n  fs:\n    description: \"first line\n    http_url: still the description\"\n    command: x\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert!(out.changed.is_empty());
    assert_eq!(out.skipped, vec!["fs".to_string()]);
}

#[test]
fn a_backend_name_with_spaces_is_rewritten() {
    for name in ["my server", "\"my server\""] {
        let text = format!("backends:\n  {name}:\n    http_url: \"https://a.example.com/mcp\"\n");
        let out = rewrite_url_aliases(&text, None);
        assert!(
            out.text.contains("    url: \"https://a"),
            "{name}: {}",
            out.text
        );
        assert_eq!(out.changed, vec![3], "{name}");
    }
}

#[test]
fn one_unsafe_backend_rolls_back_every_rename_in_the_file() {
    // `fs` really has an `http_url`, written as an explicit `? key` the line
    // scanner cannot see, while a line inside its quoted description looks
    // like the key. Renaming that line fails the parse check, so the whole
    // file is left as it was and both backends are reported.
    let text = "backends:\n  ok:\n    http_url: \"https://ok.example.com/mcp\"\n  fs:\n    description: \"first line\n    http_url: still the description\"\n    ? http_url\n    : \"https://fs.example.test/mcp\"\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert!(out.changed.is_empty());
    assert_eq!(out.skipped, vec!["ok".to_string(), "fs".to_string()]);
}

#[test]
fn an_address_that_is_not_a_literal_of_its_key_keeps_its_alias() {
    // `${FS_URL}` is not an address (backend addresses are never expanded);
    // an `http_url` holding a ws address would change transport if renamed.
    let text = "backends:\n  fs:\n    http_url: \"${FS_URL}\"\n  odd:\n    http_url: \"wss://odd.example.test/mcp\"\n  rt:\n    ws_url: \"wss://rt.example.test/mcp\"\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.changed, vec![7], "{}", out.text);
    assert_eq!(out.kept, vec!["fs".to_string(), "odd".to_string()]);
    assert!(out.text.contains("http_url: \"${FS_URL}\""), "{}", out.text);
}

/// The binary keeps its own copy of the scheme table (the library's is not
/// public); this holds the copy to what the loader actually does.
#[test]
fn the_scheme_table_agrees_with_the_loader() {
    use mcp_gateway::config::{Config, TransportConfig};
    for address in [
        "http://a.example.test/mcp",
        "https://a.example.test/mcp",
        "HTTPS://a.example.test/mcp",
        "ws://a.example.test/mcp",
        "wss://a.example.test/mcp",
        "WSS://a.example.test/mcp",
        "ftp://a.example.test/mcp",
        "a.example.test/mcp",
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(
            &path,
            format!("backends:\n  b:\n    url: \"{address}\"\n"),
        )
        .expect("write config");
        let loaded = Config::load(Some(&path))
            .ok()
            .map(|c| match c.backends["b"].transport {
                TransportConfig::Http { .. } => "http_url",
                TransportConfig::WebSocket { .. } => "ws_url",
                TransportConfig::Stdio { .. } => "another transport",
                #[cfg(feature = "a2a")]
                TransportConfig::A2a { .. } => "another transport",
            });
        assert_eq!(transport_key_for(address), loaded, "{address}");
    }
}

#[test]
fn a_line_that_is_not_a_key_is_skipped_while_another_backend_is_rewritten() {
    // `fs` has no real alias (the line is inside its description), so it is
    // reported for a hand edit; `ok` is still rewritten in the same pass.
    let text = "backends:\n  ok:\n    http_url: \"https://ok.example.test/mcp\"\n  fs:\n    description: \"first line\n    http_url: still the description\"\n    command: x\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.changed, vec![3], "{}", out.text);
    assert_eq!(out.skipped, vec!["fs".to_string()]);
    assert!(out.kept.is_empty());
    assert!(
        out.text.contains("    url: \"https://ok") && out.text.contains("still the description"),
        "{}",
        out.text
    );
}

#[test]
fn a_flow_style_backends_map_is_reported_not_missed() {
    // The whole `backends:` map on one line: the line scan sees no entry,
    // so the parsed file decides which backends hold an older key.
    let text = "backends: {svc: {http_url: \"https://svc.example.test/mcp\"}}\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert!(out.changed.is_empty());
    assert_eq!(out.skipped, vec!["svc".to_string()]);
    assert!(out.kept.is_empty(), "{:?}", out.kept);
}

#[test]
fn a_flow_style_backend_that_is_not_an_address_of_its_scheme_is_kept() {
    // A hand edit to `url` would be refused (`${X}`) or switch transport
    // (a ws address under `http_url`), so neither is sent to a hand edit.
    let text = "backends:\n  fs: { http_url: \"${FS_URL}\" }\n  odd: { http_url: \"wss://odd.example.test/mcp\" }\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert_eq!(out.kept, vec!["fs".to_string(), "odd".to_string()]);
}

#[test]
fn a_flow_style_backend_is_reported_in_a_file_with_a_repeated_key() {
    // The gateway loads a repeated key (the last one wins), so the report
    // reads the file that way too; the edit is still proved strictly.
    let text = "server: {port: 39400}\nserver: {port: 39400}\nbackends:\n  svc: {http_url: 'https://svc.example.test/mcp'}\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert_eq!(out.skipped, vec!["svc".to_string()]);
}

#[test]
fn only_the_named_flow_style_backends_are_reported() {
    let text = "backends:\n  a: { http_url: \"https://a.example.test/mcp\" }\n  b: { http_url: \"${B_URL}\" }\n  c: { http_url: \"https://c.example.test/mcp\" }\n";
    let only: BTreeSet<String> = ["b".to_string(), "c".to_string()].into();
    let out = rewrite_url_aliases(text, Some(&only));
    assert_eq!(out.skipped, vec!["c".to_string()]);
    assert_eq!(out.kept, vec!["b".to_string()]);
}

#[test]
fn a_block_style_rename_in_a_file_with_a_repeated_key_is_rolled_back() {
    // The strict proof cannot read the file, so nothing is written and the
    // backend is named for a hand edit.
    let text = "server: {port: 1}\nserver: {port: 2}\nbackends:\n  fs:\n    http_url: \"https://fs.example.test/mcp\"\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.text, text);
    assert!(out.changed.is_empty(), "{:?}", out.changed);
    assert_eq!(out.skipped, vec!["fs".to_string()]);
}

#[test]
fn a_repeated_alias_is_judged_by_its_last_value() {
    let address = "\"https://fs.example.test/mcp\"";
    let last_address = format!("backends:\n  fs: {{http_url: \"${{X}}\", http_url: {address}}}\n");
    let out = rewrite_url_aliases(&last_address, None);
    assert_eq!(out.skipped, vec!["fs".to_string()], "{:?}", out.kept);
    let last_variable = format!("backends:\n  fs: {{http_url: {address}, http_url: \"${{X}}\"}}\n");
    let out = rewrite_url_aliases(&last_variable, None);
    assert_eq!(out.kept, vec!["fs".to_string()], "{:?}", out.skipped);
}

#[test]
fn a_backend_name_holding_a_colon_is_rewritten() {
    // YAML ends a key at the `:` that a space or the line end follows, and a
    // quoted key at its closing quote, so neither name is cut at its colon.
    let text = "backends:\n  \"team:svc\":\n    http_url: \"https://a.example.test/mcp\"\n  team:ops:\n    ws_url: \"wss://b.example.test/mcp\"\n";
    let out = rewrite_url_aliases(text, None);
    assert_eq!(out.changed, vec![3, 5], "{:?} {:?}", out.skipped, out.kept);
    assert!(out.skipped.is_empty() && out.kept.is_empty(), "{out:?}");
}

#[test]
fn a_mapping_key_is_read_as_yaml_reads_it() {
    let cases: &[(&str, Option<(&str, &str)>)] = &[
        ("  fs:", Some(("fs", ""))),
        ("  'a:b': x", Some(("a:b", "x"))),
        ("  \"a\": {x: 1}", Some(("a", "{x: 1}"))),
        ("  a: b: c", Some(("a", "b: c"))),
        ("  - a: b", None),
        ("  key:value", None),
        ("  \"open: x", None),
        // An escaped quote ends the scan early; the backend is then left to
        // the parsed-file report rather than misread.
        ("  'it''s': x", None),
    ];
    for (line, want) in cases {
        let got = key_of(line);
        let got = got.as_ref().map(|(k, r)| (k.as_str(), *r));
        assert_eq!(got, *want, "{line:?}");
    }
}
