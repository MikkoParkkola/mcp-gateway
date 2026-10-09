// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Splicing into a file whose backends spell their address `url`.

use super::with_backend_edited;
use crate::config::Config;

/// A file `init` wrote spells each address `url`; adding a backend beside
/// those entries is still a text edit that keeps the comments.
#[test]
fn a_backend_is_added_beside_entries_spelled_url() {
    let original = "# mine\nbackends:\n  a:\n    url: \"https://a.example.test/mcp\"\n";
    let before = Config::from_file_text(original).expect("before loads");
    let config = Config::from_file_text(
        "backends:\n  a:\n    url: \"https://a.example.test/mcp\"\n  b:\n    command: b\n",
    )
    .expect("config loads");
    let text = with_backend_edited(original, &before, &config, "b").expect("spliced");
    assert!(
        text.starts_with("# mine\n") && text.contains("    url: \"https://a"),
        "{text}"
    );
}

/// Editing a backend whose file entry says `url` edits `url`; writing
/// `http_url` beside it would be refused by the loader.
#[test]
fn a_backend_spelled_url_is_edited_in_its_own_spelling() {
    let original = "backends:\n  svc:  # mine\n    url: \"https://a.example.test/mcp\"\n";
    let before = Config::from_file_text(original).expect("before loads");
    let config =
        Config::from_file_text("backends:\n  svc:\n    url: \"https://b.example.test/mcp\"\n")
            .expect("config loads");
    let text = with_backend_edited(original, &before, &config, "svc").expect("spliced");
    assert!(text.contains("# mine"), "{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with("    url: ") && l.contains("https://b.example.test/mcp")),
        "{text}"
    );
    assert!(!text.contains("http_url"), "{text}");
}

/// The edit `before` -> `after` on a commented entry spelled `url`.
fn switched(after: &str) -> String {
    let original = "backends:\n  svc:  # mine\n    url: \"https://a.example.test/mcp\"\n";
    let before = Config::from_file_text(original).expect("before loads");
    let config = Config::from_file_text(after).expect("config loads");
    with_backend_edited(original, &before, &config, "svc").expect("spliced")
}

#[test]
fn switching_a_url_backend_to_websocket_keeps_one_url_key() {
    let text = switched("backends:\n  svc:\n    url: \"wss://b.example.test/mcp\"\n");
    assert!(text.contains("# mine"), "{text}");
    assert!(text.contains("wss://b.example.test/mcp"), "{text}");
    assert!(
        !text.contains("http_url") && !text.contains("ws_url"),
        "{text}"
    );
    assert_eq!(text.matches("url:").count(), 1, "{text}");
}

#[test]
fn switching_a_url_backend_to_a_command_drops_the_url() {
    let text = switched("backends:\n  svc:\n    command: srv\n");
    assert!(
        text.contains("# mine") && text.contains("command: srv"),
        "{text}"
    );
    assert!(!text.contains("url"), "{text}");
}

/// A backend a write adds is spelled `url`, whatever transport it is.
#[test]
fn a_new_backend_is_spliced_in_as_url() {
    let original = "backends:\n  a:  # mine\n    command: a\n";
    let before = Config::from_file_text(original).expect("before loads");
    for (address, key) in [
        ("https://b.example.test/mcp", "http_url"),
        ("wss://b.example.test/mcp", "ws_url"),
    ] {
        let config = Config::from_file_text(&format!(
            "backends:\n  a:\n    command: a\n  b:\n    {key}: \"{address}\"\n"
        ))
        .expect("config loads");
        let text = with_backend_edited(original, &before, &config, "b").expect("spliced");
        assert!(text.contains("# mine") && text.contains(address), "{text}");
        assert!(text.contains("    url: ") && !text.contains(key), "{text}");
    }
}

/// An `http_url` holding a ws address keeps its alias: as `url` it would
/// switch the backend to the WebSocket transport.
#[test]
fn a_new_backend_whose_address_is_of_the_other_scheme_keeps_its_alias() {
    let original = "backends:\n  a:  # mine\n    command: a\n";
    let before = Config::from_file_text(original).expect("before loads");
    let config = Config::from_file_text(
        "backends:\n  a:\n    command: a\n  b:\n    http_url: \"wss://b.example.test/mcp\"\n",
    )
    .expect("config loads");
    let text = with_backend_edited(original, &before, &config, "b").expect("spliced");
    assert!(
        text.contains("http_url: ") && !text.contains("    url: "),
        "{text}"
    );
    assert!(Config::from_file_text(&text).is_ok(), "{text}");
}

/// A file the splice cannot edit (flow style) is rewritten in full; the
/// rewrite keeps `url` where the file had it and uses it for a new backend.
#[test]
fn a_full_rewrite_keeps_url_and_uses_it_for_a_new_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        "backends: {a: {url: \"https://a.example.test/mcp\"}}\n",
    )
    .expect("write");
    let config = Config::from_file_text(
        "backends:\n  a:\n    url: \"https://a.example.test/mcp\"\n  b:\n    http_url: \"https://b.example.test/mcp\"\n",
    )
    .expect("config loads");
    crate::config_persistence::edit_config(
        &path,
        crate::config_persistence::CommentLoss::Refuse,
        |c| {
            *c = config.clone();
            Ok(())
        },
    )
    .map(drop)
    .expect("written");
    let text = std::fs::read_to_string(&path).expect("read");
    assert_eq!(text.matches("url: ").count(), 2, "{text}");
    assert!(!text.contains("http_url"), "{text}");
}

/// A full rewrite that adds no backend leaves every alias as it was, and the
/// file it writes passes the gateway's own load.
#[test]
fn a_full_rewrite_that_adds_nothing_keeps_the_aliases() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let flow = "backends: {a: {http_url: \"https://a.example.test/mcp\"}, b: {ws_url: \"wss://b.example.test/mcp\"}}\n";
    crate::gateway::test_helpers::write_owner_only(&path, flow).expect("write");
    let mut config = Config::from_file_text(flow).expect("config loads");
    config.backends.get_mut("a").expect("a").description = "edited".into();
    crate::config_persistence::edit_config(
        &path,
        crate::config_persistence::CommentLoss::Refuse,
        |c| {
            *c = config.clone();
            Ok(())
        },
    )
    .map(drop)
    .expect("written");
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(
        text.contains("http_url: ") && text.contains("ws_url: "),
        "{text}"
    );
    assert!(!text.contains("    url: "), "{text}");
    assert!(Config::load(Some(&path)).is_ok(), "{text}");
}
