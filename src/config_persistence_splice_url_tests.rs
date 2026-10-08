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
