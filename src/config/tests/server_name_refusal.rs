// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Server names that loading refuses: one holding a control character, which could start a forged line wherever the
//! name is printed, and `.` or `..`, which no address can reach. A name with a space or a non-ASCII letter still
//! loads. The same rules hold for `capabilities.name`, which shares the backend name space.

use super::*;
use crate::gateway::test_helpers::write_owner_only;

/// A character a refusal message must not carry raw: any the log's own escaper rewrites (controls, separators, bidi).
fn the_log_escapes(c: char) -> bool {
    crate::log_escape::escaped(&c.to_string()) != c.to_string()
}

fn with_backend(name: &str) -> Config {
    let mut config = Config::default();
    config
        .backends
        .insert(name.to_owned(), BackendConfig::default());
    config
}

fn refusal(config: &Config) -> String {
    match config.validate() {
        Err(crate::Error::ConfigValidation(message)) => message,
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

/// NAME.1: a line feed, DEL and a C1 control in a backend name are each refused, and the message that names the
/// server carries none of them raw.
#[test]
fn a_backend_name_with_a_control_character_is_refused_and_named_escaped() {
    for control in ['\n', '\u{7f}', '\u{85}'] {
        let name = format!("ok{control}FORGED x");
        let message = refusal(&with_backend(&name));
        assert!(
            message.contains("control character"),
            "{control:?}: the refusal should say why: {message:?}"
        );
        assert!(
            !message.chars().any(the_log_escapes),
            "{control:?}: the refusal carries a raw line-breaking character: {message:?}"
        );
        assert!(
            message.contains("FORGED x"),
            "{control:?}: the refusal should still name the server: {message:?}"
        );
    }
}

/// NAME.1, the older message: a name refused for a slash that also holds a line separator is named escaped too.
#[test]
fn the_invalid_character_refusal_names_the_server_escaped() {
    let message = refusal(&with_backend("a/\u{2028}FORGED"));
    assert!(message.contains("invalid character"), "{message:?}");
    assert!(
        !message.chars().any(the_log_escapes),
        "the refusal carries a raw line separator: {message:?}"
    );
}

/// NAME.1 for `capabilities.name`: it is a server name too.
#[test]
fn a_capabilities_name_with_a_control_character_is_refused() {
    let mut config = Config::default();
    config.capabilities.name = "caps\nFORGED".to_owned();
    let message = refusal(&config);
    assert!(message.contains("control character"), "{message:?}");
    assert!(!message.chars().any(the_log_escapes), "{message:?}");
}

/// NAME.2: `.` and `..` load today, and no address can reach them.
#[test]
fn the_names_dot_and_dot_dot_are_refused_as_unreachable() {
    for name in [".", ".."] {
        let message = refusal(&with_backend(name));
        assert!(
            message.contains("no address can name"),
            "{name:?}: the refusal should say why: {message:?}"
        );
    }
    let mut config = Config::default();
    config.capabilities.name = ".".to_owned();
    let message = refusal(&config);
    assert!(message.contains("no address can name"), "{message:?}");
}

/// NAME.2 on the routes that add a server: their name check refuses `.` and `..` itself, with the load's sentence,
/// so the add and preview routes answer 422 before any write instead of a failed write's 500.
#[test]
fn the_add_check_refuses_dot_names_in_the_load_s_words() {
    for name in [".", ".."] {
        let Err(why) = crate::config::backend_add::validate_backend_name(name) else {
            panic!("{name:?} passes the add check");
        };
        assert!(why.contains("no address can name"), "{name:?}: {why:?}");
    }
    assert!(crate::config::backend_add::validate_backend_name("server.prod").is_ok());
}

/// NAME.3: no new refusal for a sane install.
#[test]
fn a_name_with_a_space_or_a_non_ascii_letter_still_loads() {
    for name in ["my server", "päivä"] {
        let mut config = with_backend(name);
        // A complete backend, so only its name is judged: the default one has an empty URL, refused for that alone.
        let Some(BackendConfig {
            transport: TransportConfig::Http { http_url, .. },
            ..
        }) = config.backends.get_mut(name)
        else {
            panic!("the default backend is no longer an HTTP one");
        };
        *http_url = "http://127.0.0.1:1/mcp".to_owned();
        assert!(
            config.validate().is_ok(),
            "{name:?} is refused: {:?}",
            config.validate()
        );
    }
}

/// The precondition the stdio rows rest on: a load error can quote gateway.yaml text raw. An extra key under a
/// section that refuses extra keys comes back in serde's message as written, line feed included. If this ever
/// fails, the stdio rows no longer feed the printer a hostile byte and must be redesigned.
#[test]
fn a_load_error_quotes_an_extra_key_with_its_line_feed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, "idempotency:\n  \"x\\nFORGED y\": 1\n").expect("write config");
    let Err(error) = Config::load(Some(&path)) else {
        panic!("an extra key under idempotency: must not load");
    };
    let text = error.to_string();
    assert!(
        text.contains("x\nFORGED y"),
        "the load error no longer quotes the key raw: {text:?}"
    );
}

/// The check the refusal rows use flags every kind of character the log escapes, and leaves plain text alone.
#[test]
fn the_check_flags_what_the_log_escapes_and_nothing_else() {
    for c in ['\n', '\u{7f}', '\u{85}', '\u{2028}', '\u{202e}'] {
        assert!(the_log_escapes(c), "{c:?} should be flagged");
    }
    for c in ['a', ' ', 'ä', '/'] {
        assert!(!the_log_escapes(c), "{c:?} should not be flagged");
    }
}

/// The collision refusal quotes the name escaped too, for a name that passes the name rule but holds a line
/// separator or a bidi mark.
#[test]
fn the_collision_refusal_names_the_server_escaped() {
    for odd in ['\u{2028}', '\u{202e}'] {
        let name = format!("caps{odd}x");
        let mut config = with_backend(&name);
        config.capabilities.name = name.clone();
        let message = refusal(&config);
        assert!(message.contains("is also backends"), "{odd:?}: {message:?}");
        assert!(
            !message.chars().any(the_log_escapes),
            "{odd:?}: the collision refusal carries it raw: {message:?}"
        );
    }
}
