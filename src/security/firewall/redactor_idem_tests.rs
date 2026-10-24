// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8794: redacting twice changes nothing. A redacted span that held
//! whitespace, or was shorter than the marker, was the only thing ending a
//! connection-string run; without it the marker carried the run past the
//! rule's ten-character floor and a second pass redacted again.

use super::*;

/// The schemes of the connection-string rule, the one pattern whose class
/// runs through the marker.
const SCHEMES: [&str; 4] = ["redis", "postgres", "mysql", "mongodb"];

/// "Bearer", a separator, and a 20-character token of `fill`, built at run
/// time so no credential literal sits in source.
fn bearer_with(separator: &str, fill: &str) -> String {
    format!("{}{separator}{}", "Bearer", fill.repeat(20))
}

fn bearer() -> String {
    bearer_with(" ", "t")
}

/// `text` delivered once and twice; the second must equal the first, and
/// the first must still hide the token.
fn assert_stable(text: &str, token: &str) -> String {
    let (once, _) = deliver(text);
    let (twice, _) = deliver(&once);
    assert_eq!(twice, once, "a second pass changed the first's {once:?}");
    assert!(
        !once.contains(token),
        "pass 1 still hides the token: {once}"
    );
    once
}

#[test]
fn i1_each_scheme_in_text_a_key_and_an_array_value_is_stable() {
    let bearer = bearer();
    let token = "t".repeat(20);
    for scheme in SCHEMES {
        for text in [
            format!("{scheme}://{bearer}"),
            format!(r#"{{"{scheme}://":"{bearer}"}}"#),
            // An array, not an object: `","b":"Bearer` is already ten
            // characters, so pass 1 would match there and redact both.
            format!(r#"["{scheme}://","{bearer}"]"#),
        ] {
            assert_stable(&text, &token);
        }
    }
}

#[test]
fn i2_a_header_line_is_byte_identical_to_today() {
    // A space already precedes the span, so no barrier is written.
    let text = format!("Authorization: {}", bearer());
    let once = assert_stable(&text, &"t".repeat(20));
    assert_eq!(once, format!("Authorization: {MARK}"));
}

#[test]
fn i3_nbsp_and_vt_separators_are_stable() {
    for separator in ["\u{a0}", "\u{b}"] {
        let text = format!("redis://{}", bearer_with(separator, "t"));
        assert_stable(&text, &"t".repeat(20));
    }
}

#[test]
fn i4_a_key_after_a_prefix_value_is_stable() {
    let text = format!(r#"{{"a":"redis://","{}":1}}"#, bearer());
    assert_stable(&text, &"t".repeat(20));
}

#[test]
fn i5_a_short_value_after_a_prefix_key_is_stable() {
    // No whitespace anywhere: the DSN span ends in the value "x", which is
    // shorter than the marker that replaces it.
    let text = r#"{"p":"postgres://abcdefghij","redis://":"x"}"#;
    let (once, _) = deliver(text);
    let (twice, _) = deliver(&once);
    assert_eq!(twice, once, "a second pass changed {once:?}");
    assert!(!once.contains("abcdefghij"), "{once}");
}

#[test]
fn i6_a_parsed_collision_suffix_does_not_lengthen_the_run() {
    // Two keys that differ only in their token, with an 8-character tail:
    // below the floor on pass 1, at it once `#2` is appended.
    let tail = " redis://abcdefgh";
    let mut value = json!({
        format!("{}{tail}", bearer_with(" ", "t")): 1,
        format!("{}{tail}", bearer_with(" ", "u")): 2,
    });
    redactor().scan_and_redact(&mut value);
    let once = value.clone();
    redactor().scan_and_redact(&mut value);
    assert_eq!(value, once, "a second pass renamed a key of {once}");
    let keys: Vec<&String> = once.as_object().expect("object").keys().collect();
    assert_eq!(keys.len(), 2, "no entry is lost: {once}");
}

#[test]
fn i7_a_json_text_collision_suffix_does_not_lengthen_the_run() {
    // On JSON text the raw run continues with `":`, so the tail is two
    // characters shorter than the parsed row's; pretty-printed, a space
    // follows the colon and ends the run.
    let tail = " redis://abcdef";
    let text = format!(
        "{{\"{}{tail}\": 1, \"{}{tail}\": 2}}",
        bearer_with(" ", "t"),
        bearer_with(" ", "u")
    );
    let once = assert_stable(&text, &"t".repeat(20));
    assert!(!once.contains(&"u".repeat(20)), "{once}");
    let parsed: Value = serde_json::from_str(&once).expect("still parses");
    assert_eq!(parsed.as_object().expect("object").len(), 2, "{once}");
}
