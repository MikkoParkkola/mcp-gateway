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
    assert!(
        keys.iter().all(|key| key.contains(tail)),
        "the short tail is not redacted: {once}"
    );
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
    let keys = parsed.as_object().expect("object");
    assert_eq!(keys.len(), 2, "{once}");
    assert!(
        keys.keys().all(|key| key.contains(tail)),
        "the short tail is not redacted: {once}"
    );
}

/// The barrier's inputs, built in code and checked against literal
/// expectations, independent of the oracle that shares the writer.
#[test]
fn i8_the_barrier_holds_only_after_an_open_prefix() {
    let raw_tab = format!("redis://ab{}t", '\\');
    for (out_so_far, want) in [
        ("redis://".to_owned(), true),
        ("REDIS://".to_owned(), true),
        ("Postgres://x".to_owned(), true),
        ("redis:// ".to_owned(), false),
        (format!(r#"{{"p":"{MARK}","#), false),
        (r#"{"redis://":""#.to_owned(), true),
        (raw_tab, true),
        ("no prefix here".to_owned(), false),
        (String::new(), false),
    ] {
        assert_eq!(ends_open(&out_so_far), want, "{out_so_far:?}");
    }
}

/// Only the connection-string rule's class runs through the marker, which
/// is what lets the barrier ignore every other rule. Each rule's sample has
/// the marker inserted at every position; a match crossing it counts.
#[test]
fn i9_only_the_connection_string_rule_runs_through_the_marker() {
    let r = redactor();
    let all = secrets();
    let mut through = Vec::new();
    for (index, (_, description)) in CREDENTIAL_PATTERNS.iter().enumerate() {
        let (_, sample) = all
            .iter()
            .find(|(name, _)| name == description)
            .unwrap_or_else(|| panic!("a sample for {description}"));
        assert!(
            r.regexes[index].is_match(sample),
            "{description}: its sample must match"
        );
        let crosses = (1..sample.len())
            .filter(|&at| sample.is_char_boundary(at))
            .any(|at| {
                let probe = format!("{}{MARK}{}", &sample[..at], &sample[at..]);
                r.regexes[index]
                    .find_iter(&probe)
                    .any(|m| m.start() < at && m.end() > at + MARK.len())
            });
        if crosses {
            through.push(*description);
        }
    }
    assert_eq!(
        through,
        ["Database Connection String"],
        "another rule runs through the marker: extend the barrier's prefix"
    );
}

/// Neither the marker nor the marker behind its barrier space matches any
/// rule, so nothing can start inside it.
#[test]
fn i10_the_marker_matches_no_rule() {
    for text in [MARK.to_owned(), format!(" {MARK}")] {
        assert!(!redactor().set.is_match(&text), "{text:?}");
    }
}

/// Thousands of credentials with no whitespace between them: the run is
/// never reset, so a writer rescanning it would be quadratic.
#[test]
fn i11_many_insertions_in_one_run_stay_linear() {
    let token = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let r = redactor();
    let time = |n: usize| {
        let text = format!("x:{}", vec![token.as_str(); n].join(":"));
        (0..5)
            .map(|_| {
                let mut value = Value::String(text.clone());
                let started = std::time::Instant::now();
                r.scan_and_redact(&mut value);
                started.elapsed()
            })
            .min()
            .expect("five runs")
    };
    let (small, large) = (time(500), time(8_000));
    // Sixteen times the input: about 16x when linear, 256x when quadratic,
    // so a busy runner has a wide margin either way.
    assert!(
        large < small * 64,
        "8000 took {large:?}, 500 took {small:?}"
    );
}

/// The writer's run state, tracked as text arrives, agrees with a full
/// rescan of the output at every split of every pinned input.
#[test]
fn i12_the_tracked_run_agrees_with_a_rescan() {
    let prefix = Regex::new(connection_prefix!()).expect("compiles");
    let rescan = |text: &str| {
        let run = text
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map_or(0, |(at, c)| at + c.len_utf8());
        prefix.is_match(&text[run..])
    };
    let long = format!("{}redis://{}", "x".repeat(60), "\u{e9}".repeat(20));
    for text in [
        "redis://",
        "REDIS:// x",
        "a\u{a0}postgres://",
        "mongodb://\u{b}y",
        r#"{"redis://":""#,
        "\u{e9}\u{e9}mysql://\u{1f600}",
        long.as_str(),
    ] {
        for split in (0..=text.len()).filter(|&at| text.is_char_boundary(at)) {
            let mut out = Spliced::with_capacity(text.len());
            out.push(&text[..split]);
            out.push(&text[split..]);
            assert_eq!(out.barrier(), rescan(text), "{text:?} split at {split}");
        }
    }
}

/// A spaced and an unspaced suffix never collide, so each spelling takes
/// its own first free number (two keys can decode to one name while only
/// one's raw text ends in an open prefix, e.g. an escaped `redis://`).
#[test]
fn i13_each_suffix_spelling_takes_its_first_free_number() {
    let mut names = KeyNames::default();
    assert_eq!(names.claim("k", true), None);
    assert_eq!(names.claim("k", true), Some(2));
    assert_eq!(names.claim("k", false), Some(2));
    assert_eq!(names.claim("k", false), Some(3));
}
