// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8772: a credential span that starts in a JSON key is redacted inside
//! that key, which takes the first free `#n` in its object; the rows check
//! the same oracle as the rest of the MIK-8745 rows.

use super::*;

/// Oracle: whether some credential pattern matches starting at a position
/// in `text[start..end]`. Every position is tried with every pattern anchored
/// there, so no scan window or merged span is involved.
pub(super) fn a_match_starts_in(text: &str, start: usize, end: usize) -> bool {
    static ANCHORED: std::sync::OnceLock<Vec<Regex>> = std::sync::OnceLock::new();
    let anchored = ANCHORED.get_or_init(|| {
        CREDENTIAL_PATTERNS
            .iter()
            .map(|(pattern, _)| Regex::new(&format!(r"\A(?:{pattern})")).expect("compiles"))
            .collect()
    });
    (start..end)
        .filter(|&at| text.is_char_boundary(at))
        .any(|at| anchored.iter().any(|re| re.is_match(&text[at..])))
}

fn parsed(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

#[test]
fn k1_a_dsn_key_keeps_the_count_before_and_after_it() {
    for text in [
        format!(
            r#"{{"items":[{{"{}":{{"pool":10}}}}],"total_count":3}}"#,
            pg_url()
        ),
        format!(
            r#"{{"total_count":3,"items":[{{"{}":{{"pool":10}}}}]}}"#,
            pg_url()
        ),
    ] {
        let out = assert_projected(&text);
        assert_eq!(parsed(&out)["total_count"], 3, "{out}");
        assert!(!out.contains("pw@"), "{out}");
    }
}

#[test]
fn k2_a_redis_node_map_keeps_every_node() {
    let (a, b) = (
        db_url("redis", "u:pw", "10.0.0.1:6379"),
        db_url("redis", "u:pw", "10.0.0.2:6379"),
    );
    let text = format!(r#"{{"{a}":{{"role":"master"}},"{b}":{{"role":"replica"}}}}"#);
    let out = assert_projected(&text);
    let map = parsed(&out);
    let map = map.as_object().expect("object");
    let keys: Vec<&str> = map.keys().map(String::as_str).collect();
    assert_eq!(keys.len(), 2, "{out}");
    assert!(keys.contains(&MARK), "{out}");
    assert!(keys.contains(&format!("{MARK}#2").as_str()), "{out}");
}

#[test]
fn k3_a_value_after_a_dsn_key_stays_hidden() {
    let text = format!(r#"{{"{}":{{"password":"xyz"}}}}"#, pg_url());
    let out = assert_projected(&text);
    assert!(parsed(&out).is_object());
    assert!(!out.contains("xyz"), "{out}");
}

#[test]
fn k4_a_dsn_key_with_an_escaped_quote_in_its_password() {
    let text = format!(
        r#"{{"{}":{{"pool":10}},"n":1}}"#,
        db_url("postgres", r#"u:pa\"ss"#, "db.local:5432/app")
    );
    let out = assert_projected(&text);
    assert_eq!(parsed(&out)["n"], 1, "{out}");
    assert!(!out.contains("ss@"), "{out}");
}

#[test]
fn k5_a_key_span_starting_in_an_escape() {
    for text in [
        format!(r#"{{"\u0030x{}":1,"n":2}}"#, "e".repeat(64)),
        format!(r#"{{"\ud83d\ude00x{}":1,"n":2}}"#, "e".repeat(64)),
    ] {
        let out = assert_projected(&text);
        assert_eq!(out, format!(r#"{{"{MARK}":1,"n":2}}"#));
    }
}

#[test]
fn k6_suffixes_are_per_object_and_skip_taken_names() {
    let key = format!("ghp_{}", "k".repeat(36));
    // Sibling objects each get the plain marker.
    let text = format!(r#"[{{"{key}":1}},{{"{key}":2}}]"#);
    assert_eq!(
        assert_projected(&text),
        format!(r#"[{{"{MARK}":1}},{{"{MARK}":2}}]"#)
    );
    // A clean key already holding the marker, or `#2`, is kept and skipped.
    let text = format!(r#"{{"{MARK}":0,"{MARK}#2":0,"{key}":1}}"#);
    assert_eq!(
        assert_projected(&text),
        format!(r#"{{"{MARK}":0,"{MARK}#2":0,"{MARK}#3":1}}"#)
    );
}

#[test]
fn k7_a_key_past_the_scans_restart_window_is_still_redacted() {
    // A greedy match from the first key runs to the end; the scan restarts
    // only near that end, so it never sees the later keys' own starts.
    let pad = "p".repeat(400);
    let urls: Vec<String> = (1..=3)
        .map(|n| db_url("redis", "u:pw", &format!("10.0.0.{n}:6379")))
        .collect();
    let two = format!(
        r#"{{"{}":{{"role":"master"}},"{}":{{"role":"replica","note":"{pad}"}}}}"#,
        urls[0], urls[1]
    );
    let three = format!(
        r#"{{"{}":{{"n":1}},"{}":{{"n":2}},"{}":{{"n":3,"note":"{pad}"}}}}"#,
        urls[0], urls[1], urls[2]
    );
    for (text, nodes) in [(two, 2), (three, 3)] {
        let out = assert_projected(&text);
        assert!(!out.contains("pw@"), "{out}");
        assert_eq!(parsed(&out).as_object().map(Map::len), Some(nodes), "{out}");
    }
}

#[test]
fn k8_a_suffixed_key_keeps_the_escapes_it_was_sent_with() {
    // `\u0061` splits the token's run, so neither key matches as sent; the
    // clean key decodes to the redacted key's name, so the redacted one takes
    // `#2`. Written decoded, its tail would become a raw 36-char token.
    let head = format!("ghp_{}", "k".repeat(36));
    let tail = format!("ghp_{}\\u0061{}", "a".repeat(18), "a".repeat(17));
    let text = format!(r#"{{"{MARK} {tail}":0,"{head} {tail}":1}}"#);
    let out = assert_projected(&text);
    assert_eq!(out, format!(r#"{{"{MARK} {tail}":0,"{MARK} {tail}#2":1}}"#));
    let decoded: Value = serde_json::from_str(&out).expect("parses");
    assert!(
        decoded
            .as_object()
            .is_some_and(|map| map.keys().all(|key| key.contains(&"a".repeat(36)))),
        "the escape decodes into the token run: {out}"
    );
}

#[test]
fn k9_a_short_dsn_key_that_matches_only_past_its_quote() {
    // `redis://:pw@h/0` is 7 characters after `://`, short of the rule's 10,
    // so it matches only together with the `":{"note…` after it; and its own
    // start sits behind the first key's greedy match, past the restart window.
    let pad = "p".repeat(400);
    let first = db_url("redis", "u:pw", "host:6379");
    let short = db_url("redis", ":pw", "h/0");
    let text = format!(r#"{{"{first}":0,"{short}":{{"note":"{pad}"}}}}"#);
    let out = assert_projected(&text);
    assert!(!out.contains("pw@"), "{out}");
    assert_eq!(parsed(&out).as_object().map(Map::len), Some(2), "{out}");
}

/// The keys P1 places: every family's secret whole and cut short (a cut
/// may still match together with the bytes after the key's quote), plus
/// connection strings of every length below the rule's 10.
fn key_cases() -> Vec<String> {
    let mut keys = Vec::new();
    for (_, secret) in secrets() {
        let len = secret.len();
        for cut in [len, len - 1, len / 2, 6.min(len)] {
            if secret.is_char_boundary(cut) {
                keys.push(secret[..cut].to_owned());
            }
        }
    }
    for n in 1..10 {
        keys.push(format!("redis://{}", "q".repeat(n)));
        keys.push(db_url("postgres", ":pw", &"h".repeat(n)));
    }
    keys
}

/// P1, the MIK-8772 invariant over generated documents: every credential
/// match whose leftmost start lies inside a key redacts that key, and no
/// output key holds the start of one.
#[test]
fn p1_every_key_a_match_starts_in_is_redacted() {
    let greedy = serde_json::to_string(&pg_url()).expect("encodes");
    let mut checked = 0;
    for key in key_cases() {
        let quoted = serde_json::to_string(&key).expect("encodes");
        for lead in [None, Some(&greedy)] {
            for before in [0, 250, 256, 300] {
                for after in [0, 255, 400] {
                    let (b, a) = ("b".repeat(before), "a".repeat(after));
                    let head = lead.map_or(String::new(), |g| format!(r#"{g}:{{"p":"{b}"}},"#));
                    let text = format!(r#"{{{head}{quoted}:{{"v":"{a}"}},"n":3}}"#);
                    let out = assert_projected(&text);
                    assert!(parses(&out), "P1(a) parses: {out}");
                    let (input, output) = (literals(&text), literals(&out));
                    assert_eq!(input.len(), output.len(), "literal count: {out}");
                    for (&(s, e, is_key, _), &(os, oe, _, _)) in input.iter().zip(&output) {
                        if !is_key {
                            continue;
                        }
                        if a_match_starts_in(&text, s, e) {
                            assert!(
                                out[os..oe].contains(MARK),
                                "P1(b) key {:?} kept: {out}",
                                &text[s..e]
                            );
                        }
                        assert!(
                            !a_match_starts_in(&out, os, oe),
                            "P1(c) key {:?} holds a match: {out}",
                            &out[os..oe]
                        );
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 1000, "P1 ran {checked} cases");
}

/// P2, half of the precondition `match_starts_in` rests on: no credential
/// pattern has an anchor or a word boundary, so a cut haystack cannot invent
/// a match. The other half, every shortest match within `OVERLAP_WINDOW`, is
/// the bound that window's doc states for the existing scan.
#[test]
fn p2_no_pattern_has_an_anchor_or_a_word_boundary() {
    for (pattern, name) in CREDENTIAL_PATTERNS {
        let outside_classes = pattern.replace("[^", "[");
        for token in [r"\b", r"\B", r"\A", r"\z", "$"] {
            assert!(!pattern.contains(token), "{name}: {token} in {pattern}");
        }
        assert!(!outside_classes.contains('^'), "{name}: ^ in {pattern}");
    }
}
