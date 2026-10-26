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
    for n in 0..10 {
        keys.push(format!("redis://{}", "q".repeat(n)));
        keys.push(db_url("postgres", ":pw", &"h".repeat(n)));
        // Multibyte characters: the rule counts characters, not bytes.
        keys.push(format!("redis://{}", "\u{e9}".repeat(n)));
        // Four-byte characters, so the cut can land inside one.
        keys.push(format!("redis://{}", "\u{1f600}".repeat(n)));
    }
    // An API-key body far longer than any window: the match ends on the
    // key's own quote, so the tail bound holds at that start too.
    keys.push(format!("{}='{}", "api_key", "A".repeat(300)));
    // One under each rule's minimum, so only bytes after the key can complete it.
    let b64 = "A".repeat(19);
    keys.extend([
        format!("AKIA{}", "Z".repeat(15)),
        format!("ghp_{}", "a".repeat(35)),
        format!("xoxb-{}", "1".repeat(9)),
        format!("{}='{b64}", "api_key"),
        format!("{}='{b64}A", "api_key"),
        format!("eyJ{0}.eyJ{0}.{1}", "x".repeat(12), "x".repeat(9)),
        format!("{} {}", "Bearer", "t".repeat(19)),
        format!("sk-proj-{}", "p".repeat(39)),
        format!("0x{}", "e".repeat(63)),
    ]);
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
            for before in [0, 250, 255, 256, 257, 300] {
                for after in [0, 63, 64, 65, 255, 400] {
                    // At 64 the value is four-byte characters, so the cut
                    // past the key lands inside one and must back up.
                    let a = if after == 64 {
                        "\u{1f600}".repeat(16)
                    } else {
                        "a".repeat(after)
                    };
                    let b = "b".repeat(before);
                    let head = lead.map_or(String::new(), |g| format!(r#"{g}:{{"p":"{b}"}},"#));
                    let compact = format!(r#"{{{head}{quoted}:{{"v":"{a}"}},"n":3}}"#);
                    // Every fourth case also as `wrap_tool_success` prints it.
                    let pretty = checked % 4 == 0;
                    let text = if pretty {
                        let value: Value = serde_json::from_str(&compact).expect("valid");
                        serde_json::to_string_pretty(&value).expect("prints")
                    } else {
                        compact
                    };
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
    assert!(checked > 5000, "P1 ran {checked} cases");
}

/// P2, the precondition `match_starts_in` rests on, pinned two ways. A scan
/// of each pattern: no anchor or word boundary, and only the API-key and
/// connection-string rules can match a `"`. And the full pattern text, as
/// reviewed for `KEY_MATCH_TAIL`: a class like `\W`, `\S` or `[!-#]` can
/// match a quote without the scan seeing it, so any change to a pattern
/// fails here and reopens that argument.
#[test]
fn p2_the_patterns_are_the_reviewed_ones() {
    let reviewed = [
        r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"gho_[A-Za-z0-9]{36}",
        r"ghs_[A-Za-z0-9]{36}",
        r"ghr_[A-Za-z0-9]{36}",
        r"xox[bprs]-[A-Za-z0-9-]{10,}",
        r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9+/=]{20,}['"]"#,
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})+",
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}",
        r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]{10,}",
        r"sk-proj-[A-Za-z0-9_-]{40,}",
        r"0x[a-fA-F0-9]{64}",
    ];
    let live: Vec<&str> = CREDENTIAL_PATTERNS.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        live, reviewed,
        "a pattern changed: recheck KEY_MATCH_TAIL's bound, and MIK-8794's barrier \
         (only the connection-string class may run through the marker)"
    );
    let mut crossers = Vec::new();
    for (pattern, name) in CREDENTIAL_PATTERNS {
        for token in [r"\b", r"\B", r"\A", r"\z", "$"] {
            assert!(!pattern.contains(token), "{name}: {token} in {pattern}");
        }
        let (mut class, mut escaped, mut can_cross) = (false, false, pattern.contains('"'));
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '[' if !class => {
                    class = true;
                    can_cross |= chars.peek() == Some(&'^');
                }
                ']' if class => class = false,
                '^' if !class => panic!("{name}: ^ outside a class in {pattern}"),
                '.' if !class => can_cross = true,
                _ => {}
            }
        }
        if can_cross {
            crossers.push(*name);
        }
    }
    assert_eq!(
        crossers,
        ["Generic API Key in key=value", "Database Connection String"],
        "a pattern that can match a quote needs its bound in KEY_MATCH_TAIL"
    );
}

/// F2: an object near the size cap whose first key starts a greedy match
/// over every later key, so each one runs the key check, against base's
/// whole-leaf path. Timing, so run by hand on Spark:
/// `cargo test --lib -- --ignored f2_many_overlapped_keys_cost --nocapture`.
///
/// The bar is 8x, not F1's 3x (lead ruling 2026-10-24). This is the worst
/// case: every one of about 96,000 keys runs the check. Measured on Spark
/// (release, 2026-10-24): 5.72x, about 66 ms against 11.6 ms for the
/// whole-leaf path, and the 1 MiB cap bounds it at that. A prefilter that
/// skips keys no pattern can start in is planned for 4.0.1 (MIK-8822).
#[test]
#[ignore = "timing; run by hand"]
fn f2_many_overlapped_keys_cost() {
    use std::fmt::Write as _;
    let mut text = format!(r#"{{"{}":0"#, pg_url());
    let mut i = 0_usize;
    while text.len() < CAP - 200 {
        write!(text, r#","k{i}":0"#).unwrap();
        i += 1;
    }
    text.push('}');
    // One redactor built and warmed before timing, as production reuses one;
    // the median of five samples of each path.
    let r = redactor();
    // Built once, so the clock times the redaction, not building the leaf.
    let proto = json!({ "content": [{ "type": "text", "text": text }] });
    let leaf = || proto.clone();
    let mut warm = leaf();
    r.scan_and_redact(&mut warm);
    let median = |f: &dyn Fn()| {
        let mut runs: Vec<_> = (0..5)
            .map(|_| {
                let started = std::time::Instant::now();
                f();
                started.elapsed()
            })
            .collect();
        runs.sort();
        runs[2]
    };
    let projected = median(&|| {
        let mut value = leaf();
        r.scan_and_redact(&mut value);
    });
    let base = median(&|| {
        let _ = splice(&text, &r.credential_spans(&text));
    });
    let mut value = leaf();
    r.scan_and_redact(&mut value);
    let out = value["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    assert!(
        parses(&out) && out != today(&text),
        "many keys: the projection must have run"
    );
    let ratio = projected.as_secs_f64() / base.as_secs_f64();
    println!(
        "{i} overlapped keys: projection {projected:?}, whole leaf {base:?}, ratio {ratio:.2}"
    );
    assert!(
        ratio < 8.0,
        "many keys: ratio {ratio:.2} over the 8x worst-case bar"
    );
}

/// The redaction marker holds no whitespace, so redacting a span that did
/// (`Bearer` and its token) could join the text around it into a new match,
/// and a second pass changed the first pass's output; production re-scans
/// the same bytes on a dead-letter event replay. MIK-8794's barrier ends the
/// run at the marker, so a second pass now changes nothing.
#[test]
fn g1_a_second_pass_changes_these_no_more_mik_8794() {
    let bearer = format!("{} {}", "Bearer", "t".repeat(20));
    let rows = [
        format!("redis://{bearer}"),
        format!(r#"{{"redis://":"{bearer}"}}"#),
        // An array, not an object: `","b":"Bearer` would already be ten
        // characters, so the first pass would match there and redact both.
        format!(r#"["redis://","{bearer}"]"#),
    ];
    for text in rows {
        let (once, _) = deliver(&text);
        let (twice, _) = deliver(&once);
        assert_eq!(twice, once, "a second pass changed {once:?}");
        assert!(
            !once.contains(&"t".repeat(20)),
            "pass 1 still hides the token: {once}"
        );
    }
}

/// The key's match window ends 64 bytes past it, inside a run of "é"; one of
/// the two pads puts that end mid-char, and the key is projected either way.
#[test]
fn k8_the_key_match_window_never_splits_a_multibyte_char() {
    let key = format!("ghp_{}", "k".repeat(36));
    let tail = "é".repeat(60);
    for pad in ["", "x"] {
        let text = format!(r#"{{"{key}":"{pad}{tail}"}}"#);
        assert_eq!(
            assert_projected(&text),
            format!(r#"{{"{MARK}":"{pad}{tail}"}}"#)
        );
    }
}
