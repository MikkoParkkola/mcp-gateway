// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8745: a credential span inside JSON-in-text is redacted inside the
//! string values it overlaps, and the JSON around them stays as sent.
//!
//! The expected output of every row comes from [`expected`], an oracle
//! written apart from the product walk: its own literal scan, its own escape
//! widening. It encodes the rule of the MIK-8745 design: today's spans
//! (`credential_spans` over the raw leaf), projected onto every value
//! literal they overlap; keys, quotes, punctuation, numbers and keywords are
//! kept; a span that starts in a key sends the leaf down today's path.

use super::*;
use serde_json::json;

const MARK: &str = "[REDACTED:credential]";
/// The design's `B2_MAX_LEAF_BYTES`.
const CAP: usize = 1 << 20;

fn redactor() -> Redactor {
    Redactor::new()
}

/// A connection string built from parts, so no literal one sits in source.
fn db_url(scheme: &str, userinfo: &str, rest: &str) -> String {
    format!("{scheme}://{userinfo}@{rest}")
}

fn pg_url() -> String {
    db_url(
        "postgres",
        &format!("{}:{}", "u", "pw"),
        "db.local:5432/app",
    )
}

/// Deliver `text` as a tool answer's text block; return the delivered text
/// and the finding descriptions, sorted.
fn deliver(text: &str) -> (String, Vec<String>) {
    let mut value = json!({ "content": [{ "type": "text", "text": text }] });
    let findings = redactor().scan_and_redact(&mut value);
    let out = value["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    let mut descriptions: Vec<String> = findings.into_iter().map(|f| f.description).collect();
    descriptions.sort();
    (out, descriptions)
}

/// The base behaviour: every merged span over the whole leaf replaced.
fn today(text: &str) -> String {
    splice(text, &redactor().credential_spans(text))
}

fn splice(text: &str, ranges: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for &(start, end) in ranges {
        out.push_str(&text[cursor..start]);
        out.push_str(MARK);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// The finding descriptions base records for `text`: one per matched pattern.
fn base_findings(text: &str) -> Vec<String> {
    let r = redactor();
    let mut out: Vec<String> = r
        .set
        .matches(text)
        .into_iter()
        .map(|i| format!("Credential detected: {}", r.descriptions[i]))
        .collect();
    out.sort();
    out
}

/// Oracle: each string literal's content range (quotes excluded) in valid
/// JSON text, and whether it is an object key.
fn literals(text: &str) -> Vec<(usize, usize, bool)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let is_key = text[j + 1..].trim_start().starts_with(':');
            out.push((start, j, is_key));
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Oracle: the escape sequences in `text[start..end]`, as byte ranges.
fn escapes(text: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut k = start;
    while k < end {
        if b[k] != b'\\' {
            k += 1;
            continue;
        }
        let mut len = if b[k + 1] == b'u' { 6 } else { 2 };
        if len == 6 {
            let high = u32::from_str_radix(&text[k + 2..k + 6], 16).unwrap_or(0);
            let paired = (0xD800..=0xDBFF).contains(&high)
                && text.get(k + 6..k + 8) == Some("\\u")
                && u32::from_str_radix(&text[k + 8..k + 12], 16)
                    .is_ok_and(|low| (0xDC00..=0xDFFF).contains(&low));
            if paired {
                len = 12;
            }
        }
        out.push((k, k + len));
        k += len;
    }
    out
}

/// Oracle: what the design says the leaf `text` is delivered as.
fn expected(text: &str) -> String {
    let spans = redactor().credential_spans(text);
    let trimmed = text.trim_start();
    let gated = !spans.is_empty()
        && text.len() <= CAP
        && matches!(trimmed.as_bytes().first(), Some(b'{' | b'[' | b'"'))
        && serde_json::from_str::<Value>(text)
            .is_ok_and(|v| v.is_object() || v.is_array() || v.is_string());
    if !gated {
        return today(text);
    }
    let lits = literals(text);
    let in_key = |at: usize| {
        lits.iter()
            .any(|&(start, end, key)| key && start <= at && at < end)
    };
    if spans.iter().any(|&(start, _)| in_key(start)) {
        return today(text);
    }
    let mut ranges = Vec::new();
    for &(lit_start, lit_end, key) in &lits {
        if key {
            continue;
        }
        let escs = escapes(text, lit_start, lit_end);
        for &(span_start, span_end) in &spans {
            let (mut from, mut to) = (span_start.max(lit_start), span_end.min(lit_end));
            if from >= to {
                continue;
            }
            for &(esc_start, esc_end) in &escs {
                if esc_start < from && from < esc_end {
                    from = esc_start;
                }
                if esc_start < to && to < esc_end {
                    to = esc_end;
                }
            }
            ranges.push((from, to));
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (from, to) in ranges {
        match merged.last_mut() {
            Some(last) if from <= last.1 => last.1 = last.1.max(to),
            _ => merged.push((from, to)),
        }
    }
    splice(text, &merged)
}

/// Every row: delivered as the oracle says, findings as base records, and a
/// second pass changes nothing.
fn assert_projected(text: &str) -> String {
    let (out, findings) = deliver(text);
    assert_eq!(out, expected(text), "delivered text for {text:?}");
    assert_eq!(findings, base_findings(text), "findings for {text:?}");
    let (again, refound) = deliver(&out);
    assert_eq!(again, out, "second pass changed {out:?}");
    assert!(
        refound.is_empty(),
        "second pass found {refound:?} in {out:?}"
    );
    out
}

fn parses(text: &str) -> bool {
    serde_json::from_str::<Value>(text).is_ok()
}

// ── A: acceptance ─────────────────────────────────────────────────────────

#[test]
fn a1_compact_json_in_text_keeps_its_structure() {
    let text = json!({ "dsn": pg_url(), "rows": 3 }).to_string();
    let out = assert_projected(&text);
    assert_eq!(out, format!(r#"{{"dsn":"{MARK}","rows":3}}"#));
    assert_eq!(
        base_findings(&text),
        ["Credential detected: Database Connection String"]
    );
}

#[test]
fn a2_pretty_wrapper_stays_its_own_printing() {
    let text = serde_json::to_string_pretty(&json!({ "dsn": pg_url(), "rows": 3 })).unwrap();
    let out = assert_projected(&text);
    let parsed: Value = serde_json::from_str(&out).expect("parses");
    assert_eq!(parsed, json!({ "dsn": MARK, "rows": 3 }));
    assert_eq!(out, serde_json::to_string_pretty(&parsed).unwrap());
}

/// One secret per rule in `CREDENTIAL_PATTERNS`, built from parts.
fn secrets() -> Vec<(&'static str, String)> {
    let b64 = "A".repeat(24);
    vec![
        (
            "AWS Access Key ID",
            format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE"),
        ),
        (
            "GitHub Personal Access Token",
            format!("ghp_{}", "a".repeat(36)),
        ),
        ("GitHub OAuth Token", format!("gho_{}", "b".repeat(36))),
        ("GitHub App Token", format!("ghs_{}", "c".repeat(36))),
        ("GitHub Refresh Token", format!("ghr_{}", "d".repeat(36))),
        ("Slack Token", format!("xoxb-{}", "1".repeat(12))),
        (
            "Generic API Key in key=value",
            format!("{}='{b64}'", "api_key"),
        ),
        (
            "JSON Web Token",
            format!("eyJ{0}.eyJ{0}.{0}", "x".repeat(12)),
        ),
        (
            "Private Key",
            format!("-----BEGIN {}PRIVATE KEY-----", "RSA "),
        ),
        ("Bearer Token", format!("{} {}", "Bearer", "t".repeat(24))),
        ("Database Connection String", pg_url()),
        (
            "OpenAI Project API Key",
            format!("sk-proj-{}", "p".repeat(40)),
        ),
        ("Ethereum Private Key", format!("0x{}", "e".repeat(64))),
    ]
}

#[test]
fn a3_family_table_every_rule_in_three_carriers() {
    for (rule, secret) in secrets() {
        // (a) prose: exactly base.
        let prose = format!("note {secret} end");
        let (out, findings) = deliver(&prose);
        assert_eq!(out, today(&prose), "{rule} prose");
        assert_eq!(findings, base_findings(&prose), "{rule} prose findings");
        // (b) compact JSON in a string.
        let compact = json!({ "s": secret, "n": 1, "t": "tail" }).to_string();
        let out = assert_projected(&compact);
        assert!(parses(&out), "{rule} compact: {out}");
        assert!(!out.contains(&secret), "{rule} compact kept the secret");
        // (c) a root JSON string whose content is compact JSON.
        let root = serde_json::to_string(&compact).unwrap();
        let out = assert_projected(&root);
        assert!(parses(&out), "{rule} root string: {out}");
        assert!(!out.contains(&secret), "{rule} root string kept the secret");
    }
}

// ── B: nothing hidden today becomes visible, and the JSON stays valid ─────

#[test]
fn b1_a_value_the_greedy_span_covers_stays_hidden() {
    let url = db_url("postgres", "u", "h");
    // Built by hand: `json!` sorts keys and would put the URL last.
    let text = format!(r#"{{"url":"{url}","password":"xyz"}}"#);
    let out = assert_projected(&text);
    assert_eq!(out, format!(r#"{{"url":"{MARK}","password":"{MARK}"}}"#));
}

#[test]
fn b2_url_then_api_key_assignment_in_one_literal() {
    let text = format!(
        r#"{{"s":"{} {}='{}'"}}"#,
        db_url("redis", "u:pw", "host/db"),
        "api_key",
        "A".repeat(20)
    );
    let out = assert_projected(&text);
    assert!(parses(&out), "{out}");
    assert!(!out.contains(&"A".repeat(20)), "{out}");
}

#[test]
fn b3_url_with_an_escaped_space_in_its_userinfo() {
    let text = format!(r#"{{"s":"{}://u:pw\u0020SECRET@host/db"}}"#, "redis");
    let out = assert_projected(&text);
    assert!(parses(&out), "{out}");
    assert!(!out.contains("SECRET@host"), "{out}");
}

#[test]
fn b4_api_key_ending_on_the_strings_own_quote() {
    let text = format!(r#"{{"s":"{}='{}"}}"#, "api_key", "a".repeat(20));
    let out = assert_projected(&text);
    assert_eq!(out, format!(r#"{{"s":"{MARK}"}}"#));
}

#[test]
fn b5_span_starting_in_an_escapes_hex_digits() {
    // `\u0030` decodes to `0`; the raw text holds `0x…` from its last digit.
    let text = format!(r#"{{"s":"\u0030x{}"}}"#, "e".repeat(64));
    let out = assert_projected(&text);
    assert!(parses(&out), "{out}");
    assert!(
        !out.contains("\\u00"),
        "the escape must be replaced whole: {out}"
    );
}

#[test]
fn b6_surrogate_pair_inside_a_span_is_replaced_whole() {
    let text = format!(
        r#"{{"s":"{}/\ud83d\ude00x","n":1}}"#,
        db_url("redis", "u:pw", "h")
    );
    let out = assert_projected(&text);
    let parsed: Value = serde_json::from_str(&out).expect("parses");
    assert_eq!(parsed["n"], 1);
    assert!(!out.contains("\\ude00"), "{out}");
}

#[test]
fn b7_short_url_in_compact_json() {
    // Built by hand so the URL comes first: alone at the end it is under the
    // rule's 10-character floor, on base too.
    let text = format!(r#"{{"u":"{}","n":1}}"#, db_url("redis", ":pw", "h/0"));
    let out = assert_projected(&text);
    assert_eq!(out, format!(r#"{{"u":"{MARK}","n":1}}"#));
}

#[test]
fn b8_url_shapes_stay_hidden_and_parse() {
    let urls = [
        db_url("postgres", "u:pw", "[::1]:5432/db"),
        db_url("mongodb", "u:pw", "h1:1,h2:2/db?replicaSet=r"),
        db_url("mysql", "u:p'w%27", "h:3306/db?ssl=true#frag"),
        db_url("postgres", "u:p\"w@x", "h/db"),
    ];
    for url in urls {
        let text = json!({ "u": url, "z": [1, 2] }).to_string();
        let out = assert_projected(&text);
        assert!(parses(&out), "{out}");
        assert!(!out.contains("pw") && !out.contains("p'w"), "{out}");
    }
}

#[test]
fn b9_keys_and_scalars_the_span_crosses_are_kept() {
    let text = format!(r#"{{"a":"{}","n":42,"b":true,"c":"x"}}"#, pg_url());
    let out = assert_projected(&text);
    assert_eq!(
        out,
        format!(r#"{{"a":"{MARK}","n":42,"b":true,"c":"{MARK}"}}"#)
    );
}

#[test]
fn b10_residual_numeric_secret_after_url_is_visible() {
    // Stated residual (lead ruling N): today 1234 is hidden only by the
    // over-match that breaks the JSON; a numeric secret needs MIK-8757.
    let text = format!(r#"{{"a":"{}","pin":1234}}"#, pg_url());
    let out = assert_projected(&text);
    assert_eq!(out, format!(r#"{{"a":"{MARK}","pin":1234}}"#));
}

#[test]
fn b11_an_escaped_lookalike_is_copied_raw() {
    let plain = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let text = format!(r#"{{"s":"{plain} \u0041KIA{}"}}"#, "1".repeat(16));
    let out = assert_projected(&text);
    assert_eq!(
        out,
        format!(r#"{{"s":"{MARK} \u0041KIA{}"}}"#, "1".repeat(16))
    );
}

// ── C: structure and fallback ─────────────────────────────────────────────

#[test]
fn c1_a_span_starting_in_a_key_takes_todays_path() {
    let key = format!("ghp_{}", "k".repeat(36));
    let text = format!(r#"{{"inner":{{"{key}":1}},"n":2}}"#);
    let (out, _) = deliver(&text);
    assert_eq!(out, today(&text));
    assert_eq!(out, expected(&text));
}

#[test]
fn c1b_a_span_running_over_later_keys_keeps_them() {
    let text = format!(r#"{{"dsn":"{}","rows":3,"more":"m"}}"#, pg_url());
    let out = assert_projected(&text);
    assert_eq!(
        out,
        format!(r#"{{"dsn":"{MARK}","rows":3,"more":"{MARK}"}}"#)
    );
}

#[test]
fn c2_two_credential_shaped_keys_take_todays_path() {
    let (a, b) = (
        format!("ghp_{}", "a".repeat(36)),
        format!("gho_{}", "b".repeat(36)),
    );
    let text = format!(r#"{{"o":{{"{a}":1,"{b}":2}}}}"#);
    let (out, _) = deliver(&text);
    assert_eq!(out, today(&text));
}

#[test]
fn c3_a_leaf_over_the_cap_takes_todays_path() {
    let head = format!(r#"{{"dsn":"{}","pad":""#, pg_url());
    let pad = "x".repeat(CAP + 1 - head.len() - 2);
    let text = format!("{head}{pad}\"}}");
    assert_eq!(text.len(), CAP + 1);
    let (out, _) = deliver(&text);
    assert_eq!(out, today(&text));
}

#[test]
fn c4_prose_before_json_takes_todays_path() {
    let text = format!(r#"result: {{"dsn":"{}","rows":3}}"#, pg_url());
    let (out, _) = deliver(&text);
    assert_eq!(out, today(&text));
}

#[test]
fn c5_truncated_json_takes_todays_path() {
    let text = format!(r#"{{"dsn":"{}","rows":"#, pg_url());
    let (out, _) = deliver(&text);
    assert_eq!(out, today(&text));
}

#[test]
fn c7_depth_is_one_level() {
    let inner = json!({ "dsn": pg_url(), "rows": 3 }).to_string();
    let text = serde_json::to_string(&inner).unwrap();
    let out = assert_projected(&text);
    let outer: String = serde_json::from_str(&out).expect("outer parses");
    // Inside the decoded content the span still runs to the end (stated bound).
    assert_eq!(outer, format!(r#"{{"dsn":"{MARK}"#));
}

// ── D: properties ─────────────────────────────────────────────────────────

/// A small deterministic generator (no new dependency).
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(self.0 >> 33).expect("31 bits fit")
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.next() % items.len()]
    }
    fn string(&mut self, secret: bool) -> String {
        let plain = [
            "word",
            "two words",
            "line\nbreak",
            "q\"uote",
            "back\\slash",
            "é",
            "😀",
            "",
        ];
        if secret {
            let all = secrets();
            let (_, s) = self.pick(&all).clone();
            format!(
                "{}{s}{}",
                self.pick(&["", "x ", "pre-"]),
                self.pick(&["", " y", "/tail"])
            )
        } else {
            (*self.pick(&plain)).to_owned()
        }
    }
    fn value(&mut self, depth: u32, secret: bool) -> Value {
        let kind = if depth == 0 {
            3 + self.next() % 3
        } else {
            self.next() % 6
        };
        match kind {
            0 | 1 => {
                let mut map = Map::new();
                for i in 0..=self.next() % 3 {
                    let key = format!("{}{i}", self.pick(&["k", "name", "rows", "e\u{e9}"]));
                    map.insert(key, self.value(depth - 1, secret && i == 0));
                }
                Value::Object(map)
            }
            2 => Value::Array(
                (0..=self.next() % 3)
                    .map(|i| self.value(depth - 1, secret && i == 0))
                    .collect(),
            ),
            3 => Value::String(self.string(secret)),
            4 => json!(self.next() % 1000),
            _ => json!(self.next().is_multiple_of(2)),
        }
    }
    fn document(&mut self, secret: bool) -> String {
        let root = if self.next().is_multiple_of(2) {
            json!({ "a": self.value(2, secret), "b": self.value(2, false) })
        } else {
            json!([self.value(2, secret), self.value(2, false)])
        };
        if self.next().is_multiple_of(2) {
            root.to_string()
        } else {
            serde_json::to_string_pretty(&root).unwrap()
        }
    }
}

#[test]
fn d1_no_secret_is_byte_identical() {
    let mut g = Gen(1);
    for _ in 0..300 {
        let text = g.document(false);
        let (out, findings) = deliver(&text);
        assert_eq!(out, text);
        assert!(findings.is_empty(), "{text}");
    }
}

#[test]
fn d2_d3_d4_with_secrets_matches_the_projection() {
    let mut g = Gen(7);
    for _ in 0..300 {
        let text = g.document(true);
        let out = assert_projected(&text);
        assert!(parses(&out), "{text}\n=> {out}");
    }
}

#[test]
fn d5_deterministic() {
    let mut g = Gen(11);
    for _ in 0..50 {
        let text = g.document(true);
        assert_eq!(deliver(&text), deliver(&text));
    }
}

#[test]
fn d6_no_pattern_matches_after_a_splice() {
    let mut g = Gen(13);
    for _ in 0..300 {
        let text = g.document(true);
        let out = expected(&text);
        if out != today(&text) {
            assert!(
                redactor().credential_spans(&deliver(&text).0).is_empty(),
                "{text}"
            );
        }
    }
}

// ── E: consumers ──────────────────────────────────────────────────────────

#[test]
fn e3_direct_row_count_is_observed_after_redaction() {
    // Keys print sorted: the span starts in `items` and runs over the
    // `total_count` key and its number, which projection keeps.
    let text = json!({
        "total_count": 5,
        "incomplete_results": false,
        "items": [{ "dsn": pg_url() }],
    })
    .to_string();
    let mut result = json!({ "content": [{ "type": "text", "text": text }] });
    redactor().scan_and_redact(&mut result);
    let count = crate::trust::extract_row_count("github", "github_search_repos", &result, true);
    assert_eq!(count, Some(5), "{result}");
}

#[test]
fn e5_plain_text_spans_are_unchanged() {
    // The connection-string floor stays `{10,}` (superseded by projection),
    // so a short URL in prose is not a span, as on base.
    let short = format!("see {} now", db_url("redis", ":pw", "h/0"));
    assert!(redactor().credential_spans(&short).is_empty(), "{short}");
    let long = format!("see {} now", pg_url());
    assert_eq!(
        redactor().credential_spans(&long),
        [(4, 4 + pg_url().len())]
    );
}
