// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8774: a leaf over the 1 MiB cap is projected like one under it, with
//! two exceptions that take base's whole-value path: a key a match starts in,
//! and an object led by serde_json's raw-value token. Every row goes through
//! the same [`expected`] oracle, which validates with `serde_json::Value`, so
//! a rejection row also checks that the over-cap validator agrees with it.

use super::*;

/// `doc` as the `doc` member of an object padded past the cap.
fn over_cap(doc: &str) -> String {
    let pad = "x".repeat(CAP + 1024);
    format!(r#"{{"pad":"{pad}","doc":{doc}}}"#)
}

/// A JSON unicode escape of `hex`, built so no source line holds one decoded.
fn esc(hex: &str) -> String {
    format!("{}u{hex}", '\\')
}

/// A distinctive password, so "the secret is gone" can be checked by search.
const PASSWORD: &str = "s3cretPW8774";

fn secret_url() -> String {
    db_url("postgres", &format!("u:{PASSWORD}"), "db.local:5432/app")
}

/// decomp-8488 probe q2's shape: a countable `github_search_repos` page past
/// the cap, the connection string in a value before `total_count`. Base
/// redacts from the URL to the next whitespace, so the count is lost.
#[test]
fn s1_q2_a_countable_page_over_the_cap_keeps_its_count() {
    // Real descriptions have spaces, where base's match stops.
    let description = "word ".repeat(800);
    let items: Vec<String> = (0..300)
        .map(|i| format!(r#"{{"full_name":"o/r{i}","description":"{description}"}}"#))
        .collect();
    let text = format!(
        r#"{{"items":[{{"homepage":"{}"}},{}],"total_count":3,"incomplete_results":false}}"#,
        secret_url(),
        items.join(",")
    );
    assert!(text.len() > CAP, "{}", text.len());
    let out = assert_projected(&text);
    assert!(parses(&out), "STREAM.1 parses");
    assert!(!out.contains(PASSWORD), "STREAM.1 the secret is gone");
    let mut result = json!({ "content": [{ "type": "text", "text": text }] });
    redactor().scan_and_redact(&mut result);
    let count = crate::trust::extract_row_count("github", "github_search_repos", &result, true);
    assert_eq!(count, Some(3), "STREAM.1 total_count survives");
}

#[test]
fn s1_pretty_page_over_the_cap() {
    let doc = json!({ "rows": [{ "dsn": secret_url() }, { "dsn": pg_url() }], "n": 2 });
    let value: Value = serde_json::from_str(&over_cap(&doc.to_string())).expect("valid");
    let text = serde_json::to_string_pretty(&value).expect("prints");
    let out = assert_projected(&text);
    assert!(
        parses(&out) && !out.contains(PASSWORD),
        "{}",
        &out[out.len() - 200..]
    );
}

/// STREAM.2: each document beside a value span, over the cap. The oracle
/// takes base's path exactly when `Value` rejects the text, so the
/// delivered text pins the validator to `Value` both ways.
#[test]
fn s2_validity_over_the_cap_agrees_with_value() {
    let url = serde_json::to_string(&pg_url()).expect("encodes");
    let nested = |depth: usize| format!("{}{url}{}", "[".repeat(depth), "]".repeat(depth));
    let rows = [
        format!(r#"[{url},"\ud800"]"#),
        format!(r#"[{url},"\udc00"]"#),
        format!(r#"[{url},"\udc00\ud800"]"#),
        format!(r#"[{url},"{}{}"]"#, esc("d83d"), esc("de00")),
        format!("[{url},1e400]"),
        format!("[{url},-1e400]"),
        format!("[{url},18446744073709551615]"),
        format!("[{url},18446744073709551616]"),
        format!("[{url},-9223372036854775809]"),
        // A raw tab inside a string, which JSON forbids.
        format!("[{url},\"tab\tin\"]"),
        format!(r#"[{url},"esc\"aped\n"]"#),
        format!("[{url},]"),
        format!("[{url}] x"),
        format!(r#"{{"a":{url},"a":1}}"#),
        format!("[{url},01]"),
        format!("[{url},tru]"),
        // The pad's object and `doc` add one level, so these straddle 128.
        nested(125),
        nested(126),
        nested(127),
    ];
    for doc in rows {
        let text = over_cap(&doc);
        let (out, _) = deliver(&text);
        assert_eq!(
            out,
            expected(&text),
            "row {}",
            &doc[doc.len().saturating_sub(40)..]
        );
    }
}

/// The over-cap path renames no key: a match that starts in a key, alone or
/// behind a greedy span, sends the leaf down base's path.
#[test]
fn s3_a_key_span_over_the_cap_takes_todays_path() {
    let key = serde_json::to_string(&pg_url()).expect("encodes");
    let greedy = serde_json::to_string(&secret_url()).expect("encodes");
    for doc in [
        format!(r#"{{{key}:1,"n":3}}"#),
        format!(r#"[{greedy},{{{key}:1}}]"#),
        format!(r#"{{"v":{greedy},"ghp_{}":1}}"#, "a".repeat(36)),
    ] {
        let text = over_cap(&doc);
        let (out, _) = deliver(&text);
        assert_eq!(out, today(&text), "{doc}");
        assert_eq!(out, expected(&text), "{doc}");
    }
}

/// An object whose first key is the raw-value token, at any depth and in any
/// spelling, takes base's path; the token as a later key is an ordinary key.
#[test]
fn s4_the_raw_value_token_over_the_cap() {
    let url = serde_json::to_string(&pg_url()).expect("encodes");
    let fallback = [
        format!(r#"[{url},{{"{RAW_VALUE_TOKEN}":"[1]"}}]"#),
        format!(r#"[{url},{{"{RAW_VALUE_TOKEN}":null}}]"#),
        format!(r#"[{url},[[{{"{RAW_VALUE_TOKEN}":"{{}}","b":1}}]]]"#),
        format!(
            r#"[{url},{{"$serde_json::private::Raw{}alue":"[1]"}}]"#,
            esc("0056")
        ),
    ];
    for doc in fallback {
        let text = over_cap(&doc);
        let (out, _) = deliver(&text);
        assert_eq!(out, today(&text), "{doc}");
    }
    let later = over_cap(&format!(r#"{{"a":{url},"{RAW_VALUE_TOKEN}":"[1]"}}"#));
    let out = assert_projected(&later);
    assert!(parses(&out));
}

/// Two matches in one value whose escape-widened ranges touch become one
/// marker, as under the cap.
#[test]
fn s5_touching_ranges_merge_over_the_cap() {
    let key = format!("AKIA{}", "Z".repeat(16));
    for doc in [
        // The second match starts on the escape's last nibble and widens
        // back onto the first range's end.
        format!(r#"["{key}{}0x{}"]"#, esc("0030"), "e".repeat(64)),
        format!(r#"["{key}{}{key}"]"#, esc("0041")),
        format!(r#"["{key}\n{key}"]"#),
        format!(
            r#"["{}{key}{}{}{key}"]"#,
            esc("00e9"),
            esc("d83d"),
            esc("de00")
        ),
    ] {
        let text = over_cap(&doc);
        let out = assert_projected(&text);
        assert!(parses(&out), "{doc}");
    }
}

/// P1 and D2 over the cap: every family in a value and in a key, and
/// generated documents, each padded past the cap.
#[test]
fn s6_families_and_generated_documents_over_the_cap() {
    for (rule, secret) in secrets() {
        let quoted = serde_json::to_string(&secret).expect("encodes");
        for doc in [
            format!(r#"{{"v":{quoted},"n":3}}"#),
            format!(r#"{{{quoted}:{{"v":"a"}},"n":3}}"#),
        ] {
            let out = assert_projected(&over_cap(&doc));
            assert!(parses(&out), "{rule}: {doc}");
        }
    }
    let mut g = Gen(8774);
    for _ in 0..30 {
        let doc = g.document(true);
        let out = assert_projected(&over_cap(&doc));
        assert!(parses(&out), "{doc}");
    }
}

/// F1 past the cap (STREAM.4): q2's shape at 1.15 MB and at 8 MiB, and one
/// span across many keys, against base's whole-leaf path. Timing, so run by
/// hand on Spark: `cargo test --lib -- --ignored s7_ --nocapture`.
#[test]
#[ignore = "timing; run by hand"]
fn s7_over_the_cap_cost() {
    let row = r#"{"full_name":"o/r","description":"short words here"},"#;
    for size in [1_155_114_usize, 8 << 20] {
        let mut body = String::new();
        while body.len() < size {
            body.push_str(row);
        }
        let text = format!(
            r#"{{"items":[{{"homepage":"{}"}},{body}{{}}],"total_count":3}}"#,
            secret_url()
        );
        time_against_base(&format!("q2 {size}"), &text);
    }
    let keys: String = (0..100_000).map(|i| format!(r#""k{i}":{i},"#)).collect();
    let text = over_cap(&format!(r#"[{{"v":"{}",{keys}"z":0}}]"#, secret_url()));
    time_against_base("one span across 100000 keys", &text);
}

fn time_against_base(label: &str, text: &str) {
    let warm = redactor();
    let mut value = json!({ "content": [{ "type": "text", "text": text }] });
    let started = std::time::Instant::now();
    warm.scan_and_redact(&mut value);
    let projected = started.elapsed();
    let started = std::time::Instant::now();
    let whole = splice(text, &warm.credential_spans(text));
    let base = started.elapsed();
    let out = value["content"][0]["text"].as_str().expect("text");
    assert_ne!(out, whole, "{label}: the projection must have run");
    let ratio = projected.as_secs_f64() / base.as_secs_f64();
    println!("{label}: projection {projected:?}, whole leaf {base:?}, ratio {ratio:.2}");
    assert!(ratio < 3.0, "{label}: ratio {ratio:.2} over the plan's 3x");
}

/// The member password every M row carries.
const PASS: &str = "hunter2-long-enough";

/// `doc` delivered over the cap equals its own delivery under the cap,
/// wrapped: member redaction and its findings do not change at 1 MiB.
fn assert_as_under_cap(doc: &str, exempt: &dyn Fn(&str) -> bool) {
    let (small, small_findings) = deliver_unless(doc, exempt);
    let (large, large_findings) = deliver_unless(&over_cap(doc), exempt);
    assert_eq!(large, over_cap(&small), "{doc}");
    assert_eq!(large_findings, small_findings, "findings for {doc}");
}

fn deliver_unless(text: &str, exempt: &dyn Fn(&str) -> bool) -> (String, Vec<String>) {
    let mut value = json!({ "content": [{ "type": "text", "text": text }] });
    let findings = redactor().scan_and_redact_unless(&mut value, exempt);
    let out = value["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    let mut descriptions: Vec<String> = findings.into_iter().map(|f| f.description).collect();
    descriptions.sort();
    (out, descriptions)
}

/// Base's whole-value replacement with each of `members`' first occurrence
/// replaced too: what a fallback delivers.
fn today_with_members(text: &str, members: &[&str]) -> String {
    let mut ranges = redactor().credential_spans(text);
    for member in members {
        let at = text.find(member).expect("member present");
        ranges.push((at, at + member.len()));
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

/// Members over the cap, MIK-8757's families: redacted as under the cap,
/// with the same findings, including a raw match over part of a member
/// value and an AWS-shaped generic member (both findings).
#[test]
fn s8_members_over_the_cap_match_under_the_cap() {
    let aws = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let docs = [
        format!(r#"{{"password":"{PASS}","n":3}}"#),
        format!(r#"{{"pass{}ord":"{PASS}","n":3}}"#, esc("0077")),
        format!(r#"{{"client_secret":"{}","n":1}}"#, "s".repeat(20)),
        format!(r#"{{"private_key":"{}","n":1}}"#, "k".repeat(40)),
        format!(r#"{{"authorization":"Bearer {}","n":1}}"#, "a".repeat(12)),
        format!(r#"{{"api_key":"{aws}","n":1}}"#),
        format!(r#"{{"password":"prefix-{aws}","n":1}}"#),
        format!(r#"{{"password":"x\n{aws}","n":1}}"#),
        format!(r#"{{"password":{{"x":"{PASS}"}},"n":1}}"#),
        format!(
            r#"[{{"password":"{PASS}"}},{}]"#,
            serde_json::to_string(&pg_url()).unwrap()
        ),
    ];
    for doc in docs {
        assert!(parses(&doc), "{doc}");
        assert_as_under_cap(&doc, &|_| false);
    }
}

/// An exempt literal over the cap: kept when no span crosses it, and when one
/// does, the leaf falls back to base's replacement with members still
/// redacted.
#[test]
fn s10_an_exempt_literal_over_the_cap() {
    let exempt = |s: &str| s == "CONT-8774";
    let url = serde_json::to_string(&pg_url()).unwrap();
    assert_as_under_cap(&format!(r#"{{"next":"CONT-8774","dsn":{url}}}"#), &exempt);
    let crossed = over_cap(&format!(
        r#"{{"password":"{PASS}","dsn":{url},"next":"CONT-8774"}}"#
    ));
    let (out, _) = deliver_unless(&crossed, &exempt);
    assert_eq!(out, today_with_members(&crossed, &[PASS]));
    assert!(!out.contains(PASS));
}

/// Every fallback over the cap still redacts members: a match that starts
/// in a key, and an object led by the raw-value token.
#[test]
fn s11_a_fallback_over_the_cap_still_redacts_members() {
    let key = serde_json::to_string(&pg_url()).unwrap();
    for doc in [
        format!(r#"{{"password":"{PASS}",{key}:1}}"#),
        format!(r#"[{{"password":"{PASS}"}},{{"{RAW_VALUE_TOKEN}":"[1]"}},{key}]"#),
    ] {
        let text = over_cap(&doc);
        let (out, _) = deliver(&text);
        assert_eq!(out, today_with_members(&text, &[PASS]), "{doc}");
        assert!(!out.contains(PASS), "{doc}");
    }
}
