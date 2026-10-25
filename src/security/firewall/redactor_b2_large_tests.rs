// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8774: a leaf over the 1 MiB cap is redacted exactly as one under it:
//! value spans projected, keys a match starts in renamed, members paired,
//! exempt values kept. Every row goes through the same [`expected`] oracle,
//! which validates with `serde_json::Value`, or is compared with the same
//! document delivered under the cap.

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
            // A key a match starts in takes base's replacement, which may
            // cut the JSON; every projected leaf still parses.
            let text = over_cap(&doc);
            let out = assert_projected(&text);
            assert!(out == today(&text) || parses(&out), "{rule}: {doc}");
        }
    }
    let mut g = Gen(8774);
    for _ in 0..30 {
        let doc = g.document(true);
        let text = over_cap(&doc);
        let out = assert_projected(&text);
        assert!(out == today(&text) || parses(&out), "{doc}");
    }
}

/// F1 past the cap (STREAM.4): q2's shape at 1.15 MB and at 8 MiB, and one
/// span across many keys, against base's whole-leaf path. Timing, so run by
/// hand on Spark: `cargo test --lib -- --ignored s7_ --nocapture`.
#[test]
#[ignore = "timing; run by hand"]
fn s7_over_the_cap_cost() {
    let row = r#"{"full_name":"o/r","description":"short words here"},"#;
    let mut ratios = Vec::new();
    // The first size is under the cap: the same shape on MIK-8745's walk.
    for size in [1_000_000_usize, 1_155_114, 8 << 20] {
        let mut body = String::new();
        while body.len() < size {
            body.push_str(row);
        }
        let text = format!(
            r#"{{"items":[{{"homepage":"{}"}},{body}{{}}],"total_count":3}}"#,
            secret_url()
        );
        ratios.push(time_against_base(&format!("q2 {size}"), &text));
    }
    let keys = (0..100_000).fold(String::new(), |mut keys, i| {
        use std::fmt::Write as _;
        write!(keys, r#""k{i}":{i},"#).expect("writes");
        keys
    });
    let text = over_cap(&format!(r#"[{{"v":"{}",{keys}"z":0}}]"#, secret_url()));
    ratios.push(time_against_base("one span across 100000 keys", &text));
    // One literal of many matches and no escape: each escape lookup must
    // stay a forward step, not a rescan of the literal (gpt review).
    let mut body = String::new();
    for i in 0..60_000 {
        use std::fmt::Write as _;
        write!(body, "AKIA{i:016} ").expect("writes");
    }
    let text = over_cap(&format!(r#"{{"s":"{body}"}}"#));
    ratios.push(time_against("60000 matches in one literal", &text, false));
    // No secret at all: every JSON leaf over the cap now takes the walk (MIK-8756
    // ruling A), where base ran only the regex set. Reported, not asserted.
    let mut body = String::new();
    while body.len() < 8 << 20 {
        body.push_str(row);
    }
    let text = format!(r#"{{"items":[{body}{{}}],"total_count":3}}"#);
    let warm = redactor();
    let mut value = json!({ "content": [{ "type": "text", "text": &text }] });
    let started = std::time::Instant::now();
    warm.scan_and_redact(&mut value);
    let walked = started.elapsed();
    assert_eq!(value["content"][0]["text"].as_str(), Some(text.as_str()));
    let started = std::time::Instant::now();
    assert!(!warm.set.is_match(&text));
    let base = started.elapsed();
    let ratio = walked.as_secs_f64() / base.as_secs_f64();
    println!("no secret, 8 MiB: walk {walked:?}, base regex {base:?}, ratio {ratio:.2}");
    // Reported, not asserted: the ~11x over the cap is the ruling-A member
    // walk the line pays under the cap too, a known miss of STREAM.4's 3x
    // (lead ruling 2026-10-25, redactor-cost ticket).
    for (label, ratio) in ratios {
        println!("{label}: {ratio:.2}x of the whole-value path (STREAM.4 bar 3x)");
    }
}

fn time_against_base(label: &str, text: &str) -> (String, f64) {
    time_against(label, text, true)
}

/// `differs`: whether the projection must deliver other bytes than base; not
/// so when every match sits inside one literal.
fn time_against(label: &str, text: &str, differs: bool) -> (String, f64) {
    let warm = redactor();
    let mut value = json!({ "content": [{ "type": "text", "text": text }] });
    let started = std::time::Instant::now();
    warm.scan_and_redact(&mut value);
    let projected = started.elapsed();
    let started = std::time::Instant::now();
    let whole = splice(text, &warm.credential_spans(text));
    let base = started.elapsed();
    let out = value["content"][0]["text"].as_str().expect("text");
    if differs {
        assert_ne!(out, whole, "{label}: the projection must have run");
    }
    let ratio = projected.as_secs_f64() / base.as_secs_f64();
    println!("{label}: projection {projected:?}, whole leaf {base:?}, ratio {ratio:.2}");
    (label.to_owned(), ratio)
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

/// The first object key `serde_json`'s `raw_value` feature reads specially.
const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";

/// Residual (a), lead ruling 2026-10-24: a match that starts in a key, alone
/// or behind a greedy span, renames that key over the cap as under it.
#[test]
fn s3_a_key_span_over_the_cap_is_renamed_as_under_it() {
    let key = serde_json::to_string(&pg_url()).expect("encodes");
    let greedy = serde_json::to_string(&secret_url()).expect("encodes");
    for doc in [
        format!(r#"{{{key}:1,"n":3}}"#),
        format!("[{greedy},{{{key}:1}}]"),
        format!(r#"{{"v":{greedy},"ghp_{}":1}}"#, "a".repeat(36)),
        format!(r#"{{{key}:1,{key}:2,"{MARK}":3}}"#),
    ] {
        let text = over_cap(&doc);
        let out = assert_projected(&text);
        assert!(parses(&out), "{doc}");
        assert_as_under_cap(&doc, &|_| false);
    }
    // The oracle predates member pairing (MIK-8757), so a member beside the
    // renamed key is checked against the same document under the cap.
    let doc = format!(r#"{{"password":"{PASS}",{key}:1}}"#);
    assert_as_under_cap(&doc, &|_| false);
    let (out, _) = deliver(&over_cap(&doc));
    assert!(parses(&out) && !out.contains(PASS), "{doc}");
}

/// Residual (c): an object led by the raw-value token is read as `Value`
/// reads it, so a document `Value` accepts is projected over the cap and one
/// it rejects takes base's path, as under it.
#[test]
fn s4_the_raw_value_token_over_the_cap_reads_as_value_does() {
    let url = serde_json::to_string(&pg_url()).expect("encodes");
    for doc in [
        format!(r#"[{url},{{"{RAW_VALUE_TOKEN}":"[1]"}}]"#),
        format!(r#"[{url},[[{{"{RAW_VALUE_TOKEN}":"{{}}"}}]]]"#),
        format!(
            r#"[{url},{{"$serde_json::private::Raw{}alue":"[1]"}}]"#,
            esc("0056")
        ),
        format!(r#"{{"a":{url},"{RAW_VALUE_TOKEN}":"[1]"}}"#),
        format!(r#"[{{"password":"{PASS}"}},{{"{RAW_VALUE_TOKEN}":"[1]"}},{url}]"#),
    ] {
        // The same delivery as under the cap is the contract. It need not
        // parse as `Value`: a span reaching a raw-value string leaves the
        // marker there, which `Value` reads as an invalid nested document.
        assert!(parses(&doc), "{doc}");
        assert_as_under_cap(&doc, &|_| false);
    }
    for doc in [
        format!(r#"[{url},{{"{RAW_VALUE_TOKEN}":null}}]"#),
        format!(r#"[{url},{{"{RAW_VALUE_TOKEN}":"[1]","b":1}}]"#),
        format!(r#"[{url},{{"{RAW_VALUE_TOKEN}":"[1"}}]"#),
    ] {
        assert!(!parses(&doc), "{doc}");
        let text = over_cap(&doc);
        assert_eq!(deliver(&text).0, today(&text), "{doc}");
    }
}

/// Residual (b): a span that crosses an exempt value is dropped over the cap
/// as under it, so the exempt value and the JSON around it stay as sent.
#[test]
fn s10_an_exempt_literal_over_the_cap() {
    let exempt = |s: &str| s == "CONT-8774";
    let url = serde_json::to_string(&pg_url()).expect("encodes");
    for doc in [
        format!(r#"{{"next":"CONT-8774","dsn":{url}}}"#),
        format!(r#"{{"password":"{PASS}","dsn":{url},"next":"CONT-8774"}}"#),
        format!(
            r#"{{"dsn":{url},"next":"CONT-8774","k":"ghp_{}"}}"#,
            "a".repeat(36)
        ),
    ] {
        assert_as_under_cap(&doc, &exempt);
        let (out, _) = deliver_unless(&over_cap(&doc), &exempt);
        assert!(
            parses(&out) && out.contains("CONT-8774") && !out.contains(PASS),
            "{out:.200}"
        );
    }
}

/// MIK-8774 (b), found on the line: a span that crosses an exempt value loses
/// only the exempt value's bytes, so a credential beside a continuation is
/// still redacted, under the cap as over it. A pattern counts only where its
/// remaining bytes redact something.
#[test]
fn s12_a_span_crossing_an_exempt_value_still_redacts_the_rest() {
    let cont = "CONT-8774";
    let url = serde_json::to_string(&pg_url()).expect("encodes");
    let ghp = format!("ghp_{}", "a".repeat(36));
    let gho = format!("gho_{}", "b".repeat(36));
    // A continuation shaped like a connection string, apart from the dsn's.
    let cont_url = db_url("postgres", "c:t", "cont.local:5432/x");
    let exempt = |s: &str| s == cont || s == ghp || s == cont_url;
    let pretty = serde_json::to_string_pretty(&json!({ "dsn": pg_url(), "next": cont })).unwrap();
    let rows = [
        // The compact shape: the URL's match runs on across the exempt value.
        (
            format!(r#"{{"dsn":{url},"next":"{cont}"}}"#),
            format!(r#"{{"dsn":"{MARK}","next":"{cont}"}}"#),
        ),
        (
            pretty.clone(),
            serde_json::to_string_pretty(&json!({ "dsn": MARK, "next": cont })).unwrap(),
        ),
        // A match that ends exactly at its value's closing quote.
        (
            format!(r#"{{"k":"{gho}","next":"{cont}"}}"#),
            format!(r#"{{"k":"{MARK}","next":"{cont}"}}"#),
        ),
        // A token-shaped exempt value beside a credential.
        (
            format!(r#"{{"next":"{ghp}","k":"{gho}"}}"#),
            format!(r#"{{"next":"{ghp}","k":"{MARK}"}}"#),
        ),
    ];
    for (doc, want) in rows {
        let (out, findings) = deliver_unless(&doc, &exempt);
        assert_eq!(out, want, "under the cap: {doc}");
        assert!(!findings.is_empty(), "{doc}");
        assert_as_under_cap(&doc, &exempt);
    }
    // An exempt value whose own match runs past it: only syntax and a key it
    // did not start in remain, so nothing is redacted and nothing is found.
    let doc = format!(r#"{{"next":"{cont_url}","n":1}}"#);
    let (out, findings) = deliver_unless(&doc, &exempt);
    assert_eq!(out, doc);
    assert!(findings.is_empty(), "{findings:?}");
    assert_as_under_cap(&doc, &exempt);
}

/// The collected walk's worst case over the cap (lead ruling 2026-10-25): a
/// document of tiny strings, one literal every four bytes, whose key a match
/// starts in, so the leaf takes the walk under the cap on all its literals.
#[test]
fn s13_a_key_rename_in_a_document_of_tiny_strings_over_the_cap() {
    let key = serde_json::to_string(&pg_url()).expect("encodes");
    let tiny = vec![r#""a""#; (CAP / 4) + 1024].join(",");
    let text = format!("[{tiny},{{{key}:1,\"n\":3}}]");
    assert!(text.len() > CAP);
    let out = assert_projected(&text);
    assert!(parses(&out));
    assert!(!out.contains("u:pw@"), "the key is renamed");
}

/// A text whose offsets do not fit a literal's 32 bits is never walked: the
/// guard `redact_json_text` checks first sends it down the whole-value path
/// (lead ruling 2026-10-25; such a text cannot be built in a test).
#[test]
fn s14_offsets_past_32_bits_are_not_walked() {
    let max = usize::try_from(u32::MAX).expect("fits");
    assert!(json_literal::fits_offsets(max));
    assert!(!json_literal::fits_offsets(max + 1));
}
