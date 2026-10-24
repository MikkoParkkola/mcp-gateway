// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8832: a credential span that crosses an exempt value (the gateway's
//! own continuation) loses only that value's bytes. #4110 dropped the whole
//! span, so in compact JSON a connection string followed by a continuation
//! was delivered intact. A pattern still counts only where what is left of
//! its spans redacts something.

use super::*;
use serde_json::json;

const MARK: &str = "[REDACTED:credential]";
const CONT: &str = "CONT-8832";
/// The password the leak delivered, distinctive so its absence is checkable.
const PASSWORD: &str = "s3cretPW8832";

fn dsn() -> String {
    format!("{}://u:{PASSWORD}@{}", "postgres", "db.local:5432/app")
}

/// A continuation shaped like a connection string, apart from the dsn.
fn cont_url() -> String {
    format!("{}://c:t@{}", "postgres", "cont.local:5432/x")
}

fn ghp() -> String {
    format!("{}{}", "gh", "p_") + &"a".repeat(36)
}

fn gho() -> String {
    format!("{}{}", "gh", "o_") + &"b".repeat(36)
}

fn exempt(s: &str) -> bool {
    s == CONT || s == ghp() || s == cont_url()
}

fn deliver(text: &str) -> (String, Vec<String>) {
    let mut value = json!({ "content": [{ "type": "text", "text": text }] });
    let findings = Redactor::new().scan_and_redact_unless(&mut value, &exempt);
    let out = value["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    (out, findings.into_iter().map(|f| f.description).collect())
}

/// `doc` as the last member of an object padded past the 1 MiB cap.
fn over_cap(doc: &str) -> String {
    format!(
        r#"{{"pad":"{}","doc":{doc}}}"#,
        "x".repeat((1 << 20) + 1024)
    )
}

/// The four rows where a credential sits beside an exempt value, with what
/// each is delivered as under the cap.
fn rows() -> Vec<(String, String)> {
    let url = serde_json::to_string(&dsn()).expect("encodes");
    vec![
        // The leak: the URL's match runs on across the continuation.
        (
            format!(r#"{{"dsn":{url},"next":"{CONT}"}}"#),
            format!(r#"{{"dsn":"{MARK}","next":"{CONT}"}}"#),
        ),
        (
            serde_json::to_string_pretty(&json!({ "dsn": dsn(), "next": CONT })).expect("prints"),
            serde_json::to_string_pretty(&json!({ "dsn": MARK, "next": CONT })).expect("prints"),
        ),
        // A match that ends exactly at its value's closing quote.
        (
            format!(r#"{{"k":"{}","next":"{CONT}"}}"#, gho()),
            format!(r#"{{"k":"{MARK}","next":"{CONT}"}}"#),
        ),
        // A token-shaped exempt value beside a credential.
        (
            format!(r#"{{"next":"{}","k":"{}"}}"#, ghp(), gho()),
            format!(r#"{{"next":"{}","k":"{MARK}"}}"#, ghp()),
        ),
    ]
}

#[test]
fn x1_a_span_crossing_an_exempt_value_still_redacts_the_rest() {
    for (doc, want) in rows() {
        let (out, findings) = deliver(&doc);
        assert_eq!(out, want, "{doc}");
        assert!(!findings.is_empty(), "{doc}");
    }
}

/// An exempt value whose own match runs past it: what is left is syntax and
/// a key no match starts in, so nothing is redacted and nothing is found.
#[test]
fn x2_a_span_left_with_only_syntax_redacts_and_finds_nothing() {
    let doc = format!(r#"{{"next":"{}","n":1}}"#, cont_url());
    let (out, findings) = deliver(&doc);
    assert_eq!(out, doc);
    assert!(findings.is_empty(), "{findings:?}");
}

/// Over the cap the line still takes the whole-value path (MIK-8774 brings
/// the projection there): no secret byte may be left either.
#[test]
fn x3_over_the_cap_no_secret_is_left() {
    for (doc, _) in rows() {
        let (out, findings) = deliver(&over_cap(&doc));
        assert!(!out.contains(PASSWORD) && !out.contains(&gho()), "{doc}");
        assert!(!findings.is_empty(), "{doc}");
    }
}

/// The pieces right of an exempt value and between two of them are kept and
/// projected too, with one finding per pattern that still redacts.
#[test]
fn x4_pieces_after_and_between_exempt_values_still_redact() {
    let url = serde_json::to_string(&dsn()).expect("encodes");
    let db = "Credential detected: Database Connection String";
    let gh = "Credential detected: GitHub OAuth Token";
    let rows = [
        // The match starts in an exempt connection-string-shaped value and
        // runs on over a later dsn: the dsn is still covered after the cut.
        (
            format!(r#"{{"next":"{}","dsn":{url}}}"#, cont_url()),
            format!(r#"{{"next":"{}","dsn":"{MARK}"}}"#, cont_url()),
            vec![db],
        ),
        // Two exempt values around a credential, and one after it.
        (
            format!(
                r#"{{"a":"{CONT}","dsn":{url},"b":"{CONT}","k":"{}"}}"#,
                gho()
            ),
            format!(r#"{{"a":"{CONT}","dsn":"{MARK}","b":"{CONT}","k":"{MARK}"}}"#),
            vec![db, gh],
        ),
    ];
    for (doc, want, found) in rows {
        let (out, mut findings) = deliver(&doc);
        findings.sort();
        assert_eq!(out, want, "{doc}");
        assert_eq!(findings, found, "{doc}");
    }
}
