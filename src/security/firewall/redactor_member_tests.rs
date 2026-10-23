// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-8756: a JSON member whose key is one of the generic API-key rule's
//! names (`api_key`, `apikey`, `secret_key`, any case, also as a `_`/`-`
//! suffix) and whose whole string value is in that rule's class (20+ of
//! `[A-Za-z0-9+/=]`) is delivered with the value replaced by the marker.
//!
//! Parsed members are paired in `scan_recursive`'s object arm; JSON-in-text
//! members are paired inside MIK-8745's walk, so those rows stay red until
//! that walk lands (see the red record). Findings stay one per matched raw
//! pattern, plus one per member.

use super::*;
use serde_json::{Value, json};

const MARK: &str = "[REDACTED:credential]";
const MEMBER: &str = "Credential detected: Generic API Key in key=value (object member)";
const AWS: &str = "Credential detected: AWS Access Key ID";
const PAT: &str = "Credential detected: GitHub Personal Access Token";

fn redactor() -> Redactor {
    Redactor::new()
}

/// `n` characters of the rule's value class, built at run time so no
/// credential-shaped literal sits in source; includes `+`, `/` and `=`.
fn class_value(n: usize) -> String {
    "Ab3+Qz9/Kx7=Mn2".chars().cycle().take(n).collect()
}

/// An AWS-shaped access key id: it matches the AWS rule and the member class.
fn aws_value() -> String {
    format!("{}{}", "AK", "IA") + &"Q7RZ2XW4PL9MBN6K".to_owned()
}

/// A GitHub PAT: it matches its own rule, and `_` keeps it out of the class.
fn pat_value() -> String {
    format!("{}{}", "gh", "p_") + &"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
}

/// Redact `value` with nothing exempt; return the findings.
fn scan(value: &mut Value) -> Vec<Finding> {
    redactor().scan_and_redact(value)
}

fn descriptions(findings: &[Finding]) -> Vec<String> {
    let mut out: Vec<String> = findings.iter().map(|f| f.description.clone()).collect();
    out.sort();
    out
}

/// The full shape of one member finding (test plan, R1 and R2 blanket rows).
fn assert_member_finding(finding: &Finding) {
    assert_eq!(finding.description, MEMBER);
    assert_eq!(finding.scan_type, ScanType::Credentials);
    assert_eq!(finding.severity, crate::security::Severity::High);
    assert_eq!(finding.location, FindingLocation::ResponseContent);
    assert_eq!(
        finding.matched, MARK,
        "an excerpt must never carry the secret"
    );
}

// ─── R1: parsed members (red on base) ───────────────────────────────────────

const KEYS: &[&str] = &[
    "api_key",
    "api-key",
    "apikey",
    "apiKey",
    "secret_key",
    "secret-key",
    "secretkey",
    "secretKey",
    "API_KEY",
    "x-api-key",
    "openai_api_key",
];

#[test]
fn r1_parsed_member_value_is_redacted_with_one_member_finding() {
    for key in KEYS {
        for n in [20, 40, 64] {
            let mut value = json!({ *key: class_value(n), "other": "kept" });
            let findings = scan(&mut value);
            assert_eq!(value[*key], MARK, "{key} len {n}: value redacted");
            assert_eq!(value["other"], "kept", "{key} len {n}: sibling untouched");
            assert!(value.get(*key).is_some(), "{key}: key name unchanged");
            assert_eq!(findings.len(), 1, "{key} len {n}: one finding");
            assert_member_finding(&findings[0]);
        }
    }
}

#[test]
fn r1b_member_that_also_matches_a_raw_rule_keeps_both_findings_one_replacement() {
    let mut value = json!({ "api_key": aws_value() });
    let findings = scan(&mut value);
    assert_eq!(value["api_key"], MARK, "the whole value is the marker");
    assert_eq!(
        descriptions(&findings),
        vec![AWS.to_owned(), MEMBER.to_owned()]
    );
}

#[test]
fn r1c_exempt_values_stay_beside_a_redacted_secret() {
    let exempt_member = class_value(24);
    let exempt_aws = aws_value();
    let mut value = json!({ "api_key": exempt_member, "data": exempt_aws, "pat": pat_value() });
    let (m, a) = (exempt_member.clone(), exempt_aws.clone());
    let findings = redactor().scan_and_redact_unless(&mut value, &|s| s == m || s == a);
    assert_eq!(value["api_key"], exempt_member);
    assert_eq!(value["data"], exempt_aws);
    assert_eq!(value["pat"], MARK);
    assert_eq!(descriptions(&findings), vec![PAT.to_owned()]);
}

#[test]
fn r2h_parsed_two_members_both_redacted() {
    let mut value = json!({ "api_key": class_value(24), "secret_key": class_value(30) });
    let findings = scan(&mut value);
    assert_eq!(value["api_key"], MARK);
    assert_eq!(value["secret_key"], MARK);
    assert_eq!(findings.len(), 2);
    findings.iter().for_each(assert_member_finding);
}

// ─── R2: JSON-in-text members (red until MIK-8745's walk, then this PR) ─────

/// Deliver `text` as a tool answer's text block; return the delivered text
/// and the findings.
fn deliver(text: &str) -> (String, Vec<Finding>) {
    deliver_unless(text, &|_| false)
}

fn deliver_unless(text: &str, exempt: &dyn Fn(&str) -> bool) -> (String, Vec<Finding>) {
    let mut value = json!({ "content": [{ "type": "text", "text": text }] });
    let findings = redactor().scan_and_redact_unless(&mut value, exempt);
    let out = value["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    (out, findings)
}

/// The two carriers every R2 row runs on: compact, and the pretty text
/// `wrap_tool_success` writes (`serde_json::to_string_pretty`).
fn carriers(doc: &Value) -> [String; 2] {
    [
        serde_json::to_string(doc).expect("compact"),
        serde_json::to_string_pretty(doc).expect("pretty"),
    ]
}

/// The R2 blanket assertions: the delivered text parses, it equals the input
/// with only the named members' values replaced by the marker, and there is
/// one full-shape member finding per member.
fn assert_members_redacted(input: &str, members: &[&str]) {
    let (out, findings) = deliver(input);
    let mut want: Value = serde_json::from_str(input).expect("input parses");
    let got: Value = serde_json::from_str(&out).expect("output still parses");
    for path in members {
        *want.pointer_mut(path).expect("member path") = Value::String(MARK.to_owned());
    }
    assert_eq!(got, want, "only the member values change: {input}");
    let member_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.description == MEMBER)
        .collect();
    assert_eq!(
        member_findings.len(),
        members.len(),
        "member findings: {input}"
    );
    member_findings.into_iter().for_each(assert_member_finding);
    assert!(
        !out.contains(&class_value(20)),
        "no value bytes survive: {out}"
    );
}

#[test]
fn r2a_r2b_member_in_compact_and_pretty_text() {
    for text in carriers(&json!({ "status": "ok", "api_key": class_value(32) })) {
        assert_members_redacted(&text, &["/api_key"]);
    }
}

#[test]
fn r2c_member_is_the_only_secret_in_the_leaf() {
    // No raw pattern matches this text: ruling A must still admit it.
    let text = serde_json::to_string(&json!({ "secret_key": class_value(40) })).expect("json");
    assert!(
        redactor().credential_spans(&text).is_empty(),
        "no raw span on base"
    );
    assert_members_redacted(&text, &["/secret_key"]);
}

#[test]
fn r2d_escaped_key_spellings_are_paired_by_their_decoded_name() {
    let v = class_value(24);
    // Built at run time: a JSON unicode escape written in source was once
    // decoded by tooling before it reached the file (the row then tested
    // nothing).
    let bs = char::from(92);
    let keys = [
        format!("{bs}u0061pi_key"),
        format!("api{bs}u005Fkey"),
        ["0061", "0070", "0069", "005f", "006b", "0065", "0079"]
            .iter()
            .map(|h| format!("{bs}u{h}"))
            .collect::<String>(),
    ];
    for key in &keys {
        let compact = format!(r#"{{"{key}":"{v}"}}"#);
        let pretty = format!("{{\n  \"{key}\": \"{v}\"\n}}");
        for text in [compact, pretty] {
            assert!(
                !text.contains("api_key"),
                "the raw text hides the name: {text}"
            );
            assert_members_redacted(&text, &["/api_key"]);
        }
    }
}

#[test]
fn r2e_member_inside_a_top_level_array() {
    for text in carriers(&json!([{ "api_key": class_value(28) }])) {
        assert_members_redacted(&text, &["/0/api_key"]);
    }
}

#[test]
fn r2f_exempt_member_beside_a_pat_in_text() {
    let exempt = class_value(24);
    let pat = pat_value();
    for text in carriers(&json!({ "api_key": exempt, "token": pat })) {
        let e = exempt.clone();
        let (out, findings) = deliver_unless(&text, &|s| s == e);
        let got: Value = serde_json::from_str(&out).expect("parses");
        assert_eq!(got["api_key"], exempt, "exempt value untouched");
        assert_eq!(got["token"], MARK, "PAT replaced");
        assert_eq!(descriptions(&findings), vec![PAT.to_owned()]);
    }
}

#[test]
fn r2g_exempt_aws_value_beside_a_pat_in_text() {
    let aws = aws_value();
    let pat = pat_value();
    for text in carriers(&json!({ "data": aws, "pat": pat })) {
        let a = aws.clone();
        let (out, findings) = deliver_unless(&text, &|s| s == a);
        let got: Value = serde_json::from_str(&out).expect("parses");
        assert_eq!(got["data"], aws, "exempt AWS bytes unchanged");
        assert_eq!(got["pat"], MARK);
        assert_eq!(descriptions(&findings), vec![PAT.to_owned()]);
    }
}

#[test]
fn r2h_two_members_in_text() {
    for text in carriers(&json!({ "api_key": class_value(24), "secret_key": class_value(30) })) {
        assert_members_redacted(&text, &["/api_key", "/secret_key"]);
    }
}

// ─── S: the MIK-8745 projection seam ─────────────────────────────────────────

#[test]
fn s1_member_and_pat_in_one_splice() {
    let text = serde_json::to_string(&json!({ "api_key": class_value(24), "pat": pat_value() }))
        .expect("json");
    let (out, findings) = deliver(&text);
    let got: Value = serde_json::from_str(&out).expect("parses");
    assert_eq!(got["api_key"], MARK);
    assert_eq!(got["pat"], MARK);
    assert_eq!(
        descriptions(&findings),
        vec![PAT.to_owned(), MEMBER.to_owned()]
    );
    for f in &findings {
        assert!(
            !f.matched.contains(&class_value(24)),
            "no member secret in {}",
            f.matched
        );
        assert!(
            !f.matched.contains(&pat_value()[4..]),
            "no PAT in {}",
            f.matched
        );
    }
}

#[test]
fn s2_member_that_is_also_aws_shaped_in_text() {
    let text = serde_json::to_string(&json!({ "api_key": aws_value() })).expect("json");
    let (out, findings) = deliver(&text);
    let got: Value = serde_json::from_str(&out).expect("parses");
    assert_eq!(got["api_key"], MARK, "one replacement");
    assert_eq!(
        descriptions(&findings),
        vec![AWS.to_owned(), MEMBER.to_owned()]
    );
}

#[test]
fn s3_clean_json_text_with_odd_spacing_is_byte_identical() {
    // Spacing serde_json would rewrite: 4-space indent, space before colon.
    for text in [
        "{\n    \"status\" : \"ok\",\n    \"n\" :  3\n}",
        "[ { \"id\" : 1 } ,\n      { \"id\" : 2 } ]",
    ] {
        let (out, findings) = deliver(text);
        assert_eq!(out, text, "byte-identical");
        assert!(findings.is_empty());
    }
}

#[test]
fn s4_exempt_member_and_exempt_aws_in_text_leave_the_leaf_identical() {
    let member = class_value(24);
    let aws = aws_value();
    let text = format!("{{\n    \"api_key\" : \"{member}\",\n    \"data\" : \"{aws}\"\n}}");
    let (m, a) = (member.clone(), aws.clone());
    let (out, findings) = deliver_unless(&text, &|s| s == m || s == a);
    assert_eq!(out, text, "byte-identical");
    assert!(findings.is_empty());
}

// ─── Pins: green on base and after ───────────────────────────────────────────

#[test]
fn p1_values_outside_the_class_are_kept() {
    for v in [
        class_value(19),
        format!("{}-x", class_value(24)),
        format!("{}_x", class_value(24)),
        format!("{}.x", class_value(24)),
        format!("{} x", class_value(24)),
    ] {
        let mut value = json!({ "api_key": v.clone() });
        assert!(scan(&mut value).is_empty(), "{v}");
        assert_eq!(value["api_key"], v);
    }
}

#[test]
fn p2_p3_non_string_values_and_their_neighbours_are_kept() {
    let bait = class_value(24);
    let docs = [
        json!({ "api_key": 123 }),
        json!({ "api_key": null }),
        json!({ "api_key": { "nested": 1 } }),
        json!({ "api_key": null, bait.clone(): 1 }),
        json!({ "api_key": { bait.clone(): 1 } }),
    ];
    for doc in &docs {
        let mut parsed = doc.clone();
        assert!(scan(&mut parsed).is_empty(), "parsed {doc}");
        assert_eq!(&parsed, doc);
        for text in carriers(doc) {
            let (out, findings) = deliver(&text);
            assert_eq!(out, text, "text unchanged: {text}");
            assert!(findings.is_empty());
        }
    }
}

#[test]
fn p4_near_miss_key_names_are_kept() {
    for key in [
        "api_key_id",
        "apikeys",
        "token_count",
        "next_token",
        "rapikey",
        "openaiApiKey",
    ] {
        let v = class_value(24);
        let mut value = json!({ key: v.clone() });
        assert!(scan(&mut value).is_empty(), "{key}");
        assert_eq!(value[key], v);
    }
}

#[test]
fn p5_exempt_parsed_member_is_kept() {
    let v = class_value(24);
    let mut value = json!({ "api_key": v.clone() });
    let e = v.clone();
    assert!(
        redactor()
            .scan_and_redact_unless(&mut value, &|s| s == e)
            .is_empty()
    );
    assert_eq!(value["api_key"], v);
}

#[test]
fn p6_leaf_over_the_walk_cap_keeps_today_s_path() {
    // B2's cap (1 MiB, MIK-8745) sends a larger leaf down today's regex
    // path, where a member is not paired: a known gap, named in the PR.
    let pad = "x".repeat(1 << 20);
    let text =
        serde_json::to_string(&json!({ "pad": pad, "api_key": class_value(24) })).expect("json");
    let (out, findings) = deliver(&text);
    assert_eq!(out, text);
    assert!(findings.is_empty());
}

#[test]
fn p7_broken_json_text_keeps_today_s_path() {
    let text = format!("{{ \"api_key\": \"{}\"", class_value(24));
    let (out, findings) = deliver(&text);
    assert_eq!(out, text, "no pairing on a failed parse");
    assert!(findings.is_empty());
}

#[test]
fn p9_redacting_twice_changes_nothing_more() {
    let mut value = json!({ "api_key": class_value(24), "content": [{ "type": "text",
        "text": serde_json::to_string(&json!({ "secret_key": class_value(30) })).expect("json") }] });
    scan(&mut value);
    let once = value.clone();
    assert!(scan(&mut value).is_empty(), "second pass finds nothing");
    assert_eq!(value, once);
}
