// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use serde_json::json;

fn redactor() -> Redactor {
    Redactor::new()
}

// ── Detection ─────────────────────────────────────────────────────────────

#[test]
fn detects_aws_access_key() {
    let mut v = json!({ "key": "AKIAIOSFODNN7EXAMPLE12345" });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.scan_type == ScanType::Credentials)
    );
    assert!(findings.iter().any(|f| f.description.contains("AWS")));
}

#[test]
fn detects_github_pat() {
    let mut v = json!({ "token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890" });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("GitHub Personal"))
    );
}

#[test]
fn unicode_fragment_truncation_does_not_panic() {
    let fake_credential = format!("{}{}", "ghp_", "abcdefghijklmnopqrstuvwxyz1234567890");
    let mut v = json!({
        "token": format!("{}{} {fake_credential}", "a".repeat(39), "—")
    });
    let findings = redactor().scan_and_redact(&mut v);

    let finding = findings
        .iter()
        .find(|f| f.scan_type == ScanType::Credentials)
        .expect("expected credential finding");
    assert!(finding.matched.ends_with("..."));
}

#[test]
fn detects_github_oauth_token() {
    let mut v = json!({ "token": "gho_abcdefghijklmnopqrstuvwxyz1234567890" });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("GitHub OAuth"))
    );
}

#[test]
fn detects_github_app_token() {
    let mut v = json!({ "token": "ghs_abcdefghijklmnopqrstuvwxyz1234567890" });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("GitHub App"))
    );
}

#[test]
fn detects_slack_token() {
    // Build the token dynamically to avoid GitHub push protection false positive
    let slack_token = format!("xoxb-{}-abcdefghijklmnop", "1234567890");
    let mut v = json!({ "token": slack_token });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(findings.iter().any(|f| f.description.contains("Slack")));
}

#[test]
fn detects_jwt_in_response() {
    let mut v = json!({ "auth": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("JSON Web Token"))
    );
}

#[test]
fn detects_private_key_header() {
    let mut v = json!({ "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..." });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("Private Key"))
    );
}

#[test]
fn detects_bearer_token() {
    let mut v = json!({ "header": "Authorization: bearer eyJhbGciOiJIUzI1NiJ9_abcdefghijklmnopqrstuvwxyz" });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(findings.iter().any(|f| f.description.contains("Bearer")));
}

#[test]
fn detects_database_connection_string() {
    let mut v = json!({ "dsn": "postgres://user:secret@db.example.com:5432/mydb" });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("Database Connection"))
    );
}

#[test]
fn detects_openai_project_key() {
    // Synthetic, self-labelling non-secret that still matches the
    // `sk-proj-[A-Za-z0-9_-]{40,}` detector. Kept obviously fake so naive
    // external secret scanners stop filing false-positive "leaked key"
    // reports against this redaction test (see closed issues #376/#377).
    let key = "sk-proj-FAKE_EXAMPLE_KEY_FOR_REDACTION_UNIT_TEST_000000";
    let mut v = serde_json::json!({ "key": key });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("OpenAI Project")),
        "Expected OpenAI key detection"
    );
}

#[test]
fn detects_ethereum_private_key() {
    let key = format!(
        "0x{}{}",
        "ac0974bec39a17e36ba4a6b4d238ff944", "bacb478cbed5efcae784d7bf4f2ff80"
    );
    let mut v = serde_json::json!({ "pk": key });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        findings.iter().any(|f| f.description.contains("Ethereum")),
        "Expected Ethereum key detection"
    );
}

// ── Redaction ─────────────────────────────────────────────────────────────

#[test]
fn redacts_credential_in_place() {
    let mut v = json!({ "output": "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890 done" });
    redactor().scan_and_redact(&mut v);
    let s = v["output"].as_str().unwrap();
    assert!(
        s.contains("[REDACTED:credential]"),
        "Expected redaction, got: {s}"
    );
    assert!(!s.contains("ghp_"), "Token should be redacted, got: {s}");
    // Surrounding text should be preserved
    assert!(s.contains("token: "), "Prefix should remain: {s}");
    assert!(s.contains(" done"), "Suffix should remain: {s}");
}

#[test]
fn clean_response_passes_through_unchanged() {
    let original = json!({ "result": "The answer is 42", "items": [1, 2, 3] });
    let mut v = original.clone();
    let findings = redactor().scan_and_redact(&mut v);
    assert!(findings.is_empty());
    assert_eq!(v, original);
}

#[test]
fn nested_credential_redacted() {
    let mut v = json!({
        "data": {
            "nested": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        }
    });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(!findings.is_empty());
    let nested = v["data"]["nested"].as_str().unwrap();
    assert!(nested.contains("[REDACTED:credential]"));
    assert!(!nested.contains("ghp_"));
}

#[test]
fn credential_in_array_redacted() {
    let mut v = json!({
        "tokens": [
            "normal_string",
            "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        ]
    });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(!findings.is_empty());
    let second = v["tokens"][1].as_str().unwrap();
    assert!(second.contains("[REDACTED:credential]"));
}

// ── Severity ──────────────────────────────────────────────────────────────

#[test]
fn credential_finding_has_high_severity() {
    let mut v = json!({ "key": "AKIAIOSFODNN7EXAMPLE12345" });
    let findings = redactor().scan_and_redact(&mut v);
    let f = findings
        .iter()
        .find(|f| f.scan_type == ScanType::Credentials)
        .unwrap();
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.location, FindingLocation::ResponseContent);
}

// ── Object keys (#2114) ───────────────────────────────────────────────────

/// Plainly synthetic 40-char GitHub-shaped tokens, built at runtime like
/// the fixture above so no token-shaped literal sits in the source.
fn token_a() -> String {
    format!("{}{}", "ghp_", "abcdefghijklmnopqrstuvwxyz1234567890")
}

fn token_b() -> String {
    format!("{}{}0", "ghp_", "EXAMPLE".repeat(5))
}

#[test]
fn redacts_credential_in_object_key() {
    let mut v = json!({ token_a(): 1 });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 1, "one finding for the key: {findings:?}");
    assert!(findings[0].description.contains("(object key)"));
    assert_eq!(v, json!({ "[REDACTED:credential]": 1 }));
}

/// Synthetic 0x + 64-hex key. It sorts BEFORE `[`, so it is visited ahead
/// of the clean `[REDACTED:credential]` key: a rebuild that does not
/// reserve clean names first would let that clean key overwrite it.
fn hex_key() -> String {
    format!("0x{}", "ab".repeat(32))
}

#[test]
fn redacted_keys_stay_unique() {
    let mut v = json!({
        hex_key(): 1,
        token_b(): 2,
        "[REDACTED:credential]": 3,
        "[REDACTED:credential]#2": 4,
    });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 2);
    // Clean keys keep their names; redacted keys take suffixes in map order.
    assert_eq!(
        v,
        json!({
            "[REDACTED:credential]": 3,
            "[REDACTED:credential]#2": 4,
            "[REDACTED:credential]#3": 1,
            "[REDACTED:credential]#4": 2,
        })
    );
}

#[test]
fn redacts_nested_key_and_keeps_surrounding_text() {
    let mut v = json!({ "outer": { format!("x-{} y", token_a()): token_b() } });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 2, "one for the key, one for its value");
    assert_eq!(
        v,
        json!({ "outer": { "x-[REDACTED:credential] y": "[REDACTED:credential]" } })
    );
}

#[test]
fn clean_keys_are_untouched() {
    let mut v = json!({ "plain": "text", "nested": { "also_plain": 1 } });
    let original = v.clone();
    assert!(redactor().scan_and_redact(&mut v).is_empty());
    assert_eq!(v, original);
}

#[test]
fn key_finding_does_not_carry_the_secret() {
    let mut v = json!({ token_a(): 1 });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 1);
    assert!(
        !findings[0].matched.contains("ghp_"),
        "a 40-char token survives truncation whole: {:?}",
        findings[0].matched
    );
}

// ── #2210: a real token is redacted wherever it sits ────────────────────

/// A token glued after letters or digits is still a credential. Split with
/// `concat!` so no literal token sits here.
#[test]
fn a_token_glued_after_letters_or_digits_is_redacted() {
    for token in [
        concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
        concat!("gh", "s_abcdefghijklmnopqrstuvwxyz0123456789"),
        concat!("xo", "xb-1234567890abcdef"),
    ] {
        for glued in [
            format!("abc{token}"),
            format!("9{token}"),
            format!("x-{token}"),
        ] {
            let mut v = json!({ "t": glued });
            let findings = redactor().scan_and_redact(&mut v);
            assert_eq!(findings.len(), 1, "{glued}: {findings:?}");
            assert!(!v["t"].as_str().unwrap().contains(token), "{glued}");
        }
    }
}

/// A token followed by more token characters is still a credential.
#[test]
fn a_token_followed_by_a_suffix_is_redacted() {
    let token = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789");
    for glued in [
        format!("{token}_suffix"),
        format!("{token}-more"),
        format!("{token}Z9"),
    ] {
        let mut v = json!({ "t": glued });
        let findings = redactor().scan_and_redact(&mut v);
        assert_eq!(findings.len(), 1, "{glued}: {findings:?}");
        assert!(!v["t"].as_str().unwrap().contains(token), "{glued}");
    }
}

/// Two real tokens sharing one space are both still redacted.
#[test]
fn delimited_tokens_sharing_a_separator_are_both_redacted() {
    let a = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789");
    let b = concat!("gh", "o_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    let mut v = json!({ "t": format!("{a} {b}") });
    redactor().scan_and_redact(&mut v);
    assert_eq!(v["t"], "[REDACTED:credential] [REDACTED:credential]");
}

// ── #2145: overlapping patterns are redacted as one span ────────────────

/// A quoted `api_key` value with an AWS-shaped run inside it: both the AWS
/// and the generic key=value pattern match, and the AWS span sits inside
/// the generic one. Lowercase padding keeps the AWS match to its 20 chars.
fn nested_aws_in_api_key() -> String {
    format!(
        "cfg api_key=\"abcd{}EXAMPLEKEY012345wxyz\" end",
        concat!("AK", "IA")
    )
}

#[test]
fn a_credential_inside_another_leaves_no_fragment() {
    let mut v = json!({ "t": nested_aws_in_api_key() });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 2, "AWS and generic key: {findings:?}");
    assert_eq!(v["t"], "cfg [REDACTED:credential] end");
}

#[test]
fn an_overlapping_key_leaves_no_fragment_in_key_or_finding() {
    let mut v = json!({ nested_aws_in_api_key(): 1 });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(v, json!({ "cfg [REDACTED:credential] end": 1 }));
    assert_eq!(findings.len(), 2, "{findings:?}");
    for finding in &findings {
        assert_eq!(finding.matched, "cfg [REDACTED:credential] end");
    }
}

/// The GitHub span ends inside the AWS span: neither contains the other.
#[test]
fn partially_overlapping_credentials_leave_no_fragment() {
    let text = format!(
        "{}{}{}ZZEXAMPLEKEY0123 end",
        concat!("gh", "p_"),
        "abcdefghij".repeat(3),
        concat!("AK", "IA")
    );
    let mut v = json!({ "t": text });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 2, "GitHub and AWS: {findings:?}");
    assert_eq!(v["t"], "[REDACTED:credential] end");
}

/// Two matches of ONE pattern overlap: the second AWS key starts inside
/// the first, where a scan resuming after the first match would miss it.
fn overlapping_aws_keys() -> String {
    let prefix = concat!("AK", "IA");
    format!("{prefix}{}{prefix}{} end", "A".repeat(12), "B".repeat(16))
}

#[test]
fn overlapping_matches_of_one_pattern_leave_no_fragment() {
    let mut v = json!({ "t": overlapping_aws_keys() });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(v["t"], "[REDACTED:credential] end");
}

#[test]
fn overlapping_matches_of_one_pattern_in_a_key_leave_no_fragment() {
    let mut v = json!({ overlapping_aws_keys(): 1 });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(v, json!({ "[REDACTED:credential] end": 1 }));
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].matched, "[REDACTED:credential] end");
}

/// Touching tokens share one marker; multibyte text around them is kept.
#[test]
fn touching_tokens_share_one_marker_and_keep_multibyte_text() {
    let a = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789");
    let b = concat!("gh", "o_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    let mut v = json!({ "t": format!("é—{a}{b}\u{a0}ü") });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert_eq!(v["t"], "é—[REDACTED:credential]\u{a0}ü");
}

/// `overlapping_spans` restarts one char after each match start, which
/// assumes no pattern can match empty text.
#[test]
fn no_credential_pattern_matches_empty_text() {
    for re in &redactor().regexes {
        assert!(!re.is_match(""), "{re}");
    }
}

/// A repeated prefix makes every position start a match that runs to the
/// end of the text. Restarting deep inside it would rescan the text from
/// every start: about 10^10 steps here, where the bounded restart takes a
/// few milliseconds.
#[test]
fn a_repeated_token_prefix_is_redacted_in_linear_time() {
    let text = concat!("xo", "xb-").repeat(100_000);
    let started = std::time::Instant::now();
    let mut v = json!({ "t": text });
    let findings = redactor().scan_and_redact(&mut v);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(v["t"], "[REDACTED:credential]");
}

/// A JWT that starts at another's second segment, behind a long third
/// segment: its signature lies past the first match and far outside a
/// restart window, so the whole segment chain must be one match.
fn chained_jwts() -> String {
    let seg = |n: usize| format!("{}{}", concat!("ey", "J"), "a".repeat(n));
    format!(
        "{}.{}.{}.{} end",
        seg(10),
        seg(10),
        seg(512),
        "s".repeat(43)
    )
}

#[test]
fn a_jwt_overlapping_another_leaves_no_signature() {
    let mut v = json!({ "t": chained_jwts() });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(v["t"], "[REDACTED:credential] end");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].matched, "[REDACTED:credential] end");
}

#[test]
fn a_jwt_overlapping_another_in_a_key_leaves_no_signature() {
    let mut v = json!({ chained_jwts(): 1 });
    let findings = redactor().scan_and_redact(&mut v);
    assert_eq!(v, json!({ "[REDACTED:credential] end": 1 }));
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].matched, "[REDACTED:credential] end");
}
