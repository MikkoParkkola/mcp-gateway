// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Credential detection and redaction in tool response content.
//!
//! Scans JSON response values recursively for sensitive patterns and replaces
//! matched spans with `[REDACTED:credential]` before the response reaches the LLM.
//!
//! # Design
//!
//! Two complementary structures are maintained in parallel:
//!
//! * `credential_patterns` — a `RegexSet` that performs a single-pass check
//!   whether *any* pattern matches a string (fast O(n) detection).
//! * `credential_regexes` — the same patterns compiled as individual `Regex`
//!   objects, used to locate every matched span once a match is confirmed.
//!   Overlapping spans are merged and replaced once, so that surrounding
//!   text is preserved and no fragment of an overlapped match survives.
//!
//! # Privacy
//!
//! A finding's `matched` excerpt is the redacted text, truncated to 40
//! characters, so credential values are not propagated into audit logs or
//! structured spans.

use std::collections::{HashMap, HashSet};

use regex::{Regex, RegexSet};
use serde_json::{Map, Value};

use super::{Finding, FindingLocation, ScanType, Severity};

/// Pre-compiled credential/PII redactor.
pub struct Redactor {
    /// Fast multi-pattern matcher for detection (single DFA pass).
    set: RegexSet,
    /// Individual compiled regexes that locate each matched span.
    regexes: Vec<Regex>,
    /// Human-readable description for each pattern (same index as the regex vec).
    descriptions: Vec<&'static str>,
}

/// (pattern, description) pairs.
///
/// 13 credential patterns covering AWS keys, GitHub tokens (4 variants),
/// Slack tokens, generic API keys, JWTs, private keys, bearer tokens,
/// database connection strings, `OpenAI` project keys, and Ethereum private keys.
const CREDENTIAL_PATTERNS: &[(&str, &str)] = &[
    // AWS
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key ID"),
    // GitHub — personal access token
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    // GitHub — OAuth token
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
    // GitHub — App installation token
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token"),
    // GitHub — refresh token
    (r"ghr_[A-Za-z0-9]{36}", "GitHub Refresh Token"),
    // Slack tokens (bot, user, app, etc.)
    (r"xox[bprs]-[A-Za-z0-9-]{10,}", "Slack Token"),
    // Generic API key in key=value / key: value form
    (
        r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9+/=]{20,}['"]"#,
        "Generic API Key in key=value",
    ),
    // JWT — three base64url segments separated by dots
    (
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "JSON Web Token",
    ),
    // PEM private key header (RSA / EC / DSA or generic)
    (
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "Private Key",
    ),
    // Bearer token in response body text
    (r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}", "Bearer Token"),
    // Database connection strings (postgres, mysql, mongodb, redis)
    (
        r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]{10,}",
        "Database Connection String",
    ),
    // OpenAI project API keys (sk-proj-...)
    (r"sk-proj-[A-Za-z0-9_-]{40,}", "OpenAI Project API Key"),
    // Ethereum private key (0x + 64 hex nibbles = 32 bytes)
    (r"0x[a-fA-F0-9]{64}", "Ethereum Private Key"),
];

impl Redactor {
    /// Create a new redactor, compiling all credential patterns.
    ///
    /// # Panics
    ///
    /// Panics at startup if any pattern is invalid regex — programming error.
    pub fn new() -> Self {
        let patterns: Vec<&str> = CREDENTIAL_PATTERNS.iter().map(|(p, _)| *p).collect();
        let descriptions: Vec<&'static str> = CREDENTIAL_PATTERNS.iter().map(|(_, d)| *d).collect();
        let regexes: Vec<Regex> = patterns
            .iter()
            .map(|p| Regex::new(p).expect("Credential pattern must compile"))
            .collect();

        Self {
            set: RegexSet::new(&patterns).expect("Credential pattern set must compile"),
            regexes,
            descriptions,
        }
    }

    /// Scan a JSON value for credentials. Redact in place and return findings.
    ///
    /// String values and object keys that match one or more credential
    /// patterns have the matched spans replaced with `[REDACTED:credential]`.
    /// A redacted key keeps its entry and gets a unique name (`#2`, `#3`, ...
    /// on collision).
    pub fn scan_and_redact(&self, value: &mut Value) -> Vec<Finding> {
        self.scan_and_redact_unless(value, &|_| false)
    }

    /// [`Self::scan_and_redact`], leaving a string value untouched when
    /// `exempt` accepts it. Only values are exempt; object keys are always
    /// scanned. `exempt` runs only on a value that would otherwise be redacted.
    pub fn scan_and_redact_unless(
        &self,
        value: &mut Value,
        exempt: &dyn Fn(&str) -> bool,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.scan_recursive(value, exempt, &mut findings);
        findings
    }

    fn scan_recursive(
        &self,
        value: &mut Value,
        exempt: &dyn Fn(&str) -> bool,
        findings: &mut Vec<Finding>,
    ) {
        match value {
            Value::String(s) => {
                if self.set.is_match(s)
                    && !exempt(s)
                    && let Some(redacted) = self.redact_text(s, Site::Value, findings)
                {
                    *s = redacted;
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.scan_recursive(item, exempt, findings);
                }
            }
            Value::Object(map) => {
                for val in map.values_mut() {
                    self.scan_recursive(val, exempt, findings);
                }
                // Keys are backend-controlled text the client sees too (#2114).
                if map.keys().any(|key| self.set.is_match(key)) {
                    self.redact_keys(map, findings);
                }
            }
            // Numbers, booleans, and nulls cannot contain credential patterns.
            _ => {}
        }
    }

    /// Record one finding per matched pattern and return `text` with every
    /// matched span replaced, or `None` when nothing matched. Surrounding text
    /// is preserved ("token: <secret> rest" -> "token: [REDACTED:credential] rest").
    fn redact_text(&self, text: &str, site: Site, findings: &mut Vec<Finding>) -> Option<String> {
        let matched: Vec<usize> = self.set.matches(text).into_iter().collect();
        if matched.is_empty() {
            return None;
        }
        // Every span is found in the original text and overlapping spans are
        // replaced once: replacing one pattern's match first can break another
        // match and leave its characters behind (#2145).
        let mut spans: Vec<(usize, usize)> = matched
            .iter()
            .flat_map(|&idx| overlapping_spans(&self.regexes[idx], text))
            .collect();
        spans.sort_unstable();
        let mut redacted = String::with_capacity(text.len());
        let mut cursor = 0;
        for (start, end) in merge_spans(spans) {
            redacted.push_str(&text[cursor..start]);
            redacted.push_str("[REDACTED:credential]");
            cursor = end;
        }
        redacted.push_str(&text[cursor..]);
        // A finding shows the redacted text: a bare 40-char token would
        // otherwise survive the truncation whole into the audit log.
        let suffix = match site {
            Site::Value => "",
            Site::Key => " (object key)",
        };
        let shown = redacted.as_str();
        for &idx in &matched {
            findings.push(Finding {
                scan_type: ScanType::Credentials,
                severity: Severity::High,
                description: format!("Credential detected: {}{suffix}", self.descriptions[idx]),
                // Truncate so the actual secret is not propagated.
                matched: truncate(shown, 40),
                location: FindingLocation::ResponseContent,
            });
        }
        Some(redacted)
    }

    /// Rename credential-bearing keys without losing an entry. Clean keys keep
    /// their names; each redacted key takes its redacted text, or the first
    /// free `<text>#n`, so two keys never collapse into one. A per-name counter
    /// keeps n colliding keys linear rather than re-probing from `#2`.
    fn redact_keys(&self, map: &mut Map<String, Value>, findings: &mut Vec<Finding>) {
        let entries = std::mem::take(map);
        let mut taken: HashSet<String> = entries
            .keys()
            .filter(|key| !self.set.is_match(key))
            .cloned()
            .collect();
        let mut next: HashMap<String, usize> = HashMap::new();
        for (key, value) in entries {
            let Some(candidate) = self.redact_text(&key, Site::Key, findings) else {
                map.insert(key, value);
                continue;
            };
            let n = next.entry(candidate.clone()).or_insert(1);
            let mut name = candidate.clone();
            while taken.contains(&name) {
                *n += 1;
                name = format!("{candidate}#{n}");
            }
            taken.insert(name.clone());
            map.insert(name, value);
        }
    }
}

/// Where a scanned string sits in the JSON tree.
#[derive(Clone, Copy)]
enum Site {
    Value,
    Key,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

/// Every match of `re` in `text`, including matches that overlap one another:
/// `find_iter` resumes after a match's end, so a second credential starting
/// inside the first would be missed. Each search restarts one char after the
/// previous match's start.
// ponytail: a search per match start; every pattern opens with a literal
// prefix, so restarts only land on the next prefix occurrence.
fn overlapping_spans(re: &Regex, text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(m) = re.find_at(text, at) {
        spans.push((m.start(), m.end()));
        // No pattern matches empty text, so `m.start()` is inside `text`.
        at = m.start() + text[m.start()..].chars().next().map_or(1, char::len_utf8);
    }
    spans
}

/// Merge sorted spans that overlap or touch, so no character between two
/// matched spans can survive and touching tokens share one marker.
fn merge_spans(spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }

    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
            for fragment in ["abcd", "wxyz", "EXAMPLEKEY"] {
                assert!(!finding.matched.contains(fragment), "{finding:?}");
            }
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
        assert!(!findings[0].matched.contains("BBBB"), "{findings:?}");
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
}
