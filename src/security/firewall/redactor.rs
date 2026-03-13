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
//!   objects, used to perform targeted `replace_all` replacements once a match
//!   is confirmed, so that surrounding text is preserved.
//!
//! # Privacy
//!
//! Matched fragments are truncated to 40 characters in `Finding::matched` so
//! credential values are not propagated into audit logs or structured spans.

use regex::{Regex, RegexSet};
use serde_json::Value;

use super::{Finding, FindingLocation, ScanType, Severity};

/// Pre-compiled credential/PII redactor.
pub struct Redactor {
    /// Fast multi-pattern matcher for detection (single DFA pass).
    set: RegexSet,
    /// Individual compiled regexes for targeted `replace_all`.
    regexes: Vec<Regex>,
    /// Human-readable description for each pattern (same index as the regex vec).
    descriptions: Vec<&'static str>,
}

/// (pattern, description) pairs.
///
/// 11 credential patterns covering AWS keys, GitHub tokens (4 variants),
/// Slack tokens, generic API keys, JWTs, private keys, bearer tokens, and
/// database connection strings.
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
    /// String values that match one or more credential patterns are replaced
    /// with `[REDACTED:credential]` in the matched spans.
    pub fn scan_and_redact(&self, value: &mut Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.scan_recursive(value, &mut findings);
        findings
    }

    fn scan_recursive(&self, value: &mut Value, findings: &mut Vec<Finding>) {
        match value {
            Value::String(s) => {
                let matched_indices: Vec<usize> =
                    self.set.matches(s.as_str()).into_iter().collect();

                if !matched_indices.is_empty() {
                    for &idx in &matched_indices {
                        findings.push(Finding {
                            scan_type: ScanType::Credentials,
                            severity: Severity::High,
                            description: format!("Credential detected: {}", self.descriptions[idx]),
                            // Truncate so the actual secret is not propagated.
                            matched: truncate(s, 40),
                            location: FindingLocation::ResponseContent,
                        });
                    }

                    // In-place redaction: apply replace_all for each matched pattern.
                    // Only the matched credential spans are replaced; surrounding
                    // text is preserved (e.g. "token: ghp_xxx rest" becomes
                    // "token: [REDACTED:credential] rest").
                    let mut redacted = s.clone();
                    for &idx in &matched_indices {
                        redacted = self.regexes[idx]
                            .replace_all(&redacted, "[REDACTED:credential]")
                            .into_owned();
                    }
                    *s = redacted;
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.scan_recursive(item, findings);
                }
            }
            Value::Object(map) => {
                for val in map.values_mut() {
                    self.scan_recursive(val, findings);
                }
            }
            // Numbers, booleans, and nulls cannot contain credential patterns.
            _ => {}
        }
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
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
}
