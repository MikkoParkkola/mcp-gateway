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
//! characters, so credential values are not propagated into structured
//! spans. The excerpt never reaches the audit log at all: audit rows hold a
//! finding's kind, severity and location only (MIK-8236).

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
    // JWT — base64url segments separated by dots. The whole chain of segments
    // is one match: a JWT that starts at another's second segment then ends
    // with it, so no signature can survive an overlap (#2145).
    (
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})+",
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

    /// The merged byte spans of `text` the credential patterns match: what
    /// [`Self::scan_and_redact`] would replace in it.
    pub(crate) fn credential_spans(&self, text: &str) -> Vec<(usize, usize)> {
        let mut spans: Vec<(usize, usize)> = (self.set.matches(text).into_iter())
            .flat_map(|idx| overlapping_spans(&self.regexes[idx], text))
            .collect();
        spans.sort_unstable();
        merge_spans(spans)
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
        // otherwise survive the truncation whole in the in-process excerpt.
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

/// How far behind the furthest end already matched a restart may begin. The
/// longest fixed-length pattern is 66 bytes, and a match of an unbounded
/// pattern can only overlap the end of another by starting in its short
/// prefix, since the earlier greedy body stopped where its class ends. The JWT
/// pattern takes a whole chain of segments for the same reason: a JWT starting
/// at another's second segment ends with that chain.
const OVERLAP_WINDOW: usize = 256;

/// Every match of `re` in `text`, including matches that overlap one another:
/// `find_iter` resumes after a match's end, so a second credential starting
/// inside the first would be missed. Each search restarts one char after the
/// previous match's start, but never more than [`OVERLAP_WINDOW`] behind the
/// covered end: a restart deep inside a long match would rescan it to its end,
/// quadratic on text like a repeated token prefix.
fn overlapping_spans(re: &Regex, text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let (mut at, mut covered) = (0, 0);
    while let Some(m) = re.find_at(text, at) {
        spans.push((m.start(), m.end()));
        covered = covered.max(m.end());
        if m.start() == text.len() {
            break; // an empty match at the end; no pattern matches empty today
        }
        let next = m.start() + text[m.start()..].chars().next().map_or(1, char::len_utf8);
        let mut floor = covered.saturating_sub(OVERLAP_WINDOW);
        while !text.is_char_boundary(floor) {
            floor -= 1;
        }
        at = next.max(floor);
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
#[path = "redactor_tests.rs"]
mod tests;
