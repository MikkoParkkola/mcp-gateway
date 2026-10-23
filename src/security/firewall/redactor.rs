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

use super::json_literal::{self, Literal};
use super::{Finding, FindingLocation, ScanType};
use crate::security::Severity;

/// The largest JSON-in-text leaf whose credential spans are redacted inside
/// its string values (MIK-8745); a larger one is redacted whole, as before.
const B2_MAX_LEAF_BYTES: usize = 1 << 20;

/// Pre-compiled credential/PII redactor.
pub struct Redactor {
    /// Fast multi-pattern matcher for detection (single DFA pass).
    set: RegexSet,
    /// Individual compiled regexes that locate each matched span.
    regexes: Vec<Regex>,
    /// Human-readable description for each pattern (same index as the regex vec).
    descriptions: Vec<&'static str>,
    /// A JSON member name the generic API-key rule names (MIK-8756).
    member_key: Regex,
    /// A whole JSON member value in the generic API-key rule's class.
    member_value: Regex,
}

/// What [`Redactor::redact_json_text`] did with a leaf.
enum JsonText {
    /// Not a JSON document the walk takes: today's whole-leaf path applies.
    NotJson,
    /// A document with nothing left to redact: the leaf stays byte-identical.
    Kept,
    /// A document with its secret-bearing string values redacted in place.
    Redacted(String),
}

/// The replacement every redaction writes.
const REDACTED: &str = "[REDACTED:credential]";

// The generic API-key rule's two halves, shared by its text pattern and by the
// JSON-member pairing, so the two cannot drift apart (MIK-8756).
macro_rules! api_key_names {
    () => {
        "api[_-]?key|apikey|secret[_-]?key"
    };
}
macro_rules! api_key_value {
    () => {
        "[A-Za-z0-9+/=]{20,}"
    };
}
const API_KEY_DESCRIPTION: &str = "Generic API Key in key=value";

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
        concat!(
            "(?i)(?:",
            api_key_names!(),
            r#")\s*[:=]\s*['"]"#,
            api_key_value!(),
            r#"['"]"#
        ),
        API_KEY_DESCRIPTION,
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
            // invariant: a constant pattern, compiled once at construction.
            member_key: Regex::new(concat!("(?i)(?:^|[_-])(?:", api_key_names!(), ")$"))
                .expect("member key pattern must compile"),
            // invariant: a constant pattern, compiled once at construction.
            member_value: Regex::new(concat!("^", api_key_value!(), "$"))
                .expect("member value pattern must compile"),
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
                if exempt(s) {
                    return;
                }
                // Every JSON document leaf takes the walk, matched or not: a
                // member's name may be escaped in the raw text, so no raw
                // precheck can decide (MIK-8756 ruling A).
                match self.redact_json_text(s, exempt, findings) {
                    JsonText::Redacted(redacted) => *s = redacted,
                    JsonText::Kept => {}
                    JsonText::NotJson => {
                        if self.set.is_match(s)
                            && let Some(redacted) = self.redact_text(s, Site::Value, findings)
                        {
                            *s = redacted;
                        }
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.scan_recursive(item, exempt, findings);
                }
            }
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    // Judged on the value as sent, before the recursion below
                    // rewrites any span in it: a member that also matches a raw
                    // rule keeps that rule's finding and gets one replacement.
                    let member = matches!(&*val, Value::String(s)
                        if self.credential_member(key, s) && !exempt(s));
                    self.scan_recursive(val, exempt, findings);
                    if member {
                        *val = Value::String(REDACTED.to_owned());
                        findings.push(Self::member_finding());
                    }
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
        let redacted = replace_spans(text, &merge_spans(spans));
        self.record_findings(&matched, &redacted, site, findings);
        Some(redacted)
    }

    /// `text` redacted inside the string values a credential span overlaps,
    /// when `text` is a JSON document: today's spans, each clipped to the
    /// value literals it covers and widened to whole escapes. The quotes,
    /// punctuation, keys and scalars a span crosses stay as sent, so the text
    /// still parses (MIK-8745). `None` leaves the leaf to
    /// [`Self::redact_text`]: not a document, over the size cap, or a span
    /// that starts inside a key.
    fn redact_json_text(
        &self,
        text: &str,
        exempt: &dyn Fn(&str) -> bool,
        findings: &mut Vec<Finding>,
    ) -> JsonText {
        if b2_gate(text).is_none() {
            return JsonText::NotJson;
        }
        let literals = json_literal::string_literals(text);
        // A value literal whose decoded text is exempt keeps every byte, and a
        // pattern counts only where it still redacts something (MIK-8756).
        let exempt_lits: Vec<&Literal> = literals
            .iter()
            .filter(|lit| !lit.key && decoded(text, lit).is_some_and(|v| exempt(&v)))
            .collect();
        let overlaps_exempt = |&(start, end): &(usize, usize)| {
            exempt_lits.iter().any(|l| start < l.end && l.start < end)
        };
        let mut matched = Vec::new();
        let mut spans = Vec::new();
        for idx in &self.set.matches(text) {
            let kept: Vec<(usize, usize)> = overlapping_spans(&self.regexes[idx], text)
                .into_iter()
                .filter(|span| !overlaps_exempt(span))
                .collect();
            if !kept.is_empty() {
                matched.push(idx);
                spans.extend(kept);
            }
        }
        spans.sort_unstable();
        let spans = merge_spans(spans);
        let starts_in_value = |at: usize| {
            let after = literals.partition_point(|lit| lit.start <= at);
            after
                .checked_sub(1)
                .is_some_and(|i| at < literals[i].end && !literals[i].key)
        };
        if !spans.iter().all(|&(start, _)| starts_in_value(start)) {
            tracing::debug!(
                "a credential span starts outside a string value; redacting the leaf whole"
            );
            return JsonText::NotJson;
        }
        let members = self.member_values(text, &literals, exempt);
        if spans.is_empty() && members.is_empty() {
            return JsonText::Kept;
        }
        let mut ranges = project(text, &spans, &literals);
        ranges.extend(members.iter().map(|lit| (lit.start, lit.end)));
        ranges.sort_unstable();
        let redacted = replace_spans(text, &merge_spans(ranges));
        self.record_findings(&matched, &redacted, Site::Value, findings);
        findings.extend(members.iter().map(|_| Self::member_finding()));
        JsonText::Redacted(redacted)
    }

    /// The value literals of `text`'s credential-named members: a key literal
    /// followed, after `:` and whitespace only, by a string value whose
    /// decoded text the member rule accepts and `exempt` does not. Keys and
    /// values are compared decoded, so an escaped name is still a name.
    fn member_values<'a>(
        &self,
        text: &str,
        literals: &'a [Literal],
        exempt: &dyn Fn(&str) -> bool,
    ) -> Vec<&'a Literal> {
        literals
            .windows(2)
            .filter(|pair| pair[0].key && !pair[1].key)
            .filter(|pair| text[pair[0].end + 1..pair[1].start - 1].trim() == ":")
            .filter(|pair| {
                matches!(
                    (decoded(text, &pair[0]), decoded(text, &pair[1])),
                    (Some(key), Some(value))
                        if self.credential_member(&key, &value) && !exempt(&value)
                )
            })
            .map(|pair| &pair[1])
            .collect()
    }

    /// One finding per matched pattern, showing `redacted`.
    fn record_findings(
        &self,
        matched: &[usize],
        redacted: &str,
        site: Site,
        findings: &mut Vec<Finding>,
    ) {
        // A finding shows the redacted text: a bare 40-char token would
        // otherwise survive the truncation whole in the in-process excerpt.
        let suffix = match site {
            Site::Value => "",
            Site::Key => " (object key)",
        };
        for &idx in matched {
            findings.push(Finding {
                scan_type: ScanType::Credentials,
                severity: Severity::High,
                description: format!("Credential detected: {}{suffix}", self.descriptions[idx]),
                // Truncate so the actual secret is not propagated.
                matched: truncate(redacted, 40),
                location: FindingLocation::ResponseContent,
            });
        }
    }

    /// A JSON member the generic API-key rule describes: the key is one of its
    /// names (any case, alone or after `_`/`-`) and the whole value is in its
    /// class (MIK-8756). The rule itself needs both halves in one string, which a
    /// parsed member never is.
    fn credential_member(&self, key: &str, value: &str) -> bool {
        self.member_key.is_match(key) && self.member_value.is_match(value)
    }

    fn member_finding() -> Finding {
        Finding {
            scan_type: ScanType::Credentials,
            severity: Severity::High,
            description: format!("Credential detected: {API_KEY_DESCRIPTION} (object member)"),
            matched: REDACTED.to_owned(),
            location: FindingLocation::ResponseContent,
        }
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

/// `lit`'s content decoded, quotes included in the parse, so JSON escapes
/// read as the characters they stand for.
fn decoded(text: &str, lit: &Literal) -> Option<String> {
    serde_json::from_str::<String>(&text[lit.start - 1..lit.end + 1]).ok()
}

/// The parsed document when `text` is JSON whose credential spans can be
/// redacted inside its string values: an object, an array or a string, within
/// the size cap. One function, so MIK-8756 can widen the entry.
fn b2_gate(text: &str) -> Option<Value> {
    let opens = matches!(
        text.trim_start().as_bytes().first(),
        Some(b'{' | b'[' | b'"')
    );
    if text.len() > B2_MAX_LEAF_BYTES || !opens {
        return None;
    }
    serde_json::from_str::<Value>(text)
        .ok()
        .filter(|value| value.is_object() || value.is_array() || value.is_string())
}

/// `spans` (merged, in order) clipped to every value literal they overlap,
/// each piece widened to whole escapes so no escape is cut, then merged.
/// Spans and literals are both in order, so this is one pass over each, and
/// each end is widened by a binary search of its literal's escapes.
fn project(text: &str, spans: &[(usize, usize)], literals: &[Literal]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut first = 0;
    for lit in literals.iter().filter(|lit| !lit.key) {
        while first < spans.len() && spans[first].1 <= lit.start {
            first += 1;
        }
        let mut lit_escapes = None;
        for &(start, end) in spans[first..].iter().take_while(|span| span.0 < lit.end) {
            let (mut from, mut to) = (start.max(lit.start), end.min(lit.end));
            if from >= to {
                continue; // an empty value: the span covers none of its bytes
            }
            let escapes = lit_escapes
                .get_or_insert_with(|| json_literal::escapes(&text[lit.start..lit.end], lit.start));
            if let Some(escape) = escape_around(escapes, from) {
                from = escape.0;
            }
            if let Some(escape) = escape_around(escapes, to) {
                to = escape.1;
            }
            ranges.push((from, to));
        }
    }
    ranges.sort_unstable();
    merge_spans(ranges)
}

/// The escape in `escapes` (in order, disjoint) that `at` falls strictly
/// inside, if any.
fn escape_around(escapes: &[(usize, usize)], at: usize) -> Option<(usize, usize)> {
    let after = escapes.partition_point(|escape| escape.0 < at);
    after
        .checked_sub(1)
        .map(|i| escapes[i])
        .filter(|escape| at < escape.1)
}

/// `text` with every range in `ranges` (merged, in order) replaced by the
/// redaction marker.
fn replace_spans(text: &str, ranges: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for &(start, end) in ranges {
        out.push_str(&text[cursor..start]);
        out.push_str(REDACTED);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
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

#[cfg(test)]
#[path = "redactor_b2_tests.rs"]
mod b2_tests;

#[cfg(test)]
#[path = "redactor_member_tests.rs"]
mod member_tests;
