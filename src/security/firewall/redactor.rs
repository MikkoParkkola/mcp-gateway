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
use crate::truncate::{Budget, Suffix, truncate};

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
                    && let Some(redacted) = self
                        .redact_json_text(s, findings)
                        .or_else(|| self.redact_text(s, Site::Value, findings))
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
        merge_spans(self.match_spans(text))
    }

    /// Every match of every credential pattern in `text`, in order, unmerged.
    fn match_spans(&self, text: &str) -> Vec<(usize, usize)> {
        let mut spans: Vec<(usize, usize)> = (self.set.matches(text).into_iter())
            .flat_map(|idx| overlapping_spans(&self.regexes[idx], text))
            .collect();
        spans.sort_unstable();
        spans
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

    /// `text` redacted inside the string literals a credential span covers,
    /// when `text` is a JSON document: today's spans, each clipped to the
    /// value literals it covers, or to the key it starts in, and widened to
    /// whole escapes. The quotes, punctuation, scalars and other keys a span
    /// crosses stay as sent, so the text still parses (MIK-8745). A redacted
    /// key takes the first free name in its object, as [`Self::redact_keys`]
    /// does, so no entry is lost (MIK-8772). `None` leaves the leaf to
    /// [`Self::redact_text`]: not a document, over the size cap, or a span
    /// that starts outside every literal.
    fn redact_json_text(&self, text: &str, findings: &mut Vec<Finding>) -> Option<String> {
        b2_gate(text)?;
        let found = self.match_spans(text);
        let starts: Vec<usize> = found.iter().map(|&(start, _)| start).collect();
        let spans = merge_spans(found);
        let literals = json_literal::string_literals(text);
        let starts_in_literal = |at: usize| {
            let after = literals.partition_point(|lit| lit.start <= at);
            after.checked_sub(1).is_some_and(|i| at < literals[i].end)
        };
        if !spans.iter().all(|&(start, _)| starts_in_literal(start)) {
            tracing::debug!(
                "a credential span starts outside a string literal; redacting the leaf whole"
            );
            return None;
        }
        // A key is redacted when a match starts in it, or when its own text
        // matches: past a greedy match the scan restarts only near its end
        // (OVERLAP_WINDOW), so a later key's start can go unseen.
        let redact_key = |lit: &Literal| {
            let after = starts.partition_point(|&at| at < lit.start);
            starts.get(after).is_some_and(|&at| at < lit.end)
                || self.set.is_match(&text[lit.start..lit.end])
        };
        let ranges = project(text, &spans, redact_key, &literals);
        let redacted = if literals.iter().any(|lit| lit.key && covers(&ranges, lit)) {
            rename_keys(text, &ranges, &literals)
        } else {
            replace_spans(text, &ranges)
        };
        let matched: Vec<usize> = self.set.matches(text).into_iter().collect();
        self.record_findings(&matched, &redacted, Site::Value, findings);
        Some(redacted)
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
                matched: truncate(redacted, Budget::Bytes(40), "...", Suffix::After),
                location: FindingLocation::ResponseContent,
            });
        }
    }

    /// Rename credential-bearing keys without losing an entry. Clean keys keep
    /// their names; each redacted key takes its redacted text, or the first
    /// free `<text>#n`, so two keys never collapse into one. A per-name counter
    /// keeps n colliding keys linear rather than re-probing from `#2`.
    fn redact_keys(&self, map: &mut Map<String, Value>, findings: &mut Vec<Finding>) {
        let entries = std::mem::take(map);
        let mut names = KeyNames::reserving(
            entries
                .keys()
                .filter(|key| !self.set.is_match(key))
                .cloned(),
        );
        for (key, value) in entries {
            let Some(candidate) = self.redact_text(&key, Site::Key, findings) else {
                map.insert(key, value);
                continue;
            };
            let name = match names.claim(&candidate) {
                Some(n) => format!("{candidate}#{n}"),
                None => candidate,
            };
            map.insert(name, value);
        }
    }
}

/// The names one object's keys hold, for giving a redacted key a free name.
/// A per-name counter keeps n colliding keys linear rather than re-probing
/// from `#2`.
#[derive(Default)]
struct KeyNames {
    taken: HashSet<String>,
    next: HashMap<String, usize>,
}

impl KeyNames {
    /// The clean keys' names, reserved before any redacted key is named.
    fn reserving(clean: impl Iterator<Item = String>) -> Self {
        Self {
            taken: clean.collect(),
            next: HashMap::new(),
        }
    }

    /// Claim `candidate`, or else the first free `<candidate>#n`: `None`
    /// when `candidate` itself was free, else the `n`.
    fn claim(&mut self, candidate: &str) -> Option<usize> {
        if self.taken.insert(candidate.to_owned()) {
            return None;
        }
        let n = self.next.entry(candidate.to_owned()).or_insert(1);
        loop {
            *n += 1;
            if self.taken.insert(format!("{candidate}#{n}")) {
                return Some(*n);
            }
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

/// `spans` (merged, in order) clipped to every value literal they overlap
/// and to every key `redact_key` takes (one merged span can cover several
/// keys), each piece widened to whole escapes so no escape is cut, then
/// merged. Any other key stays as sent. Spans and literals are both in
/// order, so this is one pass over each, and each end is widened by a binary
/// search of its literal's escapes.
fn project(
    text: &str,
    spans: &[(usize, usize)],
    redact_key: impl Fn(&Literal) -> bool,
    literals: &[Literal],
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut first = 0;
    for lit in literals {
        while first < spans.len() && spans[first].1 <= lit.start {
            first += 1;
        }
        let mut lit_escapes = None;
        if lit.key && !redact_key(lit) {
            continue; // a key spans only cross
        }
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

/// Whether any of `ranges` (in order, disjoint) falls inside `lit`.
fn covers(ranges: &[(usize, usize)], lit: &Literal) -> bool {
    let after = ranges.partition_point(|range| range.0 < lit.start);
    ranges.get(after).is_some_and(|range| range.0 < lit.end)
}

/// `text` with `ranges` replaced, where a key holding a range is renamed as
/// [`Redactor::redact_keys`] renames one: within its object every clean key
/// keeps its name, and each redacted key takes its redacted name or the first
/// free `<name>#n`. Names compare decoded, so an escaped spelling of a taken
/// name collides too; the suffix is appended to the raw text, so escapes the
/// redaction left are written as sent.
fn rename_keys(text: &str, ranges: &[(usize, usize)], literals: &[Literal]) -> String {
    let decode = |raw: &str| serde_json::from_str::<String>(&format!("\"{raw}\"")).ok();
    let keys = literals.iter().filter(|lit| lit.key);
    let mut objects: HashMap<usize, KeyNames> = HashMap::new();
    for lit in keys.clone().filter(|lit| !covers(ranges, lit)) {
        if let Some(name) = decode(&text[lit.start..lit.end]) {
            objects.entry(lit.container).or_default().taken.insert(name);
        }
    }
    let mut renamed: Vec<(usize, usize, String)> = Vec::new();
    for lit in keys.filter(|lit| covers(ranges, lit)) {
        let (lo, hi) = (
            ranges.partition_point(|range| range.0 < lit.start),
            ranges.partition_point(|range| range.0 < lit.end),
        );
        let inside: Vec<(usize, usize)> = ranges[lo..hi]
            .iter()
            .map(|range| (range.0 - lit.start, range.1 - lit.start))
            .collect();
        let mut raw = replace_spans(&text[lit.start..lit.end], &inside);
        if let Some(candidate) = decode(&raw)
            && let Some(n) = objects.entry(lit.container).or_default().claim(&candidate)
        {
            raw = format!("{raw}#{n}");
        }
        renamed.push((lit.start, lit.end, raw));
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut keys = renamed.into_iter().peekable();
    for &(start, end) in ranges {
        if start < cursor {
            continue; // inside a key already written whole
        }
        let (from, to, with) = match keys.next_if(|key| key.0 <= start && start < key.1) {
            Some(key) => key,
            None => (start, end, "[REDACTED:credential]".to_owned()),
        };
        out.push_str(&text[cursor..from]);
        out.push_str(&with);
        cursor = to;
    }
    out.push_str(&text[cursor..]);
    out
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
        out.push_str("[REDACTED:credential]");
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "redactor_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "redactor_b2_tests.rs"]
mod b2_tests;
