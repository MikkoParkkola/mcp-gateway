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

use super::json_literal::{self, Literal, decoded, trimmed_content};
use super::json_valid;
use super::{Finding, FindingLocation, ScanType};
use crate::security::Severity;
use crate::truncate::{Budget, Suffix, truncate};

#[path = "credential_names.rs"]
mod credential_names;
use credential_names::Family;

/// The largest JSON-in-text leaf walked on its collected literals (MIK-8745);
/// a larger one takes the streaming walk in `redactor_large.rs` (MIK-8774).
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

/// The connection-string rule's prefix. The barrier [`Spliced`] writes
/// tracks the same schemes byte by byte; a test pins the lists.
macro_rules! connection_prefix {
    () => {
        "(?i)(?:postgres|mysql|mongodb|redis)://"
    };
}

// MIK-8794: the writer every redaction insertion goes through; declared
// after the macro it uses.
#[path = "redactor_splice.rs"]
mod splice;
use splice::{Spliced, collision_suffix, ends_open};

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
pub(crate) const REDACTED: &str = "[REDACTED:credential]";

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
        concat!(connection_prefix!(), r"[^\s]{10,}"),
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
                    let member = match &*val {
                        Value::String(s) if !exempt(s) => self.credential_member(key, s),
                        _ => None,
                    };
                    self.scan_recursive(val, exempt, findings);
                    if let Some(family) = member {
                        // A newer family adds no finding where the raw rules
                        // already replaced the whole value: one secret, one finding.
                        let covered = matches!(&*val, Value::String(s) if s.trim() == REDACTED);
                        *val = Value::String(REDACTED.to_owned());
                        if family == Family::Generic || !covered {
                            findings.push(Self::member_finding(family));
                        }
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

    /// `text` redacted inside the string literals a credential span covers,
    /// when `text` is a JSON document: today's spans, each clipped to the
    /// value literals it covers, or to a key a match starts in, and widened to
    /// whole escapes. The quotes, punctuation, scalars and other keys a span
    /// crosses stay as sent, so the text still parses (MIK-8745). A redacted
    /// key takes the first free name in its object, as [`Self::redact_keys`]
    /// does, so no entry is lost (MIK-8772). `None` leaves the leaf to
    /// [`Self::redact_text`]: not a document, over the size cap, or a span
    /// that starts outside every literal.
    fn redact_json_text(
        &self,
        text: &str,
        exempt: &dyn Fn(&str) -> bool,
        findings: &mut Vec<Finding>,
    ) -> JsonText {
        if !json_literal::fits_offsets(text.len()) {
            return JsonText::NotJson;
        }
        if text.len() > B2_MAX_LEAF_BYTES {
            return self.redact_large_json(text, exempt, findings);
        }
        // An object, an array or a string, as `Value` would read it.
        if json_valid::walkable(text) != Some(true) {
            return JsonText::NotJson;
        }
        self.redact_collected(text, exempt, findings)
    }

    /// [`Self::redact_json_text`] on a document already validated: its
    /// literals collected, projected, and keys renamed where a match starts.
    fn redact_collected(
        &self,
        text: &str,
        exempt: &dyn Fn(&str) -> bool,
        findings: &mut Vec<Finding>,
    ) -> JsonText {
        let literals = json_literal::string_literals(text);
        let found_by: Vec<(usize, Vec<(usize, usize)>)> = (self.set.matches(text).iter())
            .map(|idx| (idx, overlapping_spans(&self.regexes[idx], text)))
            .collect();
        // A value literal whose decoded text is exempt keeps every byte, and a
        // pattern counts only where it still redacts something (MIK-8756).
        let exempt_contents = exempt_crossed(text, &literals, &found_by, exempt);
        let starts_in_literal = |at: usize| {
            let after = literals.partition_point(|lit| lit.start() <= at);
            after.checked_sub(1).is_some_and(|i| at < literals[i].end())
        };
        let mut matched = Vec::new();
        let mut spans = Vec::new();
        for (idx, found) in found_by {
            // Judged on the matches as found: a piece left after an exempt
            // value is cut out can start on that value's closing quote. No
            // pattern starts on a quote (P2 pins their text), so a match in
            // an exempt value starts inside it and passes; a pattern that
            // could start on one must revisit this check.
            if !found.iter().all(|&(start, _)| starts_in_literal(start)) {
                tracing::debug!(
                    "a credential span starts outside a string literal; redacting the leaf whole"
                );
                return JsonText::NotJson;
            }
            // An exempt value loses only its own bytes from a span that
            // crosses it; dropping the whole span delivered the credential
            // beside it (MIK-8832).
            let crossed = found
                .iter()
                .any(|&(start, end)| exempt_contents.iter().any(|&(a, b)| a < end && start < b));
            let mut kept = without(&found, &exempt_contents);
            kept.sort_unstable();
            let kept = merge_spans(kept);
            // A pattern counts only where what is left still redacts.
            let redacts = if crossed {
                !project(
                    text,
                    &kept,
                    |lit| self.match_starts_in(text, lit),
                    &literals,
                )
                .is_empty()
            } else {
                !kept.is_empty()
            };
            if redacts {
                matched.push(idx);
            }
            spans.extend(kept);
        }
        spans.sort_unstable();
        let spans = merge_spans(spans);
        let members = self.member_values(text, &literals, exempt);
        if spans.is_empty() && members.is_empty() {
            return JsonText::Kept;
        }
        // Member values join the projected spans in one merged list, so a key
        // projection and its member's value redaction are spliced in one pass.
        let raw = project(
            text,
            &spans,
            |lit| self.match_starts_in(text, lit),
            &literals,
        );
        // A newer family adds no finding where one raw range already covers the
        // value's trimmed content: one secret, one finding (family 1 keeps two).
        // Decided before the member ranges join `raw`, by a search of its
        // sorted ranges, so it costs no copy and no rescan per member.
        let reported: Vec<Family> = (members.iter())
            .filter(|&&(lit, family)| {
                let (start, end) = trimmed_content(text, lit);
                let after = raw.partition_point(|range| range.0 <= start);
                let covered = after.checked_sub(1).is_some_and(|i| end <= raw[i].1);
                family == Family::Generic || !covered
            })
            .map(|&(_, family)| family)
            .collect();
        let mut ranges = raw;
        ranges.extend(members.iter().map(|(lit, _)| (lit.start(), lit.end())));
        ranges.sort_unstable();
        let ranges = merge_spans(ranges);
        let redacted = if literals.iter().any(|lit| lit.key && covers(&ranges, lit)) {
            rename_keys(text, &ranges, &literals)
        } else {
            replace_spans(text, &ranges)
        };
        self.record_findings(&matched, &redacted, Site::Value, findings);
        findings.extend(reported.into_iter().map(Self::member_finding));
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
    ) -> Vec<(&'a Literal, Family)> {
        // Whether a key can name a credential at all depends on its text
        // alone, and a document repeats few keys, so each is decided once; a
        // key that names none makes [`Self::credential_member`] refuse any value.
        let mut names: HashMap<&str, bool> = HashMap::new();
        literals
            .windows(2)
            .filter(|pair| pair[0].key && !pair[1].key)
            .filter(|pair| text[pair[0].end() + 1..pair[1].start() - 1].trim() == ":")
            .filter(|pair| {
                *names
                    .entry(&text[pair[0].start()..pair[0].end()])
                    .or_insert_with(|| {
                        decoded(text, &pair[0]).is_some_and(|key| {
                            self.member_key.is_match(&key)
                                || credential_names::family_of(&key).is_some()
                        })
                    })
            })
            .filter_map(
                |pair| match (decoded(text, &pair[0]), decoded(text, &pair[1])) {
                    (Some(key), Some(value)) if !exempt(&value) => self
                        .credential_member(&key, &value)
                        .map(|family| (&pair[1], family)),
                    _ => None,
                },
            )
            .collect()
    }

    /// Whether a credential match starts inside `lit`, read with the text
    /// after it. The spans cannot tell: past a greedy match the scan restarts
    /// only near its end, so a later key's own start goes unseen, and a short
    /// key may match only together with the bytes after its quote. No pattern
    /// has an anchor or a word boundary, so cutting the text after
    /// [`KEY_MATCH_TAIL`] cannot invent a match, and that tail holds every
    /// match a key can start.
    fn match_starts_in(&self, text: &str, lit: &Literal) -> bool {
        let end = text.floor_char_boundary((lit.end() + KEY_MATCH_TAIL).min(text.len()));
        let near = &text[..end];
        self.set
            .matches_at(near, lit.start())
            .into_iter()
            .any(|idx| {
                self.regexes[idx]
                    .find_at(near, lit.start())
                    .is_some_and(|found| found.start() < lit.end())
            })
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

    /// A JSON member the generic API-key rule describes: the key is one of its
    /// names (any case, alone or after `_`/`-`) and the whole value is in its
    /// class (MIK-8756). The rule itself needs both halves in one string, which a
    /// parsed member never is. Beyond that rule, a key naming another credential
    /// family (MIK-8757) counts when its value passes that family's own rule.
    /// A key the generic rule names keeps that rule's value class unchanged.
    fn credential_member(&self, key: &str, value: &str) -> Option<Family> {
        if self.member_key.is_match(key) {
            return self.member_value.is_match(value).then_some(Family::Generic);
        }
        credential_names::family_of(key)
            .filter(|&family| credential_names::value_matches(family, value, REDACTED))
    }

    fn member_finding(family: Family) -> Finding {
        Finding {
            scan_type: ScanType::Credentials,
            severity: Severity::High,
            description: format!("Credential detected: {}", family.description()),
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
            // A parsed key is its own document, so its end is judged alone.
            let spaced = ends_open(&candidate);
            let name = match names.claim(&candidate, spaced) {
                Some(n) => format!("{candidate}{}", collision_suffix(n, spaced)),
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
    /// Per candidate and spacing: the two spellings of a suffix never
    /// collide, so each keeps its own first free `n`.
    next: HashMap<(String, bool), usize>,
}

impl KeyNames {
    /// The clean keys' names, reserved before any redacted key is named.
    fn reserving(clean: impl Iterator<Item = String>) -> Self {
        Self {
            taken: clean.collect(),
            next: HashMap::new(),
        }
    }

    /// Claim `candidate`, or else the first free `<candidate><suffix>`, the
    /// suffix [`collision_suffix`] writes for `spaced`: `None` when
    /// `candidate` itself was free, else the `n`.
    fn claim(&mut self, candidate: &str, spaced: bool) -> Option<usize> {
        if self.taken.insert(candidate.to_owned()) {
            return None;
        }
        let n = self.next.entry((candidate.to_owned(), spaced)).or_insert(1);
        loop {
            *n += 1;
            if self
                .taken
                .insert(format!("{candidate}{}", collision_suffix(*n, spaced)))
            {
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

/// How far past a key's closing quote a match starting in the key can need
/// to read before it is complete. Only two patterns can match a `"`, so only
/// they can cross that quote: the API-key rule ends on it (`['"]`), one byte
/// past, and the connection-string rule needs at most its 10 `[^\s]`
/// characters, 40 bytes in UTF-8. Every other pattern's classes exclude `"`,
/// so its match ends inside the key. The b2 tests pin which patterns can
/// match a quote, and the reviewed pattern text this bound was argued for.
const KEY_MATCH_TAIL: usize = 64;

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
        let floor = text.floor_char_boundary(covered.saturating_sub(OVERLAP_WINDOW));
        at = next.max(floor);
    }
    spans
}

#[path = "redactor_rewrite.rs"]
mod rewrite;
use rewrite::{project, rename_keys, replace_spans};

// ─── Tests ────────────────────────────────────────────────────────────────────

#[path = "redactor_spans.rs"]
mod spans;
use spans::{covers, exempt_crossed, merge_spans, spliced_capacity, without};

#[path = "redactor_large.rs"]
mod large;

#[cfg(test)]
#[path = "redactor_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "redactor_b2_tests.rs"]
mod b2_tests;

#[cfg(test)]
#[path = "redactor_member_tests.rs"]
mod member_tests;

#[cfg(test)]
#[path = "redactor_exempt_span_tests.rs"]
mod exempt_span_tests;
