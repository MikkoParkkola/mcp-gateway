// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Removing the values of secrets the gateway injected from text and JSON
//! the gateway did not author: a CLI capability's output, and a backend's
//! answer. One redactor for every caller (MIK-8065).

#[cfg(feature = "firewall")]
use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use serde_json::Value;

#[cfg(feature = "firewall")]
use crate::security::firewall::redactor::Redactor;

/// Caller values shorter than this stay in diagnostics: replacing every `a`
/// or `1` would destroy the message, and secrets never travel as caller values.
const MIN_REDACTED_CALLER_VALUE: usize = 4;

#[cfg(feature = "firewall")]
static REDACTOR: LazyLock<Redactor> = LazyLock::new(Redactor::new);

/// Injected secrets (any length) and caller values (from 4 bytes), longest
/// first so a value containing another is removed whole.
fn needles<'a>(secrets: &'a [String], caller: &'a [String]) -> Vec<&'a str> {
    let mut needles: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .chain(
            caller
                .iter()
                .map(String::as_str)
                .filter(|s| s.len() >= MIN_REDACTED_CALLER_VALUE),
        )
        .collect();
    needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
    needles
}

/// Replace every occurrence of every needle with a marker. All matches are
/// located in the ORIGINAL text and overlapping ones merge into one marker, so
/// two credentials that overlap leave no fragment of either behind.
///
/// Memory is one flag per byte of `text`, whatever the number of matches (a
/// one-character needle in a long text matches at every position); one pass
/// finds every needle, however many there are and however much their
/// matches overlap.
///
/// A credential the scanner would find in the ORIGINAL text and that a
/// literal overlaps is removed with it: removing the literal alone (an
/// injected value equal to `Bearer`) would leave the rest of that credential
/// where the scanner no longer recognises it.
///
/// `None` when nothing matched: a clean text is never copied (MIK-9035).
fn scrub(text: &str, matcher: &AhoCorasick) -> Option<String> {
    let mut covered: Vec<bool> = Vec::new();
    // Matches arrive in order of their end, so a match that starts at or
    // before the end of the current run extends it, and a run is filled once
    // it can grow no further: the marking is linear in the text however many
    // matches overlap.
    let mut run: Option<(usize, usize)> = None;
    for found in matcher.find_overlapping_iter(text) {
        let (start, end) = (found.start(), found.end());
        run = match run {
            Some((from, to)) if start <= to => Some((from.min(start), end.max(to))),
            Some((from, to)) => {
                fill(&mut covered, text.len(), from, to);
                Some((start, end))
            }
            None => Some((start, end)),
        };
    }
    let (from, to) = run?;
    fill(&mut covered, text.len(), from, to);
    #[cfg(feature = "firewall")]
    for (start, end) in REDACTOR.credential_spans(text) {
        if covered[start..end].contains(&true) {
            covered[start..end].fill(true);
        }
    }
    // The first marker that leaves no needle in the output: a needle can be
    // the marker's own text, or form where a marker meets its neighbours.
    for marker in MARKERS {
        let out = render(text, &covered, marker);
        if !matcher.is_match(&out) {
            return Some(out);
        }
    }
    Some(String::new())
}

/// Marks `from..to` covered, allocating the map on the first match.
fn fill(covered: &mut Vec<bool>, len: usize, from: usize, to: usize) {
    if covered.is_empty() {
        *covered = vec![false; len];
    }
    covered[from..to].fill(true);
}

/// One automaton over `needles`, or `None` when it cannot be built (a needle
/// set past the automaton's size limits): the caller then fails closed.
fn matcher(needles: &[&str]) -> Option<AhoCorasick> {
    AhoCorasick::new(needles).ok()
}

/// Suffixed names tried for a renamed key before its entry is dropped.
const MAX_RENAME_TRIES: usize = 1024;

/// Markers tried in turn; each starts and ends with characters the others
/// do not, so a needle formed at the edge of one is not formed by the next.
const MARKERS: [&str; 3] = ["[redacted]", "<removed>", "{hidden}"];

/// The first marker containing no needle, or nothing at all.
fn marker_for(needles: &[&str]) -> &'static str {
    MARKERS
        .into_iter()
        .find(|m| !needles.iter().any(|n| !n.is_empty() && m.contains(n)))
        .unwrap_or("")
}

/// One `marker` per covered run. Output longer than twice the input plus one
/// marker (many short matches) collapses everything from the first covered
/// byte to the last into one marker: that removes more, never less. Ordinary
/// redaction, a few markers in a line, stays under the cap and keeps the text
/// between them.
fn render(text: &str, covered: &[bool], marker: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        if covered[at] {
            while at < text.len() && covered[at] {
                at += 1;
            }
            out.push_str(marker);
        } else {
            let start = at;
            while at < text.len() && !covered[at] {
                at += 1;
            }
            out.push_str(&text[start..at]);
        }
    }
    if out.len() > 2 * text.len() + marker.len()
        && let (Some(first), Some(last)) = (
            covered.iter().position(|&c| c),
            covered.iter().rposition(|&c| c),
        )
    {
        // Covered runs start and end on character boundaries.
        return format!("{}{marker}{}", &text[..first], &text[last + 1..]);
    }
    out
}

/// [`redact`] without the truncation: for a result the caller receives whole.
/// Removes the literals only; a credential a literal overlaps goes with it
/// (see [`scrub`]).
///
/// A credential-shaped value the gateway did not inject is left for the
/// response firewall, which inspects every result and error the caller
/// receives: replacing it here would hand the firewall only a marker, so its
/// rules, its Block and its audit finding would never see the credential.
pub(crate) fn redact_untruncated(text: &str, secrets: &[String], caller: &[String]) -> String {
    let needles = needles(secrets, caller);
    if needles.is_empty() {
        return text.to_owned();
    }
    match matcher(&needles) {
        Some(matcher) => scrub(text, &matcher).unwrap_or_else(|| text.to_owned()),
        // Fail closed: no automaton, no text.
        None => String::new(),
    }
}

/// Redact a successful JSON result in place: every string value and object key,
/// never the structure, so the document still parses and a redacted string
/// stays a string. No truncation. Injected literals only, as
/// [`redact_untruncated`]: the credential scanner is the response firewall's.
///
/// `secrets` are injected credentials only, never caller values: numbers are
/// matched by value at any length here, which the caller-value floor
/// ([`MIN_REDACTED_CALLER_VALUE`]) would forbid (MIK-8065).
///
/// `true` when anything was replaced.
pub(crate) fn redact_value(value: &mut Value, secrets: &[String]) -> bool {
    redact_value_with(value, &Compiled::new(secrets))
}

/// A secret list compiled once for [`redact_value_with`]: the needles longest
/// first, their automaton, and the ones that read as JSON scalars. A caller
/// that scrubs many values with one list (a backend's value set) keeps one
/// and rebuilds it only when the list changes (MIK-9035 DELTA-11).
pub(crate) struct Compiled {
    needles: Vec<String>,
    /// `None` when the automaton could not be built: every value is then
    /// replaced whole (fail closed).
    matcher: Option<AhoCorasick>,
    literals: Vec<Value>,
}

impl Compiled {
    pub(crate) fn new(secrets: &[String]) -> Self {
        let needles: Vec<String> = needles(secrets, &[])
            .into_iter()
            .map(str::to_owned)
            .collect();
        let borrowed: Vec<&str> = needles.iter().map(String::as_str).collect();
        let matcher = if borrowed.is_empty() {
            None
        } else {
            matcher(&borrowed)
        };
        // A secret that reads as a JSON number or as `true`, `false` or
        // `null`: a result scalar equal to it by exact JSON equality is
        // redacted whatever the secret's length, before any by-value
        // comparison. "007" and "TRUE" are not JSON: no match here, and
        // "007" is then compared by value below.
        let literals = borrowed
            .iter()
            .filter_map(|n| serde_json::from_str::<Value>(n).ok())
            .filter(|v| !matches!(v, Value::String(_) | Value::Array(_) | Value::Object(_)))
            .collect();
        Self {
            needles,
            matcher,
            literals,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// The needles, longest first.
    pub(crate) fn needles(&self) -> &[String] {
        &self.needles
    }
}

/// [`redact_value`] with a list compiled beforehand.
pub(crate) fn redact_value_with(value: &mut Value, compiled: &Compiled) -> bool {
    if compiled.needles.is_empty() {
        return false;
    }
    let needles: Vec<&str> = compiled.needles.iter().map(String::as_str).collect();
    let Some(matcher) = &compiled.matcher else {
        // Fail closed: no automaton, no value.
        *value = Value::String(marker_for(&needles).to_owned());
        return true;
    };
    scrub_value(value, &needles, &compiled.literals, matcher)
}

/// The exact integer a JSON number's text names, as canonical digits, read
/// from the text so no float rounding enters: "1.2345e4" and "12345.0" both
/// give "12345". `None` when the text names a non-integer, or an exponent so
/// large the value is past any integer a JSON result can carry exactly.
fn exact_integer(text: &str) -> Option<String> {
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], &text[at + 1..]),
        None => (text, "0"),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    // Only significant digits count toward the width bound below: zeros
    // leading the fraction ("0.0001e8") are not, and a zero coefficient is 0
    // whatever its exponent, even one past i64 ("0e99", "0e9223372036854775808").
    let mut digits = format!("{whole}{fraction}")
        .trim_start_matches('0')
        .to_owned();
    if digits.is_empty() {
        return Some("0".to_owned());
    }
    let exponent = exponent.parse::<i64>().ok()?;
    let shift = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
    if shift >= 0 {
        // u128 holds at most 39 digits; anything wider cannot equal a result.
        let pad = usize::try_from(shift)
            .ok()
            .filter(|pad| digits.len() + pad <= 40)?;
        digits.extend(std::iter::repeat_n('0', pad));
    } else {
        let cut = usize::try_from(shift.unsigned_abs()).ok()?;
        let keep = digits.len().saturating_sub(cut);
        if !digits[keep..].bytes().all(|b| b == b'0') {
            return None;
        }
        digits.truncate(keep);
    }
    Some(digits)
}

/// `true` when anything in `value` was replaced.
fn scrub_value(
    value: &mut Value,
    needles: &[&str],
    literals: &[Value],
    matcher: &AhoCorasick,
) -> bool {
    if literals.contains(value) {
        *value = Value::String(marker_for(needles).to_owned());
        return true;
    }
    match value {
        Value::String(s) => match scrub(s, matcher) {
            Some(redacted) => {
                *s = redacted;
                true
            }
            None => false,
        },
        // A credential that is all digits can come back as a JSON number. It
        // matches a number of the same value only, never one whose digits merely
        // hold it: 912345 is not the secret 1234 (MIK-7954). Every injected needle
        // is compared, whatever its length: a short one left out leaked as a
        // number (MIK-8065). An all-digit needle is compared by value: printed as
        // a number, it loses its leading zeros ("012345" comes back as 12345), and
        // past u64 it parses as a float and prints in exponent form. So "007"
        // redacts the number 7 but never the 7 inside 1771. The sign is ignored on
        // both paths: a needle has none, so -12345, -12345.0 and -0.0 are the same
        // value as one.
        Value::Number(n) => {
            let digits = n.to_string();
            let float = n.as_f64().filter(|_| n.is_f64()).map(f64::abs);
            let value_f64 = n.as_f64().map(f64::abs);
            // The result's exact magnitude when it is an integer, so two
            // integers past f64 precision are never judged equal.
            let value_int = n
                .as_u64()
                .map(u128::from)
                .or_else(|| n.as_i64().map(|v| u128::from(v.unsigned_abs())));
            let same_value = |needle: &str| {
                // One leading sign is not part of the magnitude, and the
                // result's sign is ignored too: "+012345" and "-012345" are
                // the all-digit credential "012345" and take the exact path
                // below, which also keeps integers past i64 exact. Covered:
                // JSON number grammar with at most one leading sign, leading
                // zeros allowed. Other notations ("0x1F", "12_345") are out of
                // scope here (MIK-7954). Whitespace around it is dropped, as
                // the JSON parser does ("12345.0\n" is 12345).
                let needle = needle.trim_ascii();
                let needle = needle.strip_prefix(['+', '-']).unwrap_or(needle);
                // A needle with no digit before its exponent ("e123", "+",
                // whitespace) names no number: read as one it became 0 and
                // blanked every zero in the result (MIK-8065). So every needle
                // past this point is non-empty.
                let coefficient = needle.split(['e', 'E']).next().unwrap_or_default();
                if !coefficient.bytes().any(|b| b.is_ascii_digit()) {
                    return false;
                }
                if !needle.bytes().all(|b| b.is_ascii_digit()) {
                    // A credential injected in another number form ("12.5",
                    // "1.5e10") comes back printed differently, so it is
                    // compared by value: exactly, from its text, when the
                    // result is an integer; by f64 bits when the result is a
                    // float. Any number equal in value to such a
                    // needle is redacted, even one the child printed for
                    // another reason: that over-redaction is accepted.
                    // Leading zeros are not JSON, but a credential may carry
                    // them ("0012.5"): they are dropped before parsing, keeping
                    // one zero before a "." or an exponent.
                    let trimmed = needle.trim_start_matches('0');
                    let normalized: std::borrow::Cow<'_, str> =
                        if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
                            trimmed.into()
                        } else {
                            format!("0{trimmed}").into()
                        };
                    let Ok(parsed) = serde_json::from_str::<serde_json::Number>(&normalized) else {
                        return false;
                    };
                    if let Some(v) = value_int {
                        return exact_integer(&normalized).is_some_and(|e| e == v.to_string());
                    }
                    return parsed
                        .as_f64()
                        .zip(value_f64)
                        .is_some_and(|(p, v)| p.abs().to_bits() == v.to_bits());
                }
                let value = needle.trim_start_matches('0');
                let value = if value.is_empty() { "0" } else { value };
                // Parsed by serde_json, the parser that read the result, so
                // both sides round the same way whatever its float features.
                if let Some(f) = float {
                    return serde_json::from_str::<f64>(value)
                        .is_ok_and(|p| p.to_bits() == f.to_bits());
                }
                digits.trim_start_matches('-') == value
            };
            let same = needles.iter().copied().any(same_value);
            if same {
                *value = Value::String(marker_for(needles).to_owned());
            }
            same
        }
        Value::Array(items) => items.iter_mut().fold(false, |changed, v| {
            scrub_value(v, needles, literals, matcher) | changed
        }),
        Value::Object(map) => {
            let mut changed = false;
            let old = std::mem::take(map);
            let mut renamed = Vec::new();
            // Keys that survive keep their names whole: a renamed key never
            // takes one of them.
            for (key, mut item) in old {
                changed |= scrub_value(&mut item, needles, literals, matcher);
                match scrub(&key, matcher) {
                    None => {
                        map.insert(key, item);
                    }
                    Some(new) => renamed.push((new, item)),
                }
            }
            changed |= !renamed.is_empty();
            // Keys that collapse to the same marker all survive, `#2`, `#3`, ...
            let mut next: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            // A name that contains a needle is skipped too. Tries are bounded:
            // an entry left with no safe name (needles that block every
            // suffix) is dropped rather than emitted with one.
            for (base, item) in renamed {
                let taken = |key: &str, map: &serde_json::Map<String, Value>| {
                    map.contains_key(key) || matcher.is_match(key)
                };
                let mut key = base.clone();
                let mut tries = 0;
                while taken(&key, &*map) && tries < MAX_RENAME_TRIES {
                    tries += 1;
                    let n = next.entry(base.clone()).or_insert(1);
                    *n += 1;
                    key = format!("{base}#{n}");
                }
                if !taken(&key, &*map) {
                    map.insert(key, item);
                }
            }
            changed
        }
        _ => false,
    }
}

/// Spans of `text` the credential scanner recognises, merged, in order.
#[cfg(feature = "firewall")]
pub(crate) fn credential_spans(text: &str) -> Vec<(usize, usize)> {
    REDACTOR.credential_spans(text)
}
