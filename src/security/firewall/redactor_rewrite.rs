// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Rewriting a text around its redacted spans for the credential redactor:
//! clipping spans to the JSON literals they cover, renaming redacted keys,
//! and splicing in the markers.

use std::collections::HashMap;

use super::KeyNames;
use super::spans::{covers, escape_around, merge_spans, overlaps, spliced_len};
use super::splice::{Spliced, collision_suffix};
use crate::security::firewall::json_literal::{self, Literal};

/// `spans` (merged, in order) clipped to every value literal they overlap
/// and to every overlapped key `redact_key` takes (one merged span can cover
/// several keys), each piece widened to whole escapes so no escape is cut,
/// then merged. Any other key stays as sent. Spans and literals are both in
/// order, so this is one pass over each, and each end is widened by a binary
/// search of its literal's escapes.
pub(super) fn project(
    text: &str,
    spans: &[(usize, usize)],
    redact_key: impl Fn(&Literal) -> bool,
    literals: &[Literal],
) -> Vec<(usize, usize)> {
    // Sized by a first count of every literal a span overlaps (keys included,
    // so an upper bound): grown by doubling, the list held its old and new
    // buffers at the last growth.
    let mut ranges = Vec::with_capacity(overlaps(spans, literals));
    let mut first = 0;
    for lit in literals {
        while first < spans.len() && spans[first].1 <= lit.start() {
            first += 1;
        }
        let mut lit_escapes = None;
        let overlapped = spans.get(first).is_some_and(|span| span.0 < lit.end());
        if lit.key && !(overlapped && redact_key(lit)) {
            continue; // a key spans only cross, or none reach
        }
        for &(start, end) in spans[first..].iter().take_while(|span| span.0 < lit.end()) {
            let (mut from, mut to) = (start.max(lit.start()), end.min(lit.end()));
            if from >= to {
                continue; // an empty value: the span covers none of its bytes
            }
            let escapes = lit_escapes.get_or_insert_with(|| {
                json_literal::escapes(&text[lit.start()..lit.end()], lit.start())
            });
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

/// `text` with `ranges` replaced, where a key holding a range is renamed as
/// [`Redactor::redact_keys`](super::Redactor::redact_keys) renames one: within its object every clean key
/// keeps its name, and each redacted key takes its redacted name or the first
/// free `<name>#n`. Names compare decoded, so an escaped spelling of a taken
/// name collides too; the suffix is appended to the raw text, so escapes the
/// redaction left are written as sent.
pub(super) fn rename_keys(text: &str, ranges: &[(usize, usize)], literals: &[Literal]) -> String {
    let decode = |raw: &str| serde_json::from_str::<String>(&format!("\"{raw}\"")).ok();
    let keys = literals.iter().filter(|lit| lit.key);
    let mut objects: HashMap<usize, KeyNames> = HashMap::new();
    for lit in keys.clone().filter(|lit| !covers(ranges, lit)) {
        if let Some(name) = decode(&text[lit.start()..lit.end()]) {
            objects
                .entry(lit.container())
                .or_default()
                .taken
                .insert(name);
        }
    }
    let mut renamed = keys.filter(|lit| covers(ranges, lit)).peekable();
    // The key being written, and where its text starts in `out`. A key is
    // written into the document's own output, so its markers and its suffix
    // see what precedes it.
    let mut open: Option<(&Literal, usize)> = None;
    // Each renamed key may also take a collision suffix and its barrier.
    let suffixes = literals
        .iter()
        .filter(|lit| lit.key && covers(ranges, lit))
        .count();
    let mut out = Spliced::with_capacity(spliced_len(text, ranges) + suffixes * SUFFIX_ROOM);
    let mut cursor = 0;
    let mut close = |out: &mut Spliced, cursor: &mut usize, (lit, from): (&Literal, usize)| {
        out.push(&text[*cursor..lit.end()]);
        *cursor = lit.end();
        let spaced = out.barrier();
        if let Some(candidate) = decode(&out.out[from..])
            && let Some(n) = objects
                .entry(lit.container())
                .or_default()
                .claim(&candidate, spaced)
        {
            out.push(&collision_suffix(n, spaced));
        }
    };
    for &(start, end) in ranges {
        if let Some(key) = open.take_if(|(lit, _)| start >= lit.end()) {
            close(&mut out, &mut cursor, key);
        }
        if open.is_none()
            && let Some(lit) = renamed.next_if(|lit| lit.start() <= start && start < lit.end())
        {
            out.push(&text[cursor..lit.start()]);
            cursor = lit.start();
            open = Some((lit, out.out.len()));
        }
        out.push(&text[cursor..start]);
        out.insert_marker();
        cursor = end;
    }
    if let Some(key) = open {
        close(&mut out, &mut cursor, key);
    }
    out.push(&text[cursor..]);
    out.out
}

/// Room for one key's collision suffix (`#` and a counter) and its barrier.
const SUFFIX_ROOM: usize = 24;

pub(super) fn replace_spans(text: &str, ranges: &[(usize, usize)]) -> String {
    let mut out = Spliced::with_capacity(spliced_len(text, ranges));
    let mut cursor = 0;
    for &(start, end) in ranges {
        out.push(&text[cursor..start]);
        out.insert_marker();
        cursor = end;
    }
    out.push(&text[cursor..]);
    out.out
}
