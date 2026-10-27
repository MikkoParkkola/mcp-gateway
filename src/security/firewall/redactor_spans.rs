// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Byte-span arithmetic for the credential redactor.

use super::{Literal, REDACTED, decoded};

/// `spans` (in order) with every byte of `holes` (in order, disjoint) cut
/// out, so a span crossing a hole leaves the pieces on either side of it.
pub(super) fn without(spans: &[(usize, usize)], holes: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(spans.len());
    for &(mut start, end) in spans {
        for &(hole_start, hole_end) in holes {
            if hole_start >= end || hole_end <= start {
                continue;
            }
            if start < hole_start {
                out.push((start, hole_start));
            }
            start = start.max(hole_end);
        }
        if start < end {
            out.push((start, end));
        }
    }
    out
}

/// Whether any of `ranges` (in order, disjoint) falls inside `lit`.
pub(super) fn covers(ranges: &[(usize, usize)], lit: &Literal) -> bool {
    let after = ranges.partition_point(|range| range.0 < lit.start());
    ranges.get(after).is_some_and(|range| range.0 < lit.end())
}

/// The escape in `escapes` (in order, disjoint) that `at` falls strictly
/// inside, if any.
pub(super) fn escape_around(escapes: &[(usize, usize)], at: usize) -> Option<(usize, usize)> {
    let after = escapes.partition_point(|escape| escape.0 < at);
    after
        .checked_sub(1)
        .map(|i| escapes[i])
        .filter(|escape| at < escape.1)
}

/// Merge sorted spans that overlap or touch, so no character between two
/// matched spans can survive and touching tokens share one marker.
pub(super) fn merge_spans(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    // In place: a second list would double the ranges held at the peak.
    let mut kept = 0;
    for read in 0..spans.len() {
        let (start, end) = spans[read];
        if kept > 0 && start <= spans[kept - 1].1 {
            spans[kept - 1].1 = spans[kept - 1].1.max(end);
        } else {
            spans[kept] = (start, end);
            kept += 1;
        }
    }
    spans.truncate(kept);
    spans
}

/// How many literal pieces `spans` (merged, in order) cover in `literals`.
pub(super) fn overlaps(spans: &[(usize, usize)], literals: &[Literal]) -> usize {
    let mut first = 0;
    let mut count = 0;
    for lit in literals {
        while first < spans.len() && spans[first].1 <= lit.start() {
            first += 1;
        }
        count += spans[first..]
            .iter()
            .take_while(|span| span.0 < lit.end())
            .filter(|span| span.0.max(lit.start()) < span.1.min(lit.end()))
            .count();
    }
    count
}

/// `text` with every range in `ranges` (merged, in order) replaced by the
/// redaction marker. `text` is always a whole leaf, never a slice of one,
/// so the barrier sees everything before each range.
/// The length `text` has with `ranges` (in order, disjoint) replaced, each
/// marker behind its possible barrier space: sized once, the output does not
/// grow by doubling, which held two copies at the last growth (MIK-8774).
/// A renamed key's suffix may still grow it a little.
pub(super) fn spliced_len(text: &str, ranges: &[(usize, usize)]) -> usize {
    let covered: usize = ranges.iter().map(|&(start, end)| end - start).sum();
    spliced_capacity(text.len(), covered, ranges.len())
}

/// The output length of a text of `len` bytes with `count` spans covering
/// `covered` bytes replaced, each marker behind its possible barrier space:
/// one rule for both walks, so neither can undersize its buffer.
pub(super) fn spliced_capacity(len: usize, covered: usize, count: usize) -> usize {
    len - covered + count * (REDACTED.len() + 1)
}

/// The content ranges of the value literals a span of `found` crosses and
/// whose decoded text `exempt` accepts. Only such a value can keep bytes
/// from a span, so no other value is decoded. Spans go by start, each with
/// the furthest end reached so far: a literal is crossed when a span starting
/// before its end reaches past its start.
pub(super) fn exempt_crossed(
    text: &str,
    literals: &[Literal],
    found: &[(usize, Vec<(usize, usize)>)],
    exempt: &dyn Fn(&str) -> bool,
) -> Vec<(usize, usize)> {
    let mut all: Vec<(usize, usize)> = found.iter().flat_map(|(_, f)| f.iter().copied()).collect();
    all.sort_unstable();
    let reach: Vec<usize> = (all.iter())
        .scan(0, |far, &(_, end)| {
            *far = (*far).max(end);
            Some(*far)
        })
        .collect();
    let crossed = |lit: &Literal| {
        let n = all.partition_point(|&(start, _)| start < lit.end());
        n > 0 && reach[n - 1] > lit.start()
    };
    literals
        .iter()
        .filter(|lit| !lit.key && crossed(lit))
        .filter(|lit| decoded(text, lit).is_some_and(|v| exempt(&v)))
        .map(|lit| (lit.start(), lit.end()))
        .collect()
}
