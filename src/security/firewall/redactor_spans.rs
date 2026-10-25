// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Byte-span arithmetic for the credential redactor.

use super::Literal;

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
    let after = ranges.partition_point(|range| range.0 < lit.start);
    ranges.get(after).is_some_and(|range| range.0 < lit.end)
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
pub(super) fn merge_spans(spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}
