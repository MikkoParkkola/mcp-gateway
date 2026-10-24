// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Byte-span arithmetic for the credential redactor.

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
