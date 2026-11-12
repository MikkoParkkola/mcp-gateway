// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Placeholder until the generator writes the Unicode 17.0.0 tables.

pub(super) static LOWER_V1: [(u32, [u32; 3]); 0] = [];
pub(super) static CASE_IGNORABLE: [(u32, u32); 0] = [];
pub(super) static CASED_TERMINAL: [(u32, u32); 0] = [];

/// The lowercase of `c` from the frozen table, or `None` when it has none.
pub(super) fn lower(c: char) -> Option<impl Iterator<Item = char>> {
    let key = u32::from(c);
    let at = LOWER_V1.binary_search_by_key(&key, |entry| entry.0).ok()?;
    Some(
        LOWER_V1[at]
            .1
            .into_iter()
            .take_while(|&v| v != 0)
            .filter_map(char::from_u32),
    )
}

fn in_ranges(table: &[(u32, u32)], c: char) -> bool {
    let key = u32::from(c);
    table
        .binary_search_by(|&(lo, hi)| {
            if key < lo {
                std::cmp::Ordering::Greater
            } else if key > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether the first character that is not case-ignorable is cased: the
/// Final_Sigma look-around, over the frozen tables.
pub(super) fn case_ignorable_then_cased(mut chars: impl Iterator<Item = char>) -> bool {
    chars
        .find(|&c| !in_ranges(&CASE_IGNORABLE, c))
        .is_some_and(|c| in_ranges(&CASED_TERMINAL, c))
}
