// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Placeholder until the generator writes the Unicode 17.0.0 table.

pub(super) static LOWER_V1: [(u32, [u32; 3]); 0] = [];

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
