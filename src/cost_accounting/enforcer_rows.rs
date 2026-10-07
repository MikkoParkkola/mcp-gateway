// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capped per-name day rows of one budget scope.

use std::collections::HashMap;

use dashmap::DashMap;

use super::DailyAccumulator;

/// Unbudgeted names one day map keeps entries for; later names add into
/// `(other)`. A check reads only budgeted names, so with R2 off and a non-zero
/// `default_cost` the caller would otherwise choose how many entries exist.
pub(super) const MAX_UNBUDGETED_ROWS: usize = 256;

/// Add `micro` to `name`'s entry and return that entry's running total. A
/// budgeted name always has its own. Any other name has one only while `map`
/// holds fewer than [`MAX_UNBUDGETED_ROWS`] unbudgeted entries, and only if it is no longer than the cost tracker's row-name limit; past
/// either, its spend goes to `overflow`, which no budget check ever reads, so
/// a budget whose name happens to be `(other)` keeps its own total.
/// ponytail: a soft cap; racing first inserts can pass it by the caller count.
pub(super) fn add_capped(
    (map, overflow): (&DashMap<String, DailyAccumulator>, &DailyAccumulator),
    name: &str,
    limits: &HashMap<String, f64>,
    micro: u64,
) -> u64 {
    // Budgeted entries never count against the cap, present or not, so the map
    // holds at most every budgeted name plus MAX_UNBUDGETED_ROWS others.
    let unbudgeted = || {
        let budgeted = limits.keys().filter(|k| map.contains_key(*k)).count();
        // A sweep may remove entries between the two reads.
        map.len().saturating_sub(budgeted)
    };
    let own = limits.contains_key(name)
        || map.contains_key(name)
        || (name.len() <= super::super::tally::MAX_ROW_NAME_BYTES
            && unbudgeted() < MAX_UNBUDGETED_ROWS);
    if own {
        map.entry(name.to_string()).or_default().add(micro)
    } else {
        overflow.add(micro)
    }
}
