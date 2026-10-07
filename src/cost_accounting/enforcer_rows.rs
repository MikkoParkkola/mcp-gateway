// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capped per-name day rows of one budget scope.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use super::DailyAccumulator;

/// Unbudgeted names one day map keeps entries for; later names add into
/// `(other)`. A check reads only budgeted names, so with R2 off and a non-zero
/// `default_cost` the caller would otherwise choose how many entries exist.
pub(super) const MAX_UNBUDGETED_ROWS: usize = 256;

/// One scope's day rows, its overflow total, and the day an overflowing
/// spend last swept the rows.
pub(super) type Rows<'a> = (
    &'a DashMap<String, DailyAccumulator>,
    &'a DailyAccumulator,
    &'a AtomicU64,
);

/// Add `micro` to `name`'s entry and return that entry's running total. A
/// budgeted name always has its own. Any other name has one only while `map`
/// holds fewer than [`MAX_UNBUDGETED_ROWS`] unbudgeted entries, and only if it is no longer than the cost tracker's row-name limit; past
/// either, its spend goes to `overflow`, which no budget check ever reads, so
/// a budget whose name happens to be `(other)` keeps its own total.
/// ponytail: a soft cap; racing first inserts can pass it by the caller count.
pub(super) fn add_capped(
    (map, overflow, swept): Rows<'_>,
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
    let short = name.len() <= super::super::tally::MAX_ROW_NAME_BYTES;
    let mut own = limits.contains_key(name)
        || map.contains_key(name)
        || (short && unbudgeted() < MAX_UNBUDGETED_ROWS);
    // A spend that read the day just before midnight skipped the day's sweep,
    // so yesterday's rows may still fill the cap (MIK-8045). Sweep here, at
    // most once a day, so a full cap of today's rows stays O(1) per call.
    // The day is marked before the sweep finishes; no second spend can act on
    // that early mark because settles run one at a time under the ledger lock
    // and a restore runs before the enforcer is shared.
    if !own && short {
        let today = super::current_day();
        if swept.fetch_max(today, Ordering::Relaxed) < today {
            map.retain(|row, day| limits.contains_key(row) || day.is_current());
            own = unbudgeted() < MAX_UNBUDGETED_ROWS;
        }
    }
    if own {
        map.entry(name.to_string()).or_default().add(micro)
    } else {
        overflow.add(micro)
    }
}
