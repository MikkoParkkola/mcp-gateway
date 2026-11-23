// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The counters as a test reads them, one reader for every test tree.

use super::{CounterStore, Filter, Metric, Query, Window};

/// `metric` over the last 24 hours of the series `filter` names.
pub(crate) fn count(store: &CounterStore, metric: Metric, filter: Filter<'_>) -> u64 {
    let now = crate::clock::unix_secs().expect("a readable clock");
    store
        .series(
            &Query::new(metric, Window::Day, filter),
            now,
            &chrono::Local,
        )
        .points
        .iter()
        .map(|p| p.v)
        .sum()
}

/// `[calls, blocks, errors, firewall, cache hits]` on the global series.
pub(crate) fn totals(store: &CounterStore) -> [u64; 5] {
    Metric::ALL.map(|metric| count(store, metric, Filter::All))
}
