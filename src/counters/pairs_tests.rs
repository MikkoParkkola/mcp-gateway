// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The top caller x server pairs (S3b): one lock, only the last 24 hours,
//! ties by caller then server, and the pair overflow's calls counted apart.

use chrono_tz::UTC;

use super::*;

const HOUR: u64 = 3600;
/// 2026-10-20T00:00:00Z plus 7 h 10 min.
const NOW: u64 = 1_792_454_400 + 7 * HOUR + 600;

fn record(store: &CounterStore, caller: &str, server: &str, at: u64, blocked: bool) {
    let call = Call {
        caller,
        server: Label::Known(server),
        tool: Label::Untrusted,
        tally: Tally {
            blocked,
            ..Tally::default()
        },
    };
    store.record(&call, at, &UTC);
}

/// S3b: the read takes the store's lock once, whatever it returns.
#[test]
fn s3b_top_pairs_takes_one_lock() {
    let store = CounterStore::new(0);
    record(&store, "key:a", "s", NOW - 600, false);
    let before = store.reads_for_test();

    let _ = store.top_pairs(NOW, &UTC, 5);

    assert_eq!(store.reads_for_test() - before, 1);
}

/// S3b: a pair whose only calls are 25 hours old is neither listed nor
/// counted in `more`; equal counts order by caller, then server.
#[test]
fn s3b_top_pairs_lists_only_the_last_24_hours_in_order() {
    let store = CounterStore::new(0);
    record(&store, "key:b", "x", NOW - 600, true);
    record(&store, "key:a", "y", NOW - 600, false);
    record(&store, "key:old", "z", NOW - 25 * HOUR, false);

    let top = store.top_pairs(NOW, &UTC, 5);

    let pairs: Vec<(&str, &str, u64, u64)> = top
        .rows
        .iter()
        .map(|r| (r.caller.as_str(), r.server.as_str(), r.calls, r.blocks))
        .collect();
    assert_eq!(pairs, [("key:a", "y", 1, 0), ("key:b", "x", 1, 1)]);
    assert_eq!((top.more_count, top.more_calls), (0, 0));
}

/// S3b: at one pair over the store's cap the extra pair's calls are in
/// `overflow_calls`, and `more` counts the pairs the store holds past `n`.
#[test]
fn s3b_top_pairs_reports_the_overflow_calls() {
    let store = CounterStore::new(0);
    for caller in 0..4 {
        for server in 0..512 {
            record(
                &store,
                &format!("c{caller}"),
                &format!("s{server}"),
                NOW - 600,
                false,
            );
        }
    }
    assert_eq!(store.labels(Dim::CallerServer), MAX_PAIRS);
    for _ in 0..3 {
        record(&store, "c4", "s0", NOW - 600, false);
    }

    let top = store.top_pairs(NOW, &UTC, 5);

    assert_eq!(top.rows.len(), 5);
    assert_eq!(top.more_count, MAX_PAIRS - 5);
    assert_eq!(top.overflow_calls, 3);
}
