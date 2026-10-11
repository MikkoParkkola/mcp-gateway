// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T17: the webhook "last received" statistic on a host
//! clock that reads before 1970.

use std::sync::atomic::Ordering;

use super::EndpointStats;

/// MIK-8202 RECORDER (stat) rule, P2 row 18: the counter still increments and
/// the previous `last_received_at` is kept; 0 is never stored. Mutant: store 0.
#[test]
fn t17_a_receive_on_an_unreadable_clock_counts_and_keeps_the_previous_time() {
    // GIVEN: a stat that last received at a known second
    let stats = EndpointStats::default();
    stats
        .last_received_at
        .store(1_700_000_000, Ordering::Relaxed);
    // WHEN
    let _clock = crate::clock::test_clock::before_epoch();
    stats.record_received();
    // THEN
    assert_eq!(stats.received.load(Ordering::Relaxed), 1);
    assert_eq!(
        stats.last_received_at.load(Ordering::Relaxed),
        1_700_000_000
    );
}
