// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key's three-hour spend rate, on a fixed clock.

use super::{CostRecord, KeyCost};

/// The current hour (`unix_secs / 3600`), far enough from the epoch for
/// four hours back.
const H: u64 = 492_000;

fn spent(key: &KeyCost, hour: u64, usd: f64) {
    let at = hour * 3600 + 60;
    key.record(
        &CostRecord {
            timestamp: Some(at),
            backend: "alpha".to_string(),
            tool: "read".to_string(),
            token_count: 0,
            estimated_cost_usd: usd,
        },
        Some(H * 3600 + 1800),
    );
}

fn close(got: f64, want: f64) {
    assert!((got - want).abs() < 1e-9, "rate {got}, want {want}");
}

/// The three complete hours before the current one, over three: the current
/// hour and anything older than three hours do not count.
#[test]
fn s7_rate_is_three_complete_hours_over_three() {
    let now = H * 3600 + 1800;
    let key = KeyCost::new("ci");
    spent(&key, H - 3, 0.60);
    spent(&key, H - 2, 0.90);
    spent(&key, H - 1, 0.69);
    spent(&key, H, 5.00);
    close(key.rate_3h(now), 0.73);

    let one_hour = KeyCost::new("one");
    spent(&one_hour, H - 1, 0.90);
    close(one_hour.rate_3h(now), 0.30);

    let older = KeyCost::new("older");
    spent(&older, H - 4, 3.00);
    spent(&older, H - 1, 0.90);
    close(older.rate_3h(now), 0.30);
}
