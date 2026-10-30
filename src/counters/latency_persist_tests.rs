// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Latency in `counters.json` (test plan rows 12b, 13-18).

use std::time::Duration;

use chrono::Utc;

use super::*;
use crate::counters::{Call, CounterStore, End, Label, Tally};

const T0: u64 = 1_800 * 1_000_000;

fn call<'a>(server: &'a str) -> Call<'a> {
    Call {
        caller: "key:a",
        server: Label::Known(server),
        tool: Label::Known("t"),
        tally: Tally::default(),
    }
}

fn timed(store: &CounterStore, server: &str, at: u64, ms: u64) {
    store.record_timed(
        &call(server),
        at,
        &Utc,
        Some((Duration::from_millis(ms), End::Answered)),
    );
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("counters.json is JSON")
}

/// Row 13: save then restore keeps the closed p95s and the live sketches,
/// and the next record lands in the same live slot.
#[test]
fn restore_keeps_closed_and_live() {
    let store = CounterStore::new(T0);
    timed(&store, "alpha", T0 + 10, 100);
    timed(&store, "alpha", T0 + 3 * HALF + 10, 400);
    let now = T0 + 3 * HALF + 20;
    let bytes = store.encode("v1", now);
    let restored = CounterStore::from_bytes(&bytes, now, "v1", &Utc)
        .expect("restores")
        .0;
    let before = store.snapshot();
    let after = restored.snapshot();
    let lat = |inner: &Inner| inner.server.labels["alpha"].latency.clone();
    assert_eq!(lat(&after).half.closed, lat(&before).half.closed);
    assert_eq!(lat(&after).half.live, lat(&before).half.live);
    timed(&restored, "alpha", T0 + 3 * HALF + 30, 400);
    assert_eq!(
        restored.snapshot().server.labels["alpha"]
            .latency
            .half
            .live
            .len(),
        1
    );
}

/// Row 14: a file saved before latency existed restores its counts, latency
/// empty.
#[test]
fn pre_latency_file_loads_empty() {
    let store = CounterStore::new(T0);
    timed(&store, "alpha", T0 + 10, 100);
    let mut file = json(&store.encode("v1", T0 + 20));
    file.as_object_mut().unwrap().remove("latency");
    let bytes = serde_json::to_vec(&file).unwrap();
    let restored = CounterStore::from_bytes(&bytes, T0 + 20, "v1", &Utc)
        .expect("restores")
        .0;
    let inner = restored.snapshot();
    assert!(inner.server.labels["alpha"].latency.is_empty());
    assert!(!inner.server.labels["alpha"].half.is_empty(), "counts kept");
}

/// Row 15: the format stays 1, and a file with latency restores through the
/// real reader (an older binary's reader ignores the field: serde without
/// `deny_unknown_fields`).
#[test]
fn latency_file_keeps_format_one() {
    let store = CounterStore::new(T0);
    timed(&store, "alpha", T0 + 10, 100);
    let bytes = store.encode("v1", T0 + 20);
    assert_eq!(json(&bytes)["version"], 1);
    assert!(json(&bytes).get("latency").is_some());
    #[derive(serde::Deserialize)]
    #[allow(dead_code)] // only parsed: the reader of a binary without the field
    struct Fieldless {
        version: u32,
        since: u64,
    }
    let old: Fieldless = serde_json::from_slice(&bytes).expect("an older reader parses it");
    assert_eq!(old.version, 1);
}

/// Row 16: positions are `[bucket, p95_ms, calls, failed, timed_out(, late)]`
/// and a live slot is `[bucket, calls, failed, timed_out, [[bin, count]]]`.
#[test]
fn positional_encoding_shape() {
    let store = CounterStore::new(T0);
    timed(&store, "alpha", T0 + 10, 100);
    store.record_timed(
        &call("alpha"),
        T0 + 20,
        &Utc,
        Some((Duration::from_millis(100), End::TimedOut)),
    );
    let now = T0 + 3 * HALF;
    let file = json(&store.encode("v1", now));
    let alpha = &file["latency"]["server"][0];
    assert_eq!(alpha[0], "alpha");
    let live = &alpha[1]["half"]["live"][0];
    assert_eq!(live[0], T0 / HALF);
    assert_eq!(live[1], 2, "calls");
    assert_eq!(live[3], 1, "timed_out");
    assert!(live[4].is_array());
}

/// One label's counts in the size fills.
struct Fill {
    calls: u32,
    failed: u32,
    timed_out: u32,
    late: u32,
    /// Live bins per sketch, and each bin's count.
    bins: u8,
    per_bin: u32,
}

/// The encoded size of a full cap (514 series: 512 labels, the overflow and
/// global) with every slot held, every name at the 128-byte label limit.
fn full_cap_bytes(fill: &Fill) -> usize {
    use super::super::latency::{Closed, LatencySeries, Live, Sketch};
    let sketch = Sketch::from_bins((0..fill.bins).map(|b| (b, fill.per_bin)).collect());
    let closed = |bucket: u64| Closed {
        bucket,
        p95_ms: 1_638_400,
        calls: fill.calls,
        failed: fill.failed,
        timed_out: fill.timed_out,
        late: fill.late,
    };
    let live = |bucket: u64| Live {
        bucket,
        sketch: sketch.clone(),
        failed: fill.failed,
        timed_out: fill.timed_out,
    };
    let base = 99_999_000u64;
    let mut series = LatencySeries::default();
    series.half.closed = (0..94).map(|b| closed(base + b)).collect();
    series.half.live = (94..96).map(|b| live(base + b)).collect();
    series.day.closed = (0..29).map(|d| closed(base + d)).collect();
    series.day.live = std::iter::once(live(base + 29)).collect();
    let file = series.to_file();
    let labels: Vec<(String, _)> = (0..514)
        .map(|i| (format!("{i:03}{}", "x".repeat(125)), file.clone()))
        .collect();
    serde_json::to_vec(&labels).unwrap().len()
}

/// Row 17: every label filled with maximum-width values and every bin in
/// every live sketch encodes at no more than 5.8 MB.
#[test]
fn size_adversarial_max_width() {
    let bytes = full_cap_bytes(&Fill {
        calls: u32::MAX,
        failed: u32::MAX,
        timed_out: u32::MAX,
        late: u32::MAX,
        bins: 64,
        per_bin: u32::MAX,
    });
    assert!(bytes <= 5_800_000, "{bytes} bytes");
}

/// Row 18: a realistic full cap (a million calls a slot, a few failures and
/// timeouts, no late samples, latencies in 8 bins) stays under 3 MB.
#[test]
fn size_realistic_full_cap() {
    let bytes = full_cap_bytes(&Fill {
        calls: 1_000_000,
        failed: 10_000,
        timed_out: 1_000,
        late: 0,
        bins: 8,
        per_bin: 125_000,
    });
    assert!(bytes <= 3_000_000, "{bytes} bytes");
}
