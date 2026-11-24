// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/overview`'s counter rows: the call totals, server ranking,
//! top flows, chart markers, last-hour latency, server state, the counter
//! fields' absence and degradation, and the store's read count. The needs-you
//! rows live in overview_needs_you_tests.rs. Every counter row pins the clock to 2026-06-15T12:00:00Z (a date
//! with no daylight-saving change) and records calls relative to it. The
//! clock seam is per thread, so each row runs on a current-thread runtime.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::AppState;
use super::overview_tests::{ADMIN_KEY, fixture, get, overview};
use crate::backend::Backend;
use crate::clock::test_clock;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::counters::{Call, CounterStore, Label, MarkerKind, Tally};

/// 2026-06-15T12:00:00Z.
pub(super) const NOW: u64 = 1_781_524_800;
const HOUR: u64 = 3600;

/// A state with a counter store whose coverage began at `since`.
pub(super) fn with_store(state: &Arc<AppState>, since: u64) -> Arc<CounterStore> {
    let store = Arc::new(CounterStore::new(since));
    state.meta_mcp.set_counters(Arc::clone(&store));
    store
}

pub(super) fn record(store: &CounterStore, caller: &str, server: &str, at: u64, tally: Tally) {
    let call = Call {
        caller,
        server: Label::Known(server),
        tool: Label::Untrusted,
        tally,
    };
    store.record(&call, at, &crate::local_day::host_zone());
}

/// One call to `server` at `at` whose backend send took `ms`.
pub(super) fn timed(store: &CounterStore, server: &str, at: u64, ms: u64) {
    let call = Call {
        caller: "key:a",
        server: Label::Known(server),
        tool: Label::Untrusted,
        tally: Tally::default(),
    };
    let sample = (Duration::from_millis(ms), crate::counters::End::Answered);
    store.record_timed(&call, at, &crate::local_day::host_zone(), Some(sample));
}

/// `count` plain calls to `server` just before the pinned instant.
fn calls(store: &CounterStore, server: &str, count: u64) {
    for _ in 0..count {
        record(store, "key:a", server, NOW - 600, Tally::default());
    }
}

/// S1 (API16.1): the KPI strip carries the 24-hour totals.
#[tokio::test]
async fn s1_the_kpi_strip_carries_the_24_hour_totals() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    calls(&store, "name-000", 4);
    let blocked = Tally {
        blocked: true,
        ..Tally::default()
    };
    let failed = Tally {
        error: true,
        ..Tally::default()
    };
    record(&store, "key:a", "name-000", NOW - 600, blocked);
    record(&store, "key:a", "name-000", NOW - 600, blocked);
    record(&store, "key:a", "name-000", NOW - 600, failed);

    let body = overview(&state).await;

    let kpi = &body["kpi"];
    assert_eq!(kpi["calls_24h"], 7, "{body}");
    assert_eq!(kpi["blocks_24h"], 2, "{body}");
    assert_eq!(kpi["errors_24h"], 1, "{body}");
    assert_eq!(kpi["counting_since"], 0, "{body}");
}

/// S1b: the previous 24 hours is present only when the store covers all of it.
#[tokio::test]
async fn s1b_the_previous_period_needs_full_coverage() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    record(&store, "key:a", "name-000", NOW - 600, Tally::default());
    for _ in 0..4 {
        record(
            &store,
            "key:a",
            "name-000",
            NOW - 25 * HOUR,
            Tally::default(),
        );
    }
    let full = overview(&state).await;
    assert_eq!(full["kpi"]["calls_prev_24h"], 4, "{full}");

    let (partial_state, _dir) = fixture(1, false).await;
    let partial_store = with_store(&partial_state, NOW - HOUR);
    record(
        &partial_store,
        "key:a",
        "name-000",
        NOW - 600,
        Tally::default(),
    );
    let partial = overview(&partial_state).await;

    assert_eq!(partial["kpi"]["calls_24h"], 1, "{partial}");
    assert!(partial["kpi"].get("calls_prev_24h").is_none(), "{partial}");
}

/// S2 (D1): thirty servers whose call counts disagree with name order; the
/// rows are the top 24 by calls, ties by name, and the rest fold into `more`.
#[tokio::test]
async fn s2_servers_rank_by_calls_then_name() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(30, false).await;
    let store = with_store(&state, 0);
    let mut model: Vec<(String, u64)> = (0..30)
        .map(|i| {
            let count = if i >= 28 { 30 } else { (i * 11) % 28 + 2 };
            (format!("name-{i:03}"), count)
        })
        .collect();
    for (name, count) in &model {
        calls(&store, name, *count);
    }
    model.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let body = overview(&state).await;

    let rows = body["servers"]["rows"].as_array().expect("server rows");
    let shown: Vec<(&str, u64)> = rows
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap_or(""),
                r["calls_24h"].as_u64().unwrap_or(u64::MAX),
            )
        })
        .collect();
    let want: Vec<(&str, u64)> = model
        .iter()
        .take(24)
        .map(|(n, c)| (n.as_str(), *c))
        .collect();
    assert_eq!(shown, want, "{body}");
    assert_eq!(body["servers"]["more"]["count"], 6, "{body}");
    assert_eq!(body["servers"]["more"]["down"], 6, "{body}");
}

/// S3 (D2): sixty caller x server pairs; the rows are the top 48 by calls
/// (ties by caller, then server) with their blocks, and `more` counts the 12
/// left and their calls. A pair whose only calls are 25 hours old is neither
/// listed nor counted.
#[tokio::test]
async fn s3_edges_list_the_top_48_pairs() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(0, false).await;
    let store = with_store(&state, 0);
    let mut model: Vec<(String, String, u64, u64)> = Vec::new();
    for idx in 0..60u64 {
        let (caller, server) = (format!("key:c{}", idx / 20), format!("srv-{}", idx % 20));
        let count = if idx >= 58 { 60 } else { idx + 1 };
        let blocks = (idx % 3).min(count);
        for n in 0..count {
            let tally = Tally {
                blocked: n < blocks,
                ..Tally::default()
            };
            record(&store, &caller, &server, NOW - 600, tally);
        }
        model.push((caller, server, count, blocks));
    }
    record(
        &store,
        "key:old",
        "srv-0",
        NOW - 25 * HOUR,
        Tally::default(),
    );
    model.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| (&a.0, &a.1).cmp(&(&b.0, &b.1))));

    let body = overview(&state).await;

    assert!(body["edges"]["rows"].is_array(), "edges absent: {body}");
    let rows = body["edges"]["rows"].as_array().expect("edge rows");
    let shown: Vec<(String, String, u64, u64)> = rows
        .iter()
        .map(|r| {
            let text = |k: &str| r[k].as_str().unwrap_or("").to_owned();
            (
                text("caller"),
                text("server"),
                r["calls"].as_u64().unwrap_or(0),
                r["blocks"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    assert_eq!(shown, model[..48], "{body}");
    let rest: u64 = model[48..].iter().map(|row| row.2).sum();
    assert_eq!(body["edges"]["more"]["count"], 12, "{body}");
    assert_eq!(body["edges"]["more"]["calls"], rest, "{body}");
    assert_eq!(body["edges"]["more"]["overflow_calls"], 0, "{body}");
}

/// S4 (API16.1, D4): sixty markers in the last 24 hours and five older ones;
/// fifty rows come back newest first, `more` counts ten, no older marker
/// appears, and a long subject is shown as the store normalized it.
#[tokio::test]
async fn s4_markers_are_the_newest_fifty_of_the_last_day() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(0, false).await;
    let store = with_store(&state, 0);
    for i in 0..5 {
        store.mark(MarkerKind::Restart, Some("old"), NOW - 30 * HOUR - i);
    }
    for i in 0..60 {
        store.mark(
            MarkerKind::ConfigReload,
            Some(&format!("m{i:02}")),
            NOW - 3000 + i,
        );
    }
    store.mark(MarkerKind::Upgrade, Some(&"v".repeat(400)), NOW - 10);
    let want = crate::counters::normalize(&"v".repeat(400));

    let body = overview(&state).await;

    assert!(body["markers"]["rows"].is_array(), "markers absent: {body}");
    let rows = body["markers"]["rows"].as_array().expect("marker rows");
    assert_eq!(rows.len(), 50, "{body}");
    assert_eq!(rows[0]["subject"], want.as_str(), "{body}");
    assert_eq!(rows[0]["kind"], "upgrade", "{body}");
    assert_eq!(rows[1]["subject"], "m59", "{body}");
    assert_eq!(rows[49]["subject"], "m11", "{body}");
    assert_eq!(body["markers"]["more"]["count"], 11, "{body}");
    assert!(!body.to_string().contains("\"old\""), "{body}");
}

/// `count` backends named `name-NNN`, kept so a row can read their counters.
pub(super) fn register(state: &Arc<AppState>, count: usize) -> Vec<Arc<Backend>> {
    (0..count)
        .map(|i| {
            let backend = Arc::new(Backend::new(
                &format!("name-{i:03}"),
                BackendConfig::default(),
                &FailsafeConfig::default(),
                Duration::from_secs(300),
            ));
            assert!(
                state.backends.register(Arc::clone(&backend)),
                "register {i}"
            );
            backend
        })
        .collect()
}

/// S5 (D5): `tool_tried` is true when the last 30 local days hold a call;
/// `client_connected` is never sent.
#[tokio::test]
async fn s5_tool_tried_looks_back_thirty_days() {
    let _clock = test_clock::at_secs(NOW);
    for (age_days, want) in [(None, false), (Some(10), true), (Some(31), false)] {
        let (state, _dir) = fixture(0, false).await;
        let store = with_store(&state, 0);
        if let Some(days) = age_days {
            record(
                &store,
                "key:a",
                "srv",
                NOW - days * 24 * HOUR,
                Tally::default(),
            );
        }
        let body = overview(&state).await;
        assert_eq!(
            body["checklist"]["tool_tried"], want,
            "{age_days:?}: {body}"
        );
        assert!(
            body["checklist"].get("client_connected").is_none(),
            "{body}"
        );
    }
}

/// S6 (D6): thirty idle servers; each of the 24 rows carries a state and a
/// reason, and the state is worked out for those 24 only.
#[tokio::test]
async fn s6_state_is_read_for_the_rows_shown_only() {
    let (state, _dir) = fixture(0, false).await;
    let backends = register(&state, 30);

    let body = overview(&state).await;

    let rows = body["servers"]["rows"].as_array().expect("server rows");
    for row in rows {
        assert_eq!(row["state"], "dormant", "{body}");
        assert!(
            row["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "{body}"
        );
    }
    let evaluations: usize = backends
        .iter()
        .map(|b| b.server_state_evaluations_for_test())
        .sum();
    assert_eq!(evaluations, 24);
}

/// Asserts that every field the counter store feeds is absent from `body`.
fn assert_no_counter_fields(body: &Value) {
    for absent in [
        "calls_24h",
        "calls_prev_24h",
        "blocks_24h",
        "blocks_prev_24h",
        "errors_24h",
        "errors_prev_24h",
        "counting_since",
    ] {
        assert!(body["kpi"].get(absent).is_none(), "kpi.{absent}: {body}");
    }
    for row in body["servers"]["rows"].as_array().expect("server rows") {
        assert!(row.get("calls_24h").is_none(), "servers.rows: {body}");
    }
    assert!(body.get("edges").is_none(), "edges: {body}");
    assert!(body.get("markers").is_none(), "markers: {body}");
    assert!(body["checklist"].get("tool_tried").is_none(), "{body}");
    assert!(body.get("latency").is_none(), "latency: {body}");
}

/// S8: no counter store, so the counter fields are absent and nothing is
/// degraded. Green at the base: regression coverage.
#[tokio::test]
async fn s8_no_store_leaves_the_counter_fields_out() {
    let (state, _dir) = fixture(1, false).await;

    let body = overview(&state).await;

    assert_no_counter_fields(&body);
    assert!(body.get("degraded").is_none(), "{body}");
    assert_eq!(body["checklist"]["has_key"], true, "{body}");
}

/// S8b: a store but a clock that cannot be read; the counter fields are
/// absent and `degraded` names exactly them.
#[tokio::test]
async fn s8b_an_unreadable_clock_degrades_the_counter_fields() {
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    calls(&store, "name-000", 1);
    let _clock = test_clock::before_epoch();

    let (_, raw) = get(&state, Some(ADMIN_KEY)).await;

    let body: Value = serde_json::from_str(&raw).expect("a JSON body");
    assert_no_counter_fields(&body);
    let mut degraded: Vec<&str> = body["degraded"]
        .as_array()
        .expect("a degraded list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    degraded.sort_unstable();
    let mut want = [
        "kpi.calls_24h",
        "kpi.blocks_24h",
        "kpi.errors_24h",
        "servers.calls_24h",
        "edges",
        "markers",
        "checklist.tool_tried",
        "latency",
    ];
    want.sort_unstable();
    assert_eq!(degraded, want, "{body}");
}

/// S10: one read takes the store's lock exactly eight times (three KPI
/// series, the server sums, the pairs, the markers, the 30-day series, the
/// latency hour), whatever the server count.
#[tokio::test]
async fn s10_a_read_takes_the_store_lock_eight_times() {
    let _clock = test_clock::at_secs(NOW);
    for servers in [10, 140] {
        let (state, _dir) = fixture(servers, false).await;
        let store = with_store(&state, 0);
        calls(&store, "name-000", 2);
        let before = store.reads_for_test();

        let _ = overview(&state).await;

        assert_eq!(store.reads_for_test() - before, 8, "{servers} servers");
    }
}

/// S13 (latency rows 38, 39): with no sample in the last hour the latency
/// member is present and empty; the slowest server is found over every
/// server, even one outside the capped rows: 24 servers with too few calls to
/// name rank above it.
#[tokio::test]
async fn s13_latency_names_the_slowest_beyond_the_rows() {
    let _clock = test_clock::at_secs(NOW);
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    calls(&store, "name-000", 1);
    let body = overview(&state).await;
    assert_eq!(body["latency"]["servers"], serde_json::json!([]), "{body}");
    assert!(body["latency"]["slowest"].is_null(), "{body}");

    for i in 0..24 {
        for _ in 0..20 {
            timed(&store, &format!("hot-{i:02}"), NOW - 600, 60_000);
        }
    }
    for _ in 0..21 {
        timed(&store, "steady", NOW - 600, 2_000);
    }
    let body = overview(&state).await;
    let names: Vec<&str> = body["latency"]["servers"]
        .as_array()
        .expect("latency rows")
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect();
    assert_eq!(names.len(), 24, "{body}");
    assert!(!names.contains(&"steady"), "{names:?}");
    assert_eq!(body["latency"]["more"]["count"], 1, "{body}");
    assert_eq!(body["latency"]["slowest"]["name"], "steady", "{body}");
    assert_eq!(body["latency"]["slowest"]["calls"], 21, "{body}");
}
