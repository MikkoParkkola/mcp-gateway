// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The health read's answer, built from histories made with the store's own
//! calls on a literal clock: each series, both downtime kinds, what was not
//! observed, the 7-day window, survival across a restart, and that the answer
//! holds numbers and two fixed words only.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::{CLOCK_BEFORE_1970, NO_HISTORY, health_body, respond};
use crate::gateway::health_metrics::ErrorKind;
use crate::health_history::file::{self, Wait};
use crate::health_history::{HealthHistory, Restores};

/// A base second on both a six-hour and a half-hour boundary
/// (`21_600 * 83_334 = 1_800 * 1_000_008`); every time below is an offset from it.
const B0: u64 = 1_800_014_400;

fn fresh(at: u64) -> HealthHistory {
    HealthHistory::start(None, Restores::Counted(0), at).0
}

fn errors(history: &HealthHistory, kind: ErrorKind, count: usize, at: u64) {
    for _ in 0..count {
        history.record_error(kind, at);
    }
}

fn calls(history: &HealthHistory, count: usize, secs: f64, at: u64) {
    for _ in 0..count {
        history.record_latency(secs, at);
    }
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// Three runs: a clean stop then a start (measured downtime), then a run
/// that ends without a stop and a start after it (estimated downtime).
fn three_lives() -> HealthHistory {
    let (first, _) = HealthHistory::start(None, Restores::Counted(0), B0);
    first.tick(B0 + 600);
    first.stop(B0 + 600);
    let saved = first.encode(B0 + 600).expect("the first run encodes");
    let (second, started) = HealthHistory::start(Some(&saved), Restores::Counted(1), B0 + 650);
    assert!(started.restart.is_some(), "the second start is a restart");
    second.tick(B0 + 900);
    let saved = second.encode(B0 + 900).expect("the second run encodes");
    let (third, started) = HealthHistory::start(Some(&saved), Restores::Counted(2), B0 + 1_000);
    assert!(started.restart.is_some(), "the third start is a restart");
    third.tick(B0 + 1_200);
    third
}

#[test]
fn g1_tiles_serve_each_series_for_the_last_hour_and_the_hour_before() {
    let history = fresh(B0);
    // Four complete half-hours, then the one in progress at B0 + 7_200. Each
    // gets a different power of two of gateway errors, so every span sums to
    // its own number, and its own latency bucket.
    for (start, auth, secs) in [
        (B0, 1, 0.000_8),
        (B0 + 1_800, 2, 0.002),
        (B0 + 3_600, 4, 0.004),
        (B0 + 5_400, 8, 0.008),
        (B0 + 7_200, 16, 0.02),
    ] {
        errors(&history, ErrorKind::Auth, auth, start + 10);
        calls(&history, 20, secs, start + 20);
    }
    // A backend's own errors sit in a counted span: only their kind keeps
    // them out of the gateway tile.
    errors(&history, ErrorKind::Backend, 32, B0 + 5_410);
    history.sample(Some(1_000), 9, B0 + 5_430);
    history.sample(Some(73_400_320), 5, B0 + 7_230);
    let now = B0 + 7_800;
    history.tick(now);

    let body = health_body(&history, now);
    assert_eq!(
        body["tiles"],
        json!({
            "added_p95": {"now": {"ms": 10.0}, "before": {"ms": 2.5}},
            "gateway_errors": {"now": 12, "before": 3},
            "memory_bytes": 73_400_320,
            "sessions": 5,
        }),
        "{body}"
    );
}

#[test]
fn g1b_what_was_not_observed_is_null_and_a_slow_p95_keeps_its_form() {
    let now = B0 + 7_800;

    // Observed for the last 40 minutes only: the hour before is unknown.
    let late = fresh(B0 + 5_400);
    errors(&late, ErrorKind::Auth, 1, B0 + 5_410);
    late.tick(now);
    let tiles = health_body(&late, now)["tiles"].clone();
    assert_eq!(tiles["gateway_errors"]["now"], json!(1), "{tiles}");
    assert_eq!(tiles["gateway_errors"]["before"], Value::Null, "{tiles}");
    assert_eq!(tiles["added_p95"]["before"], Value::Null, "{tiles}");
    assert_eq!(
        tiles["added_p95"]["now"],
        Value::Null,
        "observed, no call: {tiles}"
    );

    // A sample in an earlier half-hour, none in the one in progress.
    let quiet = fresh(B0);
    quiet.sample(Some(500), 3, B0 + 5_430);
    quiet.tick(now);
    let tiles = health_body(&quiet, now)["tiles"].clone();
    assert_eq!(tiles["memory_bytes"], Value::Null, "{tiles}");
    assert_eq!(tiles["sessions"], Value::Null, "{tiles}");

    // Every call in the last hour is slower than the top finite bound.
    let slow = fresh(B0);
    calls(&slow, 10, 9.0, B0 + 3_620);
    slow.tick(now);
    let tiles = health_body(&slow, now)["tiles"].clone();
    assert_eq!(
        tiles["added_p95"]["now"],
        json!({"above_ms": 2500.0}),
        "{tiles}"
    );
}

#[test]
fn g2_halves_are_sixteen_oldest_first_and_an_unobserved_slot_is_null() {
    let h = B0 + 28_800;
    let now = h + 100;
    let history = fresh(B0 + 14_400);
    errors(&history, ErrorKind::Auth, 2, B0 + 14_410);
    calls(&history, 20, 0.004, B0 + 14_420);
    history.sample(Some(4_096), 2, B0 + 14_430);
    history.sample(None, 1, B0 + 27_030);
    history.tick(now);

    let body = health_body(&history, now);
    let halves = body["halves"].as_array().cloned().unwrap_or_default();
    assert_eq!(halves.len(), 16, "{body}");
    let starts: Vec<u64> = halves
        .iter()
        .filter_map(|half| half["t"].as_u64())
        .collect();
    let expected: Vec<u64> = (0..16).map(|i| 1_800_014_400 + 1_800 * i).collect();
    assert_eq!(starts, expected, "oldest first, one per slot: {body}");
    assert!(
        starts.iter().all(|&t| t < 1_800_043_200),
        "the half-hour in progress is not a point: {body}"
    );
    let five = BTreeSet::from([
        "t",
        "added_p95",
        "gateway_errors",
        "memory_max",
        "sessions_max",
    ]);
    for half in &halves {
        assert_eq!(keys(half), five, "{half}");
    }
    for half in &halves[..8] {
        assert_eq!(
            half,
            &json!({"t": half["t"], "added_p95": null, "gateway_errors": null,
                    "memory_max": null, "sessions_max": null}),
            "a slot before the history began is null, never 0"
        );
    }
    assert_eq!(
        halves[8],
        json!({"t": 1_800_028_800_u64, "added_p95": {"ms": 5.0}, "gateway_errors": 2,
               "memory_max": 4_096, "sessions_max": 2})
    );
    assert_eq!(
        halves[9],
        json!({"t": 1_800_030_600_u64, "added_p95": null, "gateway_errors": 0,
               "memory_max": null, "sessions_max": null}),
        "observed and idle"
    );
    assert_eq!(
        halves[15],
        json!({"t": 1_800_041_400_u64, "added_p95": null, "gateway_errors": 0,
               "memory_max": null, "sessions_max": 1})
    );
}

#[test]
fn g3_the_strip_serves_blocks_and_both_downtime_kinds() {
    let history = three_lives();
    let body = health_body(&history, B0 + 1_200);
    assert_eq!(
        body["restarts"],
        json!([
            {"stopped_at": 1_800_015_000_u64, "started_at": 1_800_015_050_u64, "downtime": "measured"},
            {"stopped_at": 1_800_015_300_u64, "started_at": 1_800_015_400_u64, "downtime": "estimated"},
        ]),
        "{body}"
    );
    assert_eq!(body["restarts_dropped"], json!(false), "{body}");
    assert_eq!(
        body["blocks"],
        json!([{"t": 1_800_014_400_u64, "running_seconds": 1_050, "down_seconds": 150,
                "restarts": 2, "estimated": true}]),
        "{body}"
    );
    // 1_050 of 1_200 covered seconds, exactly 87.5 percent.
    assert_eq!(
        body["uptime"],
        json!({"percent": 87.5, "running_seconds": 1_050, "down_seconds": 150,
               "covered_seconds": 1_200, "coverage_complete": false}),
        "{body}"
    );
    assert_eq!(body["observed_since"], json!(1_800_014_400_u64), "{body}");
    assert_eq!(body["generated_at"], json!(1_800_015_600_u64), "{body}");
    assert_eq!(body["incomplete"], json!(false), "{body}");
}

#[test]
fn g4_the_served_history_survives_restart() {
    let history = fresh(B0);
    errors(&history, ErrorKind::Auth, 3, B0 + 10);
    calls(&history, 20, 0.004, B0 + 20);
    history.sample(Some(2_048), 4, B0 + 30);
    history.tick(B0 + 600);
    history.stop(B0 + 600);
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("health.json");
    assert!(
        file::save(&history, &path, B0 + 600, Wait::Block),
        "premise: the history is saved"
    );
    let bytes = file::read(&path).expect("the saved file reads back");
    let (restarted, _) = HealthHistory::start(Some(&bytes), Restores::Counted(1), B0 + 700);
    restarted.tick(B0 + 2_000);

    let body = health_body(&restarted, B0 + 2_000);
    assert_eq!(
        body["halves"][15],
        json!({"t": 1_800_014_400_u64, "added_p95": {"ms": 5.0}, "gateway_errors": 3,
               "memory_max": 2_048, "sessions_max": 4}),
        "{body}"
    );
    assert_eq!(
        body["restarts"],
        json!([{"stopped_at": 1_800_015_000_u64, "started_at": 1_800_015_100_u64,
                "downtime": "measured"}]),
        "{body}"
    );
    assert_eq!(
        body["observed_since"],
        json!(1_800_014_400_u64),
        "kept from the saved history, not this start: {body}"
    );
    drop(dir);
}

/// Every string in `value` is pushed to `words`; every other leaf must be a
/// number, a bool or null.
fn leaves<'a>(value: &'a Value, words: &mut Vec<&'a str>) {
    match value {
        Value::Object(object) => object.values().for_each(|v| leaves(v, words)),
        Value::Array(items) => items.iter().for_each(|v| leaves(v, words)),
        Value::String(word) => words.push(word),
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

#[test]
fn g5_the_answer_holds_only_numbers_and_fixed_words() {
    let body = health_body(&three_lives(), B0 + 1_200);
    assert_eq!(
        keys(&body),
        BTreeSet::from([
            "generated_at",
            "observed_since",
            "incomplete",
            "tiles",
            "halves",
            "uptime",
            "blocks",
            "restarts",
            "restarts_dropped",
        ]),
        "{body}"
    );
    let tiles = &body["tiles"];
    assert_eq!(
        keys(tiles),
        BTreeSet::from(["added_p95", "gateway_errors", "memory_bytes", "sessions"]),
        "{body}"
    );
    for rate in ["added_p95", "gateway_errors"] {
        assert_eq!(
            keys(&tiles[rate]),
            BTreeSet::from(["now", "before"]),
            "{body}"
        );
    }
    let p95_forms = BTreeSet::from(["ms", "above_ms"]);
    let halves = body["halves"].as_array().cloned().unwrap_or_default();
    let p95s = halves
        .iter()
        .map(|half| &half["added_p95"])
        .chain([&tiles["added_p95"]["now"], &tiles["added_p95"]["before"]]);
    for p95 in p95s.filter(|p| !p.is_null()) {
        let found = keys(p95);
        assert_eq!(found.len(), 1, "{p95}");
        assert!(found.is_subset(&p95_forms), "{p95}");
    }
    assert_eq!(
        keys(&body["uptime"]),
        BTreeSet::from([
            "percent",
            "running_seconds",
            "down_seconds",
            "covered_seconds",
            "coverage_complete",
        ]),
        "{body}"
    );
    let block_keys = BTreeSet::from([
        "t",
        "running_seconds",
        "down_seconds",
        "restarts",
        "estimated",
    ]);
    for block in body["blocks"].as_array().cloned().unwrap_or_default() {
        assert_eq!(keys(&block), block_keys, "{block}");
    }
    for restart in body["restarts"].as_array().cloned().unwrap_or_default() {
        assert_eq!(
            keys(&restart),
            BTreeSet::from(["stopped_at", "started_at", "downtime"]),
            "{restart}"
        );
    }
    let mut words = Vec::new();
    leaves(&body, &mut words);
    let distinct: BTreeSet<&str> = words.iter().copied().collect();
    assert_eq!(
        distinct,
        BTreeSet::from(["measured", "estimated"]),
        "the only strings are the two downtime words, and both are here: {body}"
    );
}

async fn status_and_body(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body reads");
    (status, serde_json::from_slice(&bytes).expect("a JSON body"))
}

#[tokio::test]
async fn g7_no_history_or_a_clock_before_1970_is_503() {
    assert_eq!(NO_HISTORY, "the health history is not running");
    assert_eq!(CLOCK_BEFORE_1970, "the system clock reads before 1970");

    let (status, body) = status_and_body(respond::<()>(None, Ok(B0))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, json!({"error": "the health history is not running"}));

    let history = Arc::new(fresh(B0));
    let (status, body) = status_and_body(respond(Some(Arc::clone(&history)), Err(()))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, json!({"error": "the system clock reads before 1970"}));

    history.tick(B0 + 600);
    let (status, body) = status_and_body(respond::<()>(Some(history), Ok(B0 + 600))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["generated_at"], json!(1_800_015_000_u64), "{body}");
}

#[test]
fn g8_seven_days_only() {
    // An old block and an old restart: two runs on the first day, then a run
    // eight days later that the history did not see coming (a missed run, so
    // no restart is recorded for it).
    let (first, _) = HealthHistory::start(None, Restores::Counted(0), B0);
    first.tick(B0 + 600);
    first.stop(B0 + 600);
    let saved = first.encode(B0 + 600).expect("encodes");
    let (second, _) = HealthHistory::start(Some(&saved), Restores::Counted(1), B0 + 650);
    second.tick(B0 + 3_600);
    let saved = second.encode(B0 + 3_600).expect("encodes");
    let (late, started) = HealthHistory::start(Some(&saved), Restores::Counted(5), B0 + 691_200);
    assert!(
        started.missed_run && started.restart.is_none(),
        "{started:?}"
    );
    let now = B0 + 691_800;
    late.tick(now);
    assert_eq!(
        late.restarts(0, u64::MAX).0.len(),
        1,
        "premise: the old restart is still in the store"
    );
    let body = health_body(&late, now);
    assert_eq!(
        body["blocks"],
        json!([{"t": 1_800_705_600_u64, "running_seconds": 600, "down_seconds": 0,
                "restarts": 0, "estimated": false}]),
        "the block that ended before the window is left out: {body}"
    );
    assert_eq!(body["restarts"], json!([]), "{body}");

    // A block that began before the window and reaches into it is served
    // with its own start.
    let long = fresh(B0 + 10_800);
    let now = B0 + 619_200;
    long.tick(now);
    let body = health_body(&long, now);
    let blocks = body["blocks"].as_array().cloned().unwrap_or_default();
    assert_eq!(blocks.len(), 29, "{body}");
    assert_eq!(
        blocks[0],
        json!({"t": 1_800_014_400_u64, "running_seconds": 10_800, "down_seconds": 0,
               "restarts": 0, "estimated": false})
    );
    assert_eq!(blocks[28]["t"], json!(1_800_619_200_u64));
    assert_eq!(body["uptime"]["coverage_complete"], json!(true), "{body}");
    assert_eq!(body["uptime"]["running_seconds"], json!(608_400), "{body}");
}

#[test]
fn g9_one_answer_is_of_one_instant() {
    let history = fresh(B0);
    errors(&history, ErrorKind::Auth, 1, B0 + 10);
    history.tick(B0 + 600);
    let copy = history.frozen();
    errors(&history, ErrorKind::Auth, 5, B0 + 700);
    history.tick(B0 + 1_200);

    let now = B0 + 1_900;
    let from_copy = health_body(&copy, now);
    assert_eq!(
        from_copy["halves"][15]["gateway_errors"],
        json!(1),
        "{from_copy}"
    );
    assert_eq!(
        from_copy["blocks"][0]["running_seconds"],
        json!(600),
        "{from_copy}"
    );
    let from_live = health_body(&history, now);
    assert_eq!(
        from_live["halves"][15]["gateway_errors"],
        json!(6),
        "{from_live}"
    );
    assert_eq!(
        from_live["blocks"][0]["running_seconds"],
        json!(1_200),
        "{from_live}"
    );
}
