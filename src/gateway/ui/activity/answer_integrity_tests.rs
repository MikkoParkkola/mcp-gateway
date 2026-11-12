// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows R17, R19, R26, R27, R31-R34, R39, R40, R42: the map's bounds
//! and the trust rule.

use serde_json::json;

use super::answer::{MAX_EVICTED, MAX_JOINED, MAX_PENDING};
use super::answer_export_tests::{export_for, ndjson};
use super::answer_fixture::{Dl, Fixture, SECRET, forge};
use super::answer_list_tests::{get, row_of, traces};

#[tokio::test]
async fn r17_eviction_names_the_call_and_spares_the_rest() {
    let fx = Fixture::new(None);
    fx.call_on("only", "gw-t0");
    for i in 1..=256 {
        fx.call(&format!("gw-t{i}"));
    }
    for i in 1..=256 {
        fx.delivery(&format!("gw-t{i}"), &Dl::effect("refused"));
    }
    fx.delivery("gw-t0", &Dl::effect("refused"));
    let (_, page) = get(&fx, &[("server", "only")]).await;
    let r = row_of(&page, "gw-t0");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(page["join_incomplete"], 1);
    let (_, rest) = get(&fx, &[("server", "srv"), ("limit", "200")]).await;
    assert!(
        rest["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["effect"] == "refused")
    );
}

#[tokio::test]
async fn r19_a_settlement_row_shares_the_delivery() {
    let fx = Fixture::new(None);
    fx.call("gw-t1");
    fx.call("gw-t1");
    fx.delivery("gw-t1", &Dl::effect("annotated"));
    let (_, page) = get(&fx, &[]).await;
    let rows = page["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["effect"] == "annotated"));
    assert_eq!(page["answer_integrity_failed"], 0);
}

#[tokio::test]
async fn r26_a_duplicate_survives_eviction() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    for i in 0..256 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(row_of(&page, "gw-t")["effect"], "unknown");
}

#[tokio::test]
async fn r27_a_tampered_delivery_record_poisons_its_trace() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| e["response_effect"] = json!("delivered"));
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "invalid");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r31_a_bad_hmac_with_a_valid_hash_is_invalid() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| {
        e["sig"] = json!(format!("hmac-sha256:{}", "0".repeat(64)));
    });
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["answer_integrity"], "invalid");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r32_a_stripped_signature_under_a_secret_never_delivers() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| {
        forge(e, "response_effect", json!("delivered"), true);
    });
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "unsigned");
    assert_eq!(page["answer_integrity_failed"], 1);
}

/// A delivery record written before signing began reads Unsigned by position
/// (a signed entry follows it), but a gateway that holds a secret still cannot
/// believe it: the effect stays fail-closed, never delivered.
#[tokio::test]
async fn r32b_a_legacy_unsigned_delivery_under_a_secret_is_not_believed() {
    let legacy = Fixture::new(None);
    legacy.call("gw-t");
    legacy.delivery("gw-t", &Dl::effect("delivered"));
    let signed = legacy.reopened_with(SECRET);
    signed.call("gw-later");
    let (_, page) = get(&signed, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "unsigned");
    assert_eq!(page["answer_integrity_failed"], 1);
}

/// The rows of one trace, newest first.
fn rows_of<'a>(page: &'a serde_json::Value, trace: &str) -> Vec<&'a serde_json::Value> {
    page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["trace_id"] == trace)
        .collect()
}

/// Retiring a joined record keeps a duplicate caught: a second delivery
/// record for a trace that was already joined still poisons the older call row.
#[tokio::test]
async fn r46_a_duplicate_after_the_join_still_poisons_the_trace() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let (_, page) = get(&fx, &[]).await;
    let rows = rows_of(&page, "gw-t");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["effect"], "unknown", "the older call row");
    assert_eq!(rows[1]["answer_integrity"], "duplicate");
    assert_eq!(page["answer_integrity_failed"], 1);
}

/// The same for a record that fails the trust rule and is met after the join.
#[tokio::test]
async fn r47_a_bad_record_after_the_join_still_poisons_the_trace() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    fx.edit(at, |e| {
        forge(e, "response_effect", json!("delivered"), true);
    });
    let (_, page) = get(&fx, &[]).await;
    let rows = rows_of(&page, "gw-t");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["effect"], "unknown", "the older call row");
    assert_eq!(rows[1]["answer_integrity"], "unsigned");
}

/// Two call rows on one trace that are not adjacent both find the record
/// after the first is joined.
#[tokio::test]
async fn r48_two_call_rows_apart_both_find_the_record() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    for i in 0..40 {
        fx.call(&format!("gw-n{i}"));
    }
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("annotated"));
    let (_, page) = get(&fx, &[("limit", "200")]).await;
    let rows = rows_of(&page, "gw-t");
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r["effect"] == "annotated"));
}

/// Past the joined set's bound a read falls back to the pending map's bounds:
/// an older call that matches the filter reads the fail-closed effect and is
/// counted, never delivered. (Joins run before the filter, so a read can see
/// more traces than it exports.)
#[tokio::test]
async fn r49_a_read_past_the_joined_bound_fails_closed() {
    let fx = Fixture::new(None);
    fx.call_on("only", "gw-old");
    fx.delivery("gw-old", &Dl::effect("delivered"));
    // Calls past the bounds: each one older than the last pair that still fit.
    let past = 100;
    for i in 0..(MAX_JOINED + MAX_PENDING + MAX_EVICTED + past) {
        let trace = format!("gw-p{i}");
        fx.call(&trace);
        fx.delivery(&trace, &Dl::effect("delivered"));
    }
    let (rows, manifest) = ndjson(&export_for(&fx, "ndjson", &[("server", "only")]).await);
    let page = json!({"rows": rows});
    let r = row_of(&page, "gw-old");
    assert_eq!(r["effect"], "unknown");
    // The join counts every call the caller may read, whatever the filter
    // keeps (`export.rs`: `count` runs after the access check and before the
    // filter; design row R36, `answer_export3_tests.rs`: a filtered-out call
    // with a failed join still counts, so a filter cannot hide it). Here that
    // is the oldest `past` pairs, past the bounds, and the filtered call.
    assert_eq!(manifest["join_incomplete"], past + 1);
}

/// A trace reopened as poisoned after its join keeps its reason through the
/// stale order entry it left behind, compaction and eviction.
#[tokio::test]
async fn r50_a_reopened_trace_keeps_its_reason_through_eviction() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    for i in 0..(2 * MAX_PENDING) {
        fx.delivery(&format!("gw-orphan{i}"), &Dl::effect("refused"));
    }
    fx.delivery("gw-t", &Dl::effect("refused"));
    let at = fx.delivery_index("gw-t");
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    fx.edit(at, |e| {
        forge(e, "response_effect", json!("delivered"), true);
    });
    let (_, page) = get(&fx, &[]).await;
    let rows = rows_of(&page, "gw-t");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["effect"], "unknown", "the older call row");
    assert_eq!(rows[1]["answer_integrity"], "unsigned");
}

/// At the joined set's exact bound nothing is dropped: the call that joins as
/// the set fills still reads its record, and a duplicate behind it is caught.
#[tokio::test]
async fn r51_the_joined_bound_drops_no_record_and_misses_no_duplicate() {
    let fx = Fixture::new(None);
    fx.call_on("only", "gw-dup");
    fx.delivery("gw-dup", &Dl::effect("delivered"));
    fx.call_on("only", "gw-dup");
    fx.delivery("gw-dup", &Dl::effect("delivered"));
    fx.call_on("only", "gw-edge");
    fx.delivery("gw-edge", &Dl::effect("delivered"));
    for i in 0..MAX_JOINED {
        let trace = format!("gw-p{i}");
        fx.call(&trace);
        fx.delivery(&trace, &Dl::effect("delivered"));
    }
    let (rows, manifest) = ndjson(&export_for(&fx, "ndjson", &[("server", "only")]).await);
    let page = json!({"rows": rows});
    assert_eq!(row_of(&page, "gw-edge")["effect"], "delivered");
    let dup = rows_of(&page, "gw-dup");
    assert_eq!(dup.len(), 2);
    assert_eq!(dup[1]["answer_integrity"], "duplicate");
    assert_eq!(manifest["answer_integrity_failed"], 1);
}

/// A delivery record edited to look like a listed row (an admin action) is
/// still checked: its trace is poisoned, so the call reads the integrity
/// failure, not a missing record.
#[tokio::test]
async fn r52_an_edited_record_that_looks_like_a_listed_row_still_poisons_its_trace() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("delivered"));
    let at = fx.delivery_index("gw-t");
    fx.edit(at, |e| {
        forge(e, "event", json!("admin_action"), false);
    });
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "invalid");
    assert_eq!(page["answer_integrity_failed"], 1);
}

#[tokio::test]
async fn r33_no_secret_cannot_vouch() {
    let signed = Fixture::new(Some(SECRET));
    signed.call("gw-t");
    signed.delivery("gw-t", &Dl::effect("delivered"));
    let mut logs = signed.logs();
    logs.secret = None;
    let response = super::list_page(&logs, &signed.access(), &super::ListQuery::default());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let r = row_of(&page, "gw-t");
    assert_eq!(r["effect"], "delivered");
    assert_eq!(r["answer_integrity"], "unverifiable");
    let _ = traces(&page);
}
