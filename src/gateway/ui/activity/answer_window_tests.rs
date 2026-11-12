// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JOIN.4: one delivery window for the list, the export and the receipt. A
//! record reaches a call only when it lies within `DELIVERY_WINDOW` bytes
//! after the call's line; the list answers the same at every page size.

use std::collections::BTreeMap;

use super::answer::{DELIVERY_WINDOW, LOOK_ABOVE, RECEIPT_SCAN};
use super::answer_export_tests::{export_for, ndjson};
use super::answer_fixture::{Dl, Fixture, SECRET, fat_findings};
use super::answer_list_tests::{get, row_of};
use super::answer_receipt_tests::rcpt;

/// Padding between a call and its delivery, in bytes of log: 20 KiB inside the
/// window and 20 KiB outside it (a margin over any one record's size).
const INSIDE: u64 = DELIVERY_WINDOW - 20 * 1024;
const OUTSIDE: u64 = DELIVERY_WINDOW + 20 * 1024;

/// The bytes one fat padding record takes in a log, measured on a scratch log.
fn fat_record_bytes() -> u64 {
    let scratch = Fixture::new(None);
    let before = std::fs::metadata(&scratch.path).map_or(0, |m| m.len());
    scratch.delivery(
        "gw-probe",
        &Dl::effect("annotated").findings(fat_findings()),
    );
    std::fs::metadata(&scratch.path).unwrap().len() - before
}

/// Write fat padding records totalling at least `bytes` of log (rotation-safe:
/// the count comes from one measured record, not from the file's length).
fn pad(fx: &Fixture, bytes: u64) {
    let each = fat_record_bytes();
    for i in 0..bytes.div_ceil(each) {
        fx.delivery(
            &format!("gw-f{i}"),
            &Dl::effect("annotated").findings(fat_findings()),
        );
    }
}

/// `gw-c1` and `gw-c2`, `gap` bytes of padding, then `gw-c1`'s delivery.
fn layout(gap: u64) -> Fixture {
    fill(Fixture::new(None), gap)
}

fn fill(fx: Fixture, gap: u64) -> Fixture {
    fx.call("gw-c1");
    fx.call("gw-c2");
    pad(&fx, gap);
    fx.delivery("gw-c1", &Dl::effect("delivered"));
    fx
}

/// Every call's effect, reading the list `limit` rows at a time through its cursors.
async fn effects_at(fx: &Fixture, limit: &str) -> BTreeMap<String, String> {
    let mut seen = BTreeMap::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query = vec![("limit", limit)];
        if let Some(token) = cursor.as_deref() {
            query.push(("cursor", token));
        }
        let (_, page) = get(fx, &query).await;
        for row in page["rows"].as_array().unwrap() {
            if let (Some(t), Some(e)) = (row["trace_id"].as_str(), row["effect"].as_str()) {
                if t == "gw-c1" || t == "gw-c2" {
                    seen.insert(t.to_string(), e.to_string());
                }
            }
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => return seen,
        }
    }
}

#[tokio::test]
async fn w1_a_delivery_inside_the_window_is_found_and_one_outside_is_not() {
    let near = layout(INSIDE);
    let (_, page) = get(&near, &[("limit", "200")]).await;
    assert_eq!(
        row_of(&page, "gw-c1")["effect"],
        "delivered",
        "inside, list"
    );
    let far = layout(OUTSIDE);
    let (_, page) = get(&far, &[("limit", "200")]).await;
    assert_eq!(
        row_of(&page, "gw-c1")["effect"],
        "no_record",
        "outside, list"
    );
    let (rows, _) = ndjson(&export_for(&far, "ndjson", &[]).await);
    let exported = rows.iter().find(|r| r["trace_id"] == "gw-c1").unwrap();
    assert_eq!(exported["effect"], "no_record", "outside, export");
    assert_eq!(
        rcpt(&far, "gw-c1")["effect"],
        "no_record",
        "outside, receipt"
    );
    assert_eq!(
        rcpt(&near, "gw-c1")["effect"],
        "delivered",
        "inside, receipt"
    );
}

#[tokio::test]
async fn w3_the_answer_does_not_depend_on_the_page_size() {
    for gap in [INSIDE, OUTSIDE] {
        // Small segments, as the look-above row does: each page reads across them.
        let fx = fill(Fixture::rotating(None, 4096), gap);
        let whole = effects_at(&fx, "200").await;
        for limit in ["1", "2", "3"] {
            assert_eq!(
                effects_at(&fx, limit).await,
                whole,
                "gap {gap}, limit {limit}"
            );
        }
    }
}

#[tokio::test]
async fn w6_a_delivery_beyond_the_window_is_counted_and_one_inside_is_not() {
    let far = layout(OUTSIDE);
    let (_, page) = get(&far, &[("limit", "200")]).await;
    assert_eq!(page["delivery_beyond_window"], 1, "{page}");
    assert_eq!(page["delivery_window_bytes"], DELIVERY_WINDOW, "{page}");
    let (_, manifest) = ndjson(&export_for(&far, "ndjson", &[]).await);
    assert_eq!(manifest["delivery_beyond_window"], 1, "{manifest}");
    assert_eq!(
        manifest["delivery_window_bytes"], DELIVERY_WINDOW,
        "{manifest}"
    );
    let near = layout(INSIDE);
    let (_, page) = get(&near, &[("limit", "200")]).await;
    assert_eq!(page["delivery_beyond_window"], 0, "{page}");
}

#[tokio::test]
async fn w7_tamper_evidence_beyond_the_window_reads_no_record_and_counts() {
    // A far record with a broken hash.
    let bad = Fixture::new(Some(SECRET));
    bad.call("gw-c1");
    pad(&bad, OUTSIDE);
    bad.delivery("gw-c1", &Dl::effect("delivered"));
    let at = bad.delivery_index("gw-c1");
    bad.edit(at, |e| e["response_effect"] = serde_json::json!("refused"));
    let (_, page) = get(&bad, &[("limit", "200")]).await;
    let row = row_of(&page, "gw-c1");
    assert_eq!(row["effect"], "no_record", "{row}");
    assert_eq!(page["delivery_beyond_window"], 1, "{page}");
    // Two far records for one trace count the call once.
    let dup = Fixture::new(None);
    dup.call("gw-c1");
    pad(&dup, OUTSIDE);
    dup.delivery("gw-c1", &Dl::effect("delivered"));
    dup.delivery("gw-c1", &Dl::effect("refused"));
    let (_, page) = get(&dup, &[("limit", "200")]).await;
    assert_eq!(row_of(&page, "gw-c1")["effect"], "no_record");
    assert_eq!(page["delivery_beyond_window"], 1, "{page}");
}

#[tokio::test]
async fn w8_the_no_record_wording_names_the_window() {
    let far = layout(OUTSIDE);
    let (_, page) = get(&far, &[("limit", "200")]).await;
    assert_eq!(
        row_of(&page, "gw-c1")["answer_findings"],
        "no delivery record within 256 KiB after the call"
    );
    let line = super::answer_receipt_tests::line_of(&rcpt(&far, "gw-c1"));
    assert!(
        line.contains("256 KiB") || line.contains("262144"),
        "{line}"
    );
}

#[test]
fn w9_the_three_window_constants_are_one_value() {
    assert_eq!(LOOK_ABOVE, DELIVERY_WINDOW);
    assert_eq!(RECEIPT_SCAN, DELIVERY_WINDOW);
}
