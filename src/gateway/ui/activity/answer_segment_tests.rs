// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows R5, R36, R37 over a rotated log: the look-above reads newer
//! segments, and says so when it cannot.

use super::answer_fixture::{Dl, Fixture, fat_findings, segments_with_delivery};
use super::answer_list_tests::{get, row_of};

/// C1 and C2 early; D1, the record of C1, in its own sealed segment among
/// fat records; the page-one cursor sits below C2. Returns the cursor.
async fn layout() -> (Fixture, String) {
    let fx = Fixture::rotating(None, 4096);
    fx.call("gw-c1");
    fx.call("gw-c2");
    let fat = |t: &str| fx.delivery(t, &Dl::effect("annotated").findings(fat_findings()));
    for i in 0..3 {
        fat(&format!("gw-a{i}"));
    }
    fx.delivery("gw-c1", &Dl::effect("delivered").findings(fat_findings()));
    for i in 0..3 {
        fat(&format!("gw-b{i}"));
    }
    let (_, first) = get(&fx, &[("limit", "1")]).await;
    assert_eq!(row_of(&first, "gw-c2")["effect"], "no_record");
    let cursor = first["next_cursor"].as_str().unwrap().to_string();
    (fx, cursor)
}

#[tokio::test]
async fn r37_the_look_above_crosses_segments_to_the_delivery() {
    let (fx, cursor) = layout().await;
    let (_, second) = get(&fx, &[("limit", "1"), ("cursor", &cursor)]).await;
    assert_eq!(row_of(&second, "gw-c1")["effect"], "delivered");
    assert_eq!(second["join_incomplete"], 0);
}

#[tokio::test]
async fn r5_a_lost_newer_segment_is_counted_not_hidden() {
    let (fx, cursor) = layout().await;
    for gone in segments_with_delivery(&fx.path, "gw-c1") {
        std::fs::remove_file(gone).unwrap();
    }
    let (_, second) = get(&fx, &[("limit", "1"), ("cursor", &cursor)]).await;
    assert_eq!(row_of(&second, "gw-c1")["effect"], "no_record");
    assert_eq!(second["join_incomplete"], 1);
}

#[tokio::test]
async fn r36_a_filtered_miss_still_counts() {
    let (fx, cursor) = layout().await;
    for gone in segments_with_delivery(&fx.path, "gw-c1") {
        std::fs::remove_file(gone).unwrap();
    }
    let q = [
        ("limit", "1"),
        ("cursor", cursor.as_str()),
        ("effect", "delivered"),
    ];
    let (_, page) = get(&fx, &q).await;
    assert!(page["rows"].as_array().unwrap().is_empty());
    assert_eq!(page["join_incomplete"], 1);
}
