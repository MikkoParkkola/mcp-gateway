// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 row R36 (export half, design I3/12a): an authorised, readable call
//! whose join is evicted or poisoned is filtered out by `effect=`, and still
//! counts in the signed manifest; the unfiltered control shows the same count.

use serde_json::{Value, json};

use super::answer_export_tests::{ndjson, signer};
use super::answer_fixture::{Dl, Fixture, SECRET};
use super::{ExportQuery, ListQuery, export_response};

/// The manifest and rows of an export under `effect`, if any.
async fn manifest(fx: &Fixture, effect: Option<&str>) -> (Vec<Value>, Value) {
    let query = ExportQuery {
        list: ListQuery {
            effect: effect.map(Into::into),
            ..ListQuery::default()
        },
        format: Some("ndjson".into()),
    };
    let response = export_response(&fx.logs(), &fx.access(), &query, Some(&signer()));
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    ndjson(std::str::from_utf8(&bytes).unwrap())
}

/// Filtered by `effect=delivered`: no rows, one count. Unfiltered: the call's
/// row (effect unknown) and the same count.
async fn assert_counted_when_filtered_out(fx: &Fixture, trace: &str, integrity: u64) {
    let (rows, filtered) = manifest(fx, Some("delivered")).await;
    assert!(rows.is_empty(), "{rows:?}");
    let (rows, control) = manifest(fx, None).await;
    let call = rows
        .iter()
        .find(|r| r["trace_id"] == trace)
        .expect("the call");
    assert_eq!(call["effect"], "unknown");
    for m in [&filtered, &control] {
        assert_eq!(m["join_incomplete"], 1);
        assert_eq!(m["answer_integrity_failed"], integrity);
    }
}

#[tokio::test]
async fn r36_a_filtered_call_with_a_poisoned_record_still_counts_in_the_manifest() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-p");
    fx.delivery("gw-p", &Dl::effect("delivered"));
    let at = fx.delivery_index("gw-p");
    fx.edit(at, |e| e["response_effect"] = json!("refused"));
    assert_counted_when_filtered_out(&fx, "gw-p", 1).await;
}

#[tokio::test]
async fn r36_a_filtered_call_with_an_evicted_record_still_counts_in_the_manifest() {
    let fx = Fixture::new(None);
    fx.call("gw-e");
    for i in 0..256 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    fx.delivery("gw-e", &Dl::effect("delivered"));
    assert_counted_when_filtered_out(&fx, "gw-e", 0).await;
}
