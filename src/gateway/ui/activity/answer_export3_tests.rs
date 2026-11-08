// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 row R36 (export half, design I3): a call whose delivery record
//! failed the trust rule is filtered out by `effect=`, and still counts in the
//! signed manifest, because counts are taken before the user filters.

use serde_json::json;

use super::answer_export_tests::{ndjson, signer};
use super::answer_fixture::{Dl, Fixture, SECRET};
use super::{ExportQuery, ListQuery, export_response};

#[tokio::test]
async fn r36_a_filtered_call_with_a_poisoned_record_still_counts_in_the_manifest() {
    let fx = Fixture::new(Some(SECRET));
    fx.call("gw-p");
    fx.delivery("gw-p", &Dl::effect("delivered"));
    let at = fx.delivery_index("gw-p");
    fx.edit(at, |e| e["response_effect"] = json!("refused"));
    let query = ExportQuery {
        list: ListQuery {
            effect: Some("delivered".into()),
            ..ListQuery::default()
        },
        format: Some("ndjson".into()),
    };
    let response = export_response(&fx.logs(), &fx.access(), &query, Some(&signer()));
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let (rows, manifest) = ndjson(std::str::from_utf8(&bytes).unwrap());
    assert!(rows.is_empty(), "{rows:?}");
    assert_eq!(manifest["join_incomplete"], 1);
    assert_eq!(manifest["answer_integrity_failed"], 1);
}
