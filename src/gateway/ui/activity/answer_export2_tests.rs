// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 export rows R25, R38 and R41: signed counts across passes and the
//! integrity-scope label at row and response scope.

use serde_json::json;

use super::answer::SCOPE_LABEL;
use super::answer_export_tests::{csv_records, export, ndjson, signer};
use super::answer_fixture::{Dl, Fixture, SECRET};
use super::answer_list_tests::get;
use crate::trust::export_verify::verify_export;
use crate::trust::provenance_public::TrustSet;

#[tokio::test]
async fn r25_manifest_counts_are_signed_and_summed_across_passes() {
    let fx = Fixture::new(Some(SECRET));
    for i in 0..250 {
        fx.call(&format!("gw-c{i}"));
    }
    fx.delivery("gw-c100", &Dl::effect("delivered"));
    let poisoned = fx.delivery_index("gw-c100");
    fx.edit(poisoned, |e| e["response_effect"] = json!("refused"));
    for i in 0..260 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    fx.delivery("gw-c20", &Dl::effect("delivered"));
    fx.delivery("gw-c200", &Dl::effect("delivered"));
    let bytes = export(&fx, "ndjson").await;
    let (rows, manifest) = ndjson(&bytes);
    assert_eq!(rows.len(), 250);
    assert_eq!(manifest["join_incomplete"], 3);
    assert_eq!(manifest["answer_integrity_failed"], 1);
    let trust = TrustSet::from_json(&signer().public_jwk().to_string()).unwrap();
    verify_export(bytes.as_bytes(), &trust).expect("verifies");
    for field in ["join_incomplete", "answer_integrity_failed"] {
        let mut lines: Vec<String> = bytes.lines().map(str::to_string).collect();
        let mut m = manifest.clone();
        m[field] = json!(0);
        *lines.last_mut().unwrap() = m.to_string();
        let edited: String = lines.iter().map(|l| l.clone() + "\n").collect();
        assert!(verify_export(edited.as_bytes(), &trust).is_err(), "{field}");
    }
}

/// C(T) with D(T) refused, then a call with no record, and the one deleted.
fn labelled() -> Fixture {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    fx.call("gw-none");
    fx
}

#[tokio::test]
async fn r41_the_scope_label_is_on_rows_and_at_response_scope() {
    let fx = labelled();
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(page["answer_integrity_scope"], SCOPE_LABEL);
    assert_eq!(
        super::answer_list_tests::row_of(&page, "gw-t")["effect"],
        "refused"
    );
    for r in page["rows"].as_array().unwrap() {
        assert_eq!(r["answer_integrity_scope"], SCOPE_LABEL);
    }
    let (rows, manifest) = ndjson(&export(&fx, "ndjson").await);
    assert_eq!(manifest["answer_integrity_scope"], SCOPE_LABEL);
    assert!(
        rows.iter()
            .all(|r| r["answer_integrity_scope"] == SCOPE_LABEL)
    );
    assert!(rows.iter().any(|r| r["effect"] == "no_record"));
    let records = csv_records(&export(&fx, "csv").await);
    let col = records[0]
        .iter()
        .position(|c| c == "answer_integrity_scope")
        .unwrap();
    assert!(records[1..].iter().all(|r| r[col] == SCOPE_LABEL));
    assert!(!page.to_string().contains("\"verified\""));
}

#[tokio::test]
async fn r38_a_deleted_record_reads_no_record_and_is_qualified_by_the_label() {
    let fx = labelled();
    let mut lines = fx.lines();
    lines.remove(fx.delivery_index("gw-t"));
    super::answer_fixture::write_lines(&fx.path, &lines);
    let (_, page) = get(&fx, &[]).await;
    let row = super::answer_list_tests::row_of(&page, "gw-t");
    assert_eq!(row["effect"], "no_record");
    assert_eq!(row["answer_integrity_scope"], SCOPE_LABEL);
    assert_eq!(page["answer_integrity_scope"], SCOPE_LABEL);
    let (_, manifest) = ndjson(&export(&fx, "ndjson").await);
    assert_eq!(manifest["answer_integrity_scope"], SCOPE_LABEL);
}
