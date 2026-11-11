// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 export rows R14, R22, R25, R41: NDJSON, CSV and the signed
//! manifest carry the join.

use serde_json::{Value, json};

use super::answer_fixture::{Dl, Fixture};
use super::answer_list_tests::{get, row_of};
use super::{ExportQuery, ListQuery, export_response};
use crate::trust::provenance_public::ProvenancePublicSigner;

pub(super) fn signer() -> ProvenancePublicSigner {
    ProvenancePublicSigner::from_seed_for_test([7u8; 32], "answer-export-1")
}

pub(super) async fn export(fx: &Fixture, format: &str) -> String {
    let query = ExportQuery {
        list: ListQuery::default(),
        format: Some(format.into()),
    };
    let response = export_response(&fx.logs(), &fx.access(), &query, Some(&signer()));
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The rows and the manifest of an NDJSON export.
pub(super) fn ndjson(text: &str) -> (Vec<Value>, Value) {
    let mut rows: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let manifest = rows.pop().unwrap();
    (rows, manifest)
}

/// RFC 4180 records of a CSV body, without the `#end` line.
pub(super) fn csv_records(text: &str) -> Vec<Vec<String>> {
    let (mut records, mut record, mut cell) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut chars) = (false, text.chars().peekable());
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (false, '"') => quoted = true,
            (false, '\r') => {}
            (false, ',') => record.push(std::mem::take(&mut cell)),
            (false, '\n') => {
                record.push(std::mem::take(&mut cell));
                records.push(std::mem::take(&mut record));
            }
            (_, c) => cell.push(c),
        }
    }
    records.retain(|r| !r[0].starts_with("#end"));
    records
}

#[tokio::test]
async fn r14_exports_carry_the_effect_and_findings() {
    let fx = Fixture::new(None);
    fx.call("gw-1");
    fx.delivery("gw-1", &Dl::effect("annotated"));
    let many: Vec<Value> = (0..32)
        .map(|i| json!({"kind": format!("={i}"), "severity": "low", "where": "text"}))
        .collect();
    fx.call("gw-2");
    let mut d = Dl::effect("annotated").findings(json!(many));
    d.total = Some(40);
    fx.delivery("gw-2", &d);
    let (_, page) = get(&fx, &[]).await;
    let (rows, _) = ndjson(&export(&fx, "ndjson").await);
    let exported_page = json!({"rows": rows});
    for trace in ["gw-1", "gw-2"] {
        let (listed, exported) = (row_of(&page, trace), row_of(&exported_page, trace));
        for key in ["effect", "answer_findings", "answer_findings_total"] {
            assert_eq!(listed.get(key), exported.get(key), "{trace} {key}");
        }
    }
    let records = csv_records(&export(&fx, "csv").await);
    assert_eq!(records[0].len(), 37);
    let col = |name: &str| records[0].iter().position(|c| c == name).unwrap();
    let two = records
        .iter()
        .find(|r| r[col("trace_id")] == "gw-2")
        .unwrap();
    let parsed: Value = serde_json::from_str(&two[col("answer_findings")]).unwrap_or(Value::Null);
    assert_eq!(parsed, json!(many));
    assert_eq!(two[col("answer_findings_total")], "40");
}

#[tokio::test]
async fn r22_an_export_joins_across_passes() {
    let fx = Fixture::new(None);
    fx.call("gw-old");
    for i in 0..100 {
        fx.call(&format!("gw-n{i}"));
    }
    fx.delivery("gw-old", &Dl::effect("delivered"));
    let (rows, manifest) = ndjson(&export(&fx, "ndjson").await);
    assert_eq!(
        row_of(&json!({"rows": rows}), "gw-old")["effect"],
        "delivered"
    );
    assert_eq!(manifest["join_incomplete"], 0);
}

/// A long export of ordinary call/delivery pairs reads every call's effect:
/// completed traces do not use up the joiner's bounds, which are for the
/// traces that are still unresolved.
#[tokio::test]
async fn r45_a_long_export_of_sequential_pairs_reads_every_effect() {
    let fx = Fixture::new(None);
    for i in 0..5000 {
        let trace = format!("gw-p{i}");
        fx.call(&trace);
        fx.delivery(&trace, &Dl::effect("delivered"));
    }
    let (rows, manifest) = ndjson(&export(&fx, "ndjson").await);
    let calls: Vec<&Value> = rows.iter().filter(|r| r["kind"] == "call").collect();
    assert_eq!(calls.len(), 5000, "every call is exported");
    let not_delivered = calls.iter().filter(|r| r["effect"] != "delivered").count();
    assert_eq!(not_delivered, 0, "calls that do not read delivered");
    assert_eq!(manifest["join_incomplete"], 0);
}
