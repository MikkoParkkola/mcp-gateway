// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record fields a delivery's facts produce.

use serde_json::{Map, Value, json};

use super::{Part, ResponseEffect, found, raise, record_fields, scanned, scope, snapshot};
use crate::security::Severity;

/// The fields the open cell records, given the frame's refusal and annotation.
fn recorded(frame_refused: bool, annotated: bool) -> Map<String, Value> {
    let mut fields = Map::new();
    record_fields(snapshot().as_ref(), frame_refused, annotated, &mut fields);
    fields
}

#[tokio::test]
async fn outside_a_cell_nothing_is_recorded() {
    let mut fields = Map::new();
    record_fields(snapshot().as_ref(), true, true, &mut fields);
    assert!(fields.is_empty(), "{fields:?}");
}

#[tokio::test]
async fn unscanned_is_null_findings_and_scanned_clean_is_empty() {
    scope(async {
        let fields = recorded(false, false);
        assert_eq!(fields["response_effect"], "delivered");
        assert_eq!(fields["response_findings"], Value::Null);
        scanned();
        assert_eq!(recorded(false, false)["response_findings"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn the_strongest_effect_wins_whatever_the_order() {
    scope(async {
        raise(ResponseEffect::Refused);
        raise(ResponseEffect::Rewritten);
        assert_eq!(recorded(false, true)["response_effect"], "refused");
    })
    .await;
    scope(async {
        assert_eq!(recorded(false, true)["response_effect"], "annotated");
        assert_eq!(recorded(true, false)["response_effect"], "refused");
    })
    .await;
}

#[tokio::test]
async fn findings_are_most_severe_first_capped_at_32_with_a_total() {
    scope(async {
        for i in 0..40 {
            found(format!("firewall:k{i:02}"), Severity::Low, Part::Result);
        }
        found("firewall:z".into(), Severity::Critical, Part::Error);
        let fields = recorded(false, false);
        let listed = fields["response_findings"].as_array().expect("a list");
        assert_eq!(listed.len(), 32);
        assert_eq!(
            listed[0],
            json!({"kind": "firewall:z", "severity": "critical", "where": "error"})
        );
        assert_eq!(fields["response_findings_total"], 41);
    })
    .await;
}

#[tokio::test]
async fn an_unvouched_delivery_records_only_a_refusal() {
    scope(async {
        found("firewall:k".into(), Severity::High, Part::Result);
        super::unvouched();
        assert!(recorded(false, false).is_empty());
        let fields = recorded(true, false);
        assert_eq!(fields["response_effect"], "refused");
        assert!(fields.get("response_findings").is_none(), "{fields:?}");
    })
    .await;
}

#[tokio::test]
async fn a_suspended_scan_writes_nothing_to_the_delivery() {
    scope(async {
        super::suspended(|| {
            raise(ResponseEffect::Refused);
            found("firewall:k".into(), Severity::High, Part::Result);
        });
        let fields = recorded(false, false);
        assert_eq!(fields["response_effect"], "delivered");
        assert_eq!(fields["response_findings"], Value::Null);
    })
    .await;
}
