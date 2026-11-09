// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows R1, R2, R6-R12, R16, R19, R21: what a call row says about its
//! delivery record.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::answer_fixture::{Dl, Fixture};
use super::{ListQuery, list_page};
use crate::security::decision_record::read::NOT_RECORDED_BY_VERSION;

pub(super) fn q(pairs: &[(&str, &str)]) -> ListQuery {
    let mut q = ListQuery::default();
    for (k, v) in pairs {
        let v = Some((*v).to_string());
        match *k {
            "outcome" => q.outcome = v,
            "effect" => q.effect = v,
            "limit" => q.limit = v,
            "cursor" => q.cursor = v,
            "server" => q.server = v,
            other => panic!("no query field {other}"),
        }
    }
    q
}

pub(super) async fn get(fx: &Fixture, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
    let response = list_page(&fx.logs(), &fx.access(), &q(pairs));
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

pub(super) fn row_of<'a>(page: &'a Value, trace: &str) -> &'a Value {
    page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["trace_id"] == trace)
        .unwrap_or_else(|| panic!("no row for {trace} in {page}"))
}

pub(super) fn traces(page: &Value) -> Vec<String> {
    let mut t: Vec<String> = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["trace_id"].as_str().unwrap().to_string())
        .collect();
    t.sort();
    t
}

/// One call and its delivery.
fn pair(fx: &Fixture, trace: &str, d: &Dl) {
    fx.call(trace);
    fx.delivery(trace, d);
}

#[tokio::test]
async fn r1_effect_copied_from_the_delivery_record() {
    let fx = Fixture::new(None);
    pair(&fx, "gw-t1", &Dl::effect("annotated"));
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t1");
    assert_eq!(r["effect"], "annotated");
    assert_eq!(r["answer_findings"], json!([]));
}

#[tokio::test]
async fn r2_cleaned_lists_rewritten_and_annotated_only() {
    let fx = Fixture::new(None);
    for (t, e) in [
        ("gw-a", "delivered"),
        ("gw-b", "annotated"),
        ("gw-c", "rewritten"),
        ("gw-d", "refused"),
    ] {
        pair(&fx, t, &Dl::effect(e));
    }
    let (status, page) = get(&fx, &[("outcome", "cleaned")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(traces(&page), ["gw-b", "gw-c"]);
}

#[tokio::test]
async fn r6_a_duplicate_record_reads_tamper() {
    let fx = Fixture::new(None);
    fx.call("gw-t1");
    fx.delivery("gw-t1", &Dl::effect("delivered"));
    fx.delivery("gw-t1", &Dl::effect("refused"));
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t1");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(r["answer_integrity"], "duplicate");
    assert_eq!(page["answer_integrity_failed"], 1);
    assert_eq!(page["join_incomplete"], 1);
}

#[tokio::test]
async fn r7_a_single_record_is_complete_on_an_unfinished_window() {
    let fx = Fixture::new(None);
    // Calls older than the page's reach of the head would leave the window
    // unfinished for a call with no record; a found record never downgrades.
    pair(&fx, "gw-t1", &Dl::effect("refused"));
    let (_, page) = get(&fx, &[("limit", "1")]).await;
    assert_eq!(row_of(&page, "gw-t1")["effect"], "refused");
    assert_eq!(page["join_incomplete"], 0);
}

#[tokio::test]
async fn r8_a_notification_record_is_ignored() {
    let fx = Fixture::new(None);
    fx.call("gw-t1");
    fx.delivery(
        "gw-t1",
        &Dl::effect("refused").stage("notification_delivered"),
    );
    fx.delivery("gw-t1", &Dl::effect("delivered"));
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(row_of(&page, "gw-t1")["effect"], "delivered");
}

#[tokio::test]
async fn r9_vouched_unscanned_reads_not_scanned() {
    let fx = Fixture::new(None);
    pair(&fx, "gw-t1", &Dl::effect("delivered").findings(Value::Null));
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(
        row_of(&page, "gw-t1")["answer_findings"],
        "answer not scanned"
    );
}

#[tokio::test]
async fn r10_an_omitted_effect_reads_unknown_never_delivered() {
    let fx = Fixture::new(None);
    pair(&fx, "gw-t1", &Dl::omitted());
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t1");
    assert_eq!(r["effect"], "unknown");
    assert_eq!(
        r["answer_findings"],
        "findings not recorded for this answer"
    );
}

#[tokio::test]
async fn r11_unvouched_refused_keeps_its_effect() {
    let fx = Fixture::new(None);
    let mut d = Dl::effect("refused");
    d.findings = None;
    pair(&fx, "gw-t1", &d);
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t1");
    assert_eq!(r["effect"], "refused");
    assert_eq!(
        r["answer_findings"],
        "findings not recorded for this answer"
    );
}

#[tokio::test]
async fn r12_answer_findings_never_fills_findings() {
    let fx = Fixture::new(None);
    let found = json!([{"kind": "secret", "severity": "high", "where": "text"}]);
    pair(
        &fx,
        "gw-t1",
        &Dl::effect("annotated").findings(found.clone()),
    );
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t1");
    assert_eq!(r["findings"], NOT_RECORDED_BY_VERSION);
    assert_eq!(r["answer_findings"], found);
    for key in ["rule_id", "decision", "revision"] {
        assert!(r["answer_findings"][0].get(key).is_none(), "{key}");
    }
}

#[tokio::test]
async fn r16_a_refused_effect_matches_effect_not_blocked() {
    let fx = Fixture::new(None);
    pair(&fx, "gw-t1", &Dl::effect("refused"));
    let (_, hit) = get(&fx, &[("effect", "refused")]).await;
    assert_eq!(traces(&hit), ["gw-t1"]);
    for outcome in ["blocked", "cleaned"] {
        let (_, none) = get(&fx, &[("outcome", outcome)]).await;
        assert!(traces(&none).is_empty(), "{outcome}");
    }
}

#[tokio::test]
async fn r21_truncated_findings_carry_their_total() {
    let fx = Fixture::new(None);
    let many: Vec<Value> = (0..32)
        .map(|i| json!({"kind": format!("k{i}"), "severity": "low", "where": "text"}))
        .collect();
    let mut d = Dl::effect("annotated").findings(json!(many));
    d.total = Some(40);
    pair(&fx, "gw-t1", &d);
    let (_, page) = get(&fx, &[]).await;
    let r = row_of(&page, "gw-t1");
    assert_eq!(r["answer_findings_total"], 40);
    assert_eq!(r["answer_findings"].as_array().unwrap().len(), 32);
}
