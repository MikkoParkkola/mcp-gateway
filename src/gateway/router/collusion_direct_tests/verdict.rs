// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 x MIN.2 (MIK-7800): on the direct route a relay receipt follows
//! the answer's fate. A read the cross-tenant judge withholds, or one a
//! fail-closed audit write replaces, was never delivered, so it leaves no
//! receipt; a delivered read still does.

use super::*;
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;

/// A second note, distinct from [`PROSE`], so a refusal of B's send can only
/// come from the second read's receipt.
const OTHER: &str = "Minutes of the harbour committee list the mooring fees for the winter \
    quarter, the dredging contract awarded to the lowest bidder, the complaint about the \
    floodlights over the fish market, and the vote to repaint the lighthouse keeper's cottage.";

/// A read naming `tenant`, carrying `note`.
fn named(tenant: &str, note: &str) -> String {
    format!("{{\"customer_id\":\"{tenant}\",\"note\":\"{note}\"}}")
}

/// The `read` of a body with no result.
async fn withheld_read(fx: &Fixture, who: &str) -> String {
    let (_, body) = fx
        .call(Some(who), &call("read", &json!({}), None, None))
        .await;
    assert!(envelope(&body).get("result").is_none(), "delivered: {body}");
    body
}

/// A reads tenant t1, then t2 (withheld under `block`); B, who never saw t2's
/// text, sends it and is not refused. The control: B reads t2 as its own
/// first tenant, delivered, and A's relay of that text is refused.
#[tokio::test]
async fn a_judged_out_direct_read_records_no_receipt() {
    let setup = Setup {
        tenants: true,
        ..Setup::default()
    };
    let fx = fixture(setup).await;
    fx.answer_read(Read::Text(named("t1", PROSE)));
    fx.read(Some("a")).await;
    fx.answer_read(Read::Text(named("t2", OTHER)));
    let body = withheld_read(&fx, "a").await;
    assert!(
        body.contains("Response withheld"),
        "base: the judge withholds the second tenant's read: {body}"
    );
    let text = named("t2", OTHER);
    assert_sent(&fx, &fx.send(Some("b"), &text).await, 1);
    fx.read(Some("b")).await;
    assert_refused(&fx, &fx.send(Some("a"), &format!("{text} ")).await, 1);
}

/// A read whose audit write fails under `fail-closed` is replaced by a 503:
/// B sending its text is not refused. The control: the next read is audited
/// and delivered, and B's relay of it is refused.
#[tokio::test]
async fn an_audit_withheld_direct_read_records_no_receipt() {
    let mut fx = fixture(Setup::default()).await;
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "rv".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    Arc::get_mut(&mut fx.state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    log.fail_next_append_for_test();
    let body = withheld_read(&fx, "a").await;
    assert!(
        body.contains("-32005"),
        "base: the failed audit write withholds the read: {body}"
    );
    assert_sent(&fx, &fx.send(Some("b"), PROSE).await, 1);
    fx.read(Some("a")).await;
    let relay = format!("{PROSE} ");
    assert_refused(&fx, &fx.send(Some("b"), &relay).await, 1);
}

/// The delivery record, which carries the read verdict, can still replace the
/// answer: with it failing under `fail-closed`, the 503 leaves no receipt
/// either.
#[tokio::test]
async fn a_read_record_failure_leaves_no_direct_receipt() {
    let mut fx = fixture(Setup {
        tenants: true,
        ..Setup::default()
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "rv".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    Arc::get_mut(&mut fx.state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    let text = named("t1", PROSE);
    fx.answer_read(Read::Text(text.clone()));
    log.fail_next_append_of_kind_for_test("response_delivery_attempt");
    let body = withheld_read(&fx, "a").await;
    assert!(
        body.contains("-32005"),
        "base: the failed read record withholds the read: {body}"
    );
    assert_sent(&fx, &fx.send(Some("b"), &text).await, 1);
    fx.read(Some("a")).await;
    assert_refused(&fx, &fx.send(Some("b"), &format!("{text} ")).await, 1);
}

/// MIK-7669: a judged direct read is one record, as on `/mcp` (MIK-7799): its
/// tenants ride the answer's `response_delivery_attempt`, and no standalone
/// `tenant_read` event is written for it.
#[tokio::test]
async fn a_judged_direct_read_is_one_record() {
    let mut fx = fixture(Setup {
        tenants: true,
        ..Setup::default()
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "rv".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    Arc::get_mut(&mut fx.state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    fx.answer_read(Read::Text(named("t1", PROSE)));
    fx.read(Some("a")).await;
    let records: Vec<Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("log line is JSON"))
        .collect();
    assert!(
        !records.iter().any(|r| r["event"] == "tenant_read"),
        "a standalone tenant_read record: {records:#?}"
    );
    let t1 = crate::security::hash_argument(&json!("t1"));
    // One delivery record for the read, and that one names t1: counting only
    // the records that carry t1 would let a second, tenantless one through.
    let deliveries: Vec<&Value> = records
        .iter()
        .filter(|r| r["event"] == "response_delivery_attempt")
        .collect();
    assert_eq!(
        deliveries.len(),
        1,
        "one delivery record for the read: {records:#?}"
    );
    assert!(
        deliveries[0].to_string().contains(&t1),
        "the delivery record names t1: {records:#?}"
    );
}
