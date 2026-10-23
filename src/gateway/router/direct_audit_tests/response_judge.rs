// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8689 R-RECJUDGE on the direct route: the read judge's verdict rides
//! the answer's own delivery record, so the judge runs before that record is
//! written (Judge < DeliveryRecord). The `/mcp` twin is
//! `tests::meta_firewall_verdict::caller_key::tenant_reads::a_judged_answer_is_one_record`.

use super::*;
use crate::security::firewall::tenant_guard::CrossTenantReads;

/// A legacy direct `tools/call t` reading `tenant`.
fn reading(id: u64, tenant: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": "t", "arguments": {"customer_id": tenant}}})
    .to_string()
}

/// `name` on a record, at its top level or one level down.
fn field<'a>(record: &'a Value, name: &str) -> Option<&'a str> {
    record.get(name).and_then(Value::as_str).or_else(|| {
        record
            .as_object()?
            .values()
            .find_map(|inner| inner.get(name).and_then(Value::as_str))
    })
}

/// R-RECJUDGE `judge_precedes_delivery_record`, `Direct` × `Fresh` ×
/// `Legacy`. One verified caller reads tenant A, then tenant B, under the
/// observing judge: both are delivered, and exactly B's delivery record
/// carries the judge's `flagged` verdict and names B. A record written before
/// the judge could not carry it.
#[tokio::test]
async fn r_recjudge_direct_verdict_rides_the_delivery_record() {
    let fx = fixture(Setup {
        tenant_limit: Some(0),
        cross_tenant_reads: CrossTenantReads::Observe,
        ..Setup::default()
    })
    .await;
    let (a, body) = post(&fx, "alpha", &reading(1, "cust-a"), &Caller::Oidc).await;
    assert_eq!(
        a,
        StatusCode::OK,
        "R-RECJUDGE Direct: A is delivered: {body}"
    );
    let (b, body) = post(&fx, "alpha", &reading(2, "cust-b"), &Caller::Oidc).await;
    assert_eq!(
        b,
        StatusCode::OK,
        "R-RECJUDGE Direct: observe never withholds: {body}"
    );
    let records: Vec<Value> = std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| record["event"] == "response_delivery_attempt")
        .collect();
    assert_eq!(
        records.len(),
        2,
        "R-RECJUDGE Direct: one delivery record per read: {records:?}"
    );
    let flagged: Vec<&Value> = records
        .iter()
        .filter(|record| field(record, "cross_tenant_read") == Some("flagged"))
        .collect();
    assert_eq!(
        flagged.len(),
        1,
        "R-RECJUDGE Direct: exactly B's record carries the judge's verdict: {records:?}"
    );
    let b_hash = crate::security::hash_argument(&json!("cust-b"));
    assert!(
        flagged[0].to_string().contains(&b_hash),
        "R-RECJUDGE Direct: the flagged record names tenant B: {}",
        flagged[0]
    );
}
