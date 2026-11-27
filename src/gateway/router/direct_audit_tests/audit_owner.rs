// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record a response-firewall refusal leaves (P4 (1), (2)): one call,
//! one block, one firewall catch and no error on the counters; with a log,
//! exactly one record, `denied` with the refusal's code and no response hash,
//! naming the call. On the meta route the scan decides after the dispatch has
//! ended, so the same row also proves a late refusal still reaches the record.

use super::counting::{attach, meta_invoke, totals};
use super::*;

/// [calls, blocks, errors, firewall catches, cache hits] after one refusal.
const ONE_FIREWALL_REFUSAL: [u64; 5] = [1, 1, 0, 1, 0];

/// What the refusal answers with and records: `INVALID_REQUEST`.
const REFUSAL_CODE: i64 = -32600;

/// Every way one route and log setting departs from the expected record.
async fn departures(route: &str, log: Log) -> Vec<String> {
    let logged = matches!(log, Log::On);
    let fx = fixture(Setup {
        log,
        tenant_limit: Some(0),
        response_rules: Some(BLOCK_T_RULES),
        reply: Some(takeover_reply()),
        ..Setup::default()
    })
    .await;
    let store = attach(&fx);
    if route == "meta" {
        let call = meta_invoke("alpha", "t", &json!({}));
        let _ = post_to(&fx, "/mcp", &call, &Caller::Anonymous).await;
    } else {
        let _ = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    }
    let case = format!("{route}, log {}", if logged { "on" } else { "off" });
    let mut wrong = Vec::new();
    let counted = totals(&store);
    if counted != ONE_FIREWALL_REFUSAL {
        wrong.push(format!(
            "{case}: counters {counted:?}, want {ONE_FIREWALL_REFUSAL:?}"
        ));
    }
    if !logged {
        return wrong;
    }
    let records = invocations(&fx);
    let [record] = records.as_slice() else {
        wrong.push(format!("{case}: {} records, want 1", records.len()));
        return wrong;
    };
    for (field, want) in [
        ("outcome", json!("denied")),
        ("error_code", json!(REFUSAL_CODE)),
        ("server", json!("alpha")),
        ("tool", json!("t")),
    ] {
        if record[field] != want {
            wrong.push(format!("{case}: {field} = {}, want {want}", record[field]));
        }
    }
    if record.get("response_hash").is_some() {
        wrong.push(format!("{case}: a refused answer carries a response_hash"));
    }
    wrong
}

#[tokio::test]
async fn p4_1_a_refused_answer_is_one_denial_on_both_routes_with_and_without_a_log() {
    let mut wrong = Vec::new();
    for route in ["meta", "direct"] {
        for log in [Log::On, Log::Off] {
            wrong.extend(departures(route, log).await);
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
