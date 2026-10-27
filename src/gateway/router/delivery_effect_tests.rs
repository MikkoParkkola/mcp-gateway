// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A delivery record says what the gateway did to the answer it delivered:
//! `response_effect` (delivered, rewritten, refused) and `response_findings`
//! (what the egress scan found, by kind, severity and part, never content).
//! Both are decided by the gateway, on the meta route and the direct route.

use serde_json::Value;

use super::direct_guards_fixture::{self as fixture, Answer, post_meta_invoke};
use super::route_matrix_driver_tests::response::{
    HttpRoute, delivery_rows, firewalled_recorded_call, planted_credential, temp_log,
};
use crate::security::firewall::FirewallAction;

/// The one delivery record of `route`'s call.
fn only_delivery(route: HttpRoute, rows: &[Value]) -> Value {
    let [row] = rows else {
        panic!("{route:?}: one delivery record: {rows:?}");
    };
    row.clone()
}

/// A clean answer under a scanning firewall: delivered unchanged, scanned,
/// nothing found.
#[tokio::test]
async fn a_clean_answer_records_delivered_and_no_findings() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let recorded = firewalled_recorded_call(route, Answer::Ok, None).await;
        let body = &recorded.body;
        assert!(
            body.get("error").is_none(),
            "{route:?}: premise: answered: {body}"
        );
        let row = only_delivery(route, &recorded.rows);
        assert_eq!(row["response_effect"], "delivered", "{route:?}: {row}");
        assert_eq!(
            row["response_findings"],
            serde_json::json!([]),
            "{route:?}: {row}"
        );
    }
}

/// A credential the egress redacts under a Warn rule: the answer is
/// delivered rewritten, and the finding is recorded by kind and part only.
#[tokio::test]
async fn a_redacted_answer_records_rewritten_and_its_finding() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let leak = planted_credential();
        let recorded =
            firewalled_recorded_call(route, Answer::Text(leak), Some(FirewallAction::Warn)).await;
        let body = recorded.body.to_string();
        assert!(
            !body.contains(leak) && body.contains("[REDACTED"),
            "{route:?}: premise: redacted and delivered: {body}"
        );
        let row = only_delivery(route, &recorded.rows);
        assert_eq!(row["response_effect"], "rewritten", "{route:?}: {row}");
        let findings = row["response_findings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(!findings.is_empty(), "{route:?}: a finding: {row}");
        for finding in &findings {
            assert!(
                finding["kind"]
                    .as_str()
                    .is_some_and(|k| k.starts_with("firewall:")),
                "{route:?}: {finding}"
            );
            assert_eq!(finding["where"], "result", "{route:?}: {finding}");
        }
        assert!(
            !row.to_string().contains(leak),
            "{route:?}: no content: {row}"
        );
    }
}

/// A credential under a Block rule: the answer is refused.
#[tokio::test]
async fn a_blocked_answer_records_refused() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let leak = planted_credential();
        let recorded =
            firewalled_recorded_call(route, Answer::Text(leak), Some(FirewallAction::Block)).await;
        let body = recorded.body.to_string();
        assert!(!body.contains(leak), "{route:?}: premise: withheld: {body}");
        let row = only_delivery(route, &recorded.rows);
        assert_eq!(row["response_effect"], "refused", "{route:?}: {row}");
    }
}

/// Two `/mcp` calls in flight on one router, one redacted and one clean, each
/// record their own facts (A14): polled together, neither cell sees the
/// other's scan.
#[tokio::test]
async fn concurrent_deliveries_record_their_own_effects() {
    let (_dir, log) = temp_log(None);
    let meta_log = std::sync::Arc::clone(&log);
    let answer = Answer::LeakOnCmd(planted_credential());
    let warn = Some(FirewallAction::Warn);
    let fx = fixture::fixture_firewalled_logged(
        answer,
        warn,
        std::sync::Arc::clone(&log),
        |mut meta| {
            meta.enable_transparency_log(meta_log);
            meta
        },
    )
    .await;
    let call = |cmd: &str| {
        let args = serde_json::json!({"cmd": cmd});
        post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None)
    };
    let ((_, leaked), (_, clean)) = tokio::join!(call("leak"), call("plain"));
    assert!(
        leaked.to_string().contains("[REDACTED"),
        "premise: {leaked}"
    );
    assert!(
        clean.get("error").is_none() && !clean.to_string().contains("[REDACTED"),
        "premise: {clean}"
    );
    let mut effects: Vec<Value> = delivery_rows(&log)
        .await
        .iter()
        .map(|row| row["response_effect"].clone())
        .collect();
    effects.sort_by_key(Value::to_string);
    assert_eq!(
        effects,
        [
            serde_json::json!("delivered"),
            serde_json::json!("rewritten")
        ]
    );
}
