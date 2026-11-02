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
        // Inspection annotates the same answer: rewritten outranks annotated.
        assert!(
            body.contains("_security_findings"),
            "{route:?}: premise: annotated too: {body}"
        );
        let row = only_delivery(route, &recorded.rows);
        assert_eq!(row["response_effect"], "rewritten", "{route:?}: {row}");
        let findings = row["response_findings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        // Response inspection reads the same credential, so its finding sits
        // beside the firewall's; the firewall's must still be there.
        assert!(
            findings.iter().any(|f| f["kind"]
                .as_str()
                .is_some_and(|k| k.starts_with("firewall:"))),
            "{route:?}: a firewall finding: {row}"
        );
        for finding in &findings {
            assert!(
                finding["kind"]
                    .as_str()
                    .is_some_and(|k| k.starts_with("firewall:") || k.starts_with("inspect:")),
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

/// A1: the grant slot's write fails under `FailClosed`, so the call's answer
/// is replaced by -32005. Its delivery record says `refused`, never the
/// replaced answer's `delivered`.
#[tokio::test]
async fn a_slot_refused_answer_records_refused() {
    use crate::gateway::meta_mcp::grant_audit::seams;
    use crate::security::audit::AuditFailurePolicy;
    let (_dir, log) = temp_log(Some(AuditFailurePolicy::FailClosed));
    let meta_log = std::sync::Arc::clone(&log);
    let fx = fixture::fixture_firewalled_logged(
        Answer::Ok,
        None,
        std::sync::Arc::clone(&log),
        |mut meta| {
            meta.enable_transparency_log(meta_log);
            meta
        },
    )
    .await;
    seams::inject_note_for_test("alpha", "read", seams::Inject::NextSlotOpen);
    seams::fail_append_at_for_test(1);
    let args = serde_json::json!({});
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    assert_eq!(
        body.pointer("/error/code").and_then(Value::as_i64),
        Some(-32005),
        "premise: the slot's refusal: {body}"
    );
    let row = only_delivery(HttpRoute::Mcp, &delivery_rows(&log).await);
    assert_eq!(row["response_effect"], "refused", "{row}");
}

/// Text response inspection flags (a long `base64:` blob, Medium, never
/// blocked) and the firewall's own scans have no rule for. The record must
/// list inspection's finding: a firewall that found nothing beside it is not
/// a clean scan of this answer.
fn inspection_only_text() -> &'static str {
    Box::leak(format!("base64: {}", "A".repeat(120)).into_boxed_str())
}

/// Response inspection's findings are this
/// delivery's findings, by kind, severity and part, never the matched text.
#[tokio::test]
async fn an_inspection_finding_is_recorded_beside_a_clean_firewall_scan() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let text = inspection_only_text();
        let recorded = firewalled_recorded_call(route, Answer::Text(text), None).await;
        assert!(
            recorded.body.get("error").is_none(),
            "{route:?}: premise: delivered: {}",
            recorded.body
        );
        let row = only_delivery(route, &recorded.rows);
        let findings = row["response_findings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            findings.iter().any(|f| f["kind"] == "inspect:encoding"
                && f["severity"] == "medium"
                && f["where"] == "result"),
            "{route:?}: inspection's finding is missing: {row}"
        );
        assert!(
            !row.to_string().contains(text),
            "{route:?}: no content: {row}"
        );
    }
}

/// A tool error on `/mcp` goes out with the gateway's `recovery` hint and
/// nothing else added: the hint is noted, and noting a counted member raises
/// `annotated`. (The direct route adds no hint.)
#[tokio::test]
async fn a_recovery_hint_records_annotated() {
    let recorded = firewalled_recorded_call(HttpRoute::Mcp, Answer::IsError, None).await;
    let body = recorded.body.to_string();
    assert!(
        body.contains("recovery")
            && !body.contains("_context_integrity")
            && !body.contains("_security_findings"),
        "premise: the hint is the only addition: {body}"
    );
    let row = only_delivery(HttpRoute::Mcp, &recorded.rows);
    assert_eq!(row["response_effect"], "annotated", "{row}");
}

/// On the direct route a call at 83 % of its key's budget goes out with the
/// gateway's `_cost_warnings` and nothing else added: noted after the egress
/// scan, it records `annotated`. (`_security_findings` cannot stand alone:
/// the context-integrity kernel runs the same inspection and attaches its
/// verdict, `src/context_integrity/kernel.rs:235`.)
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_direct_cost_warning_records_annotated() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let (_dir, log) = temp_log(None);
    let meta_log = std::sync::Arc::clone(&log);
    let fx = fixture::fixture_firewalled_logged(
        Answer::Ok,
        None,
        std::sync::Arc::clone(&log),
        move |mut meta| {
            meta.enable_transparency_log(meta_log);
            let mut cfg = CostGovernanceConfig {
                enabled: true,
                ..Default::default()
            };
            cfg.tool_costs.insert("read".to_string(), 1.0);
            cfg.budgets.per_key.insert("k-std".to_string(), 1.2);
            let registry =
                std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
            let enforcer =
                std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
                    cfg,
                    std::sync::Arc::clone(&registry),
                ));
            meta.with_cost_governance(enforcer, registry)
        },
    )
    .await;
    let params = serde_json::json!({"name": "read", "arguments": {}});
    let body = fixture::send(&fx, "/mcp/alpha", "k-std", "tools/call", params, None)
        .await
        .1;
    let sent = body.to_string();
    assert!(
        sent.contains("_cost_warnings")
            && !sent.contains("_context_integrity")
            && !sent.contains("_security_findings"),
        "premise: the warning is the only addition: {sent}"
    );
    let rows = delivery_rows(&log).await;
    let row = only_delivery(HttpRoute::Direct, &rows);
    assert_eq!(row["response_effect"], "annotated", "{row}");
}

/// The same answer goes out with the gateway's `_security_findings` added
/// and its text unchanged: the record says `annotated`, never `delivered`.
#[tokio::test]
async fn an_annotated_answer_records_annotated() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let text = inspection_only_text();
        let recorded = firewalled_recorded_call(route, Answer::Text(text), None).await;
        let body = recorded.body.to_string();
        assert!(
            body.contains("_security_findings") && body.contains(text),
            "{route:?}: premise: annotated, text unchanged: {body}"
        );
        let row = only_delivery(route, &recorded.rows);
        assert_eq!(row["response_effect"], "annotated", "{route:?}: {row}");
    }
}

/// A direct call to a tool the routing profile excludes is answered as an
/// absent name (an `isError` result); the gateway refused it, so its delivery record says
/// `refused`. The profile is judged in `withheld_verdict` and raised by
/// `guard_tool_call`, its caller.
#[tokio::test]
async fn a_direct_profile_withheld_call_records_refused() {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let (_dir, log) = temp_log(None);
    let meta_log = std::sync::Arc::clone(&log);
    let fx = fixture::fixture_firewalled_logged(
        Answer::Ok,
        None,
        std::sync::Arc::clone(&log),
        move |mut meta| {
            meta.enable_transparency_log(meta_log);
            let mut configs = std::collections::HashMap::new();
            configs.insert(
                "no-read".to_string(),
                RoutingProfileConfig {
                    deny_tools: Some(vec!["read".to_string()]),
                    ..RoutingProfileConfig::default()
                },
            );
            meta.with_profile_registry(ProfileRegistry::from_config(&configs, "no-read"))
        },
    )
    .await;
    let params = serde_json::json!({"name": "read", "arguments": {}});
    let body = fixture::send(&fx, "/mcp/alpha", "k-std", "tools/call", params, None)
        .await
        .1;
    assert!(
        body.pointer("/result/isError") == Some(&Value::Bool(true))
            && body
                .to_string()
                .contains("does not list a tool named `read`"),
        "premise: answered as an absent name: {body}"
    );
    let row = only_delivery(HttpRoute::Direct, &delivery_rows(&log).await);
    assert_eq!(row["response_effect"], "refused", "{row}");
}

/// An injected value the backend echoes as its `error.code`.
const ECHOED_CODE: i32 = 7_391_540;

/// The backend's error echoing [`ECHOED_CODE`], as the transport's scrub
/// hands it on: run inside the fixture's send, on the call's own task, as a
/// real transport runs it, so it is that call's scrub that built the
/// refusal.
fn echo_refused() -> crate::Error {
    let needles =
        crate::security::needles::NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
    needles.insert("b", &ECHOED_CODE.to_string());
    let echo = crate::Error::JsonRpc {
        code: ECHOED_CODE,
        message: "no".into(),
        data: None,
    };
    crate::security::needles::scrub_answer(&needles, Err(echo)).expect_err("replaced")
}

/// The same refusal's code and text sent by the backend itself, with no
/// value echoed: nothing was replaced, so it is the backend's own error.
fn lookalike() -> crate::Error {
    crate::Error::JsonRpc {
        code: -32_603,
        message: "the backend's answer contained a credential the gateway injected".into(),
        data: None,
    }
}

/// W0, W1: an answer the scrub replaced with its refusal, delivered (the
/// meta route's `isError` result, the direct route's error frame), records
/// `refused`.
#[tokio::test]
async fn an_echo_refusal_delivered_records_refused() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let recorded = firewalled_recorded_call(route, Answer::FailsWith(echo_refused), None).await;
        let body = recorded.body.to_string();
        assert!(
            body.contains("contained a credential the gateway injected")
                && !body.contains(&ECHOED_CODE.to_string()),
            "{route:?}: premise: the refusal was delivered: {body}"
        );
        let row = only_delivery(route, &recorded.rows);
        assert_eq!(row["response_effect"], "refused", "{route:?}: {row}");
    }
}

/// M2b: the backend's own error reading as that refusal is not one.
#[tokio::test]
async fn a_lookalike_echo_refusal_records_no_refusal() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let recorded = firewalled_recorded_call(route, Answer::FailsWith(lookalike), None).await;
        let row = only_delivery(route, &recorded.rows);
        // The scrub's two effects are absent. The meta route answers a failed
        // dispatch as a tool result carrying the gateway's recovery hint,
        // which is an annotation; the direct route frames the error as sent.
        let expected = match route {
            HttpRoute::Mcp => "annotated",
            HttpRoute::Direct => "delivered",
        };
        assert_eq!(row["response_effect"], expected, "{route:?}: {row}");
    }
}
