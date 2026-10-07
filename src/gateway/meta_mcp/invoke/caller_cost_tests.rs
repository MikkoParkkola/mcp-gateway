// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7653: a caller with no session sees its own spend in the cost report,
//! keyed on its caller key, and never another caller's, even one presenting
//! the same credential.

use serde_json::{Value, json};

use super::MetaMcp;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};

/// A gateway with backend `alpha`, which answers any tool.
fn gateway() -> MetaMcp {
    MetaMcp::new(counted_backend("alpha").0)
}

/// Caller `key` presenting the one shared credential `shared`.
fn caller(key: &'static str) -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        caller_key: Some(key),
        api_key_name: Some("shared"),
        ..ctx(&AllowAll)
    }
}

/// Run `alpha:tool` as `who` on `session`; the call must be served.
async fn spend(meta: &MetaMcp, who: &MetaMcpCallerContext<'_>, session: Option<&str>, tool: &str) {
    let served = meta
        .invoke_tool(&invoke_args("alpha", tool), session, who)
        .await;
    assert!(served.is_ok(), "the spend call on {tool}: {served:?}");
}

/// `(tool_key, call_count)` of every `by_tool` row under `report[part]`, sorted.
fn tools(report: &Value, part: &str) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = report[part]["by_tool"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            (
                row["tool_key"].as_str().unwrap_or_default().to_string(),
                row["call_count"].as_u64().unwrap_or_default(),
            )
        })
        .collect();
    rows.sort();
    rows
}

#[tokio::test]
async fn two_callers_on_one_credential_each_see_only_their_own_spend() {
    let meta = gateway();
    let (alice, bob) = (caller("subject:alice"), caller("subject:bob"));
    // GIVEN: two callers on the same credential, no session, each spends on its own tool
    spend(&meta, &alice, None, "read").await;
    spend(&meta, &bob, None, "write").await;

    // WHEN: each asks for its report
    let for_alice = meta
        .get_cost_report(&json!({}), None, &alice)
        .await
        .expect("alice's report");
    let for_bob = meta
        .get_cost_report(&json!({}), None, &bob)
        .await
        .expect("bob's report");

    // THEN: each breakdown holds that caller's call and nothing else
    assert_eq!(
        tools(&for_alice, "caller"),
        vec![("alpha:read".to_string(), 1)],
        "alice's report: {for_alice}"
    );
    assert_eq!(
        tools(&for_bob, "caller"),
        vec![("alpha:write".to_string(), 1)],
        "bob's report: {for_bob}"
    );
}

#[tokio::test]
async fn a_caller_with_a_session_is_reported_under_its_session_only() {
    let meta = gateway();
    let alice = caller("subject:alice");
    // GIVEN: a caller spending on a session
    spend(&meta, &alice, Some("s-7653"), "read").await;

    // WHEN: it asks for its report on that session
    let report = meta
        .get_cost_report(&json!({}), Some("s-7653"), &alice)
        .await
        .expect("the report");

    // THEN: the spend is the session's; there is no caller breakdown
    assert_eq!(
        tools(&report, "session"),
        vec![("alpha:read".to_string(), 1)],
        "{report}"
    );
    assert!(
        report["caller"].is_null(),
        "a sessioned call was also keyed on its caller: {report}"
    );
}

/// MIK-8000: an auth-off caller (the shared `anonymous` name, no caller key,
/// no session) spending repeatedly keeps a bounded number of cost entries.
#[tokio::test]
async fn an_unauthenticated_callers_repeated_spend_stays_bounded() {
    let meta = gateway();
    let anonymous = MetaMcpCallerContext {
        caller_key: None,
        api_key_name: Some("anonymous"),
        ..ctx(&AllowAll)
    };
    // GIVEN: 50 served session-less calls on one tool
    for _ in 0..50 {
        spend(&meta, &anonymous, None, "read").await;
    }
    // THEN: the key holds one hour bucket and one tool row, not one per call
    let counted = meta
        .cost_tracker
        .key_snapshot("anonymous")
        .expect("the key's spend");
    assert_eq!(counted.by_tool[0].call_count, 50, "every call was counted");
    // One tool row and an hour bucket, two if the calls crossed an hour
    let held = meta.cost_tracker.key_retained("anonymous");
    assert!(
        held <= 3,
        "the anonymous key holds {held} entries after 50 calls"
    );
}
