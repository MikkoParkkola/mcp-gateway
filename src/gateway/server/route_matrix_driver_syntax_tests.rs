// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S4 on stdio (part 3b-1 of the decision fixture table): the stdio
//! authorizer's name check, `ToolPolicyAuthorizer::decide`
//! (`gateway/authz.rs:734-741`), through the real stdio dispatch.

use super::{Counting, stdio_meta, stdio_send};
use crate::gateway::meta_mcp::grant_audit_fixture::{entries, logger};
use crate::security::decision_fixture_table::{DecisionRow, Findings, RuleId, assert_row};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// S4: a stdio `gateway_invoke` naming `read.v2`. The route stage authorizes
/// the requested target first (`stdio_route_stage.rs:180-196`, through
/// `chokepoint.rs:221`), and the stdio authorizer refuses the name's shape
/// with `(Syntax, None)` and -32600. As on `/mcp` (S3), the refusal's code
/// and pair are kept for the record and the name is answered as an absent
/// one: an `isError` result, recorded `denied` with -32600.
#[tokio::test]
async fn s4_stdio_invalid_tool_name_at_the_authorizer() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = logger(&dir, crate::security::audit::AuditFailurePolicy::FailClosed);
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: json!({"content": [{"type": "text", "text": "sent"}], "isError": false}),
    });
    let meta = stdio_meta(|meta| meta.enable_transparency_log(log), backend).await;
    let params = json!({"name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read.v2", "arguments": {}}});
    let body = stdio_send(&meta, params).await;
    assert_eq!(body["result"]["isError"], true, "the answer's form: {body}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "alpha was sent the call: {body}"
    );
    let named: Vec<Value> = entries(&dir)
        .into_iter()
        .filter(|e| e.get("tool").is_some() && e["event"] != "response_delivery_attempt")
        .collect();
    let [record] = named.as_slice() else {
        panic!("premise: one invocation record: {named:?}; answer {body}");
    };
    assert_eq!(record["outcome"], "denied", "{body}: {record}");
    assert_eq!(record["error_code"], -32600, "{body}: {record}");
    let row = DecisionRow {
        name: "s4_stdio_invalid_tool_name_at_the_authorizer",
        kind: "syntax",
        decided: "fresh",
        effect: None,
        findings: Findings::NotRun,
        grant_id: None,
        rule_id: RuleId::Absent("the stdio authorizer refuses a name with no rule"),
    };
    assert_row(&record["decision"], &row);
}
