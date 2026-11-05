// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A `gateway_invoke` of a backend the registry does not hold, through
//! `/mcp`: the invocation record names `not_found` and a refusal, and the
//! delivery record keeps its one gateway fold, with no refusal raised.

use super::*;

/// NOTFOUND.1 and NOTFOUND.3 for `/mcp` (red first).
#[tokio::test]
async fn an_mcp_call_to_a_nonexistent_backend_records_not_found() {
    let fx = fixture(Setup::default()).await;
    let call = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "nowhere", "tool": "t", "arguments": {}}}});
    let (_, answer) = post_to(&fx, "/mcp", &call.to_string(), &Caller::Anonymous).await;
    assert!(
        answer.to_string().contains("Backend not found: nowhere"),
        "the answer is the plain miss: {answer}"
    );
    let record = only_invocation(&fx);
    assert_eq!(
        record["decision"]["kind"], "not_found",
        "answer {answer}; record {record}"
    );
    assert_eq!(record["outcome"], "denied", "{record}");
    let delivery = super::composite_refusals::last_delivery(&fx);
    assert_ne!(delivery["response_effect"], "refused", "{delivery}");
    assert_ne!(delivery["response_effect"], "withheld", "{delivery}");
}

/// Control (unchanged code): a scoped key naming a backend its grant holds
/// that the registry does not records `not_found` through the scoped absent
/// answer. Its outcome is pinned as the line records it today; the unscoped
/// path's `denied` and this one are compared in the review, not changed here.
#[tokio::test]
async fn a_scoped_call_to_an_unregistered_granted_backend_records_not_found() {
    let mut auth = key_for_alpha(None);
    auth.api_keys[0].backends.push("ghost".to_string());
    let fx = fixture(Setup {
        auth: Some(auth),
        ..Setup::default()
    })
    .await;
    let call = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "ghost", "tool": "t", "arguments": {}}}});
    let (_, answer) = post_to(&fx, "/mcp", &call.to_string(), &Caller::Key).await;
    let record = only_invocation(&fx);
    assert_eq!(
        record["decision"]["kind"], "not_found",
        "answer {answer}; record {record}"
    );
    assert_eq!(
        record["outcome"], "tool_error",
        "answer {answer}; record {record}"
    );
}
