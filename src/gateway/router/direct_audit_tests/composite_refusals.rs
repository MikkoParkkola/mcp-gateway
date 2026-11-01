// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A composite (a chain or a playbook) that ends on a step the gateway
//! refused records `refused`; one that carries on past such a step, or ends
//! on something else, records no effect. Over-claiming is the worse failure,
//! so most rows here pin the absence.

use super::unvouched_effect::{run_playbook, run_playbook_as};
use super::*;

/// The last delivery record, which is the composite's.
pub(super) fn last_delivery(fx: &Fixture) -> Value {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .rfind(|entry| entry["event"] == "response_delivery_attempt")
        .expect("the composite's delivery record")
}

/// Under `require`, every backend's unchained answer is refused after the
/// call was sent: a late refusal every step meets.
async fn chained() -> Fixture {
    fixture(Setup {
        chain: crate::config::ChainMode::Require,
        meta_mode: MetaMode::CodeMode,
        ..Setup::default()
    })
    .await
}

const ONE_STEP: &str = "description: one step\n\
    steps:\n  - name: read\n    server: alpha\n    tool: t\n    arguments: {}\n";

/// Row 1: a chain whose step's answer is refused ends on that refusal.
#[tokio::test]
async fn a_chain_ending_on_a_late_refusal_records_refused() {
    let fx = chained().await;
    let chain = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"chain": [{"tool": "alpha:t", "arguments": {}}]}}});
    let (status, body) = post_to(&fx, "/mcp", &chain.to_string(), &Caller::Anonymous).await;
    assert!(
        body.get("error").is_some(),
        "premise: ended on it: {status} {body}"
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "premise: the step was sent"
    );
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// Row 2: a playbook (abort on error) whose step's answer is refused ends on
/// that refusal.
#[tokio::test]
async fn a_playbook_ending_on_a_late_refusal_records_refused() {
    let fx = chained().await;
    let yaml = format!("name: ends\n{ONE_STEP}");
    let (status, body) = run_playbook(&fx, &yaml, "ends").await;
    assert!(
        body.get("error").is_some(),
        "premise: ended on it: {status} {body}"
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "premise: the step was sent"
    );
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// Row 3: a playbook that carries on past the same refusal delivers its
/// report; nothing it delivers was refused.
#[tokio::test]
async fn a_playbook_continuing_past_a_late_refusal_records_no_refused() {
    let fx = chained().await;
    let yaml = format!("name: onward\non_error: continue\n{ONE_STEP}");
    let (status, body) = run_playbook(&fx, &yaml, "onward").await;
    assert!(
        body.to_string().contains("steps_failed"),
        "premise: the report was delivered: {status} {body}"
    );
    let record = last_delivery(&fx);
    assert!(record.get("response_effect").is_none(), "{record}");
}

/// Row 4 at the route: under `retry` a late refusal follows the send, so the
/// step may have run and is sent once, not retried; the playbook carries on
/// to its report: no refused.
#[tokio::test]
async fn a_retrying_playbook_sends_a_late_refused_step_once_and_records_no_refused() {
    let fx = chained().await;
    let yaml = format!("name: again\non_error: retry\nmax_retries: 2\n{ONE_STEP}");
    let (status, body) = run_playbook(&fx, &yaml, "again").await;
    assert!(
        body.to_string().contains("steps_failed"),
        "premise: the report was delivered: {status} {body}"
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "premise: a step refused after its send is not sent again"
    );
    let record = last_delivery(&fx);
    assert!(record.get("response_effect").is_none(), "{record}");
}

/// Row 2b: a playbook ending on a refusal answered as a tool error (an
/// argument the tool does not declare, refused before it is sent) records
/// refused too: the engine turns that error result into the playbook's error.
#[tokio::test]
async fn a_playbook_ending_on_an_undeclared_argument_records_refused() {
    let fx = fixture(Setup {
        extras: &[Extra::DeclaredKeys],
        ..Setup::default()
    })
    .await;
    let yaml = "name: bogus\ndescription: one refused step\n\
        steps:\n  - name: read\n    server: alpha\n    tool: t\n    arguments: {bogus: x}\n";
    let (status, body) = run_playbook(&fx, yaml, "bogus").await;
    assert!(
        body.get("error").is_some() && body.to_string().contains("bogus"),
        "premise: ended on the key refusal: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "premise: never sent");
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// A single-tool `gateway_execute` answered with the refusal of an
/// argument the tool does not declare: the refusal comes back as a tool
/// error result, and the composite still records refused.
#[tokio::test]
async fn a_single_tool_execute_ending_on_an_undeclared_argument_records_refused() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::CodeMode,
        extras: &[Extra::DeclaredKeys],
        ..Setup::default()
    })
    .await;
    let call = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"tool": "alpha:t", "arguments": {"bogus": "x"}}}});
    let (status, body) = post_to(&fx, "/mcp", &call.to_string(), &Caller::Anonymous).await;
    assert!(
        body.to_string().contains("bogus"),
        "premise: the key refusal: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "premise: never sent");
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// A chain whose step names a backend outside the key's scope is refused
/// whole at the route stage, before any step runs: refused (a guard row; the
/// step's own cell is pinned by the invalid-schema row below).
#[tokio::test]
async fn a_chain_ending_on_a_withheld_step_records_refused() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        meta_mode: MetaMode::CodeMode,
        ..Setup::default()
    })
    .await;
    let chain = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"chain": [{"tool": "beta:t", "arguments": {}}]}}});
    let (status, body) = post_to(&fx, "/mcp", &chain.to_string(), &Caller::Key).await;
    assert!(
        body.get("error").is_some() || body["result"]["isError"] == true,
        "premise: the step was withheld: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "premise: never sent");
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// A playbook refused whole, before any step runs (a step argument names a
/// step's sealed `requestState`), ends on the gateway's refusal.
#[tokio::test]
async fn a_playbook_refused_before_any_step_records_refused() {
    let fx = fixture(Setup::default()).await;
    let yaml = "name: sealed\ndescription: hands the envelope on\n\
        steps:\n  - name: read\n    server: alpha\n    tool: t\n    arguments: {}\n  \
        - name: pass\n    server: alpha\n    tool: t\n    arguments: {s: $read.requestState}\n";
    let (status, body) = run_playbook(&fx, yaml, "sealed").await;
    assert!(
        body.to_string().contains("sealed requestState"),
        "premise: refused whole: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "premise: never sent");
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// A chain whose one step names a tool withheld for its invalid schema is
/// answered with that step absent, inside the step's own cell: the chain
/// ends on the gateway's refusal.
#[tokio::test]
async fn a_chain_ending_on_a_step_withheld_for_its_schema_records_refused() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::CodeMode,
        extras: &[Extra::InvalidSchema],
        ..Setup::default()
    })
    .await;
    let chain = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"chain": [{"tool": "alpha:t", "arguments": {}}]}}});
    let (status, body) = post_to(&fx, "/mcp", &chain.to_string(), &Caller::Anonymous).await;
    assert!(
        body.get("error").is_some() || body["result"]["isError"] == true,
        "premise: the step was withheld: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "premise: never sent");
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// A playbook step the caller's key may not invoke: the route stage
/// authorizes the playbook's step targets and refuses the call whole, so it
/// records refused (a guard row; the dispatch-time refusal is pinned in
/// `meta_mcp/playbook_dispatch_refusal_tests.rs`).
#[tokio::test]
async fn a_playbook_ending_on_a_step_its_key_may_not_invoke_records_refused() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(Some(vec!["t".to_string()]))),
        ..Setup::default()
    })
    .await;
    let yaml = format!("name: one\n{ONE_STEP}");
    let (status, body) = run_playbook_as(&fx, &yaml, "one", &Caller::Key).await;
    assert_eq!(
        body["error"]["message"],
        crate::gateway::meta_mcp::STEP_NOT_PERMITTED,
        "premise: the step's neutral refusal: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "premise: never sent");
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}

/// A playbook step on a backend the operator killed: the kill switch is not
/// a visibility rule, so the step passes the gate and meets the policy at
/// dispatch. The playbook (abort) ends on that refusal.
#[tokio::test]
async fn a_playbook_ending_on_a_killed_backend_records_refused() {
    let fx = fixture(Setup::default()).await;
    fx.state.meta_mcp.kill_switch().kill("alpha");
    let yaml = format!("name: one\n{ONE_STEP}");
    let (status, body) = run_playbook(&fx, &yaml, "one").await;
    assert!(
        body.get("error").is_some(),
        "premise: ended on the kill switch: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "premise: never sent");
    let record = last_delivery(&fx);
    assert_eq!(record["response_effect"], "refused", "{record}");
}
