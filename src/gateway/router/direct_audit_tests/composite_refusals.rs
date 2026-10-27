// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A composite (a chain or a playbook) that ends on a step the gateway
//! refused records `refused`; one that carries on past such a step, or ends
//! on something else, records no effect. Over-claiming is the worse failure,
//! so most rows here pin the absence.

use super::unvouched_effect::run_playbook;
use super::*;

/// The last delivery record, which is the composite's.
pub(super) fn last_delivery(fx: &Fixture) -> Value {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .next_back()
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

/// Row 4 at the route: under `retry` every attempt is refused, the retries
/// run out and the playbook carries on to its report: no refused.
#[tokio::test]
async fn a_playbook_retrying_past_a_late_refusal_records_no_refused() {
    let fx = chained().await;
    let yaml = format!("name: again\non_error: retry\nmax_retries: 2\n{ONE_STEP}");
    let (status, body) = run_playbook(&fx, &yaml, "again").await;
    assert!(
        body.to_string().contains("steps_failed"),
        "premise: the report was delivered: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 2, "premise: retried");
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

/// A chain whose step names a backend outside the key's scope is answered
/// with that step withheld: the chain ends on the gateway's refusal.
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
