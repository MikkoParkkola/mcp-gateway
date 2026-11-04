// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored task read refused after a reload names, in its delivery record,
//! the check that refused it and, when a configured rule decided, that rule
//! (MIK-9191.RULEID.2, .3). The task ran under an admitting policy, so the
//! worker wrote no refusal: only the read's own record can carry the id.

use serde_json::{Value, json};

use super::rule_ids::tool_policy_id;
use super::{Logged, configured, fixture, key_admits_policy_denies, std_key};
use crate::config::Config;
use crate::security::rule_id::RuleId;

/// The key's scope admits `read`; the tool policy denies by default.
fn policy_denies_by_default(c: &mut Config) {
    c.auth = std_key(None);
    c.security.tool_policy.enabled = true;
    c.security.tool_policy.allow.clear();
    c.security.tool_policy.deny.clear();
    c.security.tool_policy.default_action = crate::security::policy::PolicyAction::Deny;
}

/// The refused `tasks/get` delivery records in the log: the reads' own.
fn refused_reads(fx: &Logged) -> Vec<Value> {
    std::fs::read_to_string(fx.log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| {
            row["event"] == "response_delivery_attempt"
                && row["tool"] == "tasks/get"
                && row["response_effect"] == "refused"
        })
        .collect()
}

/// Run a task to completion under the fixture's admitting policy and read
/// it once, delivered; publish `then`; read it again. The second answer.
async fn read_after_reload(fx: &Logged, key: &str, then: fn(&mut Config)) -> Value {
    read_after(fx, key, |fx| fx.state.live_config.set(configured(fx, then))).await
}

/// [`read_after_reload`] with `change` made between the two reads.
async fn read_after(fx: &Logged, key: &str, change: impl FnOnce(&Logged)) -> Value {
    let id = super::submit_task(fx, key, json!({})).await;
    let first = super::settled_task(fx, &id).await;
    assert!(
        first.get("error").is_none()
            && first.pointer("/result/status").and_then(Value::as_str) == Some("completed"),
        "premise: the task completed and its first read is delivered: {first}"
    );
    let _ = super::invocations(fx).await;
    assert!(refused_reads(fx).is_empty(), "premise: nothing refused yet");
    change(fx);
    let got = super::read_task(fx, &id).await;
    let _ = super::invocations(fx).await;
    got
}

/// The one refused read's `refused_by`, after checking the delivered answer
/// carries no trace of `id`.
fn refused_by(fx: &Logged, got: &Value, id: &RuleId) -> Value {
    assert!(
        got.get("error").is_some(),
        "premise: the read after the reload is refused: {got}"
    );
    let hex = id.as_str().split_once(':').map_or(id.as_str(), |(_, h)| h);
    assert!(
        !got.to_string().contains(hex),
        "the answer names the rule: {got}"
    );
    let reads = refused_reads(fx);
    let [read] = reads.as_slice() else {
        panic!("wanted one refused read: {reads:?}");
    };
    read["refused_by"].clone()
}

#[tokio::test(flavor = "current_thread")]
async fn a_stored_read_refused_by_a_deny_entry_names_it() {
    let fx = fixture(super::Answer::Ok, None).await;
    let got = read_after_reload(&fx, "stored-deny", key_admits_policy_denies).await;
    let expected = tool_policy_id(&fx, "deny", "alpha:read");
    assert_eq!(
        refused_by(&fx, &got, &expected),
        json!({"kind": "tool_policy", "rule_id": expected.as_str()})
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_stored_read_refused_by_the_default_action_names_it() {
    let fx = fixture(super::Answer::Ok, None).await;
    let got = read_after_reload(&fx, "stored-default", policy_denies_by_default).await;
    let expected = tool_policy_id(&fx, "default_action", "deny");
    assert_eq!(
        refused_by(&fx, &got, &expected),
        json!({"kind": "tool_policy", "rule_id": expected.as_str()})
    );
}

/// The key, after the reload, reaches only another backend: `alpha` is out
/// of its scope.
fn key_out_of_scope(c: &mut Config) {
    c.auth = std_key(None);
    if let Some(key) = c.auth.api_keys.first_mut() {
        key.backends = vec!["beta".to_string()];
    }
}

/// The key, after the reload, may call only another tool.
fn key_allows_another_tool(c: &mut Config) {
    c.auth = std_key(None);
    if let Some(key) = c.auth.api_keys.first_mut() {
        key.allowed_tools = Some(vec!["other".to_string()]);
    }
}

/// The one refused read's `refused_by`, for a refusal no configured rule
/// decided: it carries a kind and no `rule_id`.
fn kind_only(fx: &Logged, got: &Value) -> Value {
    assert!(
        got.get("error").is_some(),
        "premise: the read after the reload is refused: {got}"
    );
    let reads = refused_reads(fx);
    let [read] = reads.as_slice() else {
        panic!("wanted one refused read: {reads:?}");
    };
    assert!(
        read["refused_by"].get("rule_id").is_none(),
        "no rule decided: {read}"
    );
    read["refused_by"].clone()
}

#[tokio::test(flavor = "current_thread")]
async fn a_stored_read_out_of_the_keys_scope_names_the_scope() {
    let fx = fixture(super::Answer::Ok, None).await;
    let got = read_after_reload(&fx, "stored-scope", key_out_of_scope).await;
    assert_eq!(kind_only(&fx, &got), json!({"kind": "backend_scope"}));
}

#[tokio::test(flavor = "current_thread")]
async fn a_stored_read_outside_the_keys_tools_names_the_tool_scope() {
    let fx = fixture(super::Answer::Ok, None).await;
    let got = read_after_reload(&fx, "stored-tools", key_allows_another_tool).await;
    assert_eq!(kind_only(&fx, &got), json!({"kind": "client_tool_scope"}));
}

/// `alpha`'s `read` withheld by the descriptor gate after the task ran: the
/// read is refused at the visibility exit, named by the descriptor block.
#[tokio::test(flavor = "current_thread")]
async fn a_stored_read_of_a_descriptor_blocked_tool_names_the_block() {
    let fx = fixture(super::Answer::Ok, None).await;
    let got = read_after(&fx, "stored-descriptor", |fx| {
        fx.state
            .backends
            .get("alpha")
            .expect("the fixture's backend")
            .block_descriptor_for_test("read");
    })
    .await;
    assert_eq!(kind_only(&fx, &got), json!({"kind": "descriptor_block"}));
}

/// `alpha`'s shared catalogue, after the task ran, lists `read` with an input
/// schema that is not an object's (CAP-003): the read is refused at the
/// visibility exit for its schema, recorded under the descriptor block.
#[tokio::test(flavor = "current_thread")]
async fn a_stored_read_of_a_tool_with_a_broken_schema_names_the_block() {
    let fx = fixture(super::Answer::Ok, None).await;
    let got = read_after(&fx, "stored-schema", |fx| {
        let tool: crate::protocol::Tool =
            serde_json::from_value(json!({"name": "read", "inputSchema": {"type": "string"}}))
                .expect("a tool");
        fx.state
            .backends
            .get("alpha")
            .expect("the fixture's backend")
            .store_shared_tools_for_test(vec![tool]);
    })
    .await;
    assert_eq!(kind_only(&fx, &got), json!({"kind": "descriptor_block"}));
}

/// A repeated task-augmented call (the same idempotency key) after a reload
/// whose deny list names the tool is refused from the stored task, and that
/// call's own delivery record names the deny entry (MIK-9191.RULEID.3).
#[tokio::test(flavor = "current_thread")]
async fn a_repeated_task_call_refused_by_a_deny_entry_names_it() {
    let fx = fixture(super::Answer::Ok, None).await;
    let id = super::submit_task(&fx, "stored-repeat", json!({})).await;
    let first = super::settled_task(&fx, &id).await;
    assert!(
        first.pointer("/result/status").and_then(Value::as_str) == Some("completed"),
        "premise: the task completed: {first}"
    );
    fx.state
        .live_config
        .set(configured(&fx, key_admits_policy_denies));
    let got = super::submit_task_raw(&fx, "stored-repeat", json!({})).await;
    let _ = super::invocations(&fx).await;
    let expected = tool_policy_id(&fx, "deny", "alpha:read");
    let hex = expected.as_str().trim_start_matches("tool_policy:");
    assert!(
        got.get("error").is_some() || got.pointer("/result/isError") == Some(&json!(true)),
        "premise: the repeat is refused: {got}"
    );
    assert!(
        !got.to_string().contains(hex),
        "the answer names the rule: {got}"
    );
    let log = std::fs::read_to_string(fx.log.path()).unwrap_or_default();
    let repeats: Vec<Value> = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| {
            row["event"] == "response_delivery_attempt"
                && row["tool"] == "gateway_invoke"
                && row["response_effect"] == "refused"
        })
        .collect();
    let [repeat] = repeats.as_slice() else {
        panic!("wanted one refused repeat: {repeats:?}");
    };
    assert_eq!(
        repeat["refused_by"],
        json!({"kind": "tool_policy", "rule_id": expected.as_str()}),
        "{repeat}"
    );
}
