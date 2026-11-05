// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored read judged against alpha's OWN catalogue on a per-user backend
//! (MIK-9191.RULEID.3): the caller-catalogue verdict is deferred until after policy
//! and accounts, so its record names that verdict only when it is the answer
//! delivered, and a lacked tool, which is no policy refusal, names nothing.

use serde_json::{Value, json};

use super::{Gateway, backend, finished, gateway, task_get};
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BACKEND, BINDING, CallerSlot, Surfaced, TOOL,
};

/// Alpha's own slot relisted with the tool's input schema broken (CAP-003).
fn alpha_breaks_the_schema(gw: &Gateway) {
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "description": "Reads.", "inputSchema": {"type": "string"}
    }))
    .expect("a tool");
    backend(gw).store_per_user_tools_for_test(BINDING, vec![tool]);
}

/// The last `tasks/get` delivery record: the read's own.
fn read_record(gw: &Gateway) -> Value {
    gw.audit_records()
        .into_iter()
        .rev()
        .find(|row| row["event"] == "response_delivery_attempt" && row["tool"] == "tasks/get")
        .expect("the read's delivery record")
}

/// A lacked tool is the caller's catalogue, not a policy refusal: answered
/// absent, recorded with no refusal.
#[tokio::test]
async fn a_lacked_stored_read_names_no_refusal() {
    let gw = gateway(CallerSlot::Valid, super::CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "rb-lacked").await;
    super::alpha_lacks(&gw);
    let read = task_get(&gw, &id).await;
    assert!(read.get("error").is_some(), "premise: refused: {read}");
    let record = read_record(&gw);
    assert!(record.get("refused_by").is_none(), "{record}");
}

/// Alpha's own slot breaks the schema after the task ran: the deferred
/// caller-catalogue verdict is the answer, and its record names it.
#[tokio::test]
async fn a_deferred_caller_catalogue_refusal_names_its_check() {
    let gw = gateway(CallerSlot::Valid, super::CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "rb-deferred").await;
    alpha_breaks_the_schema(&gw);
    let read = task_get(&gw, &id).await;
    assert!(read.get("error").is_some(), "premise: refused: {read}");
    assert_eq!(
        read_record(&gw)["refused_by"],
        json!({"kind": "descriptor_block"})
    );
}

/// Cross-phase: alpha's own slot breaks the schema (deferred, its verdict
/// noted early) and the backend is then killed (the policy phase, met first
/// in delivery order). The record names the kill switch, the refusal
/// delivered, not the deferred verdict's early note.
#[tokio::test]
async fn a_policy_refusal_ahead_of_a_deferred_verdict_names_the_policy() {
    let gw = gateway(CallerSlot::Valid, super::CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "rb-cross").await;
    alpha_breaks_the_schema(&gw);
    gw.meta.kill_switch().kill(BACKEND);
    let read = task_get(&gw, &id).await;
    assert!(read.get("error").is_some(), "premise: refused: {read}");
    assert_eq!(
        read_record(&gw)["refused_by"],
        json!({"kind": "kill_switch"})
    );
}
