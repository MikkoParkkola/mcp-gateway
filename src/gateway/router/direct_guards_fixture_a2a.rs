// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8139 FW.3: an A2A backend beside the fixture's MCP pair, so an egress
//! row can drive the same leak through the A2A transport. `alpha-a2a` is a
//! real `A2aTransport` against the shared stub agent (`a2a::test_agent`); its
//! config is `transport: a2a`, so `Backend::is_a2a` holds.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::future::BoxFuture;
use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_firewalled_with};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// The A2A backend's name in the fixture.
pub(crate) const A2A_BACKEND: &str = "alpha-a2a";

/// What the stub agent answers each `SendMessage` with.
#[derive(Clone, Copy)]
pub(crate) enum A2aAnswer {
    /// A completed task whose closing message is this text.
    Text(&'static str),
    /// A completed task whose one data part is the object `{"note": text}`,
    /// which the translator promotes to `structuredContent`.
    DataNote(&'static str),
    /// The agent's own JSON-RPC error, with this message.
    RpcError(&'static str),
    /// A task that ended `TASK_STATE_FAILED` with this status text.
    Failed(&'static str),
    /// The agent's own JSON-RPC error, a plain message with this text as its
    /// `data` (which the A2A client discards, `a2a/client.rs`).
    RpcErrorData(&'static str),
}

fn reply(answer: A2aAnswer, id: Value) -> Value {
    let task = |state: &str, parts: Value| {
        json!({"jsonrpc": "2.0", "id": id, "result": {"task": {
            "id": "t-1", "contextId": "c-1",
            "status": {"state": state, "message": {
                "messageId": "m", "role": "ROLE_AGENT", "parts": parts}}}}})
    };
    match answer {
        A2aAnswer::Text(text) => task("TASK_STATE_COMPLETED", json!([{"text": text}])),
        A2aAnswer::DataNote(text) => {
            task("TASK_STATE_COMPLETED", json!([{"data": {"note": text}}]))
        }
        A2aAnswer::RpcError(text) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32001, "message": text}})
        }
        A2aAnswer::Failed(text) => task("TASK_STATE_FAILED", json!([{"text": text}])),
        A2aAnswer::RpcErrorData(text) => json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32001, "message": "benign refusal", "data": text}}),
    }
}

/// [`fixture_firewalled_with`] plus `alpha-a2a`, answering `a2a`. Each
/// `SendMessage` counts in `fx.calls`, as an MCP backend's call does, and in
/// the returned counter alone, so a row can show the agent was reached.
pub(crate) async fn fixture_firewalled_with_a2a(
    answer: Answer,
    a2a: A2aAnswer,
    rule: Option<crate::security::firewall::FirewallAction>,
) -> (Fx, Arc<AtomicUsize>) {
    let fx = fixture_firewalled_with(answer, rule, false).await;
    let (calls, sends) = (Arc::clone(&fx.calls), Arc::new(AtomicUsize::new(0)));
    let counted = Arc::clone(&sends);
    let base = crate::a2a::test_agent::serve(move |body: Value| -> BoxFuture<'static, Value> {
        if body["method"] == "SendMessage" {
            calls.fetch_add(1, Ordering::SeqCst);
            counted.fetch_add(1, Ordering::SeqCst);
        }
        let id = body["id"].clone();
        Box::pin(async move { reply(a2a, id) })
    })
    .await;
    let backend = Arc::new(Backend::new(
        A2A_BACKEND,
        BackendConfig {
            transport: TransportConfig::A2a {
                a2a_url: base.clone(),
                a2a_agent_card_path: None,
            },
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(crate::a2a::test_agent::started(&base).await);
    assert!(fx.state.backends.register(backend), "fixture registration");
    (fx, sends)
}
