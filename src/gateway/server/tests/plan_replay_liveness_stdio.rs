// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 P4: stdio's route stage (stdio_dispatch.rs) serves no retained
//! plan result to an operator whose grant was revoked (test plan t0). The
//! HTTP rows are in gateway/router/plan_replay_liveness_tests.rs.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::config::AuthConfig;
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::gateway::server::account_bindings::ServeMode;

const MARKER: &str = "stored-plan-output-8406-stdio";
const PLAYBOOK: &str = "two_reads";

fn two_reads() -> crate::playbook::PlaybookDefinition {
    let read = |name: &str| json!({"name": name, "server": BACKEND, "tool": "read", "arguments": {"folder": "inbox"}});
    serde_json::from_value(json!({"playbook": "1.0", "name": PLAYBOOK,
        "description": "reads", "steps": [read("s0"), read("s1")]}))
    .expect("the playbook deserialises")
}

fn keyed_playbook(key: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
    "name": "gateway_run_playbook",
    "arguments": {"name": PLAYBOOK, "arguments": {}},
    "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
    }}})
}

/// P4 (stdio twin of P1): a keyed `gateway_run_playbook` runs while
/// connected; the grant is revoked; the same call is refused and nothing is
/// sent. Red on the release line: the retained result is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p4_stdio_keyed_playbook_replay_after_revocation_is_refused() {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let meta = gateway.take_meta();
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(two_reads());
    meta.set_playbook_engine(engine);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    if let Some(backend) = gateway.backends().get(BACKEND) {
        backend.store_shared_tools_for_test(vec![tool]);
    }
    let meta = Arc::new(meta);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let session = super::super::STDIO_SESSION_ID;
    for _ in 0..2 {
        gateway
            .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    }
    let first = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_playbook("p4"), session)
        .await
        .expect("a response");
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    let sent = gateway.tool_calls().len();
    let entered = crate::gateway::meta_mcp::plan_entries::count(&meta);
    gateway.revoke_operator_grant().await;
    let again = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_playbook("p4"), session)
        .await
        .expect("a response");
    assert!(
        !again.to_string().contains(MARKER),
        "P4: the stored plan output was served after revocation: {again}"
    );
    assert!(again.get("error").is_some(), "P4: not a refusal: {again}");
    assert_eq!(
        gateway.tool_calls().len(),
        sent,
        "P4: the replay reached the backend: {again}"
    );
    assert_eq!(
        crate::gateway::meta_mcp::plan_entries::count(&meta),
        entered,
        "P4: the replay entered the plan executor: {again}"
    );
}
