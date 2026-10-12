// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 R2: stdio's admission (`stdio_dispatch.rs`) serves no
//! retained result to an operator whose grant was revoked.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::config::AuthConfig;
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::gateway::server::account_bindings::ServeMode;

const MARKER: &str = "stored-output-8392-stdio";

fn keyed_invoke(key: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
    "name": "gateway_invoke",
    "arguments": {"server": BACKEND, "tool": "read", "arguments": {"folder": "inbox"}},
    "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
    }}})
}

/// R2 (P2 over stdio): a keyed `gateway_invoke` dispatches while connected;
/// the grant is revoked; the same call is refused, nothing is sent, and the
/// retained result is never delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_stdio_keyed_invoke_after_revocation_is_not_served_the_retained_result() {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let meta = Arc::new(gateway.take_meta());
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let session = super::super::STDIO_SESSION_ID;
    gateway.answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    let first = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_invoke("r2"), session)
        .await
        .expect("a response");
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = gateway.tool_calls().len();
    gateway.revoke_operator_grant().await;
    let again = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_invoke("r2"), session)
        .await
        .expect("a response");
    assert!(
        !again.to_string().contains(MARKER),
        "R2: the stored output was served: {again}"
    );
    assert!(again.get("error").is_some(), "R2: not a refusal: {again}");
    assert_eq!(
        gateway.tool_calls().len(),
        sent,
        "R2: the call reached the backend: {again}"
    );
}

/// E8a over stdio (no-leak twin; mutant M40): the sole operator's keyed call by
/// the SURFACED name runs; the grant is revoked; the repeat with the key that
/// has a stored result answers byte-for-byte (normalising only `id`) as the
/// same call with a fresh key. No key state is consulted before the live
/// answer, so the stored key is not revealed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e8a_stdio_a_stored_key_and_a_fresh_key_answer_alike_for_a_hidden_name() {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let meta = Arc::new(gateway.take_meta().with_surfaced_tools(vec![
        crate::config::SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: "read".to_string(),
        },
    ]));
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let session = super::super::STDIO_SESSION_ID;
    let call = |key: &str| {
        json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
        "name": "read",
        "arguments": {"folder": "inbox"},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
        }}})
    };
    gateway.answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    let first = Gateway::dispatch_single(&meta, &policy, &mtls, &call("e8a-s"), session)
        .await
        .expect("a response");
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    gateway.revoke_operator_grant().await;
    let mut stored = Gateway::dispatch_single(&meta, &policy, &mtls, &call("e8a-s"), session)
        .await
        .expect("a response");
    let mut fresh = Gateway::dispatch_single(&meta, &policy, &mtls, &call("e8a-s-fresh"), session)
        .await
        .expect("a response");
    eprintln!("E8a stdio stored key: {stored}");
    eprintln!("E8a stdio fresh key: {fresh}");
    stored["id"] = Value::Null;
    fresh["id"] = Value::Null;
    assert_eq!(
        stored, fresh,
        "E8a stdio: the stored key answers differently"
    );
}
