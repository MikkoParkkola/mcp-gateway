// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 R2: stdio's admission (stdio_dispatch.rs) serves no
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
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = gateway.tool_calls().len();
    gateway.revoke_operator_grant().await;
    let again = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_invoke("r2"), session)
        .await
        .expect("a response");
    assert!(!again.to_string().contains(MARKER), "R2: the stored output was served: {again}");
    assert!(again.get("error").is_some(), "R2: not a refusal: {again}");
    assert_eq!(gateway.tool_calls().len(), sent, "R2: the call reached the backend: {again}");
}
