// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a T22: the stdio `dispatch_tools_call` opener. An ungranted call is
//! refused at sync admission, before `handle_tools_call`, and that refusal
//! is recorded once.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend, decisions, grants, logger,
};
use crate::security::audit::AuditFailurePolicy;

#[tokio::test]
async fn stdio_admission_refusal_writes_one_record() {
    let dir = tempfile::tempdir().expect("a private log directory");
    let endpoint = Endpoint::start(false).await;
    let mut meta =
        MetaMcp::new(Arc::new(BackendRegistry::new())).with_identity_grants(grants(vec![]));
    meta.enable_transparency_log(logger(&dir, AuditFailurePolicy::BestEffort));
    meta.set_capabilities(capability_backend(endpoint.port, ("api_key", "alice")));
    let meta = Arc::new(meta);
    let tool_policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({
        "jsonrpc": "2.0",
        "id": "d3a-t22",
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": CAPS, "tool": PERSONAL, "arguments": {} },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });

    let response = super::super::Gateway::dispatch_single_with_sink(
        &meta,
        &tool_policy,
        &mtls_policy,
        request,
        super::super::StdioClient {
            session_id: "d3a-stdio",
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            modern: false,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id is answered");

    assert!(
        response
            .pointer("/error/code")
            .and_then(Value::as_i64)
            .is_some(),
        "stdio carries no grant subject, so the personal call is refused: {response}"
    );
    assert_eq!(endpoint.arrivals(), 0, "the refused call reaches nothing");
    let records = decisions(&dir);
    assert_eq!(records.len(), 1, "{records:#?}");
    assert_eq!(records[0]["outcome"], json!("denied"), "{:#?}", records[0]);
}
