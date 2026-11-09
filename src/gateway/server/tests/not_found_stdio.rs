// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio `gateway_invoke` of a backend the registry does not hold: its
//! invocation record names `not_found` and a refusal, never `default_allow`.

use std::sync::Arc;

use serde_json::json;

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::grant_audit_fixture::{invocations, logger};
use crate::security::audit::AuditFailurePolicy;

/// NOTFOUND.1 and NOTFOUND.3 for stdio (red first).
#[tokio::test]
async fn a_stdio_call_to_a_nonexistent_backend_records_not_found() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_transparency_log(logger(&dir, AuditFailurePolicy::BestEffort));
    let meta = Arc::new(meta);
    let mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({
        "jsonrpc": "2.0",
        "id": "not-found",
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": { "server": "nowhere", "tool": "t", "arguments": {} }
        }
    });
    let response = super::super::Gateway::dispatch_single_for_client(
        &meta,
        &crate::gateway::authz::default_line(&meta),
        &mtls_policy,
        request,
        super::super::StdioClient {
            session_id: "not-found-stdio",
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
    )
    .await
    .expect("a request carrying an id is answered");
    assert!(
        response.to_string().contains("Backend not found: nowhere"),
        "the answer is the plain miss: {response}"
    );
    let records = invocations(&dir);
    let [record] = records.as_slice() else {
        panic!("one record: {records:#?}");
    };
    assert_eq!(
        record["decision"]["kind"],
        json!("not_found"),
        "answer {response}; record {record}"
    );
    assert_eq!(record["outcome"], json!("denied"), "{record}");
}
