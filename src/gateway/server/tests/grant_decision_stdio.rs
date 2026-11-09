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
    let dir = crate::test_dir_keep::kept_tempdir();
    let endpoint = Endpoint::start(false).await;
    let mut meta =
        MetaMcp::new(Arc::new(BackendRegistry::new())).with_identity_grants(grants(vec![]));
    meta.enable_transparency_log(logger(&dir, AuditFailurePolicy::BestEffort));
    meta.set_capabilities(capability_backend(endpoint.port, ("api_key", "alice")));
    let meta = Arc::new(meta);
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

    let response = super::super::Gateway::dispatch_single_for_client(
        &meta,
        &crate::gateway::authz::default_line(&meta),
        &mtls_policy,
        request,
        super::super::StdioClient {
            session_id: "d3a-stdio",
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
    // Refused at admission: no invocation record, so Activity lists it.
    assert_eq!(
        records[0]["invocation_recorded"],
        json!(false),
        "{:#?}",
        records[0]
    );
    assert_eq!(records[0]["server"], json!(CAPS), "{:#?}", records[0]);
}

/// A signed stdio `gateway_invoke` of a personal capability whose grant is
/// missing is refused while signing is prepared (before the route stage):
/// one denied decision, no invocation record, so Activity lists it.
#[test]
fn a_signed_stdio_refusal_writes_one_unrecorded_decision() {
    use super::signing_nonce_allocations_support::{Fixture, SESSION, runtime};
    let runtime = runtime();
    let dir = Arc::new(tempfile::tempdir().expect("a private log directory"));
    let log = dir.path().join("audit.jsonl");
    runtime.block_on(async {
        let fixture = Fixture::start_audited_signed(&log).await;
        let endpoint = Endpoint::start(false).await;
        fixture
            .meta
            .set_capabilities(capability_backend(endpoint.port, ("api_key", "alice")));
        fixture.meta.set_identity_grants(grants(vec![]));
        let request = json!({
            "jsonrpc": "2.0", "id": "d14", "method": "tools/call",
            "params": {
                "name": "gateway_invoke",
                "arguments": { "server": CAPS, "tool": PERSONAL, "arguments": {} },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    crate::gateway::meta_mcp::signing::NONCE_META: "d14-nonce-0001"
                }
            }
        });
        let response = super::super::Gateway::dispatch_single_for_client(
            &fixture.meta,
            &crate::gateway::authz::published_line(&fixture.meta),
            &fixture.mtls_policy,
            request,
            super::super::StdioClient {
                session_id: SESSION,
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
            response.get("error").is_some(),
            "premise: refused: {response}"
        );
        let entries: Vec<Value> = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let held: Vec<&Value> = entries
            .iter()
            .filter(|e| e["kind"] == json!("identity_grant_decision"))
            .collect();
        assert_eq!(held.len(), 1, "{entries:#?}");
        assert_eq!(held[0]["invocation_recorded"], json!(false), "{held:#?}");
        let calls = entries.iter().filter(|e| e.get("route").is_some()).count();
        assert_eq!(calls, 0, "no invocation record of its own: {entries:#?}");
    });
}
