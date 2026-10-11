// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7886: under `security.posture: hardened` a stdio `tools/call` of ANY
//! tool is signed and nonce-checked, as on HTTP, not only `gateway_invoke`.
//!
//! The dispatcher is the one `run_stdio` calls, on a gateway built by the
//! production builder. Under `standard` the same call stays unsigned, so the
//! posture is what changes the answer.

use serde_json::{Value, json};

use super::signing_nonce_allocations_support::{Fixture, SESSION, error_of, runtime};
use crate::gateway::meta_mcp::signing::NONCE_META;

const MISSING_NONCE: (i64, &str) = (-32001, "Nonce required when message signing is enforced");
const REPLAYED_NONCE: (i64, &str) = (-32001, "Nonce replay detected");

/// A stdio `tools/call` of a meta tool that is not `gateway_invoke`.
fn list_servers(id: &str, nonce: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    if let Some(nonce) = nonce {
        meta[NONCE_META] = json!(nonce);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "gateway_list_servers", "arguments": {}, "_meta": meta}
    })
}

async fn dispatch(fixture: &Fixture, request: Value) -> Value {
    super::super::Gateway::dispatch_single_with_sink(
        &fixture.meta,
        &fixture.tool_policy,
        &fixture.mtls_policy,
        request,
        super::super::StdioClient {
            session_id: SESSION,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            modern: false,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id must produce a response")
}

fn assert_refused(response: &Value, expected: (i64, &str)) {
    let (code, message) = error_of(response);
    assert_eq!((code, message.as_str()), expected, "{response}");
}

#[test]
fn hardened_stdio_refuses_a_non_invoke_tool_call_without_a_nonce() {
    runtime().block_on(async {
        let fixture = Fixture::start_hardened().await;
        let response = dispatch(&fixture, list_servers("no-nonce", None)).await;
        assert_refused(&response, MISSING_NONCE);
    });
}

#[test]
fn hardened_stdio_admits_a_non_invoke_tool_call_once() {
    runtime().block_on(async {
        let fixture = Fixture::start_hardened().await;
        let first = dispatch(
            &fixture,
            list_servers("first", Some("stdio-hardened-nonce-0001")),
        )
        .await;
        assert!(
            first.get("error").is_none(),
            "a fresh nonce is admitted: {first}"
        );
        let signature = &first["result"]["_signature"];
        assert_eq!(signature["version"], 2, "the answer is signed: {first}");
        assert_eq!(signature["nonce"], "stdio-hardened-nonce-0001", "{first}");
        let again = dispatch(
            &fixture,
            list_servers("again", Some("stdio-hardened-nonce-0001")),
        )
        .await;
        assert_refused(&again, REPLAYED_NONCE);
    });
}

#[test]
fn standard_stdio_leaves_a_non_invoke_tool_call_unsigned() {
    runtime().block_on(async {
        let fixture = Fixture::start(true).await;
        let response = dispatch(&fixture, list_servers("standard", None)).await;
        assert!(
            response.get("error").is_none(),
            "under standard only gateway_invoke is nonce-checked: {response}"
        );
        assert!(
            response["result"].get("_signature").is_none(),
            "under standard the answer is not signed: {response}"
        );
    });
}

/// An argument the request firewall blocks as shell injection, built so no
/// such literal sits in the source.
#[cfg(feature = "firewall")]
const SHELL_PATTERN: &str = concat!(";", " rm", " -rf", " / ");

/// Route-check-parity P3: a hardened stdio `tools/call` the route-stage request
/// firewall refuses spends no nonce. Stdio admits the nonce before the route
/// stage (a bad nonce stays cheap to refuse, MIK-7377.SIGNING.5 row 40) and
/// gives it back when the route stage refuses (lead ruling), so the same nonce
/// is admitted once afterwards, and only once.
#[cfg(feature = "firewall")]
#[test]
fn a_route_refusal_spends_no_signing_nonce() {
    runtime().block_on(async {
        let fixture = Fixture::start_hardened().await;
        let blocked = json!({
            "jsonrpc": "2.0",
            "id": "blocked",
            "method": "tools/call",
            "params": {
                "name": "gateway_invoke",
                "arguments": {
                    "server": super::signing_nonce_allocations_support::BACKEND,
                    "tool": super::signing_nonce_allocations_support::TOOL,
                    "arguments": {"cmd": SHELL_PATTERN}
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    NONCE_META: "stdio-route-refusal-0001"
                }
            }
        });
        let refused = dispatch(&fixture, blocked).await;
        let (code, message) = error_of(&refused);
        assert_eq!(code, -32600, "{refused}");
        assert!(
            message.starts_with("Firewall blocked: "),
            "not refused by the route-stage firewall: {refused}"
        );
        let next = dispatch(
            &fixture,
            list_servers("next", Some("stdio-route-refusal-0001")),
        )
        .await;
        assert!(
            next.get("error").is_none(),
            "the refused call spent its nonce: {next}"
        );
        // Given back, not forgotten: it is good for exactly one more call.
        let again = dispatch(
            &fixture,
            list_servers("again", Some("stdio-route-refusal-0001")),
        )
        .await;
        assert_refused(&again, REPLAYED_NONCE);
    });
}
