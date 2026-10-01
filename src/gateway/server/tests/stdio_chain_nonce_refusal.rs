// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7324.COV.3: the stdio path's first step (`Gateway::prepare_signing`)
//! refuses a malformed chain nonce before anything parses the request, and
//! the refusal keeps the caller's id. A well-formed nonce is not refused.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::mrtr::CHAIN_NONCE_META;

async fn dispatch(nonce: Value) -> Value {
    let meta = Arc::new(MetaMcp::new(Arc::new(BackendRegistry::new())));
    let tool_policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({
        "jsonrpc": "2.0",
        "id": "cov3-nonce",
        "method": "tools/call",
        "params": {
            "name": "gateway_list_servers",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                (CHAIN_NONCE_META): nonce
            }
        }
    });
    super::super::Gateway::dispatch_single_with_sink(
        &meta,
        &tool_policy,
        &mtls_policy,
        request,
        super::super::StdioClient {
            session_id: "cov3-stdio",
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
        },
        &super::super::StdioTelemetry::default(),
    )
    .await
    .expect("a request carrying an id is answered")
}

#[tokio::test]
async fn a_malformed_chain_nonce_is_refused_with_the_callers_id() {
    let too_long = "n".repeat(257);
    for nonce in [json!(""), json!(7), json!(too_long)] {
        let response = dispatch(nonce.clone()).await;
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_i64),
            Some(-32602),
            "nonce {nonce} must be refused as invalid params: {response}"
        );
        assert_eq!(response["id"], json!("cov3-nonce"), "{response}");
        let message = response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(message.contains(CHAIN_NONCE_META), "{message}");
    }
}

#[tokio::test]
async fn a_well_formed_chain_nonce_is_not_refused() {
    let response = dispatch(json!("n-1")).await;
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["id"], json!("cov3-nonce"), "{response}");
    assert!(response.get("result").is_some(), "{response}");
}
