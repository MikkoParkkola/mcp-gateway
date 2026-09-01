// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6865.SCHEMA.1 — Meta-MCP tool schemas MUST remain valid under JSON
//! Schema 2020-12.
//!
//! Enumerates every `inputSchema` the gateway's Meta-MCP surface can produce
//! — Traditional mode (all optional meta-tools enabled) and Code Mode — via
//! the real `tools/list` handler (`MetaMcp::handle_tools_list`), and
//! validates each one against the JSON Schema 2020-12 meta-schema using the
//! `jsonschema` crate (a real validator, not a hand-rolled key check).

use std::{sync::Arc, time::Duration};

use mcp_gateway::{
    backend::BackendRegistry,
    config::{Config, FailsafeConfig, WebhookConfig},
    config_reload::{LiveConfig, ReloadContext},
    gateway::{WebhookRegistry, test_helpers::MetaMcp},
    protocol::{JsonRpcResponse, RequestId, ToolsListResult},
    stats::UsageStats,
};

fn repo_file(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn decode_tools_list(response: JsonRpcResponse) -> ToolsListResult {
    serde_json::from_value(response.result.expect("tools/list should return a result"))
        .expect("tools/list result should deserialize")
}

fn make_reload_context(backends: Arc<BackendRegistry>) -> Arc<ReloadContext> {
    Arc::new(ReloadContext::new(
        repo_file("examples/gateway-full.yaml"),
        Arc::new(LiveConfig::new(Config::default())),
        backends,
        FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

/// Traditional-mode `MetaMcp` with every optional meta-tool switched on
/// (stats, cost report, webhooks, reload) so its `tools/list` response
/// includes the maximum schema surface — the same construction
/// `public_claims_validation.rs` uses for its "operational" scenario.
fn operational_meta_mcp() -> MetaMcp {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = MetaMcp::with_features(
        Arc::clone(&backends),
        None,
        Some(Arc::new(UsageStats::new())),
        None,
        Duration::from_secs(60),
    );
    meta_mcp.set_reload_context(make_reload_context(Arc::clone(&backends)));
    meta_mcp.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    ))));
    meta_mcp
}

fn code_mode_meta_mcp() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new())).with_code_mode(true)
}

/// Every `inputSchema` the gateway can hand a client across both tool
/// surfaces, tagged with `"<mode>/<tool name>"` for failure messages.
fn all_meta_tool_schemas() -> Vec<(String, serde_json::Value)> {
    let mut schemas = Vec::new();
    for (mode, meta_mcp) in [
        ("traditional", operational_meta_mcp()),
        ("code_mode", code_mode_meta_mcp()),
    ] {
        let tools = decode_tools_list(meta_mcp.handle_tools_list(RequestId::Number(1))).tools;
        assert!(
            !tools.is_empty(),
            "{mode} tools/list returned zero tools — fixture is not exercising real schemas"
        );
        for tool in tools {
            schemas.push((format!("{mode}/{}", tool.name), tool.input_schema));
        }
    }
    schemas
}

/// Asserts every enumerated Meta-MCP `inputSchema` is a structurally valid
/// JSON Schema 2020-12 document per the official meta-schema.
#[test]
fn meta_mcp_tool_schemas_are_valid_json_schema_2020_12() {
    let schemas = all_meta_tool_schemas();
    for (name, schema) in &schemas {
        if let Err(err) = jsonschema::meta::validate(schema) {
            panic!("tool `{name}` has an invalid JSON Schema 2020-12 inputSchema: {err}");
        }
    }
}

/// Falsifier: proves the validator above can actually fail, not just pass by
/// construction. `minLength` MUST be a non-negative integer under 2020-12;
/// a string value is structurally invalid and must be rejected.
#[test]
fn falsifier_invalid_schema_is_rejected_by_the_same_validator() {
    let broken = serde_json::json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "minLength": "not-a-number" }
        },
        "required": ["query"]
    });
    let result = jsonschema::meta::validate(&broken);
    assert!(
        result.is_err(),
        "validator accepted a schema with minLength as a string — it cannot distinguish valid from invalid, so the passing test above proves nothing"
    );
}
