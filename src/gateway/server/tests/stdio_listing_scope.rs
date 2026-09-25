// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A3 over stdio: the stdio authorizer is the global tool policy, so a tool
//! that policy denies is neither listed nor counted (T11, T9's stdio half).

use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};

struct Catalogue;

#[async_trait::async_trait]
impl crate::transport::Transport for Catalogue {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let tools: Vec<Value> = ["alpha_read", "alpha_write"]
            .iter()
            .map(|name| json!({ "name": name, "inputSchema": { "type": "object" } }))
            .collect();
        let body = if method == "tools/list" {
            json!({ "tools": tools })
        } else {
            json!({})
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

async fn dispatch(method: &str) -> Value {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Catalogue) as Arc<dyn crate::transport::Transport>);
    backend
        .get_tools_shared()
        .await
        .expect("warm the tool cache");
    assert!(registry.register(backend));
    let surfaced = ["alpha_read", "alpha_write"]
        .iter()
        .map(|tool| SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: (*tool).to_string(),
        })
        .collect();
    let meta = Arc::new(MetaMcp::new(registry).with_surfaced_tools(surfaced));
    let policy = Arc::new(crate::security::ToolPolicy::from_config(
        &crate::security::ToolPolicyConfig {
            enabled: true,
            deny: vec!["alpha:alpha_write".to_string()],
            use_default_deny: false,
            ..Default::default()
        },
    ));
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let params = if method == "initialize" {
        json!({ "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "a3", "version": "1" } })
    } else {
        json!({})
    };
    let request = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-a3")
        .await
        .expect("a request is answered")
}

/// T11: stdio `tools/list` withholds a tool the global policy denies.
#[tokio::test]
async fn stdio_tools_list_hides_policy_denials() {
    let body = dispatch("tools/list").await;
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list: {body}"))
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"alpha_read"), "{names:?}");
    assert!(
        !names.contains(&"alpha_write"),
        "policy denial listed over stdio: {names:?}"
    );
}

/// T9 (stdio half): the initialize preamble counts only the admitted tool.
#[tokio::test]
async fn stdio_initialize_counts_exclude_policy_denials() {
    let body = dispatch("initialize").await;
    let text = body["result"]["instructions"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"));
    assert!(text.contains("manages 1 tools across 1 backends"), "{text}");
}
