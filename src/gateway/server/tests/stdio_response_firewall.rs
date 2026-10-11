// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7407.RESPONSE.3/.5 over stdio: the real stdio dispatch refuses a
//! response the firewall blocks, and inspects each response once. Counted on
//! the firewall the stdio Meta-MCP holds, which is its only instance.

use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};

const TOOL: &str = "leaky_echo";

/// Credential-shaped material the detector blocks by default (High). Built at
/// run time so no token-shaped literal sits in the source.
fn canary() -> String {
    format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890")
}

/// A backend whose one tool's description is `description`, and whose calls
/// return `answer`.
struct Backendish {
    description: String,
    answer: String,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Backendish {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({ "tools": [{
                "name": TOOL,
                "description": self.description,
                "inputSchema": { "type": "object" },
                "annotations": { "readOnlyHint": true }
            }]})
        } else {
            json!({ "content": [{ "type": "text", "text": self.answer }], "isError": false })
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

struct Stdio {
    meta: Arc<MetaMcp>,
    firewall: Arc<Firewall>,
}

impl Stdio {
    async fn new(description: &str, answer: &str, rules: Vec<FirewallRule>) -> Self {
        let registry = Arc::new(BackendRegistry::new());
        let backend = Arc::new(Backend::new(
            "demo",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        backend.set_transport_for_test(Arc::new(Backendish {
            description: description.to_string(),
            answer: answer.to_string(),
        }) as Arc<dyn crate::transport::Transport>);
        backend
            .get_tools_shared()
            .await
            .expect("warm the tool cache");
        assert!(registry.register(backend));
        let firewall = Arc::new(
            Firewall::from_config(
                FirewallConfig {
                    enabled: true,
                    scan_responses: true,
                    scan_requests: false,
                    credential_redaction: true,
                    rules,
                    ..FirewallConfig::default()
                },
                None,
            )
            .keyed_for_test(),
        );
        let mut meta = MetaMcp::new(registry).with_surfaced_tools(vec![SurfacedToolConfig {
            server: "demo".to_string(),
            tool: TOOL.to_string(),
        }]);
        meta.set_firewall(Some(Arc::clone(&firewall)));
        meta.share_keyring_with_for_test(&firewall);
        Self {
            meta: Arc::new(meta),
            firewall,
        }
    }

    /// One stdio request; returns the answer and the inspections it cost.
    async fn send(&self, method: &str, params: Value) -> (Value, usize) {
        let policy = Arc::new(crate::security::ToolPolicy::default());
        let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
            &crate::mtls::MtlsConfig::default(),
        ));
        let before = self.firewall.response_inspection_counts().inspections;
        let request = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
        let body = super::super::Gateway::dispatch_single(
            &self.meta,
            &policy,
            &mtls,
            &request,
            "stdio-7407",
        )
        .await
        .expect("a request is answered");
        let after = self.firewall.response_inspection_counts().inspections;
        (body, after - before)
    }
}

fn assert_refused(body: &Value) {
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(
        body["error"]["message"], "Response blocked by security firewall",
        "{body}"
    );
    assert_eq!(body["id"], 7, "{body}");
    assert!(!body.to_string().contains(&canary()), "leaked: {body}");
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "every call site passes an owned json! literal"
)]
fn call(tool: &str, arguments: Value) -> Value {
    json!({ "name": tool, "arguments": arguments })
}

/// A blocked tool call, a blocked surfaced listing and a blocked discovery
/// listing are each refused over stdio, with one inspection.
#[tokio::test]
async fn stdio_refuses_blocked_responses_with_one_inspection() {
    let leaky = format!("uses {}", canary());
    let stdio = Stdio::new(&leaky, &format!("fetched {}", canary()), Vec::new()).await;
    let cases = [
        ("tools/call", call(TOOL, json!({}))),
        ("tools/list", json!({})),
        (
            "tools/call",
            call("gateway_list_tools", json!({ "server": "demo" })),
        ),
        (
            "tools/call",
            call("gateway_search_tools", json!({ "query": "echo" })),
        ),
        (
            "tools/call",
            call("gateway_search", json!({ "query": "echo" })),
        ),
        // Not a discovery tool: the marker must not skip its inspection.
        (
            "tools/call",
            call(
                "gateway_invoke",
                json!({ "server": "demo", "tool": TOOL, "arguments": {} }),
            ),
        ),
    ];
    for (method, params) in cases {
        let (body, inspected) = stdio.send(method, params.clone()).await;
        assert_refused(&body);
        assert_eq!(inspected, 1, "{method} {params}: one inspection");
    }
}

/// Positive controls: clean content is served, one inspection each, and a
/// Warn rule on listings serves a redacted list rather than refusing it.
#[tokio::test]
async fn stdio_serves_allowed_responses_with_one_inspection() {
    let stdio = Stdio::new("echo", "fine", Vec::new()).await;
    let cases = [
        ("tools/call", call(TOOL, json!({}))),
        ("tools/list", json!({})),
        (
            "tools/call",
            call("gateway_list_tools", json!({ "server": "demo" })),
        ),
        (
            "tools/call",
            call("gateway_search_tools", json!({ "query": "echo" })),
        ),
        (
            "tools/call",
            call("gateway_search", json!({ "query": "echo" })),
        ),
    ];
    for (method, params) in cases {
        let (body, inspected) = stdio.send(method, params.clone()).await;
        assert!(body.get("error").is_none(), "{method} {params}: {body}");
        assert_eq!(inspected, 1, "{method} {params}: one inspection");
    }

    let warn = vec![FirewallRule {
        tool_match: "tools/list".to_string(),
        action: FirewallAction::Warn,
        reason: None,
        scan: Vec::new(),
    }];
    let stdio = Stdio::new(&format!("uses {}", canary()), "fine", warn).await;
    let (body, inspected) = stdio
        .send(
            "tools/call",
            call("gateway_list_tools", json!({ "server": "demo" })),
        )
        .await;
    assert!(body.get("error").is_none(), "{body}");
    assert!(
        !body.to_string().contains(&canary()),
        "not redacted: {body}"
    );
    assert_eq!(inspected, 1, "one inspection under Warn");
}
