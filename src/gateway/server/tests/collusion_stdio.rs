// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 §13.3 M8: over stdio the local operator is one principal. Its
//! own copy excuses it under `block`; what an HTTP caller was delivered,
//! sent from stdio, is refused.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
};

/// What `alpha:read` answers, long enough for several fingerprints.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// Text only an HTTP caller was delivered.
const OTHER: &str = "The vineyard register for the south terrace lists nine blocks of old vines, \
    the dates each block was netted against the starlings, the litres pressed from every row in \
    the wet harvest, and the names of the pickers who stayed for the late frost. It ends with a \
    tally of barrels sold to the abbey and a remark about the cracked vat in the cellar.";

fn text_result(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// Backend `alpha`: `read` answers [`PROSE`]; `send` counts deliveries.
struct Alpha {
    sends: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Alpha {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tools: Vec<Value> = ["read", "send"]
                .iter()
                .map(|n| json!({"name": n, "description": "A tool.", "inputSchema": {"type": "object"}}))
                .collect();
            return Ok(JsonRpcResponse::success(id, json!({ "tools": tools })));
        }
        let send = params.as_ref().is_some_and(|p| p["name"] == "send");
        if send {
            self.sends.fetch_add(1, Ordering::SeqCst);
            return Ok(JsonRpcResponse::success(id, text_result("sent")));
        }
        Ok(JsonRpcResponse::success(id, text_result(PROSE)))
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

/// One stdio `gateway_invoke` of `alpha:{tool}`; the answer.
async fn invoke(meta: &Arc<MetaMcp>, tool: &str, arguments: &Value) -> Value {
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let params = json!({"name": "gateway_invoke",
                        "arguments": {"server": "alpha", "tool": tool, "arguments": arguments}});
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    super::super::Gateway::dispatch_single(meta, &policy, &mtls, &request, "stdio-m8")
        .await
        .expect("a request is answered")
}

#[tokio::test]
async fn stdio_operator_is_one_principal() {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let sends = Arc::new(AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(Alpha {
        sends: Arc::clone(&sends),
    }));
    assert!(registry.register(backend));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:read".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let meta = Arc::new(meta);

    // An HTTP caller was delivered both texts from `alpha:read`.
    for text in [PROSE, OTHER] {
        let http = RelayCaller::Keyed("http-caller");
        firewall.record_delivery(http, "alpha", "read", &text_result(text));
    }

    let read = invoke(&meta, "read", &json!({})).await;
    assert!(
        read.get("error").is_none(),
        "base: the read is delivered: {read}"
    );
    let own = invoke(&meta, "send", &json!({"text": PROSE})).await;
    assert!(
        own.get("error").is_none(),
        "its own copy must excuse the operator: {own}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "{own}");

    let relay = invoke(&meta, "send", &json!({"text": OTHER})).await;
    assert_eq!(relay["error"]["code"], -32002, "relay not refused: {relay}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "the relay reached the backend"
    );
}
