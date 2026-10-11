// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.2 over stdio: a `gateway_execute` plan's step receipts
//! pass the stdio route's final rebuild, which keeps each to the answer the
//! operator was delivered. Regression coverage: the route reaches the shared
//! plan retention; the RED rows sit at the unit and POST-route level.
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
};

/// What `alpha:a` delivers.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

/// What `alpha:b` delivers.
const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale.";

/// Backend `alpha`: `a` answers [`PROSE`], `b` answers [`OTHER_PROSE`].
struct Alpha;

#[async_trait::async_trait]
impl crate::transport::Transport for Alpha {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tools: Vec<Value> = ["a", "b"]
                .iter()
                .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
                .collect();
            return Ok(JsonRpcResponse::success(id, json!({ "tools": tools })));
        }
        let name = params
            .as_ref()
            .and_then(|p| p["name"].as_str())
            .unwrap_or_default();
        let text = if name == "a" { PROSE } else { OTHER_PROSE };
        Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": text}], "isError": false}),
        ))
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

/// Whether `bob` sending `text` through `alpha:a` is refused as a relay.
fn relayed_by_bob(firewall: &Firewall, text: &str) -> bool {
    let params = json!({"name": "a", "arguments": {"text": text}});
    !firewall
        .check_relay(
            RelayCaller::Keyed("bob"),
            "alpha",
            "a",
            &params,
            ("s", "bob"),
        )
        .allowed
}

#[tokio::test]
async fn a_stdio_plan_receipts_each_step_it_delivered() {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Alpha));
    assert!(registry.register(backend));
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    sources: vec!["alpha:*".to_string()],
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    );
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    meta.share_keyring_with_for_test(&firewall);
    let meta = Arc::new(meta);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let chain = json!([{"tool": "alpha:a", "arguments": {}}, {"tool": "alpha:b", "arguments": {}}]);
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                         "params": {"name": "gateway_execute", "arguments": {"chain": chain}}});
    let read = super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-r2")
        .await
        .expect("a request is answered");
    assert!(
        read.get("error").is_none(),
        "base: the plan is delivered: {read}"
    );

    assert!(relayed_by_bob(&firewall, PROSE), "step A lost its receipt");
    assert!(
        relayed_by_bob(&firewall, OTHER_PROSE),
        "step B lost its receipt"
    );
}
