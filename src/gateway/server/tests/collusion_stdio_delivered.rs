// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.4 over stdio: a surfaced tool's answer has its
//! `cacheScope` clamped on the way out, so backend text stuffed there never
//! reaches the operator. The receipt is built from the answer delivered.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
};

/// What `alpha:read` delivers, long enough for several fingerprints.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// Backend text long enough to fill a receipt's cap by itself.
fn stuffing() -> String {
    (0..400).fold(String::new(), |mut text, n| {
        let _ = write!(
            text,
            "The quarry inventory line {n} lists crate {} of pressed cider. ",
            n * 7 + 3
        );
        text
    })
}

/// Backend `alpha`: `read` answers [`PROSE`] with `cacheScope` stuffed.
struct Alpha(String);

#[async_trait::async_trait]
impl crate::transport::Transport for Alpha {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "read", "description": "A tool.", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({ "tools": [tool] })));
        }
        Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": PROSE}], "isError": false, "cacheScope": self.0}),
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

/// Whether `bob` sending `text` through `alpha:read` is refused as a relay.
fn relayed_by_bob(firewall: &Firewall, text: &str) -> bool {
    let params = json!({"name": "read", "arguments": {"text": text}});
    !firewall
        .check_relay(
            RelayCaller::Keyed("bob"),
            "alpha",
            "read",
            &params,
            ("s", "bob"),
        )
        .allowed
}

#[tokio::test]
async fn a_stdio_answer_is_receipted_as_delivered() {
    let stuffing = stuffing();
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Alpha(stuffing.clone())));
    assert!(registry.register(backend));
    let firewall = Arc::new(Firewall::from_config(
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
    ));
    let mut meta = MetaMcp::new(registry).with_surfaced_tools(vec![SurfacedToolConfig {
        server: "alpha".to_string(),
        tool: "read".to_string(),
    }]);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let meta = Arc::new(meta);

    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                         "params": {"name": "read", "arguments": {}}});
    let read = super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-r4")
        .await
        .expect("a request is answered");
    assert!(
        read.get("error").is_none(),
        "base: the read is delivered: {read}"
    );
    assert_eq!(
        read["result"]["cacheScope"], "private",
        "base: the scope is clamped: {read}"
    );

    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the delivered text lost its receipt"
    );
    let piece: String = stuffing.chars().take(400).collect();
    assert!(
        !relayed_by_bob(&firewall, &piece),
        "undelivered cacheScope text was receipted"
    );
}
