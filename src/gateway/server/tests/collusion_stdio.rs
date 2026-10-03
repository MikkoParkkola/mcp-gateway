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
    /// What `read` answers.
    read: Arc<parking_lot::Mutex<String>>,
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
        let text = self.read.lock().clone();
        Ok(JsonRpcResponse::success(id, text_result(&text)))
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
        read: Arc::new(parking_lot::Mutex::new(PROSE.to_string())),
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

/// A stdio gateway whose firewall judges tenants (`block`) and detects relays
/// (`block`), over a backend whose `read` answers what the returned cell holds.
fn judged_stdio() -> (Arc<MetaMcp>, Arc<Firewall>, Arc<parking_lot::Mutex<String>>) {
    use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let read = Arc::new(parking_lot::Mutex::new(String::new()));
    backend.set_transport_for_test(Arc::new(Alpha {
        sends: Arc::new(AtomicUsize::new(0)),
        read: Arc::clone(&read),
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
            tenant_guard: TenantGuardConfig {
                arg_keys: vec!["customer_id".to_string()],
                cross_tenant_reads: CrossTenantReads::Block,
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    (Arc::new(meta), firewall, read)
}

/// One operator `read` of `text`, dispatched as the serve loop does: the
/// answer, what it read, its request's params and the receipts it staged.
async fn staged_read(
    meta: &Arc<MetaMcp>,
    reads: &crate::gateway::outbound::StdioReads,
    cell: &parking_lot::Mutex<String>,
    text: String,
) -> (
    Value,
    Option<crate::security::tenant_reads::ReadAttribution>,
    Option<Value>,
    crate::gateway::meta_mcp::invoke::relay::StagedReceipts,
) {
    use crate::gateway::server::{Gateway, StdioClient, StdioTelemetry};
    *cell.lock() = text;
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let params = json!({"name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}}});
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    let client = StdioClient {
        session_id: "stdio-7800",
        channel: &crate::gateway::input_bridge::NoClientChannel,
        handshake_capabilities: crate::protocol::meta::Declared::NONE,
        tasks: None,
        modern: false,
    };
    let ((answer, staged), hidden) = crate::gateway::outbound::read_scoped(
        reads.guard(),
        Box::pin(Gateway::dispatch_single_staged(
            meta,
            &policy,
            &mtls,
            request.clone(),
            client,
            &StdioTelemetry::default(),
        )),
    )
    .await;
    let value = answer.expect("a request is answered");
    (value, hidden, request.get("params").cloned(), staged)
}

/// Whether an HTTP caller sending `text` through `alpha:send` is refused.
fn http_relay_refused(firewall: &Firewall, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    let verdict = firewall.check_relay(
        RelayCaller::Keyed("http-caller"),
        "alpha",
        "send",
        &params,
        ("s", "http"),
    );
    !verdict.allowed
}

fn tenant_note(tenant: &str, note: &str) -> String {
    format!("{{\"customer_id\":\"{tenant}\",\"note\":\"{note}\"}}")
}

/// MIK-7800: over stdio a read the cross-tenant judge withholds records no
/// receipt for the operator. The operator reads tenant t1 (delivered), then
/// t2 (withheld under `block`); an HTTP caller sending t2's text is not
/// refused, while sending t1's text is (the control).
#[tokio::test]
async fn stdio_judged_out_read_records_no_receipt() {
    use crate::gateway::server::Gateway;
    let (meta, firewall, cell) = judged_stdio();
    let reads = meta.stdio_reads();
    let (first, second) = (tenant_note("t1", PROSE), tenant_note("t2", OTHER));
    for (text, expect_delivered) in [(&first, true), (&second, false)] {
        let (value, hidden, params, staged) = staged_read(&meta, &reads, &cell, text.clone()).await;
        let frame =
            Gateway::judge_and_commit(&reads, (value, params.as_ref(), hidden.as_ref()), staged)
                .await;
        assert_eq!(frame.delivers_result(), expect_delivered, "base: {text}");
        // The sink writes it: that is what commits the read history.
        frame.stdio_written();
    }
    assert!(
        http_relay_refused(&firewall, &first),
        "control: a delivered read records a receipt"
    );
    assert!(
        !http_relay_refused(&firewall, &second),
        "a read the judge withheld must record no receipt"
    );
}

/// The same in a JSON-RPC batch: each item's receipts follow its own frame.
#[tokio::test]
async fn stdio_judged_out_batch_item_records_no_receipt() {
    let (meta, firewall, cell) = judged_stdio();
    let reads = meta.stdio_reads();
    let (first, second) = (tenant_note("t1", PROSE), tenant_note("t2", OTHER));
    let mut answers = Vec::new();
    for text in [&first, &second] {
        answers.push(staged_read(&meta, &reads, &cell, text.clone()).await);
    }
    reads.batch(answers).await.stdio_written();
    assert!(
        http_relay_refused(&firewall, &first),
        "control: a delivered batch item records a receipt"
    );
    assert!(
        !http_relay_refused(&firewall, &second),
        "a batch item the judge withheld must record no receipt"
    );
}
