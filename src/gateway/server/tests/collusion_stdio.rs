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
        // The catalogue: one resource and one prompt, both answering `read`'s text.
        let text = self.read.lock().clone();
        match method {
            "resources/list" => {
                let listed = json!({"resources": [{"uri": "res://orchard", "name": "orchard"}]});
                return Ok(JsonRpcResponse::success(id, listed));
            }
            "prompts/list" => {
                return Ok(JsonRpcResponse::success(
                    id,
                    json!({"prompts": [{"name": "orchard"}]}),
                ));
            }
            "resources/read" => {
                let doc = json!({"contents": [{"uri": "res://orchard", "text": text}]});
                return Ok(JsonRpcResponse::success(id, doc));
            }
            "prompts/get" => {
                let message = json!({"role": "user", "content": {"type": "text", "text": text}});
                return Ok(JsonRpcResponse::success(id, json!({"messages": [message]})));
            }
            _ => {}
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
fn judged_stdio(
    audit: Option<Arc<crate::security::TransparencyLogger>>,
) -> (Arc<MetaMcp>, Arc<Firewall>, Arc<parking_lot::Mutex<String>>) {
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
                sources: vec!["alpha:*".to_string()],
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
    if let Some(log) = audit {
        meta.enable_transparency_log(log);
    }
    (Arc::new(meta), firewall, read)
}

/// The stdio session the operator reads in.
const SESSION: &str = "stdio-7800";

/// One operator `read` of `text`, dispatched as the serve loop does: the
/// answer, what it read, its request's params and the receipts it staged.
async fn staged_read(
    meta: &Arc<MetaMcp>,
    reads: &crate::gateway::outbound::StdioReads,
    cell: &parking_lot::Mutex<String>,
    text: String,
) -> (
    crate::gateway::server::stdio_delivery::StdioAnswer,
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
        session_id: SESSION,
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
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let (first, second) = (tenant_note("t1", PROSE), tenant_note("t2", OTHER));
    for (text, expect_delivered) in [(&first, true), (&second, false)] {
        let (value, hidden, params, staged) = staged_read(&meta, &reads, &cell, text.clone()).await;
        let frame = Gateway::judge_and_commit(
            &meta,
            &reads,
            SESSION,
            (value, params.as_ref(), hidden.as_ref()),
            staged,
        )
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

/// A batch of one operator `read` of `text`, dispatched and judged by the
/// serve loop's batch path; whether its answer carries a result.
async fn batch_read_delivers(
    meta: &Arc<MetaMcp>,
    reads: &crate::gateway::outbound::StdioReads,
    cell: &parking_lot::Mutex<String>,
    text: &str,
) -> bool {
    use crate::gateway::server::{Gateway, StdioTelemetry};
    *cell.lock() = text.to_string();
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let rpc = |id: u64, tool: &str, arguments: Value| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
               "params": {"name": "gateway_invoke",
                          "arguments": {"server": "alpha", "tool": tool, "arguments": arguments}}})
    };
    let batch = json!([rpc(1, "read", json!({}))]);
    let frames = Gateway::dispatch_batch_read(
        meta,
        &policy,
        &mtls,
        batch,
        "stdio-7800",
        &StdioTelemetry::default(),
        reads,
    )
    .await;
    let delivered = frames
        .iter()
        .all(crate::gateway::outbound::OutboundFrame::delivers_result);
    crate::gateway::outbound::StdioReads::batch_of(frames).stdio_written();
    delivered
}

/// The same in a JSON-RPC batch: each item's receipts follow its own frame.
#[tokio::test]
async fn stdio_judged_out_batch_item_records_no_receipt() {
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let (first, second) = (tenant_note("t1", PROSE), tenant_note("t2", OTHER));
    assert!(batch_read_delivers(&meta, &reads, &cell, &first).await);
    assert!(!batch_read_delivers(&meta, &reads, &cell, &second).await);
    assert!(
        http_relay_refused(&firewall, &first),
        "control: a delivered batch item records a receipt"
    );
    assert!(
        !http_relay_refused(&firewall, &second),
        "a batch item the judge withheld must record no receipt"
    );
}

/// A later batch item sees what an earlier one delivered: the operator reads
/// text an HTTP caller also holds, then sends it, in one batch. Its own copy
/// excuses it; deferring the receipt past the later item would refuse it.
#[tokio::test]
async fn a_batch_item_sees_the_receipt_of_an_earlier_item() {
    use crate::gateway::server::{Gateway, StdioTelemetry};
    let (meta, firewall, cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    *cell.lock() = PROSE.to_string();
    firewall.record_delivery(
        RelayCaller::Keyed("http-caller"),
        "alpha",
        "read",
        &text_result(PROSE),
    );
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let rpc = |id: u64, tool: &str, arguments: Value| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
               "params": {"name": "gateway_invoke",
                          "arguments": {"server": "alpha", "tool": tool, "arguments": arguments}}})
    };
    let batch = json!([
        rpc(1, "read", json!({})),
        rpc(2, "send", json!({"text": PROSE}))
    ]);
    let frames = Gateway::dispatch_batch_read(
        &meta,
        &policy,
        &mtls,
        batch,
        "stdio-7800",
        &StdioTelemetry::default(),
        &reads,
    )
    .await;
    let answers: Vec<Value> = frames
        .iter()
        .filter_map(|f| f.stdio_value().map(std::borrow::Cow::into_owned))
        .collect();
    assert_eq!(answers.len(), 2, "{answers:?}");
    assert!(
        answers[0].get("error").is_none(),
        "base: the earlier read is delivered: {}",
        answers[0]
    );
    assert!(
        answers[1].get("error").is_none(),
        "the operator's own earlier copy must excuse the send: {}",
        answers[1]
    );
}

/// A fail-closed log whose next delivery record fails.
fn failing_audit() -> (Arc<crate::security::TransparencyLogger>, tempfile::TempDir) {
    use crate::security::audit::AuditFailurePolicy;
    use crate::security::transparency_log::TransparencyLogConfig;
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "rv".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    // The read verdict rides the delivery record (MIK-7799, MIK-7920): that
    // is the record whose failure must withhold the answer.
    log.fail_next_append_of_kind_for_test("response_delivery_attempt");
    (log, dir)
}

/// An allowed result replaced by a fail-closed audit refusal leaves no
/// receipt; the next, audited read does (the control).
#[tokio::test]
async fn stdio_audit_withheld_read_records_no_receipt() {
    use crate::gateway::server::Gateway;
    let (log, _dir) = failing_audit();
    let (meta, firewall, cell) = judged_stdio(Some(log));
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    let (value, hidden, params, staged) = staged_read(&meta, &reads, &cell, note.clone()).await;
    let frame = Gateway::judge_and_commit(
        &meta,
        &reads,
        SESSION,
        (value, params.as_ref(), hidden.as_ref()),
        staged,
    )
    .await;
    assert!(
        !frame.delivers_result(),
        "base: the failed delivery record replaces the answer"
    );
    assert!(
        !http_relay_refused(&firewall, &note),
        "an audit-withheld read must record no receipt"
    );
    let (value, hidden, params, staged) = staged_read(&meta, &reads, &cell, note.clone()).await;
    let frame = Gateway::judge_and_commit(
        &meta,
        &reads,
        SESSION,
        (value, params.as_ref(), hidden.as_ref()),
        staged,
    )
    .await;
    assert!(
        frame.delivers_result(),
        "control: the audited read is delivered"
    );
    assert!(
        http_relay_refused(&firewall, &note),
        "control: it records a receipt"
    );
}

/// The same through the batch path.
#[tokio::test]
async fn stdio_audit_withheld_batch_item_records_no_receipt() {
    let (log, _dir) = failing_audit();
    let (meta, firewall, cell) = judged_stdio(Some(log));
    let reads = meta.stdio_reads();
    let note = tenant_note("t1", PROSE);
    assert!(!batch_read_delivers(&meta, &reads, &cell, &note).await);
    assert!(!http_relay_refused(&firewall, &note), "no receipt");
    assert!(batch_read_delivers(&meta, &reads, &cell, &note).await);
    assert!(http_relay_refused(&firewall, &note), "control: a receipt");
}

/// Text only the operator's catalogue read delivers.
const THIRD: &str = "The lighthouse log for the outer skerry notes the oil used per night, the \
    lamp glass cleaned after each storm, the supply boat's missed visits in the autumn gales, and \
    a list of the gulls that nest on the gallery rail. It ends with a remark about the stuck door.";

/// MIK-7765: over stdio the catalogue is relay-checked, and the operator is
/// the one principal `tools/call` keys. An HTTP caller's `resources/read`
/// text, sent as `prompts/get` arguments, is refused; the operator's own
/// `resources/read` copy excuses it and refuses an HTTP caller's relay.
#[tokio::test]
async fn stdio_catalogue_is_inside_relay_detection() {
    let (meta, firewall, cell) = judged_stdio(None);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let rpc = |method: &str, params: Value| {
        let request = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
        let (meta, policy, mtls) = (Arc::clone(&meta), Arc::clone(&policy), Arc::clone(&mtls));
        async move {
            super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-7765")
                .await
                .expect("a request is answered")
        }
    };
    *cell.lock() = PROSE.to_string();

    // An HTTP caller was delivered OTHER through `resources/read`.
    let delivered = json!({"contents": [{"uri": "res://orchard", "text": OTHER}]});
    firewall.record_delivery(
        RelayCaller::Keyed("http-caller"),
        "alpha",
        "resources/read",
        &delivered,
    );
    let relay = rpc(
        "prompts/get",
        json!({"name": "alpha/orchard", "arguments": {"topic": OTHER}}),
    )
    .await;
    assert_eq!(relay["error"]["code"], -32002, "relay not refused: {relay}");
    let clean = rpc(
        "prompts/get",
        json!({"name": "alpha/orchard", "arguments": {"topic": "harbour"}}),
    )
    .await;
    assert!(clean.get("error").is_none(), "control: {clean}");

    // One operator across methods: a `tools/call` copy of PROSE excuses the
    // operator's `prompts/get` arguments carrying it (keyed as tools/call is).
    let tool_read = rpc(
        "tools/call",
        json!({"name": "gateway_invoke",
               "arguments": {"server": "alpha", "tool": "read", "arguments": {}}}),
    )
    .await;
    assert!(tool_read.get("error").is_none(), "base: {tool_read}");
    let own = rpc(
        "prompts/get",
        json!({"name": "alpha/orchard", "arguments": {"topic": PROSE}}),
    )
    .await;
    assert!(
        own.get("error").is_none(),
        "the operator's own copy excuses it: {own}"
    );

    // The operator's own `resources/read` of THIRD is a delivery to the operator.
    *cell.lock() = THIRD.to_string();
    let read = rpc("resources/read", json!({"uri": "res://orchard"})).await;
    assert!(read.get("error").is_none(), "base: {read}");
    let params = json!({"name": "send", "arguments": {"text": THIRD}});
    let sent = firewall.check_relay(
        RelayCaller::Keyed("http-caller"),
        "alpha",
        "send",
        &params,
        ("s", "http"),
    );
    assert!(
        !sent.allowed,
        "the operator's catalogue read records a receipt"
    );
}

/// A refusal the gateway builds before dispatch (here, a request with no
/// method) is judged and sent as the gateway wrote it: the client's id, the
/// gateway's code and words, and no result, so it delivers nothing a receipt
/// could describe.
#[tokio::test]
async fn stdio_gateway_built_refusal_is_sent_as_written() {
    use crate::gateway::server::stdio_delivery::StdioAnswer;
    use crate::gateway::server::{Gateway, StdioClient, StdioTelemetry};
    let (meta, _firewall, _cell) = judged_stdio(None);
    let reads = meta.stdio_reads();
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let client = StdioClient {
        session_id: SESSION,
        channel: &crate::gateway::input_bridge::NoClientChannel,
        handshake_capabilities: crate::protocol::meta::Declared::NONE,
        tasks: None,
        modern: false,
    };
    let ((answer, staged), hidden) = crate::gateway::outbound::read_scoped(
        reads.guard(),
        Box::pin(Gateway::dispatch_single_staged(
            &meta,
            &policy,
            &mtls,
            json!({"jsonrpc": "2.0", "id": 7}),
            client,
            &StdioTelemetry::default(),
        )),
    )
    .await;
    let answer = answer.expect("a request with an id is answered");
    assert!(
        matches!(answer, StdioAnswer::Built(_)),
        "a parse refusal is built before anything runs"
    );
    let frame = Gateway::judge_and_commit(
        &meta,
        &reads,
        SESSION,
        (answer, None, hidden.as_ref()),
        staged,
    )
    .await;
    assert!(!frame.delivers_result(), "a refusal delivers no result");
    assert!(
        frame.assessment().is_some(),
        "the built answer must pass through the judge, not around it"
    );
    assert_eq!(frame.answer_id(), Some(RequestId::Number(7)));
    let document = frame
        .answer_document()
        .expect("the frame answers the request")
        .expect("the answer serializes");
    assert_eq!(document.pointer("/error/code"), Some(&json!(-32600)));
    assert_eq!(
        document.pointer("/error/message"),
        Some(&json!("Missing method"))
    );
    assert!(document.get("result").is_none(), "{document}");
}
