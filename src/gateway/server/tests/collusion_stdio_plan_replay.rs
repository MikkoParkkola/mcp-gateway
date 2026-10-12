// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 R3s/R4s over stdio: a keyed plan repeated is served from the
//! retained answer, and that second delivery renews the operator's receipt for
//! each step it delivered. The row lets the live receipt lapse on the frozen
//! clock (P1), proves the repeat dispatched nothing (P2), then asserts.
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

/// What `alpha:a` delivers.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

/// What `alpha:b` delivers.
const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale.";

const WINDOW_SECS: u64 = 1;

/// Backend `alpha`: `a` answers [`PROSE`], `b` answers [`OTHER_PROSE`]; every
/// `tools/call` is counted.
struct Alpha(Arc<AtomicUsize>);

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
        self.0.fetch_add(1, Ordering::SeqCst);
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

/// The stdio Meta-MCP over `alpha`, the relay firewall (every k-gram kept,
/// one fingerprint enough), the backend's call counter, and `playbook`
/// registered when given.
fn stdio_meta(playbook: Option<&str>) -> (Arc<MetaMcp>, Arc<Firewall>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Alpha(Arc::clone(&calls))));
    assert!(registry.register(backend));
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: vec!["alpha:*".to_string()],
                    window_secs: WINDOW_SECS,
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test()
        .keeping_every_kgram(),
    );
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    meta.share_keyring_with_for_test(&firewall);
    if let Some(playbook) = playbook {
        let definition: crate::playbook::PlaybookDefinition =
            serde_yaml::from_str(playbook).expect("playbook fixture must parse");
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
    }
    (Arc::new(meta), firewall, calls)
}

/// A keyed stdio `tools/call` of `name(arguments)`.
fn keyed_request(id: i64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments,
                      "_meta": {"io.mcp-gateway/idempotency-key": "stdio-replay"}}})
}

async fn dispatch(meta: &Arc<MetaMcp>, request: &Value) -> Value {
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    super::super::Gateway::dispatch_single(meta, &policy, &mtls, request, "stdio-replay")
        .await
        .expect("a request is answered")
}

/// The shared row: deliver, lapse (P1), repeat (P2: nothing dispatched), then
/// bob relaying step A's text must be refused again.
async fn keyed_plan_replay_renews(playbook: Option<&str>, name: &str, arguments: &Value) {
    let (meta, firewall, calls) = stdio_meta(playbook);
    let first = dispatch(&meta, &keyed_request(1, name, arguments.clone())).await;
    assert!(first.get("error").is_none(), "base: delivered: {first}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "premise: both steps dispatched"
    );
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "premise: the live receipt holds"
    );
    firewall.advance_collusion_clock_for_test(Duration::from_secs(WINDOW_SECS + 1));
    assert!(
        !relayed_by_bob(&firewall, PROSE),
        "premise P1: the live receipt lapsed"
    );
    let replay = dispatch(&meta, &keyed_request(2, name, arguments.clone())).await;
    assert!(replay.get("error").is_none(), "base: replayed: {replay}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "premise P2: the repeat was served from the retained answer"
    );
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the stdio replay renewed no receipt for step A"
    );
}

/// R3s (REPLAY.6).
#[tokio::test]
async fn a_keyed_chain_replay_renews_each_step_receipt_over_stdio() {
    let chain = json!({"chain": [{"tool": "alpha:a", "arguments": {}},
                                 {"tool": "alpha:b", "arguments": {}}]});
    keyed_plan_replay_renews(None, "gateway_execute", &chain).await;
}

/// R4s (REPLAY.6).
#[tokio::test]
async fn a_keyed_playbook_replay_renews_each_step_receipt_over_stdio() {
    let playbook = "name: replay\ndescription: plan steps\non_error: continue\ninputs: {}\nsteps:\n\
                    \x20 - name: s1\n    server: alpha\n    tool: a\n\
                    \x20 - name: s2\n    server: alpha\n    tool: b\n\
                    output:\n  type: object\n  properties:\n\
                    \x20   a:\n      path: $s1.content[0].text\n\
                    \x20   b:\n      path: $s2.content[0].text\n";
    keyed_plan_replay_renews(
        Some(playbook),
        "gateway_run_playbook",
        &json!({"name": "replay", "arguments": {}}),
    )
    .await;
}
