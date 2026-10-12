// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406: a keyed plan's retained result is served only when every account
//! the plan uses is proven live in the request (design d1, test plan t0). The
//! sync-replay rows (P1, P2, P3) are red on the release line; P5 is the
//! control. The fixture is MIK-8392 STORED.2's shape: the sole operator over
//! the managed-account backend, connected, then revoked.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};

const KEY: &str = "sole-operator-key";
const TOOL: &str = "read";
const MARKER: &str = "stored-plan-output-8406";
const PLAYBOOK: &str = "two_reads";

struct Fx {
    router: axum::Router,
    gateway: DirectAccountGateway,
    _store: tempfile::TempDir,
}

fn sole_operator() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(KEY.as_bytes())),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// A playbook of two reads on the managed-account backend.
fn two_reads() -> crate::playbook::PlaybookDefinition {
    serde_json::from_value(json!({
        "playbook": "1.0", "name": PLAYBOOK, "description": "two reads",
        "steps": [
            {"name": "a", "server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            {"name": "b", "server": BACKEND, "tool": TOOL, "arguments": {"folder": "sent"}}
        ]
    }))
    .expect("the playbook deserialises")
}

async fn fixture() -> Fx {
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut meta = gateway.take_meta();
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(two_reads());
    meta.set_playbook_engine(engine);
    state_mut.meta_mcp = Arc::new(meta);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
    Fx {
        router: super::create_router(state),
        gateway,
        _store: store,
    }
}

fn meta(key: &str) -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
    })
}

async fn send(fx: &Fx, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// The three plan shapes the rows replay.
enum Plan {
    Playbook,
    Chain,
    Single,
}

impl Plan {
    fn params(&self, key: &str) -> (&'static str, Value) {
        let read = |folder: &str| json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": folder}});
        match self {
            Self::Playbook => (
                "gateway_run_playbook",
                json!({"name": "gateway_run_playbook",
                       "arguments": {"name": PLAYBOOK, "arguments": {}}, "_meta": meta(key)}),
            ),
            Self::Chain => (
                "gateway_execute",
                json!({"name": "gateway_execute",
                       "arguments": {"chain": [read("inbox"), read("sent")]}, "_meta": meta(key)}),
            ),
            Self::Single => (
                "gateway_execute",
                json!({"name": "gateway_execute", "arguments": read("inbox"), "_meta": meta(key)}),
            ),
        }
    }

    fn steps(&self) -> usize {
        match self {
            Self::Single => 1,
            Self::Playbook | Self::Chain => 2,
        }
    }
}

/// Run `plan` once while connected, keyed `key`: every step answers
/// [`MARKER`], and the retained result carries it.
async fn run_once(fx: &Fx, plan: &Plan, key: &str) -> Value {
    for _ in 0..plan.steps() {
        fx.gateway
            .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    }
    let (name, params) = plan.params(key);
    let first = send(fx, name, params).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    first
}

/// After revocation the same keyed plan call is refused: no stored output and
/// nothing sent.
async fn refused_after_revoke(row: &str, plan: Plan) {
    let fx = fixture().await;
    run_once(&fx, &plan, row).await;
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let (name, params) = plan.params(row);
    let again = send(&fx, name, params).await;
    assert!(
        !again.to_string().contains(MARKER),
        "{row}: the stored plan output was served after revocation: {again}"
    );
    assert!(
        again.get("error").is_some(),
        "{row}: not a refusal: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "{row}: the replay reached the backend: {again}"
    );
}

/// P1 (HTTP, keyed gateway_run_playbook): revoked after the run, the replay
/// is refused. Red on the release line: the retained result is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p1_keyed_playbook_replay_after_revocation_is_refused() {
    refused_after_revoke("P1", Plan::Playbook).await;
}

/// P2: the same for a gateway_execute chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2_keyed_code_mode_chain_replay_after_revocation_is_refused() {
    refused_after_revoke("P2", Plan::Chain).await;
}

/// P3: the same for the single gateway_execute form.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_keyed_code_mode_single_replay_after_revocation_is_refused() {
    refused_after_revoke("P3", Plan::Single).await;
}

/// P5 CONTROL: not revoked, the replay is the retained result and sends
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p5_control_live_plan_replay_is_served_stored() {
    let fx = fixture().await;
    run_once(&fx, &Plan::Playbook, "P5").await;
    let sent = fx.gateway.tool_calls().len();
    let (name, params) = Plan::Playbook.params("P5");
    let again = send(&fx, name, params).await;
    assert!(
        again.to_string().contains(MARKER),
        "P5: not served stored: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "P5: the replay was sent: {again}"
    );
}
