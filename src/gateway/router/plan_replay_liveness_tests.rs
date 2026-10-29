// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406: a keyed plan's retained result is served only when every account
//! the plan uses is proven live in the request (design d1, test plan t0). The
//! vault rows P1, P2 and P3 are red at 1577d7ff6: STORED.1 does not refuse a
//! revoked vault plan replay, the stored output is served. The sole
//! operator's live twin is the unmarked resolution error (-32603), never an
//! offer (no bridged caller). P5 and P8 are controls. The fixture is MIK-8392 STORED.2's shape: the sole operator over
//! the managed-account backend, connected, then revoked.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway, PERSONAL_BACKEND, Second,
};

const KEY: &str = "sole-operator-key";
const TOOL: &str = "read";
const MARKER: &str = "stored-plan-output-8406";
const PLAYBOOK: &str = "two_reads";

struct Fx {
    router: axum::Router,
    /// The gateway the router serves, for its plan-execution count.
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    gateway: DirectAccountGateway,
    _store: crate::gateway::router::tests::FixtureDir,
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
            ..Default::default()
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// A playbook named `name` of reads, one per `(server, condition)`.
fn reads(name: &str, steps: &[(&str, Option<&str>)]) -> crate::playbook::PlaybookDefinition {
    let named: Vec<(String, &str, Option<&str>)> = steps
        .iter()
        .enumerate()
        .map(|(n, (server, condition))| (format!("s{n}"), *server, *condition))
        .collect();
    playbook_of(name, "abort", &named)
}

/// A playbook named `name` of reads, one per `(step name, server,
/// condition)`, handling a failed step by `on_error`.
fn playbook_of(
    name: &str,
    on_error: &str,
    steps: &[(String, &str, Option<&str>)],
) -> crate::playbook::PlaybookDefinition {
    let steps: Vec<Value> = steps
        .iter()
        .map(|(step, server, condition)| {
            let mut step = json!({"name": step, "server": server, "tool": TOOL,
                                  "arguments": {"folder": "inbox"}});
            if let Some(condition) = condition {
                step["condition"] = json!(condition);
            }
            step
        })
        .collect();
    serde_json::from_value(json!({"playbook": "1.0", "name": name,
        "description": "reads", "steps": steps, "on_error": on_error}))
    .expect("the playbook deserialises")
}

/// Every playbook the rows run: two reads on the managed account, and a
/// managed read with a conditional read on the second account (P8).
fn playbooks() -> Vec<crate::playbook::PlaybookDefinition> {
    vec![
        // N1: one step that is itself a plan (a `gateway_execute` of a read).
        serde_json::from_value(json!({"playbook": "1.0", "name": "nested",
            "description": "a plan in a step", "on_error": "abort",
            "steps": [{"name": "inner", "server": "gateway", "tool": "gateway_execute",
                       "arguments": {"tool": format!("{BACKEND}:{TOOL}"),
                                     "arguments": {"folder": "inbox"}}}]}))
        .expect("the playbook deserialises"),
        reads(PLAYBOOK, &[(BACKEND, None), (BACKEND, None)]),
        reads(
            "conditional",
            &[
                (BACKEND, None),
                (PERSONAL_BACKEND, Some("$inputs.deep == 'true'")),
            ],
        ),
    ]
}

async fn fixture() -> Fx {
    fixture_with(None).await
}

/// The fixture, with `second` registered beside the managed backend.
async fn fixture_with(second: Option<Second>) -> Fx {
    let auth = sole_operator();
    let mut gateway = match second {
        None => DirectAccountGateway::new(auth.clone(), &Binding::Connected),
        Some(second) => {
            DirectAccountGateway::with_second(auth.clone(), &Binding::Connected, second)
        }
    };
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let meta = gateway.take_meta();
    let mut engine = crate::playbook::PlaybookEngine::new();
    for definition in playbooks() {
        engine.register(definition);
    }
    meta.set_playbook_engine(engine);
    let meta = Arc::new(meta);
    state_mut.meta_mcp = Arc::clone(&meta);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    for name in [BACKEND, PERSONAL_BACKEND] {
        if let Some(backend) = gateway.backends().get(name) {
            backend.store_shared_tools_for_test(vec![tool.clone()]);
        }
    }
    Fx {
        router: super::create_router(state),
        meta,
        gateway,
        _store: store,
    }
}

/// Plan executions the fixture's gateway has started (MIK-8406 t0).
fn plan_entries(fx: &Fx) -> usize {
    crate::gateway::meta_mcp::plan_entries::count(&fx.meta)
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
    serde_json::from_slice(&bytes).expect("a JSON-RPC body")
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
    let entered = plan_entries(&fx);
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
    // mProceed is killed only by this entries assert: a fall-through to the
    // live run refuses the same way and sends nothing. Keep it.
    assert_eq!(
        plan_entries(&fx),
        entered,
        "{row}: the replay entered the plan executor: {again}"
    );
    // The live twin, sent last so the counts above are the replay's own: the
    // single form under a fresh key. A chain or playbook answers as its first
    // unproven step (CR-1), which is this answer.
    let (name, params) = Plan::Single.params(&format!("{row}-live"));
    let mut live = send(&fx, name, params).await;
    // Measured (M1): the sole operator's live twin is the unmarked
    // resolution error, never an offer (no bridged caller).
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32603)),
        "premise: the live twin is the resolution error: {live}"
    );
    let mut again = again;
    again["id"] = Value::Null;
    live["id"] = Value::Null;
    assert_eq!(
        again, live,
        "{row}: the replay is not the live twin's answer"
    );
}

/// P1 (HTTP, keyed `gateway_run_playbook`): revoked after the run, the replay
/// is refused. Red on the release line: the retained result is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p1_keyed_playbook_replay_after_revocation_is_refused() {
    refused_after_revoke("P1", Plan::Playbook).await;
}

/// P2: the same for a `gateway_execute` chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2_keyed_code_mode_chain_replay_after_revocation_is_refused() {
    refused_after_revoke("P2", Plan::Chain).await;
}

/// P3: the same for the single `gateway_execute` form.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_keyed_code_mode_single_replay_after_revocation_is_refused() {
    refused_after_revoke("P3", Plan::Single).await;
}

/// P5 CONTROL: not revoked, the replay is the retained result and sends
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p5_control_live_plan_replay_is_served_stored() {
    let fx = fixture().await;
    let before = plan_entries(&fx);
    run_once(&fx, &Plan::Playbook, "P5").await;
    assert_eq!(
        plan_entries(&fx),
        before + 1,
        "premise: the first run entered the executor once"
    );
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
    assert_eq!(
        plan_entries(&fx),
        before + 1,
        "P5: the replay entered the plan executor"
    );
}

/// A keyed `gateway_run_playbook` of `playbook` with `inputs`.
fn playbook_params(playbook: &str, key: &str, inputs: &Value) -> Value {
    json!({"name": "gateway_run_playbook",
           "arguments": {"name": playbook, "arguments": inputs}, "_meta": meta(key)})
}

/// Run `playbook` once on the two-account fixture, every dispatched step
/// answering [`MARKER`]; `steps` is how many dispatch.
async fn run_two_account(fx: &Fx, playbook: &str, key: &str, steps: usize) {
    for _ in 0..steps {
        fx.gateway
            .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    }
    let first = send(
        fx,
        "gateway_run_playbook",
        playbook_params(playbook, key, &json!({})),
    )
    .await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
}

/// P8 CONTROL (d1 reopen 2026-10-12): the conditional step never ran, and its
/// account is revoked afterwards. Only executed steps are judged, as on the
/// task paths (STORED.1 T23, P9c), so the replay is served stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8_control_unrun_conditional_step_revoked_does_not_block() {
    let fx = fixture_with(Some(Second::PersonalAccount)).await;
    run_two_account(&fx, "conditional", "P8", 1).await;
    assert_eq!(
        fx.gateway.tool_calls_to(PERSONAL_BACKEND),
        0,
        "premise: the branch was not taken"
    );
    let sent = fx.gateway.tool_calls_to(BACKEND);
    let entered = plan_entries(&fx);
    fx.gateway.revoke_operator_grant_on(PERSONAL_BACKEND).await;
    let again = send(
        &fx,
        "gateway_run_playbook",
        playbook_params("conditional", "P8", &json!({})),
    )
    .await;
    assert!(
        again.to_string().contains(MARKER),
        "P8: not served stored: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls_to(BACKEND),
        sent,
        "P8: the replay was sent: {again}"
    );
    assert_eq!(
        plan_entries(&fx),
        entered,
        "P8: the replay entered the plan executor: {again}"
    );
}

/// N1 (GUARD, d4 §12.4): a plan step that names a meta plan tool is not a
/// plan. Neither a chain step `gateway:gateway_execute` nor a playbook step
/// on server `gateway` runs an inner plan: `gateway` is no backend, so the
/// step fails "Backend not found" and nothing is sent. No plan nests inside
/// a step by that route; a backend fanning out through the meta layer stays
/// untraced (the changelog's MIK-8409 sentence).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n1_a_step_naming_a_meta_plan_runs_no_inner_plan() {
    let fx = fixture().await;
    let entered = plan_entries(&fx);
    let inner = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}});
    let chain = json!({"name": "gateway_execute",
        "arguments": {"chain": [{"tool": "gateway:gateway_execute", "arguments": inner}]},
        "_meta": meta("n1-chain")});
    let chained = send(&fx, "gateway_execute", chain).await;
    assert!(
        chained.to_string().contains("Backend not found: gateway"),
        "N1: the chain's meta-plan step was not refused as a missing backend: {chained}"
    );
    let playbook = send(
        &fx,
        "gateway_run_playbook",
        playbook_params("nested", "n1-pb", &json!({})),
    )
    .await;
    assert!(
        playbook.to_string().contains("Backend not found: gateway"),
        "N1: the playbook's meta-plan step was not refused as a missing backend: {playbook}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), 0, "N1: an inner plan sent");
    assert_eq!(
        plan_entries(&fx) - entered,
        2,
        "N1: only the two outer plans entered the executor"
    );
}
