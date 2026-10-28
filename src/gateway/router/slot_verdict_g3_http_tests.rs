// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), group 3, router rows that compile on the
//! parent of the caller-verdict commits: C6c and F4 (controls), P5 (red).
//! Every test name starts with `g3_`.

use crate::security::transparency_log::temp::TempLog;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::r2_identity_keys_tests::transparency_logger;
use super::tests::direct_route_state_with_identity;
use crate::config::InputSchemaEnforcement;
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    Asked, BACKEND, CallerSlot, CountingMint, Surfaced, TOOL, Warmth, invalid,
    per_user_backend_with, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// One per-user (or, with `configure`, shared) backend behind the router, with
/// what its upstreams and the mint saw, and the firewall's audit file.
pub(super) struct Gateway {
    pub(super) router: axum::Router,
    pub(super) caller: Arc<Asked>,
    pub(super) shared: Arc<Asked>,
    pub(super) mints: Arc<AtomicUsize>,
    #[cfg(feature = "firewall")]
    firewall_audit: std::path::PathBuf,
    _store: crate::gateway::router::tests::FixtureDir,
    _files: [TempLog; 3],
}

impl Gateway {
    pub(super) fn dispatched(&self) -> usize {
        self.caller.calls() + self.shared.calls()
    }

    pub(super) fn mints(&self) -> usize {
        self.mints.load(Ordering::SeqCst)
    }

    /// Every backend request either upstream has seen, `tools/list` included.
    #[cfg(feature = "firewall")]
    pub(super) fn requests(&self) -> usize {
        self.dispatched() + self.caller.lists() + self.shared.lists()
    }

    /// The `policy_targets` of each response row the firewall audited.
    #[cfg(feature = "firewall")]
    fn response_targets_audited(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.firewall_audit)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|row| row["event"] == "response")
            .map(|row| row["policy_targets"].clone())
            .collect()
    }
}

/// The router over a backend whose two slots hold `slot` (alpha's) and
/// `shared_schema`; `configure` edits the backend's config before it is built.
/// A firewall scans responses and audits them to a file.
pub(super) async fn gateway(
    slot: CallerSlot,
    shared_schema: &Value,
    warmth: Warmth,
    surfaced: Surfaced,
    configure: impl FnOnce(&mut crate::config::BackendConfig),
) -> Gateway {
    gateway_armed(slot, shared_schema, warmth, surfaced, configure, |_| {}).await
}

/// [`gateway`] with `arm` applied to the Meta-MCP before it is mounted.
pub(super) async fn gateway_armed(
    slot: CallerSlot,
    shared_schema: &Value,
    warmth: Warmth,
    surfaced: Surfaced,
    configure: impl FnOnce(&mut crate::config::BackendConfig),
    arm: impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp),
) -> Gateway {
    let (backend, caller, shared) =
        per_user_backend_with(slot, shared_schema, warmth, CLOSED, configure);
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let files = [TempLog::new(), TempLog::new(), TempLog::new()];
    let mints = Arc::new(AtomicUsize::new(0));
    let mut meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&state_mut.backends))
        .with_surfaced_tools(surfaced.configs());
    meta.set_identity_propagation(Arc::new(CountingMint(Arc::clone(&mints))));
    meta.enable_transparency_log(transparency_logger(&files[0]));
    meta.set_multi_user(true);
    #[cfg(feature = "firewall")]
    let firewall_audit = files[2].path().to_path_buf();
    #[cfg(feature = "firewall")]
    {
        let firewall = Arc::new(
            crate::security::firewall::Firewall::from_config(
                crate::security::firewall::FirewallConfig {
                    enabled: true,
                    scan_responses: true,
                    scan_requests: true,
                    audit_log: Some(firewall_audit.clone()),
                    ..crate::security::firewall::FirewallConfig::default()
                },
                None,
            )
            .with_continuations(meta.continuation()),
        );
        meta.set_firewall(Some(Arc::clone(&firewall)));
        state_mut.firewall = Some(firewall);
    }
    arm(&mut meta);
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(transparency_logger(&files[1]));
    Gateway {
        router: create_router(state),
        caller,
        shared,
        mints,
        #[cfg(feature = "firewall")]
        firewall_audit,
        _store: store,
        _files: files,
    }
}

/// POST `body` to `uri` as alpha (auth is off in this state, so the verified
/// identity rides in as a request extension).
pub(super) async fn post_as_alpha(
    router: &axum::Router,
    uri: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(), // the fixture identity's issuer
    });
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub(super) fn tools_call(name: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}})
}

fn shared_catalogue(config: &mut crate::config::BackendConfig) {
    config.identity_propagation = None;
}

/// F4 (control): a shared-catalogue backend (no identity propagation) whose
/// shared slot holds an invalid schema yields no route target, and the call
/// answers as a name no catalogue has, exactly as #3807 does. Green on the
/// parent and on the fix.
#[tokio::test]
async fn g3_f4_shared_backend_route_filter_unchanged() {
    let control = gateway(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        Surfaced::Yes,
        shared_catalogue,
    )
    .await;
    let ok = post_as_alpha(
        &control.router,
        "/mcp",
        &tools_call(TOOL, &json!({"q": "x"})),
    )
    .await;
    assert_eq!(
        control.shared.calls(),
        1,
        "premise: a valid shared schema must dispatch on the shared upstream: {ok:?}"
    );

    let withheld = gateway(
        CallerSlot::Valid,
        &invalid(),
        Warmth::Cold,
        Surfaced::Yes,
        shared_catalogue,
    )
    .await;
    let answer = post_as_alpha(
        &withheld.router,
        "/mcp",
        &tools_call(TOOL, &json!({"q": "x"})),
    )
    .await;
    let absent_gw = gateway(
        CallerSlot::Valid,
        &invalid(),
        Warmth::Cold,
        Surfaced::No,
        shared_catalogue,
    )
    .await;
    let absent = post_as_alpha(
        &absent_gw.router,
        "/mcp",
        &tools_call(TOOL, &json!({"q": "x"})),
    )
    .await;
    assert_eq!(
        absent.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: an unsurfaced name answers -32601: {absent:?}"
    );
    assert_eq!(withheld.dispatched(), 0, "F4: dispatched; {answer:?}");
    assert_eq!(answer, absent, "F4: {answer:?} vs unsurfaced {absent:?}");
}

/// P5: the -32601 answer for a name the caller's catalogue withholds leaves
/// through the same delivery path as the answer for a name no catalogue has:
/// the firewall's response row names the same policy targets for both, and
/// never the withheld backend and tool (an audit row would otherwise confirm
/// the name exists). Red on the parent, where nothing answers -32601 for a
/// caller-withheld slot and the call dispatches.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn g3_p5_withheld_answer_touches_no_response_targets() {
    let unknown = gateway(
        CallerSlot::Lacks,
        &valid(),
        Warmth::Warm,
        Surfaced::No,
        |_| {},
    )
    .await;
    let absent = post_as_alpha(
        &unknown.router,
        "/mcp",
        &tools_call(TOOL, &json!({"q": "x"})),
    )
    .await;
    let absent_rows = unknown.response_targets_audited();
    assert!(
        !absent_rows.is_empty(),
        "premise: the firewall audited no response row for the absent answer: {absent:?}"
    );

    let gw = gateway(
        CallerSlot::Invalid,
        &valid(),
        Warmth::Warm,
        Surfaced::Yes,
        |_| {},
    )
    .await;
    let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL, &json!({"q": "x"}))).await;
    assert_eq!(
        answer.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "P5: a caller-withheld name must answer -32601: {answer:?}"
    );
    assert_eq!(gw.dispatched(), 0, "P5: dispatched; {answer:?}");
    let rows = gw.response_targets_audited();
    assert!(
        !rows.iter().any(|row| row.to_string().contains(BACKEND)),
        "P5: a response row names the withheld backend: {rows:?}"
    );
    assert_eq!(
        rows, absent_rows,
        "P5: response rows differ from the absent twin's"
    );
}

#[cfg(feature = "firewall")]
fn refused(answer: &(StatusCode, Value)) -> bool {
    !answer.0.is_success() || answer.1.get("error").is_some()
}

/// `body` with every occurrence of `tool` replaced by a placeholder, and how
/// many there were: the twin bodies are compared byte for byte with only the
/// tool name factored out (MIK-8361, lead ruling on F5(a)).
fn normalised(body: &str, tool: &str) -> (String, usize) {
    (body.replace(tool, "<tool>"), body.matches(tool).count())
}

/// F5(a) (MIK-8361 lead ruling 2026-10-12, per-user class; guard, kills
/// M18): a step route authorize refuses (`run_command`, on the default deny
/// list) resolves no credential and sends nothing of its own. `[note,
/// run_command]` is measured against `[note]` alone: the same mints and sends,
/// so `run_command`'s share is zero. The caller sees the status and body the
/// twin `[note, nosuch]` gets (tool name factored out). Labelled residual
/// (design A4): on this per-user backend the twin's caller-slot fill mints and
/// lists where the withheld name does neither, which the caller cannot see.
#[tokio::test]
async fn g3_f5a_route_authorize_refusal_resolves_nothing() {
    async fn chain(second: Option<&str>) -> ((StatusCode, Value), usize, usize) {
        let gw = gateway(
            CallerSlot::Valid,
            &valid(),
            Warmth::Cold,
            Surfaced::No,
            |_| {},
        )
        .await;
        let mut steps = vec![json!({"tool": format!("{BACKEND}:note"), "arguments": {"q": "x"}})];
        if let Some(second) = second {
            steps.push(json!({"tool": format!("{BACKEND}:{second}"), "arguments": {}}));
        }
        let body = json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
        "params": {"name": "gateway_execute", "arguments": {"chain": steps}}});
        let answer = post_as_alpha(&gw.router, "/mcp", &body).await;
        (answer, gw.mints(), gw.dispatched())
    }
    let (hidden, mints, sent) = chain(Some("run_command")).await;
    let (missing, _, _) = chain(Some("nosuch")).await;
    let (alone, alone_mints, alone_sent) = chain(None).await;
    assert!(
        alone_mints >= 1 && alone_sent >= 1,
        "premise: the visible step alone mints and sends: {alone:?}"
    );
    let (hidden_body, named) = normalised(&hidden.1.to_string(), "run_command");
    let (missing_body, twin_named) = normalised(&missing.1.to_string(), "nosuch");
    assert_eq!(
        named, twin_named,
        "premise: each answer names its own step as often: {hidden:?} / {missing:?}"
    );
    assert_eq!(
        (hidden.0, hidden_body),
        (missing.0, missing_body),
        "F5(a): the hidden step's answer differs from a missing step's"
    );
    assert_eq!(
        (mints, sent),
        (alone_mints, alone_sent),
        "F5(a): run_command minted or sent beyond the visible step: {hidden:?}"
    );
}

/// F5(b): a request the request firewall refuses (a path-traversal argument)
/// resolves nothing and fills nothing, for a per-user target with a cold
/// caller slot. A verdict taken ahead of the firewall would fill and mint.
/// Guard: kills M17.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn g3_f5b_firewall_refusal_resolves_nothing() {
    let gw = gateway(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        Surfaced::Yes,
        |_| {},
    )
    .await;
    let (mints, requests) = (gw.mints(), gw.requests());
    let args = json!({"q": "../../../etc/passwd"});
    let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL, &args)).await;
    assert!(
        refused(&answer),
        "premise: the firewall let it through: {answer:?}"
    );
    assert_eq!(
        gw.mints(),
        mints,
        "F5(b): a credential was resolved: {answer:?}"
    );
    assert_eq!(
        gw.requests(),
        requests,
        "F5(b): the backend was asked: {answer:?}"
    );
}

/// C6c (control): a shared-catalogue backend (`edits`) whose complete list
/// lacks the tool still answers with the design's text A through
/// `gateway_invoke`. Green on the parent and on the fix.
#[tokio::test]
async fn g3_c6c_shared_backend_lacked_keeps_text_a() {
    use super::f13_fetch_on_miss_tests::{ListMode, cold};
    let fx = cold(CLOSED, ListMode::Serve).await;
    let args = json!({"server": "edits", "tool": "nosuch", "arguments": {}});
    let (_, body) = post_as_alpha(&fx.router, "/mcp", &tools_call("gateway_invoke", &args)).await;
    let text = body.to_string();
    assert!(
        text.contains("the backend does not list a tool named `nosuch`"),
        "C6c: a shared backend's lacked tool no longer answers text A: {body}"
    );
    assert!(!text.contains("-32601"), "C6c: answered as absent: {body}");
}

/// F5(b), step variant (guard, kills M17): a playbook step whose declared
/// arguments the request firewall refuses at the route (`ScanTarget::Step`,
/// MIK-8362) resolves nothing and fills nothing, for a per-user target with a
/// cold caller slot. A verdict taken ahead of the firewall would fill and mint.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn g5_f5b_step_firewall_refusal_resolves_nothing() {
    let definition = serde_json::from_value(json!({
        "playbook": "1.0", "name": "steps", "description": "steps",
        "steps": [{"name": "s0", "tool": TOOL, "server": BACKEND,
            "arguments": {"q": "../../../etc/passwd"}}]
    }))
    .expect("the playbook deserialises");
    let gw = gateway_armed(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        Surfaced::Yes,
        |_| {},
        |meta| {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
        },
    )
    .await;
    let (mints, requests) = (gw.mints(), gw.requests());
    let call = tools_call("gateway_run_playbook", &json!({"name": "steps"}));
    let answer = post_as_alpha(&gw.router, "/mcp", &call).await;
    assert!(
        refused(&answer),
        "premise: the firewall let the step through: {answer:?}"
    );
    assert_eq!(
        gw.mints(),
        mints,
        "F5(b)-step: a credential was resolved: {answer:?}"
    );
    assert_eq!(
        gw.requests(),
        requests,
        "F5(b)-step: the backend was asked: {answer:?}"
    );
}
