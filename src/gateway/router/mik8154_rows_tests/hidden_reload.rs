// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend that becomes hidden from a caller partway through a task run
//! answers as one removed at that moment, and is sent nothing. The caller
//! holds an mTLS certificate; the rule is fixed at setup, so a backend turns
//! hidden by a catalogue change (every tool it lists is refused) and the twin
//! is a registry removal.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tower::ServiceExt;

use super::*;
use crate::gateway::router::AppState;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// The one tool the rule refuses everywhere.
const BLOCKED: &str = "blocked";

/// What happens to a backend mid-run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Change {
    None,
    Hide,
    Remove,
    /// Still visible, but no longer listing `read`.
    Drop,
}

fn tool(name: &str) -> crate::protocol::Tool {
    serde_json::from_value(json!({"name": name, "inputSchema": {"type": "object"}}))
        .expect("a tool")
}

/// Apply `change` to backend `name`.
fn apply(state: &AppState, name: &str, change: Change) {
    match change {
        Change::None => {}
        Change::Hide => state
            .backends
            .get(name)
            .expect("the backend")
            .store_shared_tools_for_test(vec![tool(BLOCKED)]),
        Change::Drop => state
            .backends
            .get(name)
            .expect("the backend")
            .store_shared_tools_for_test(vec![tool("other")]),
        Change::Remove => {
            state.backends.remove(name);
        }
    }
}

/// List `read` on each of `names`, so hiding is judged on a held catalogue.
fn warm(fx: &Fx, names: &[&str]) {
    for name in names {
        fx.state
            .backends
            .get(name)
            .expect("the backend")
            .store_shared_tools_for_test(vec![tool("read")]);
    }
}

/// Install the `agent` certificate's rule: everything allowed, `blocked` and
/// the backends in `deny` refused.
fn with_rule(mut fx: Fx, deny: &[&str]) -> Fx {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let owned = |names: &[&str]| names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>();
    // The router holds the state; drop it to install the policy.
    fx.router = axum::Router::new();
    Arc::get_mut(&mut fx.state)
        .expect("sole owner during setup")
        .mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![PolicyRuleConfig {
            match_criteria: CertMatchConfig {
                cn: Some("agent".to_string()),
                ..Default::default()
            },
            allow: ToolScopeConfig {
                backends: vec!["*".to_string()],
                tools: vec!["*".to_string()],
            },
            deny: ToolScopeConfig {
                backends: owned(deny),
                tools: vec![BLOCKED.to_string()],
            },
        }],
        ..Default::default()
    }));
    fx.router = super::super::create_router(Arc::clone(&fx.state));
    fx
}

/// A modern request as the `agent` certificate, with `k-std`'s key.
async fn send_cert(fx: &Fx, method: &str, name: &str, params: Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string(),
        ))
        .expect("request");
    let mut request = request;
    request.extensions_mut().insert(crate::mtls::CertIdentity {
        common_name: Some("agent".to_string()),
        display_name: "agent".to_string(),
        ..Default::default()
    });
    let response = fx.router.clone().oneshot(request).await.expect("answers");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

fn task_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "elicitation": {"form": {}},
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

/// Submit `tool` with `arguments` as a keyed task; returns its id.
async fn submit(fx: &Fx, tool: &str, arguments: Value, key: &str) -> String {
    let mut meta = task_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let params = json!({"name": tool, "arguments": arguments, "task": {}, "_meta": meta});
    let created = send_cert(fx, "tools/call", tool, params).await;
    created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the submit was refused: {created}"))
        .to_owned()
}

/// Poll `tasks/get` until the status is none of `passing`.
async fn settled(fx: &Fx, id: &str, passing: &[&str]) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let get = json!({"taskId": id, "_meta": task_meta()});
            let body = send_cert(fx, "tasks/get", id, get).await;
            let status = body.pointer("/result/status").and_then(Value::as_str);
            if !status.is_some_and(|status| passing.contains(&status)) {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task never settled")
}

/// The settled answer's bytes: status, error and result, with the task id and
/// trace ids masked.
fn answer(body: &Value, id: &str) -> String {
    let mut kept = serde_json::Map::new();
    for member in ["status", "statusMessage", "error", "result"] {
        if let Some(value) = body.pointer(&format!("/result/{member}")) {
            kept.insert(member.to_owned(), value.clone());
        }
    }
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    let text = Value::Object(kept).to_string().replace(id, "TASK");
    trace.replace_all(&text, "gw-ID").into_owned()
}

/// Backend whose every answer is ok, counting `tools/call`s, running a hook
/// after the call numbered `n` answers, and noting what the run judged at
/// each call.
struct Script {
    calls: Arc<AtomicUsize>,
    hooks: std::sync::Mutex<HashMap<usize, Box<dyn FnOnce() + Send>>>,
    judged: std::sync::Mutex<Vec<(Option<String>, bool)>>,
}

impl Script {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Arc::default(),
            hooks: std::sync::Mutex::default(),
            judged: std::sync::Mutex::default(),
        })
    }

    fn after_call(&self, n: usize, hook: impl FnOnce() + Send + 'static) {
        self.hooks.lock().expect("hooks").insert(n, Box::new(hook));
    }
}

#[async_trait::async_trait]
impl Transport for Script {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(
                id,
                json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
            ));
        }
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let memo = crate::gateway::meta_mcp::visible::memo::judged;
        self.judged.lock().expect("judged").push((
            crate::gateway::meta_mcp::visible::memo::judged_playbook(),
            memo().is_empty(),
        ));
        let hook = self.hooks.lock().expect("hooks").remove(&n);
        if let Some(hook) = hook {
            hook();
        }
        Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
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

/// The two-step playbook `pb` on `alpha`, run as a task; `change` lands on
/// `alpha` once step 1 has been answered. Returns the answer, the sends, and
/// the settled status.
async fn between_steps(change: Change, key: &str) -> (String, usize, Value) {
    let script = Script::new();
    let definition = playbook_definition(["alpha", "alpha"]);
    let fx = Box::pin(super::super::direct_guards_fixture::fixture_built_on(
        Arc::clone(&script) as Arc<dyn Transport>,
        move |meta| {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    ))
    .await;
    let fx = with_rule(fx, &[]);
    warm(&fx, &["alpha"]);
    let state = Arc::clone(&fx.state);
    script.after_call(0, move || apply(&state, "alpha", change));
    let args = json!({"name": "pb", "arguments": {"x": "v"}});
    let id = submit(&fx, "gateway_run_playbook", args, key).await;
    let body = settled(&fx, &id, &["working"]).await;
    let sent = script.calls.load(Ordering::SeqCst);
    (answer(&body, &id), sent, body)
}

/// Between two composite steps a backend that turns hidden answers the next
/// step as one removed, and step 2 sends nothing. With no change, step 2 runs.
#[tokio::test]
async fn a_backend_hidden_between_two_steps_answers_as_one_removed() {
    let (control, control_sent, control_body) =
        Box::pin(between_steps(Change::None, "hr1-c")).await;
    assert_eq!(
        control_sent, 2,
        "control: step 2 did not run: {control_body}"
    );
    assert_eq!(
        control_body.pointer("/result/status"),
        Some(&json!("completed")),
        "control: {control_body}"
    );
    let (hidden, hidden_sent, _) = Box::pin(between_steps(Change::Hide, "hr1-h")).await;
    let (removed, removed_sent, removed_body) =
        Box::pin(between_steps(Change::Remove, "hr1-r")).await;
    assert_eq!(removed_sent, 1, "premise: step 2 reached a removed backend");
    assert_ne!(
        removed, control,
        "premise: removal changed nothing: {removed_body}"
    );
    assert_eq!(hidden_sent, 1, "hidden: step 2 was sent");
    assert_eq!(hidden, removed, "hidden and removed answer alike");
}

/// A `gateway_invoke` task on `alpha` that parks on the backend's question;
/// `change` lands on `alpha` before the client answers. Returns the answer,
/// the sends, and the settled body.
async fn between_rounds(change: Change, key: &str) -> (String, usize, Value) {
    let fx = Box::pin(fixture_built(Answer::AskOnce, |meta| meta)).await;
    let fx = with_rule(fx, &[]);
    warm(&fx, &["alpha"]);
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let id = submit(&fx, "gateway_invoke", args, key).await;
    let parked = settled(&fx, &id, &["working"]).await;
    assert_eq!(
        parked.pointer("/result/status"),
        Some(&json!("input_required")),
        "premise: the task did not park: {parked}"
    );
    assert_eq!(calls(&fx), 1, "premise: the asking round");
    apply(&fx.state, "alpha", change);
    let update = json!({
        "taskId": id,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "work"}}},
        "_meta": task_meta(),
    });
    let _ = send_cert(&fx, "tasks/update", &id, update).await;
    let body = settled(&fx, &id, &["working", "input_required"]).await;
    (answer(&body, &id), calls(&fx), body)
}

/// Between two input rounds a backend that turns hidden answers the resumed
/// round as one removed, and the round sends nothing. With no change the
/// resumed round runs.
#[tokio::test]
async fn a_backend_hidden_between_two_rounds_answers_as_one_removed() {
    let (control, control_sent, control_body) =
        Box::pin(between_rounds(Change::None, "hr2-c")).await;
    assert_eq!(
        control_sent, 2,
        "control: round 2 did not run: {control_body}"
    );
    let (hidden, hidden_sent, _) = Box::pin(between_rounds(Change::Hide, "hr2-h")).await;
    let (removed, removed_sent, removed_body) =
        Box::pin(between_rounds(Change::Remove, "hr2-r")).await;
    assert_eq!(
        removed_sent, 1,
        "premise: round 2 reached a removed backend"
    );
    assert_ne!(
        removed, control,
        "premise: removal changed nothing: {removed_body}"
    );
    assert_eq!(hidden_sent, 1, "hidden: round 2 was sent");
    assert_eq!(hidden, removed, "hidden and removed answer alike");
}

/// A surfaced `read` (on `alpha`) submitted as a task while visible; `change`
/// lands before the worker runs. Returns the answer, the sends and the body.
#[cfg(feature = "firewall")]
async fn surfaced_run(change: Change, key: &str) -> (String, usize, Value) {
    let surfaced = vec![crate::config::SurfacedToolConfig {
        server: "alpha".to_string(),
        tool: "read".to_string(),
    }];
    let fx = Box::pin(fixture_built(Answer::Ok, move |meta| {
        meta.with_surfaced_tools(surfaced)
    }))
    .await;
    let fx = with_rule(fx, &[]);
    warm(&fx, &["alpha"]);
    let state = Arc::clone(&fx.state);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        apply(&state, "alpha", change);
    });
    let id = submit(&fx, "read", json!({}), key).await;
    let body = settled(&fx, &id, &["working"]).await;
    (answer(&body, &id), calls(&fx), body)
}

/// A surfaced-pin task whose backend turns hidden between submit and run
/// settles as one whose surfaced name is no longer listed, and sends nothing.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_surfaced_task_hidden_before_its_run_answers_as_a_missing_name() {
    let (control, control_sent, control_body) = Box::pin(surfaced_run(Change::None, "hr3-c")).await;
    assert_eq!(
        control_sent, 1,
        "control: the run did not send: {control_body}"
    );
    let (hidden, hidden_sent, _) = Box::pin(surfaced_run(Change::Hide, "hr3-h")).await;
    let (missing, missing_sent, missing_body) = Box::pin(surfaced_run(Change::Drop, "hr3-m")).await;
    assert_eq!(
        missing_sent, 0,
        "premise: a missing name was sent: {missing_body}"
    );
    assert_ne!(
        missing, control,
        "premise: the miss changed nothing: {missing_body}"
    );
    assert_eq!(hidden_sent, 0, "hidden: the run was sent");
    assert_eq!(hidden, missing, "hidden and missing answer alike");
}

/// Playbook `pb3`: a read on each of `alpha-pt`, `beta-pt`, `alpha-pt`,
/// carrying on past a failed step.
fn continuing_playbook() -> crate::playbook::PlaybookDefinition {
    let steps: Vec<Value> = ["alpha-pt", "beta-pt", "alpha-pt"]
        .iter()
        .enumerate()
        .map(|(n, server)| {
            json!({"name": format!("s{n}"), "tool": "read", "server": server,
                   "arguments": {"cmd": "$inputs.x"}})
        })
        .collect();
    serde_json::from_value(json!({
        "playbook": "1.0", "name": "pb", "description": "three reads",
        "on_error": "continue", "steps": steps
    }))
    .expect("the playbook deserialises")
}

/// The three-step playbook over passthrough backends, sanitizing on, so
/// intake judges an exemption. `change` lands on `beta-pt` after step 1.
/// Returns the answer, the sends, and what the run judged at each send.
async fn judged_run(change: Change, key: &str) -> (String, usize, Vec<(Option<String>, bool)>) {
    let script = Script::new();
    let definition = continuing_playbook();
    let fx = Box::pin(sanitizing(
        true,
        super::super::direct_guards_fixture::fixture_built_on(
            Arc::clone(&script) as Arc<dyn Transport>,
            move |meta| {
                let mut engine = crate::playbook::PlaybookEngine::new();
                engine.register(definition);
                meta.set_playbook_engine(engine);
                meta
            },
        ),
    ))
    .await;
    let beta = Arc::new(crate::backend::Backend::new(
        "beta-pt",
        crate::config::BackendConfig {
            passthrough: true,
            ..Default::default()
        },
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    beta.set_transport_for_test(Arc::clone(&script) as Arc<dyn Transport>);
    assert!(fx.state.backends.register(beta), "beta-pt registered");
    let fx = with_rule(fx, &[]);
    warm(&fx, &["alpha-pt", "beta-pt"]);
    let state = Arc::clone(&fx.state);
    script.after_call(0, move || apply(&state, "beta-pt", change));
    let args = json!({"name": "pb", "arguments": {"x": "v"}});
    let id = submit(&fx, "gateway_run_playbook", args, key).await;
    let body = settled(&fx, &id, &["working"]).await;
    let sent = script.calls.load(Ordering::SeqCst);
    let judged = script.judged.lock().expect("judged").clone();
    (answer(&body, &id), sent, judged)
}

/// A step hidden mid-run answers as a removed one, and the run-wide judgement
/// intake made is the same at the step after it as at the step before it.
#[tokio::test]
async fn hiding_a_step_leaves_the_runs_judged_record_unchanged() {
    let (control, control_sent, seen) = Box::pin(judged_run(Change::None, "hr4-c")).await;
    assert_eq!(control_sent, 3, "control: not every step ran");
    assert!(!seen[0].1, "premise: intake judged nothing: {seen:?}");
    assert_eq!(
        seen[0], seen[2],
        "control: the judged record moved: {seen:?}"
    );
    let (hidden, hidden_sent, hidden_seen) = Box::pin(judged_run(Change::Hide, "hr4-h")).await;
    let (removed, removed_sent, _) = Box::pin(judged_run(Change::Remove, "hr4-r")).await;
    assert_eq!(removed_sent, 2, "premise: the removed step was sent");
    assert_ne!(removed, control, "premise: removal changed nothing");
    assert_eq!(hidden_sent, 2, "hidden: the hidden step was sent");
    assert_eq!(hidden, removed, "hidden and removed answer alike");
    assert_eq!(
        hidden_seen.first(),
        hidden_seen.last(),
        "hiding moved the judged record: {hidden_seen:?}"
    );
}

/// `gateway_invoke` of `read` on `server` with a NUL argument, as the
/// `agent` certificate, sanitizing on and `deny` refused by its rule.
async fn invoke_nul(server: &str, deny: &[&str]) -> (String, bool) {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let fx = with_rule(fx, deny);
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": server, "tool": "read", "arguments": {"cmd": NUL}},
        "_meta": task_meta(),
    });
    let body = send_cert(&fx, "tools/call", "gateway_invoke", params).await;
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    let text = trace.replace_all(&body.to_string(), "gw-ID").into_owned();
    (text.replace(server, "SERVER"), forwarded_nul(&fx))
}

/// A passthrough backend hidden by the caller's rule is sanitized like an
/// unregistered name, so a NUL is refused alike; a visible one keeps its
/// exemption.
#[tokio::test]
async fn a_hidden_passthrough_backend_is_sanitized_as_an_unregistered_one() {
    let (visible, forwarded) = Box::pin(invoke_nul("alpha-pt", &["gamma"])).await;
    assert!(
        forwarded,
        "control: the NUL did not reach the visible backend: {visible}"
    );
    let (hidden, hidden_forwarded) = Box::pin(invoke_nul("alpha-pt", &["alpha-pt", "gamma"])).await;
    let (unregistered, _) = Box::pin(invoke_nul("gamma", &["alpha-pt", "gamma"])).await;
    assert!(
        !hidden_forwarded,
        "hidden: the NUL reached the backend: {hidden}"
    );
    assert_eq!(hidden, unregistered, "hidden and unregistered answer alike");
}

/// The two-step playbook `pb` (`alpha`, then `second`) run as a task, the
/// certificate's rule denying `alpha-pt` and `gamma` by name. Returns what
/// the caller is shown, refused at intake or settled after the run, with
/// `second` masked, and the sends.
async fn deferred_step(second: &str, key: &str) -> (String, usize) {
    let script = Script::new();
    let definition = playbook_definition(["alpha", second]);
    let fx = Box::pin(super::super::direct_guards_fixture::fixture_built_on(
        Arc::clone(&script) as Arc<dyn Transport>,
        move |meta| {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    ))
    .await;
    let fx = with_rule(fx, &["alpha-pt", "gamma"]);
    warm(&fx, &["alpha", "alpha-pt"]);
    let mut meta = task_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let params = json!({"name": "gateway_run_playbook", "task": {}, "_meta": meta,
                        "arguments": {"name": "pb", "arguments": {"x": "v"}}});
    let created = send_cert(&fx, "tools/call", "gateway_run_playbook", params).await;
    // Refused at intake, or run: either way the caller's whole answer.
    let shown = match created.pointer("/result/taskId").and_then(Value::as_str) {
        Some(id) => {
            let id = id.to_owned();
            answer(&settled(&fx, &id, &["working"]).await, &id)
        }
        None => created.to_string(),
    };
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    let shown = trace.replace_all(&shown, "gw-ID").replace(second, "SECOND");
    (shown, script.calls.load(Ordering::SeqCst))
}

/// A playbook task naming a backend the caller's rule hides by name answers
/// as one naming an unregistered name the same rule denies, wherever it is
/// refused, and the hidden step is sent nothing.
#[tokio::test]
async fn a_task_step_on_a_backend_hidden_by_name_answers_as_an_unregistered_one() {
    let (hidden, hidden_sent) = Box::pin(deferred_step("alpha-pt", "hr6-h")).await;
    let (unregistered, unregistered_sent) = Box::pin(deferred_step("gamma", "hr6-u")).await;
    assert!(hidden_sent <= 1, "hidden: step 2 was sent");
    assert_eq!(hidden_sent, unregistered_sent, "the two runs sent alike");
    assert_eq!(hidden, unregistered, "hidden and unregistered answer alike");
}

/// [`send_cert`] with `bearer`'s key.
async fn send_as(fx: &Fx, bearer: &str, method: &str, name: &str, params: Value) -> Value {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(crate::mtls::CertIdentity {
        common_name: Some("agent".to_string()),
        display_name: "agent".to_string(),
        ..Default::default()
    });
    let response = fx.router.clone().oneshot(request).await.expect("answers");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// A playbook task under `k-alpha-ghost` (it grants `alpha` and `ghost`) whose
/// second step names `second`: what the submit answers, and the sends.
async fn submit_playbook_under_alpha_ghost(second: &str, key: &str) -> (Value, usize) {
    let script = Script::new();
    let definition = playbook_definition(["alpha", second]);
    let fx = Box::pin(super::super::direct_guards_fixture::fixture_built_on(
        Arc::clone(&script) as Arc<dyn Transport>,
        move |meta| {
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    ))
    .await;
    warm(&fx, &["alpha", "alpha-pt"]);
    let mut meta = task_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let params = json!({"name": "gateway_run_playbook", "task": {}, "_meta": meta,
                        "arguments": {"name": "pb", "arguments": {"x": "v"}}});
    let created = send_as(
        &fx,
        "k-alpha-ghost",
        "tools/call",
        "gateway_run_playbook",
        params,
    )
    .await;
    (created, script.calls.load(Ordering::SeqCst))
}

/// A playbook step outside the key's grant is refused at intake, before any
/// task is made: every step's target meets the strict route authorize
/// (`dispatch_tools_call.rs`), so a run never reaches a backend its key did not
/// grant at submit. That is why the run's hiding judgment, built from the
/// submit-time key, never disagrees with the key re-checked at dispatch; a
/// relaxed intake would reopen that. Control: a step the key grants is
/// accepted.
#[tokio::test]
async fn a_playbook_step_outside_the_keys_grant_is_refused_at_intake() {
    let (refused, refused_sent) =
        Box::pin(submit_playbook_under_alpha_ghost("alpha-pt", "grant-out")).await;
    assert_eq!(
        (refused["error"]["code"].clone(), refused_sent),
        (json!(-32003), 0),
        "a step outside the key's grant was not refused at intake: {refused}"
    );
    assert!(
        refused.pointer("/result/taskId").is_none(),
        "a task was made: {refused}"
    );
    let (accepted, _) = Box::pin(submit_playbook_under_alpha_ghost("alpha", "grant-in")).await;
    assert!(
        accepted.pointer("/result/taskId").is_some(),
        "control: a step the key grants was refused: {accepted}"
    );
}
