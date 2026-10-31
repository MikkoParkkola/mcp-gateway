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
