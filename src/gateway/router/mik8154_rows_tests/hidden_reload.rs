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
