// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's secret-injection rules apply on the direct route
//! `/mcp/{name}` as they do through `gateway_invoke`: an `argument` rule's
//! secret reaches the backend in the tool call's arguments and a `header`
//! rule's as that header. The secret is in what is sent and nowhere the
//! gateway answers or keeps.

use serde_json::json;

use super::direct_continuation_tests::call;
use super::direct_guards_fixture::{
    fixture_with_secrets, initialize, post_meta_invoke, send_with_headers, store_path,
};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};

/// The secret the rule injects: a literal, so no environment is read.
const SECRET: &str = "direct-route-secret-4c1e";

/// One `argument` rule injecting [`SECRET`] as `api_key`.
fn argument_rule() -> CredentialRule {
    CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: SECRET.to_string(),
        inject_as: InjectTarget::Argument,
        inject_key: "api_key".to_string(),
        tools: vec!["*".to_string()],
    }
}

/// The direct route applies an `argument` rule, on a gated and a passthrough
/// backend.
#[tokio::test]
async fn the_direct_route_applies_an_argument_rule() {
    for backend in ["alpha", "alpha-pt"] {
        let fx = fixture_with_secrets(vec![argument_rule()], None).await;
        let (_, body) = call(&fx, backend, None, json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: premise: {body}");
        let seen = fx.seen.lock().expect("recorder").clone();
        assert!(
            seen.iter()
                .any(|params| params.pointer("/arguments/api_key") == Some(&json!(SECRET))),
            "{backend}: the argument rule's secret never reached the backend: {seen:?}"
        );
    }
}

/// What one `tools/call` reached the backend with: its params and headers.
type Sends = std::sync::Arc<std::sync::Mutex<Vec<(serde_json::Value, Vec<(String, String)>)>>>;

/// Both fixture backends: list `read`, answer every call, record each
/// `tools/call` with its headers.
struct Recorder(Sends);

#[async_trait::async_trait]
impl crate::transport::Transport for Recorder {
    async fn request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Denied,
        )
        .await
    }
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "read", "inputSchema": {"type": "object"}});
            return Ok(crate::protocol::JsonRpcResponse::success(
                id,
                json!({"tools": [tool]}),
            ));
        }
        if method == "tools/call" {
            self.0.lock().expect("recorder").push((
                params.unwrap_or(serde_json::Value::Null),
                extra_headers.to_vec(),
            ));
        }
        Ok(crate::protocol::JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A `header` rule's secret reaches the backend as that header on the direct
/// route, on a gated and a passthrough backend.
#[tokio::test]
async fn the_direct_route_applies_a_header_rule() {
    for backend in ["alpha", "alpha-pt"] {
        let sends = Sends::default();
        let rule = CredentialRule {
            inject_as: InjectTarget::Header,
            inject_key: "X-Api-Key".to_string(),
            ..argument_rule()
        };
        let transport = std::sync::Arc::new(Recorder(std::sync::Arc::clone(&sends)));
        let fx = fixture_with_secrets(vec![rule], Some(transport)).await;
        let (_, body) = call(&fx, backend, None, json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: premise: {body}");
        let sends = sends.lock().expect("recorder").clone();
        assert!(
            sends.iter().any(|(_, headers)| headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("X-Api-Key") && value == SECRET)),
            "{backend}: no X-Api-Key header carried the secret: {sends:?}"
        );
    }
}

/// Every file under `dir`, with its bytes.
fn files_under(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            files.push((path, bytes));
        }
    }
    files
}

/// The secret goes into what is sent and into nothing the gateway answers or
/// keeps: not the answer, not a repeat the idempotency cache serves, not a
/// task's answer, and not the task store on disk.
#[tokio::test]
async fn the_secret_is_sent_and_nothing_answered_or_kept_holds_it() {
    let fx = fixture_with_secrets(vec![argument_rule()], None).await;
    let session = initialize(&fx, "k-std").await;
    let mut answers = Vec::new();
    for _ in 0..2 {
        let (_, body) = post_meta_invoke(
            &fx,
            "k-std",
            "alpha",
            "read",
            json!({}),
            Some("idem-secret-1"),
            Some(&session),
        )
        .await;
        assert!(body.get("error").is_none(), "premise: {body}");
        answers.push(body);
    }
    // A task is a modern call that declares the tasks extension.
    let modern = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":
            {"extensions": {"io.modelcontextprotocol/tasks": {}}},
    });
    let mut meta = modern.clone();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("idem-secret-task");
    let task = json!({"name": "gateway_invoke", "task": {}, "_meta": meta,
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}}});
    let call_headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    let (_, made) = send_with_headers(
        &fx,
        "/mcp",
        "k-std",
        "tools/call",
        task,
        None,
        &call_headers,
    )
    .await;
    let id = made
        .pointer("/result/task/taskId")
        .or_else(|| made.pointer("/result/taskId"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let finished = loop {
        let result_headers = [
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tasks/get"),
            ("mcp-name", id.as_str()),
        ];
        let (_, got) = send_with_headers(
            &fx,
            "/mcp",
            "k-std",
            "tasks/get",
            json!({"taskId": id, "_meta": modern.clone()}),
            None,
            &result_headers,
        )
        .await;
        if got.pointer("/result/status") == Some(&json!("completed")) {
            break got;
        }
        assert!(
            std::time::Instant::now() < bound,
            "the task never finished: {got}"
        );
        tokio::task::yield_now().await;
    };
    answers.push(made);
    answers.push(finished);
    let seen = fx.seen.lock().expect("recorder").clone();
    assert!(
        seen.iter()
            .any(|params| params.pointer("/arguments/api_key") == Some(&json!(SECRET))),
        "premise: the secret was sent: {seen:?}"
    );
    for answer in &answers {
        assert!(
            !answer.to_string().contains(SECRET),
            "an answer holds the secret: {answer}"
        );
    }
    let kept: Vec<_> = files_under(store_path(&fx))
        .into_iter()
        .filter(|(_, bytes)| {
            bytes
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        })
        .map(|(path, _)| path)
        .collect();
    assert!(kept.is_empty(), "a stored file holds the secret: {kept:?}");
}
