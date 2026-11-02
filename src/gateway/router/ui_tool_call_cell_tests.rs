// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Try a tool from the web UI (U12), at the dispatch: what a web UI call in
//! scope changes there and what it must never change. The route's own rows
//! are in `ui_tool_call_tests`.

use std::sync::Arc;

use serde_json::{Value, json};

use super::ui_tool_call_tests::{ADMIN, Fx, SERVER, fixture, invoke, post_mcp, records, sent};

/// `key`'s principal as the auth layer derives it from the secret.
fn principal_of(key: &str) -> String {
    crate::hashing::sha256_hex(key.as_bytes())[..12].to_owned()
}

fn ui_call(
    tool: &str,
    principal: &str,
    confirm: crate::gateway::ui_call::Confirm,
) -> Arc<crate::gateway::ui_call::UiCall> {
    crate::gateway::ui_call::UiCall::new(SERVER, tool, principal, confirm)
}

/// T21: a UI call whose dispatch runs as another principal than the admin
/// the route checked is refused before the send.
/// Mutant: the principal comparison removed.
#[tokio::test]
async fn t21_a_principal_mismatch_is_refused_before_the_send() {
    let fx = fixture().await;
    let call = ui_call(
        "read",
        "someone-else",
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let body = post_mcp(&fx, ADMIN, invoke("read"), Some(Arc::clone(&call))).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(body.get("error").is_some(), "{body}");
    assert_eq!(sent(&fx), 0);
    assert!(!call.outcome().dispatched);
}

/// T22: a UI call confirmed for one tool cannot send another.
/// Mutant: the target comparison removed.
#[tokio::test]
async fn t22_a_call_for_another_target_is_refused() {
    let fx = fixture().await;
    let principal = principal_of(ADMIN);
    // Control: the matching target is sent.
    let ok = ui_call(
        "write",
        &principal,
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let _ = post_mcp(&fx, ADMIN, invoke("write"), Some(Arc::clone(&ok))).await;
    assert_eq!(sent(&fx), 1, "the premise: a matching call runs");
    let other = ui_call(
        "read",
        &principal,
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let body = post_mcp(&fx, ADMIN, invoke("write"), Some(Arc::clone(&other))).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(body.get("error").is_some(), "{body}");
    assert_eq!(sent(&fx), 1, "the foreign target was never sent");
}

/// A client that declares the tasks extension, so a task request is not
/// refused for want of it.
fn tasks() -> Value {
    json!({"extensions": {"io.modelcontextprotocol/tasks": {}}})
}

/// T18: a task-augmented call under a UI call is refused before any task
/// exists: its worker would run outside the UI call.
/// Mutant: the task refusal removed.
#[tokio::test]
async fn t18_a_ui_call_never_runs_as_a_task() {
    let fx = fixture().await;
    let call = ui_call(
        "read",
        &principal_of(ADMIN),
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let mut params = invoke("read");
    params["task"] = json!({});
    params["_meta"] = json!({
        "io.modelcontextprotocol/clientCapabilities": tasks(),
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): "t18"});
    let body = post_mcp(&fx, ADMIN, params, Some(call)).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(body.get("error").is_some(), "{body}");
    // No task was made, so no worker exists to send it later.
    assert!(body.pointer("/result/taskId").is_none(), "{body}");
    assert_eq!(sent(&fx), 0);
    assert_refused_delivery(&fx);
    // Control: the same request with no UI call in scope makes a task.
    let mut params = invoke("read");
    params["task"] = json!({});
    params["_meta"] = json!({
        "io.modelcontextprotocol/clientCapabilities": tasks(),
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): "t18-control"});
    let body = post_mcp(&fx, ADMIN, params, None).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(
        body.pointer("/result/taskId").is_some(),
        "the premise: this fixture makes tasks: {body}"
    );
}

/// A result carrying a credential the response firewall withholds.
#[cfg(feature = "firewall")]
const WITH_SECRET: &str = concat!("token=", "gh", "p_", "0123456789abcdefghij0123456789abcdef");

/// T13b: the /mcp answer for a firewall-withheld result is byte-identical
/// with and without a UI call in scope: the cell never reaches the wire.
/// Mutant: the gate refuses every call in scope (the target check inverted).
#[cfg(feature = "firewall")]
#[tokio::test]
async fn t13b_mcp_bytes_are_unchanged_by_a_ui_call_in_scope() {
    use super::direct_guards_fixture::{Answer, fixture_firewalled_with};
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;
    let fx = Box::pin(fixture_firewalled_with(
        Answer::Text(WITH_SECRET),
        None,
        false,
    ))
    .await;
    let send = |scope: Option<Arc<crate::gateway::ui_call::UiCall>>| {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", "Bearer k-std")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "gateway_invoke",
                    "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
                }})
                .to_string(),
            ))
            .expect("request");
        let router = fx.router.clone();
        async move {
            let response = match scope {
                Some(call) => call.scope(router.oneshot(request)).await,
                None => router.oneshot(request).await,
            }
            .expect("response");
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body")
        }
    };
    let plain = send(None).await;
    let call = crate::gateway::ui_call::UiCall::new(
        "alpha",
        "read",
        &principal_of("k-std"),
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let scoped = send(Some(Arc::clone(&call))).await;
    let body: Value = serde_json::from_slice(&plain).expect("json");
    assert_eq!(
        body["error"]["message"], "Response blocked by security firewall",
        "the premise: the answer is withheld: {body}"
    );
    assert_eq!(plain, scoped, "the same bytes with a UI call in scope");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 2, "both were sent");
    assert!(call.outcome().dispatched, "the scoped one was recorded");
}

/// Spawns on the path that are not the send: (file, line text, why).
const SPAWN_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "src/gateway/meta_mcp/grant_audit.rs",
        "handle.spawn(async move {",
        "spawn_write: a bounded write of grant records, after the call",
    ),
    (
        "src/gateway/meta_mcp/grant_audit.rs",
        "let flush = tokio::spawn(async move { write_records(&writer, &notes).await });",
        "the slot's record flush, after the call",
    ),
    (
        "src/gateway/meta_mcp/grant_audit.rs",
        "let writer = tokio::spawn(async move {",
        "the record writer for a refused call",
    ),
];

/// T20 (design C0b): a web UI call's cell is a task-local, which does not
/// cross a spawn. Nothing between the MCP handler and the send spawns, so
/// the cell reaches the gate and the send record; a spawn added there fails
/// this row, and whoever adds it must carry the cell across.
#[test]
fn t20_no_spawn_wraps_the_send() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let handlers = root.join("src/gateway/router/handlers");
    let mut dirs = vec![
        root.join("src/gateway/meta_mcp/call_dispatch"),
        root.join("src/gateway/meta_mcp/invoke"),
    ];
    for entry in std::fs::read_dir(&handlers).expect("handlers") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "meta_handler.rs" || name.starts_with("dispatch_") {
            // A dispatch arm's child modules (`dispatch_tools_call/`) are
            // scanned with it.
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.push(root.join("src/gateway/meta_mcp/call_dispatch.rs"));
    files.push(root.join("src/gateway/meta_mcp/grant_audit.rs"));
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("a scanned directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    let mut found = Vec::new();
    let mut used = vec![false; SPAWN_ALLOWED.len()];
    for path in files {
        let rel = path
            .strip_prefix(root)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        if rel.contains("_tests") || rel.contains("/tests/") || rel.ends_with("fixture.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("readable");
        for (n, line) in text.lines().enumerate() {
            let code = line.trim();
            if code.starts_with("//") {
                continue;
            }
            let spawns = ["tokio::spawn(", "spawn_blocking(", "JoinSet", ".spawn("]
                .iter()
                .any(|p| code.contains(p));
            if !spawns {
                continue;
            }
            match SPAWN_ALLOWED
                .iter()
                .position(|(f, l, _)| *f == rel && code == *l)
            {
                Some(i) => used[i] = true,
                None => found.push(format!("{rel}:{}: {code}", n + 1)),
            }
        }
    }
    assert!(found.is_empty(), "a spawn on the dispatch path: {found:#?}");
    let stale: Vec<_> = SPAWN_ALLOWED
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|(r, _)| r.1)
        .collect();
    assert!(
        stale.is_empty(),
        "allowlist rows that match nothing: {stale:?}"
    );
}

fn capability(read_only: bool) -> crate::capability::CapabilityDefinition {
    let yaml = format!(
        r"
name: probe
description: Test capability
metadata:
  read_only: {read_only}
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /probe
"
    );
    crate::capability::parse_capability(&yaml).expect("capability")
}

/// T24: the capability executor judges the definition it is about to run,
/// so a reload after the dispatch gate cannot run a write unconfirmed.
/// Mutant: the UI arm in the capability executor removed.
#[tokio::test]
async fn t24_a_capability_is_judged_by_the_definition_it_runs() {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};
    use crate::gateway::ui_call::{Confirm, UiCall};
    for (read_only, refused) in [(false, true), (true, false)] {
        let backend = CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()));
        backend
            .register_capability(capability(read_only))
            .expect("registered");
        let call = UiCall::new("caps", "probe", "p", Confirm::DeclaredReadOnlyOnly);
        // The REST provider is unreachable, so a call the gate lets through
        // fails later, for another reason.
        let _ = call.scope(backend.call_tool("probe", json!({}))).await;
        assert_eq!(
            call.outcome().confirm_refused,
            refused,
            "read_only: {read_only}"
        );
    }
}

/// T29 (code review): the send point refuses a UI call its gate did not
/// admit, and a send to another target; it admits the gated one.
/// Mutant: the send check always admits.
#[tokio::test]
async fn t29_the_send_point_admits_only_the_gated_call() {
    use crate::gateway::ui_call::{Confirm, UiCall, admit_send, gate};
    let call = UiCall::new(SERVER, "read", "p", Confirm::Confirmed);
    call.scope(async {
        assert!(admit_send((SERVER, "read")).is_err(), "not gated yet");
        gate((SERVER, "read"), Some("p"), false).expect("the gate admits it");
        assert!(admit_send((SERVER, "read")).is_ok(), "gated");
        assert!(admit_send((SERVER, "write")).is_err(), "another target");
    })
    .await;
}

/// T32 (code review): when the route's deadline claims a call before its
/// send does, nothing is ever sent and the route says so: 504, not run.
/// The backend's catalogue is cold and its list waits on a gate the test
/// releases only after the route answered, so the call cannot reach its send
/// before the deadline: the deadline wins every time.
/// Mutants: the deadline never claims the call (it answers "may have run");
/// the deadline aborts the claimed call (no delivery record).
#[tokio::test]
async fn t32_a_deadline_that_wins_the_race_sends_nothing() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    let fx = fixture().await;
    // Replace `alpha` with one whose cold catalogue lists only when released.
    let gate = Arc::new(tokio::sync::Notify::new());
    let backend = Arc::new(crate::backend::Backend::new(
        SERVER,
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(super::ui_tool_call_tests::Stub {
        calls: Arc::clone(&fx.calls),
        declares_read: true,
        list_gate: Some(Arc::clone(&gate)),
    }));
    assert!(fx.state.backends.register(backend), "registration");
    crate::gateway::ui::DEADLINE_FOR_TEST
        .with(|d| d.set(Some(std::time::Duration::from_millis(50))));
    let request = Request::builder()
        .method("POST")
        .uri("/ui/api/tools/call")
        .header("authorization", format!("Bearer {ADMIN}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"server": SERVER, "tool": "read", "arguments": {}, "confirm_write": true})
                .to_string(),
        ))
        .expect("request");
    let response = super::create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .expect("response");
    crate::gateway::ui::DEADLINE_FOR_TEST.with(|d| d.set(None));
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_eq!(sent(&fx), 0, "the claimed call was never sent");
    // Release the list: a call that escaped the claim would now be sent.
    gate.notify_waiters();
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(sent(&fx), 0, "nothing was sent after the release either");
    // The claimed call reaches its send claim, which refuses it: the call's
    // delivery record says refused, as every other refusal of a UI call does.
    for _ in 0..4096 {
        if records(&fx)
            .iter()
            .any(|r| r.get("response_effect").is_some())
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_refused_delivery(&fx);
}

/// The internal dispatch's delivery records (the only records carrying a
/// response effect) say the gateway refused the call, and there is one.
pub(super) fn assert_refused_delivery(fx: &Fx) {
    let records = records(fx);
    let effects: Vec<&Value> = records
        .iter()
        .filter_map(|r| r.get("response_effect"))
        .collect();
    assert!(
        !effects.is_empty() && effects.iter().all(|e| *e == "refused"),
        "{records:#?}"
    );
}
