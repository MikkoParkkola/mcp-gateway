// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's `allowed_tools`, at the backend itself: the one predicate the
//! dispatch and every catalogue filter share. Calls by tasks, chains, the
//! provider and the notification path all reach the upstream through
//! [`Backend::request`], so the dispatch rows here are their rows too.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, RetryConfig, TransportConfig};

/// `tools/call` attempts the stub saw, by tool name.
type Calls = Arc<Mutex<HashMap<String, usize>>>;

/// How the stub answers the first `tools/call` of `read_a`.
#[derive(Clone)]
enum First {
    Answer,
    /// Signal `arrived`, wait for `go`, then fail with 503: the call is
    /// admitted and in its retry backoff from the test's point of view.
    HoldThenFail(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>),
}

/// A legacy Streamable stub listing `read_a` (declared read-only, so the
/// gateway may resend it), `write_b`, and `new_c` once `later` is set.
async fn stub(calls: Calls, first: First, later: Arc<std::sync::atomic::AtomicBool>) -> String {
    let app = axum::Router::new().fallback(move |body: axum::body::Bytes| {
        let (calls, first, later) = (Arc::clone(&calls), first.clone(), Arc::clone(&later));
        async move {
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let Some(id) = request.get("id").cloned() else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let result = match request["method"].as_str() {
                Some("initialize") => json!({"protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}}, "serverInfo": {"name": "sel", "version": "0"}}),
                Some("tools/list") => {
                    let mut tools = vec![
                        json!({"name": "read_a", "inputSchema": {"type": "object"},
                               "annotations": {"readOnlyHint": true}}),
                        json!({"name": "write_b", "inputSchema": {"type": "object"}}),
                    ];
                    if later.load(std::sync::atomic::Ordering::SeqCst) {
                        tools.push(json!({"name": "new_c", "inputSchema": {"type": "object"}}));
                    }
                    json!({"tools": tools})
                }
                Some("tools/call") => {
                    let name = request["params"]["name"].as_str().unwrap_or("").to_string();
                    let seen = {
                        let mut calls = calls.lock().unwrap();
                        let n = calls.entry(name.clone()).or_default();
                        *n += 1;
                        *n
                    };
                    if let (First::HoldThenFail(arrived, go), "read_a", 1) =
                        (&first, name.as_str(), seen)
                    {
                        arrived.notify_one();
                        go.notified().await;
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    json!({"content": [{"type": "text", "text": name}]})
                }
                _ => json!({}),
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/mcp")
}

fn backend(url: &str, allowed: Option<&[&str]>) -> Arc<Backend> {
    let config = BackendConfig {
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        allowed_tools: allowed.map(|names| names.iter().map(ToString::to_string).collect()),
        ..BackendConfig::default()
    };
    let failsafe = FailsafeConfig {
        retry: RetryConfig {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
            ..RetryConfig::default()
        },
        ..FailsafeConfig::default()
    };
    Arc::new(Backend::new(
        "sel",
        config,
        &failsafe,
        Duration::from_secs(30),
    ))
}

fn call(tool: &str) -> Value {
    json!({"name": tool, "arguments": {}})
}

fn count(calls: &Calls, tool: &str) -> usize {
    calls.lock().unwrap().get(tool).copied().unwrap_or(0)
}

/// The dispatch refuses a tool outside the list, and the upstream never sees
/// the call, whatever catalogue the slot holds.
#[tokio::test]
async fn an_unselected_tool_is_refused_at_dispatch_with_no_upstream_call() {
    let calls = Calls::default();
    let url = stub(Arc::clone(&calls), First::Answer, Arc::default()).await;
    let backend = backend(&url, Some(&["read_a"]));
    backend.get_tools_shared().await.expect("listed");
    let refused = backend.request("tools/call", Some(call("write_b"))).await;
    assert!(refused.is_err(), "write_b dispatched: {refused:?}");
    assert_eq!(count(&calls, "write_b"), 0, "the upstream saw write_b");
    backend
        .request("tools/call", Some(call("read_a")))
        .await
        .expect("read_a is selected");
    assert_eq!(count(&calls, "read_a"), 1);
}

/// The served catalogue leaves out every tool the list does not match,
/// including one the server adds later; `is_blocked_tool` agrees.
#[tokio::test]
async fn the_served_catalogue_leaves_out_unselected_and_later_tools() {
    let calls = Calls::default();
    let later = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let url = stub(Arc::clone(&calls), First::Answer, Arc::clone(&later)).await;
    let backend = backend(&url, Some(&["read_a"]));
    let names =
        |tools: &[crate::protocol::Tool]| tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
    assert_eq!(
        names(&backend.get_tools_shared().await.unwrap()),
        ["read_a"]
    );
    later.store(true, std::sync::atomic::Ordering::SeqCst);
    backend.invalidate_tools();
    assert_eq!(
        names(&backend.get_tools_shared().await.unwrap()),
        ["read_a"]
    );
    for tool in ["write_b", "new_c"] {
        assert!(backend.is_blocked_tool(tool), "{tool} served");
        assert!(backend.blocked_tool_refusal(None, tool).is_some(), "{tool}");
    }
    assert!(!backend.is_blocked_tool("read_a"));
    assert!(
        backend
            .request("tools/call", Some(call("new_c")))
            .await
            .is_err()
    );
    assert_eq!(count(&calls, "new_c"), 0, "the upstream saw new_c");
}

/// A trailing `prefix*` and a `server:tool` name match as an API key's list
/// does, through the same matcher.
#[tokio::test]
async fn patterns_match_as_an_api_key_list_does() {
    let url = stub(Calls::default(), First::Answer, Arc::default()).await;
    assert!(!backend(&url, Some(&["read_*"])).is_blocked_tool("read_a"));
    assert!(backend(&url, Some(&["read_*"])).is_blocked_tool("write_b"));
    assert!(!backend(&url, Some(&["sel:write_b"])).is_blocked_tool("write_b"));
    assert!(
        !backend(&url, None).is_blocked_tool("write_b"),
        "absent: every tool"
    );
}

/// Admission-time semantics (stated, and tracked for every scope in one
/// follow-up): a call admitted before a narrowing reload finishes its own
/// attempts on the instance that admitted it. The reload swaps a narrowed
/// instance into the registry while the call is in its retry backoff; the
/// retry still reaches the upstream, and a fresh call to the new instance is
/// refused.
#[tokio::test]
async fn an_admitted_call_keeps_its_retries_after_a_narrowing_reload() {
    let calls = Calls::default();
    let (arrived, go) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let first = First::HoldThenFail(Arc::clone(&arrived), Arc::clone(&go));
    let url = stub(Arc::clone(&calls), first, Arc::default()).await;
    let registry = BackendRegistry::new();
    let admitted = backend(&url, Some(&["read_a", "write_b"]));
    assert!(registry.register(Arc::clone(&admitted)));
    admitted.get_tools_shared().await.expect("listed");
    let in_flight = tokio::spawn({
        let admitted = Arc::clone(&admitted);
        async move { admitted.request("tools/call", Some(call("read_a"))).await }
    });
    arrived.notified().await;
    assert!(registry.remove("sel"));
    let narrowed = backend(&url, Some(&["write_b"]));
    assert!(registry.register(Arc::clone(&narrowed)));
    go.notify_one();
    in_flight
        .await
        .expect("joined")
        .expect("the admitted call's retry is answered");
    assert_eq!(count(&calls, "read_a"), 2, "first attempt plus one retry");
    assert!(
        narrowed
            .request("tools/call", Some(call("read_a")))
            .await
            .is_err()
    );
    assert_eq!(
        count(&calls, "read_a"),
        2,
        "the narrowed instance sent nothing"
    );
}

/// The provider adapter asks the same gate before it dispatches.
#[tokio::test]
async fn the_provider_refuses_an_unselected_tool_with_no_upstream_call() {
    use crate::provider::Provider;
    let calls = Calls::default();
    let url = stub(Arc::clone(&calls), First::Answer, Arc::default()).await;
    let backend = backend(&url, Some(&["read_a"]));
    backend.get_tools_shared().await.expect("listed");
    let provider = crate::provider::McpProvider::new(backend);
    let refused = provider.invoke("write_b", json!({})).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.to_string().contains("allowed_tools")),
        "{refused:?}"
    );
    assert_eq!(count(&calls, "write_b"), 0, "the upstream saw write_b");
}

/// A `tools/call` sent as a notification meets the same refusal.
#[tokio::test]
async fn a_notified_call_to_an_unselected_tool_is_refused() {
    let calls = Calls::default();
    let url = stub(Arc::clone(&calls), First::Answer, Arc::default()).await;
    let backend = backend(&url, Some(&["read_a"]));
    backend.get_tools_shared().await.expect("listed");
    let refused = backend.notify("tools/call", Some(call("write_b"))).await;
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(count(&calls, "write_b"), 0, "the upstream saw write_b");
}

/// The loader refuses an empty list and a pattern that matches nothing; a
/// lone `*` (every tool) and an exact name load, as on an API key.
#[test]
fn the_loader_refuses_an_unusable_list() {
    let config = |list: &[&str]| {
        let mut config = crate::config::Config::default();
        config.backends.insert(
            "sel".to_string(),
            BackendConfig {
                transport: TransportConfig::Http {
                    http_url: "http://127.0.0.1:9/mcp".to_string(),
                    streamable_http: Some(true),
                    protocol_version: None,
                },
                allowed_tools: Some(list.iter().map(ToString::to_string).collect()),
                ..BackendConfig::default()
            },
        );
        config.validate().map_err(|e| e.to_string())
    };
    for bad in [&[][..], &["re*ad"][..], &["*_write"][..]] {
        let refused = config(bad).expect_err("refused");
        assert!(refused.contains("backends.sel.allowed_tools"), "{refused}");
    }
    for good in [&["*"][..], &["read_a", "sel:write_*"][..]] {
        config(good).unwrap_or_else(|e| panic!("{good:?}: {e}"));
    }
}

/// A blocked tool's decision record names the check that blocked it: the
/// backend's `allowed_tools` list or the descriptor check, never one for the
/// other, though both refuse through the same gate.
#[cfg(feature = "firewall")]
#[test]
fn a_blocked_tool_records_the_check_that_blocked_it() {
    use crate::security::decision_record::DecisionKind;
    let backend = backend("http://127.0.0.1:9/mcp", Some(&["kept*"]));
    backend.block_descriptor_for_test("kept_poisoned");
    assert!(backend.blocked_tool_refusal(None, "dropped").is_some());
    assert_eq!(
        backend.blocked_tool_kind("dropped"),
        DecisionKind::AllowedTools
    );
    assert!(
        backend
            .blocked_tool_refusal(None, "kept_poisoned")
            .is_some()
    );
    assert_eq!(
        backend.blocked_tool_kind("kept_poisoned"),
        DecisionKind::DescriptorBlock
    );
}
