// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A modern stdio client's first `tools/list` during warm-up waits,
//! bounded, for the surfaced backends' first fill, and is sent nothing unasked.
//! The backend holds its `tools/list` answer until the row releases it, so no
//! timing decides which side of the fill a list lands on.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::watch;

use super::stdio_list_changed::{Serve, boot};

pub(super) const ARRIVAL: Duration = Duration::from_secs(20);
/// How long a list that must not wait is given to answer while held.
pub(super) const AT_ONCE: Duration = Duration::from_secs(2);
pub(super) const TOOL: &str = "firstlist_echo";

/// An MCP backend whose `tools/list` waits until released.
pub(super) struct Held {
    pub(super) url: String,
    pub(super) lists: Arc<AtomicUsize>,
    pub(super) release: watch::Sender<bool>,
}

pub(super) async fn held_backend(tools: &[&str]) -> Held {
    let lists = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);
    let counted = Arc::clone(&lists);
    let listed: Vec<Value> = tools
        .iter()
        .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
        .collect();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let (counted, mut released, listed) =
                (Arc::clone(&counted), released.clone(), listed.clone());
            async move {
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "held", "version": "0"},
                    }),
                    Some("tools/list") => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        drop(released.wait_for(|open| *open).await);
                        json!({ "tools": listed })
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the held backend");
    let address = listener.local_addr().expect("held backend address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    Held {
        url: format!("http://{address}/"),
        lists,
        release,
    }
}

/// A stdio gateway with `backends` (YAML entries under `backends:`), the
/// surfaced `(server, tool)` pairs, and `extra` top-level YAML.
pub(super) async fn start(backends: &str, surfaced: &[(&str, &str)], extra: &str) -> Serve {
    let dir = crate::test_dir_keep::kept_tempdir();
    let tasks = dir.path().join("tasks");
    let surfaced = surfaced
        .iter()
        .map(|(server, tool)| format!("    - server: {server}\n      tool: {tool}\n"))
        .collect::<Vec<_>>()
        .concat();
    let yaml = format!(
        "backends:\n{backends}meta_mcp:\n  surfaced_tools:\n{surfaced}{extra}tasks:\n  store_dir: {}\n",
        serde_json::to_string(&tasks.display().to_string()).expect("a JSON string")
    );
    boot(dir, yaml, 64 * 1024).await
}

/// One `backends:` entry for `held`, with an optional request timeout.
pub(super) fn entry(name: &str, held: &Held, timeout: Option<&str>) -> String {
    let timeout = timeout.map_or_else(String::new, |t| format!("    timeout: {t}\n"));
    format!(
        "  {name}:\n    http_url: \"{}\"\n    streamable_http: true\n{timeout}",
        held.url
    )
}

/// Premise: the backend was asked for its tools `n` times (warm-up, held).
pub(super) async fn asked(held: &Held, n: usize) {
    let by = tokio::time::Instant::now() + ARRIVAL;
    while held.lists.load(Ordering::SeqCst) < n {
        assert!(
            tokio::time::Instant::now() < by,
            "premise: the backend was never asked for its tools"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A request declaring the 2026 era in full: the version alone reads as
/// malformed, and a malformed request is classed legacy.
pub(super) fn modern(id: u64, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }}})
}

pub(super) fn names(reply: &Value) -> Vec<String> {
    reply["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list failed: {reply}"))
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

pub(super) fn holds(reply: &Value, tool: &str) -> bool {
    names(reply).iter().any(|name| name == tool)
}

/// The answer to `id` within `limit`, pushing every other frame to `seen`.
pub(super) async fn answer_within(
    serve: &mut Serve,
    id: u64,
    limit: Duration,
    seen: &mut Vec<Value>,
) -> Option<Value> {
    let until = tokio::time::Instant::now() + limit;
    while let Some(frame) = serve
        .next(until.saturating_duration_since(tokio::time::Instant::now()))
        .await
    {
        if frame["id"] == json!(id) {
            return Some(frame);
        }
        seen.push(frame);
    }
    None
}

/// Nothing the client did not ask for: no frame without an id.
pub(super) fn assert_unasked_none(seen: &[Value]) {
    let unasked: Vec<_> = seen.iter().filter(|f| f.get("id").is_none()).collect();
    assert!(unasked.is_empty(), "sent unasked: {unasked:?}");
}

/// A modern stdio client connected to a gateway whose one surfaced backend is
/// held in warm-up: discovery done, the backend asked once.
pub(super) async fn modern_during_warm_up(timeout: Option<&str>) -> (Serve, Held) {
    let held = held_backend(&[TOOL]).await;
    let mut serve = start(&entry("held", &held, timeout), &[("held", TOOL)], "").await;
    asked(&held, 1).await;
    serve.send(&modern(1, "server/discover")).await;
    serve.reply(1, &mut Vec::new()).await;
    (serve, held)
}
