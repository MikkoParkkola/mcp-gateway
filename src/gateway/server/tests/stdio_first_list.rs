// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9309 FIRST.1: a modern stdio client whose first `tools/list` lands
//! while the startup warm-up is still fetching a surfaced backend's tools
//! must either get the filled list or be told it changed once the fill
//! lands. The backend holds its `tools/list` answer until the row releases
//! it, so warm-up is in flight when the client lists: no timing decides it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::watch;

use super::stdio_list_changed::{Serve, boot};

const ARRIVAL: Duration = Duration::from_secs(20);
/// How long the first answer is waited for while the backend is held. A
/// list served from the cold cache answers at once; one that waits for the
/// fill cannot answer before the release.
const HELD: Duration = Duration::from_secs(2);
const TOOL: &str = "firstlist_echo";
const MODERN: &str = "2026-07-28";

/// An MCP backend whose `tools/list` waits until `release` is set, counting
/// the lists it was asked for.
async fn held_backend() -> (String, Arc<AtomicUsize>, watch::Sender<bool>) {
    let lists = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);
    let counted = Arc::clone(&lists);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let (counted, mut released) = (Arc::clone(&counted), released.clone());
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
                        json!({"tools": [{"name": TOOL, "inputSchema": {"type": "object"}}]})
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
    (format!("http://{address}/"), lists, release)
}

fn names(reply: &Value) -> Vec<String> {
    reply["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list failed: {reply}"))
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

fn modern(id: u64, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {
        "_meta": {"io.modelcontextprotocol/protocolVersion": MODERN}}})
}

#[tokio::test]
async fn a_modern_first_list_during_warm_up_is_filled_or_told_it_changed() {
    let (url, lists, release) = held_backend().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let tasks = dir.path().join("tasks");
    let yaml = format!(
        "backends:\n  held:\n    http_url: \"{url}\"\n    streamable_http: true\n\
meta_mcp:\n  surfaced_tools:\n    - server: held\n      tool: {TOOL}\n\
tasks:\n  store_dir: {}\n",
        serde_json::to_string(&tasks.display().to_string()).expect("a JSON string")
    );
    let mut serve: Serve = boot(dir, yaml, 64 * 1024).await;

    // Premise: the warm-up is fetching the backend's tools, and held there.
    let by = tokio::time::Instant::now() + ARRIVAL;
    while lists.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < by,
            "premise: the warm-up never asked the backend for its tools"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    serve.send(&modern(1, "server/discover")).await;
    serve.reply(1, &mut Vec::new()).await;
    serve.send(&modern(2, "tools/list")).await;
    let mut seen = Vec::new();
    let mut first = None;
    while let Some(frame) = serve.next(HELD).await {
        if frame["id"] == json!(2) {
            first = Some(frame);
            break;
        }
        seen.push(frame);
    }

    release.send(true).expect("the backend is still serving");
    let first = match first {
        Some(answer) => answer,
        None => serve.reply(2, &mut seen).await,
    };
    let filled_first = names(&first).iter().any(|name| name == TOOL);
    let told = seen
        .iter()
        .any(|frame| frame["method"] == "notifications/tools/list_changed")
        || serve.list_changed_within(ARRIVAL).await;

    // Premise: the fill landed, so a later list shows the tool.
    let by = tokio::time::Instant::now() + ARRIVAL;
    let mut id = 3;
    while !names(&{
        serve.send(&modern(id, "tools/list")).await;
        serve.reply(id, &mut Vec::new()).await
    })
    .iter()
    .any(|name| name == TOOL)
    {
        assert!(
            tokio::time::Instant::now() < by,
            "premise: the warm-up's fill never reached tools/list"
        );
        id += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        filled_first || told,
        "a modern stdio client's first tools/list during warm-up lacked {TOOL} \
         ({first}) and it was never told the list changed"
    );
    serve.close().await;
}
