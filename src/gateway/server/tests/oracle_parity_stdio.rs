// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 rows on stdio (test plan v3): a tool stdio's tool policy denies
//! answers exactly as the same name does where the backend's catalogue lacks
//! it, on `gateway_invoke`, `gateway_execute` and the surfaced name, clean or
//! firewall-tripping.
//!
//! The same name across two fixtures (v2 item 2): the withheld twin's policy
//! denies `read` over a catalogue holding it; the absent twin's policy
//! denies only `other` over the same catalogue without `read`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{BACKEND, Fixture, dispatch, fixture_on_with};

const TOOL: &str = "read";
const SIBLING: &str = "note";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Withheld,
    Absent,
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Invoke,
    Execute,
    Surfaced,
}

/// A loopback backend serving the side's catalogue, counting `tools/call`s.
async fn serve(holds: bool) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let mut tools = vec![json!({"name": SIBLING, "inputSchema": {"type": "object"}})];
    if holds {
        tools.push(json!({"name": TOOL, "description": "Reads a record.",
            "inputSchema": {"type": "object"}}));
    }
    let tools = Value::Array(tools);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            let tools = tools.clone();
            async move {
                let result = match request["method"].as_str() {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": tools}),
                    Some("tools/call") => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        json!({"content": [{"type": "text", "text": "ok"}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let address = listener.local_addr().expect("backend address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), calls)
}

struct Twin {
    fixture: Fixture,
    calls: Arc<AtomicUsize>,
}

/// Build `side`'s stdio twin, warm, with [`TOOL`] surfaced unless this is a
/// surfaced row's absent twin (which maps the name to no backend).
async fn twin(side: Side, surface_tool: bool) -> Twin {
    let (url, calls) = serve(side == Side::Withheld).await;
    let denied = match side {
        Side::Withheld => TOOL,
        Side::Absent => "other",
    };
    let policy = crate::security::ToolPolicy::from_config(&crate::security::ToolPolicyConfig {
        deny: vec![denied.to_string()],
        ..crate::security::ToolPolicyConfig::default()
    });
    let surfaced = [SIBLING, TOOL]
        .into_iter()
        .filter(|tool| surface_tool || *tool != TOOL)
        .map(|tool| crate::config::SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: tool.to_string(),
        })
        .collect::<Vec<_>>();
    let fixture = Box::pin(fixture_on_with(
        (url, Arc::clone(&calls)),
        Some(policy),
        |config| config.meta_mcp.surfaced_tools = surfaced,
    ))
    .await;
    let backend = fixture.meta.backends.get(BACKEND).expect("backend");
    backend
        .get_tools_shared()
        .await
        .expect("warm the catalogue");
    // v2 item 2: the withheld twin's catalogue holds the name, the absent
    // twin's lacks it.
    assert_eq!(
        backend.get_cached_tool(TOOL).is_some(),
        side == Side::Withheld,
        "premise: {side:?} catalogue"
    );
    Twin { fixture, calls }
}

impl Twin {
    /// Call [`TOOL`] on `entry` with `args`: the body without `id`, and the
    /// backend's sends.
    async fn call(&self, entry: Entry, args: &Value) -> (Value, usize) {
        let params = match entry {
            Entry::Invoke => json!({"name": "gateway_invoke", "arguments":
                {"server": BACKEND, "tool": TOOL, "arguments": args}}),
            Entry::Execute => json!({"name": "gateway_execute", "arguments": {"chain": [
                {"tool": format!("{BACKEND}:{TOOL}"), "arguments": args}
            ]}}),
            Entry::Surfaced => json!({"name": TOOL, "arguments": args}),
        };
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
        let mut body = dispatch(&self.fixture, request).await;
        if let Some(obj) = body.as_object_mut() {
            obj.remove("id");
        }
        (body, self.calls.load(Ordering::SeqCst))
    }
}

/// ORACLE.2 on stdio, policy reason: every entry, clean and tripping. RED on
/// base for the entries that name a backend; the surfaced name is MIK-8340's
/// (green on base, mutant MS1).
#[tokio::test]
async fn oracle2_stdio_policy_answers_as_the_missing_name() {
    let cmd = [";", " rm", " -rf", " / "].concat();
    let tripping = json!({ "cmd": cmd });
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Execute, Entry::Surfaced] {
        for (label, args) in [("clean", json!({})), ("tripping", tripping.clone())] {
            let surfaced = matches!(entry, Entry::Surfaced);
            let (withheld, sent) = twin(Side::Withheld, true).await.call(entry, &args).await;
            let (absent, _) = twin(Side::Absent, !surfaced).await.call(entry, &args).await;
            if withheld != absent || sent != 0 {
                cells.push(format!(
                    "stdio {entry:?}/{label}: withheld {withheld} (sends {sent}) vs absent {absent}"
                ));
            }
        }
    }
    assert!(cells.is_empty(), "ORACLE.2 stdio:\n{}", cells.join("\n"));
}
