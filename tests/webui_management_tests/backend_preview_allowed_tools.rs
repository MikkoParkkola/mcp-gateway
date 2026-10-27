// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend added with `allowed_tools` offers only those tools, on every
//! route, and the admin tools list still shows the rest for re-selection.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::{
    ADMIN_TOKEN, Arc, Body, IntoResponse, Json, Method, Request, Response, ServiceExt, StatusCode,
    TempDir, Value, confirmed, create_router, json, make_app_state_with_reload, router_with,
    send_json, write_owner_only,
};

/// Upstream `tools/call` count, across every tool, and of `write_b` alone.
#[derive(Default)]
struct Upstream {
    calls: AtomicUsize,
    write_b: AtomicUsize,
}

/// A stub listing `read_a` (declared read-only) and `write_b`.
async fn stub(upstream: Arc<Upstream>) -> String {
    let app = axum::Router::new().fallback(move |body: axum::body::Bytes| {
        let upstream = Arc::clone(&upstream);
        async move {
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let Some(id) = request.get("id").cloned() else {
                return StatusCode::ACCEPTED.into_response();
            };
            let result = match request["method"].as_str() {
                Some("initialize") => json!({"protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}}, "serverInfo": {"name": "s", "version": "0"}}),
                Some("tools/list") => json!({"tools": [
                    {"name": "read_a", "inputSchema": {"type": "object"},
                     "annotations": {"readOnlyHint": true}},
                    {"name": "write_b", "inputSchema": {"type": "object"}},
                ]}),
                Some("tools/call") => {
                    upstream.calls.fetch_add(1, Ordering::SeqCst);
                    if request["params"]["name"] == "write_b" {
                        upstream.write_b.fetch_add(1, Ordering::SeqCst);
                    }
                    json!({"content": [{"type": "text", "text": "done"}]})
                }
                _ => json!({}),
            };
            Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/mcp")
}

/// A reloadable gateway over an empty config file, with the router.
struct Fixture {
    router: axum::Router,
    path: std::path::PathBuf,
    _dir: TempDir,
    _store: TempDir,
}

async fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("gateway.yaml");
    let config = mcp_gateway::config::Config::default();
    write_owner_only(&path, crate::yaml::to_string(&config).unwrap()).unwrap();
    let (state, _, store) = make_app_state_with_reload(config, None, path.clone()).await;
    Fixture {
        router: create_router(state),
        path,
        _dir: dir,
        _store: store,
    }
}

/// A direct `tools/call` of `tool` on backend `sel`, as admin.
async fn direct_call(router: &axum::Router, tool: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": tool, "arguments": {}}});
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp/sel")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Whether a direct answer refuses the call: a JSON-RPC error, or the
/// absent-tool result the direct route gives a withheld name.
fn refused(answer: &Value) -> bool {
    answer.get("error").is_some() || answer["result"]["isError"] == true
}

/// Whether a direct answer is the tool's own result.
fn served(answer: &Value) -> bool {
    answer.get("result").is_some() && answer["result"]["isError"] != true
}

/// `(name, selected)` per tool the admin list shows for `sel`.
async fn admin_selection(router: &axum::Router) -> Vec<(String, Value)> {
    let (status, body) = send_json(router, Method::GET, "/ui/api/tools?server=sel", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut rows: Vec<(String, Value)> = body["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["selected"].clone(),
            )
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

async fn add(fixture: &Fixture, url: &str, allowed: Value) -> (StatusCode, Value) {
    send_json(
        &fixture.router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({"name": "sel", "url": url, "allowed_tools": allowed})),
    )
    .await
}

/// The selection is served: the direct route refuses `write_b` with no
/// upstream call, and the admin list still shows it, unselected.
#[tokio::test]
async fn an_add_with_a_selection_serves_only_the_ticked_tools() {
    let upstream = Arc::new(Upstream::default());
    let url = stub(Arc::clone(&upstream)).await;
    let fixture = fixture().await;
    let (status, body) = add(&fixture, &url, json!(["read_a"])).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let saved = std::fs::read_to_string(&fixture.path).unwrap();
    assert!(saved.contains("allowed_tools"), "{saved}");
    let answer = direct_call(&fixture.router, "write_b").await;
    assert!(refused(&answer), "{answer}");
    assert_eq!(
        upstream.write_b.load(Ordering::SeqCst),
        0,
        "write_b reached the server"
    );
    let answer = direct_call(&fixture.router, "read_a").await;
    assert!(served(&answer), "{answer}");
    assert_eq!(
        admin_selection(&fixture.router).await,
        [
            ("read_a".into(), json!(true)),
            ("write_b".into(), json!(false))
        ]
    );
}

/// PATCH: an absent key keeps the selection, a list replaces it, and null
/// removes it so every tool is served.
#[tokio::test]
async fn a_patch_keeps_replaces_or_clears_the_selection() {
    let upstream = Arc::new(Upstream::default());
    let url = stub(Arc::clone(&upstream)).await;
    let fixture = fixture().await;
    assert_eq!(
        add(&fixture, &url, json!(["read_a"])).await.0,
        StatusCode::CREATED
    );
    let patch = |body: Value| {
        send_json(
            &fixture.router,
            Method::PATCH,
            "/ui/api/backends/sel",
            Some(body),
        )
    };
    assert_eq!(
        patch(json!({"description": "unrelated"})).await.0,
        StatusCode::OK
    );
    assert!(refused(&direct_call(&fixture.router, "write_b").await));
    assert_eq!(
        patch(json!({"allowed_tools": ["read_a", "write_b"]}))
            .await
            .0,
        StatusCode::OK
    );
    assert!(served(&direct_call(&fixture.router, "write_b").await));
    assert_eq!(
        patch(json!({"allowed_tools": ["read_a"]})).await.0,
        StatusCode::OK
    );
    assert!(refused(&direct_call(&fixture.router, "write_b").await));
    assert_eq!(
        patch(json!({"allowed_tools": null})).await.0,
        StatusCode::OK
    );
    let saved = std::fs::read_to_string(&fixture.path).unwrap();
    assert!(!saved.contains("allowed_tools"), "{saved}");
    assert!(served(&direct_call(&fixture.router, "write_b").await));
}

/// An empty list or a pattern that matches nothing is refused, and the
/// config file is left byte for byte as it was.
#[tokio::test]
async fn an_unusable_selection_is_refused_and_writes_nothing() {
    let url = stub(Arc::default()).await;
    let fixture = fixture().await;
    let before = std::fs::read(&fixture.path).unwrap();
    for bad in [json!([]), json!(["re*ad"]), json!(["*_write"])] {
        let (status, body) = add(&fixture, &url, bad.clone()).await;
        assert!(status.is_client_error(), "{bad}: {status} {body}");
        assert_eq!(std::fs::read(&fixture.path).unwrap(), before, "{bad}");
    }
}

/// A previewed tool whose name the gateway would never call (here `*`, which
/// would read as a wildcard in a selection) is offered as not selectable.
#[tokio::test]
async fn a_preview_offers_no_invalid_name_for_selection() {
    fn starred(request: &Value) -> Response {
        let Some(id) = request.get("id").cloned() else {
            return StatusCode::ACCEPTED.into_response();
        };
        let result = match request["method"].as_str() {
            Some("initialize") => json!({"protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}}, "serverInfo": {"name": "s", "version": "0"}}),
            Some("tools/list") => json!({"tools": [
                {"name": "*", "inputSchema": {"type": "object"},
                 "annotations": {"readOnlyHint": true}},
                {"name": "read_a", "inputSchema": {"type": "object"}},
            ]}),
            _ => json!({}),
        };
        Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
    }
    let url = super::stub_with(&super::Log::default(), starred).await;
    let (router, _store) = router_with(false).await;
    let (status, body) = confirmed(&router, &json!({"name": "p", "url": url})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for tool in body["tools"].as_array().expect("tools") {
        let selectable = tool["name"] != "*";
        assert_eq!(tool["selectable"], selectable, "{tool}");
    }
}

/// Every change of a selection, on add and on PATCH (a list and a clear),
/// is on that request's `admin_action` record with the list before and
/// after; request bodies are otherwise never logged.
#[tokio::test]
async fn a_selection_change_is_on_its_audit_record() {
    use mcp_gateway::security::{TransparencyLogConfig, TransparencyLogger};
    let url = stub(Arc::default()).await;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("gateway.yaml");
    let audit = dir.path().join("audit.jsonl");
    let config = mcp_gateway::config::Config::default();
    write_owner_only(&path, crate::yaml::to_string(&config).unwrap()).unwrap();
    let (mut state, _, _store) = make_app_state_with_reload(config, None, path.clone()).await;
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: audit.to_string_lossy().into_owned(),
        key_id: "sel".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    Arc::get_mut(&mut state).expect("unique").transparency_log = Some(Arc::new(log));
    let router = create_router(state);
    let send = |method: Method, uri: &'static str, body: Value| {
        send_json(&router, method, uri, Some(body))
    };
    let (status, _) = send(
        Method::POST,
        "/ui/api/backends",
        json!({"name": "sel", "url": url, "allowed_tools": ["read_a"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    send(
        Method::PATCH,
        "/ui/api/backends/sel",
        json!({"allowed_tools": ["read_a", "write_b"]}),
    )
    .await;
    send(
        Method::PATCH,
        "/ui/api/backends/sel",
        json!({"allowed_tools": null}),
    )
    .await;
    send(
        Method::PATCH,
        "/ui/api/backends/sel",
        json!({"description": "unrelated"}),
    )
    .await;
    let records: Vec<Value> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    // Wherever the record's envelope nests the fields.
    fn find(value: &Value) -> Option<&Value> {
        match value {
            Value::Object(map) => map
                .get("allowed_tools")
                .or_else(|| map.values().find_map(find)),
            Value::Array(items) => items.iter().find_map(find),
            _ => None,
        }
    }
    let changes: Vec<Value> = records.iter().filter_map(find).cloned().collect();
    assert_eq!(
        changes,
        [
            json!({"backend": "sel", "before": null, "after": ["read_a"]}),
            json!({"backend": "sel", "before": ["read_a"], "after": ["read_a", "write_b"]}),
            json!({"backend": "sel", "before": ["read_a", "write_b"], "after": null}),
        ],
        "{records:?}"
    );
}
