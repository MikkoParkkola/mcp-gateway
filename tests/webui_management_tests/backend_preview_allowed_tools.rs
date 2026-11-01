// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend added with `allowed_tools` offers only those tools, on every
//! route, and the admin tools list still shows the rest for re-selection.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::{
    ADMIN_TOKEN, Arc, AuthConfig, Body, IntoResponse, Json, Method, Request, Response, ServiceExt,
    StatusCode, TempDir, Value, confirmed, create_router, json, make_app_state_with_reload,
    router_with, send_json, write_owner_only,
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
    fixture_with(|_| {}).await
}

/// [`fixture`] with `setup` applied to the state before the router is built.
async fn fixture_with(
    setup: impl FnOnce(&mut mcp_gateway::gateway::test_helpers::AppState),
) -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("gateway.yaml");
    let config = mcp_gateway::config::Config::default();
    write_owner_only(&path, crate::yaml::to_string(&config).unwrap()).unwrap();
    let (mut state, _, store) = make_app_state_with_reload(config, None, path.clone()).await;
    setup(Arc::get_mut(&mut state).expect("state is unique"));
    Fixture {
        router: create_router(state),
        path,
        _dir: dir,
        _store: store,
    }
}

/// A direct `tools/call` of `tool` on backend `sel`, as admin.
async fn direct_call(router: &axum::Router, tool: &str) -> Value {
    direct(
        router,
        ADMIN_TOKEN,
        "tools/call",
        json!({"name": tool, "arguments": {}}),
    )
    .await
}

/// A direct `method` on backend `sel`, as the caller holding `token`.
async fn direct(router: &axum::Router, token: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp/sel")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Whether a direct answer is the direct route's answer for an absent tool:
/// an `isError` result saying the backend lists no tool of that name, as it
/// answers any withheld name. Nothing else counts as this refusal.
fn absent_write_b(answer: &Value) -> bool {
    answer.get("error").is_none()
        && answer["result"]["isError"] == true
        && answer["result"]["content"][0]["text"]
            == "the backend does not list a tool named `write_b`"
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
    assert!(absent_write_b(&answer), "{answer}");
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
    let listed = direct(&fixture.router, ADMIN_TOKEN, "tools/list", json!({})).await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, ["read_a"], "direct tools/list: {listed}");
    let (status, config) = send_json(&fixture.router, Method::GET, "/ui/api/config", None).await;
    assert_eq!(status, StatusCode::OK, "{config}");
    let sel = config["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .find(|s| s["name"] == "sel")
        .expect("sel listed");
    assert_eq!(sel["allowed_tools"], json!(["read_a"]), "{sel}");
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
    assert!(absent_write_b(
        &direct_call(&fixture.router, "write_b").await
    ));
    assert_eq!(upstream.write_b.load(Ordering::SeqCst), 0, "kept selection");
    assert_eq!(
        patch(json!({"allowed_tools": ["read_a", "write_b"]}))
            .await
            .0,
        StatusCode::OK
    );
    assert!(served(&direct_call(&fixture.router, "write_b").await));
    assert_eq!(upstream.write_b.load(Ordering::SeqCst), 1, "widened");
    assert_eq!(
        patch(json!({"allowed_tools": ["read_a"]})).await.0,
        StatusCode::OK
    );
    assert!(absent_write_b(
        &direct_call(&fixture.router, "write_b").await
    ));
    assert_eq!(upstream.write_b.load(Ordering::SeqCst), 1, "narrowed again");
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
    let bad_lists = [json!([]), json!(["re*ad"]), json!(["*_write"])];
    let before = std::fs::read(&fixture.path).unwrap();
    for bad in &bad_lists {
        let (status, body) = add(&fixture, &url, bad.clone()).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "add {bad}: {body}"
        );
        assert_eq!(std::fs::read(&fixture.path).unwrap(), before, "add {bad}");
    }
    assert_eq!(
        add(&fixture, &url, json!(["read_a"])).await.0,
        StatusCode::CREATED
    );
    let before = std::fs::read(&fixture.path).unwrap();
    for bad in &bad_lists {
        let (status, body) = send_json(
            &fixture.router,
            Method::PATCH,
            "/ui/api/backends/sel",
            Some(json!({"allowed_tools": bad})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "edit {bad}: {body}"
        );
        assert_eq!(std::fs::read(&fixture.path).unwrap(), before, "edit {bad}");
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
    let tools = body["tools"].as_array().expect("tools");
    let selectable = |name: &str| {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} previewed: {body}"))["selectable"]
            .clone()
    };
    assert_eq!(selectable("*"), false);
    assert_eq!(selectable("read_a"), true);
}

/// The first `allowed_tools` value anywhere in an audit record, wherever
/// its envelope nests the fields.
fn selection_in(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(map) => map
            .get("allowed_tools")
            .or_else(|| map.values().find_map(selection_in)),
        Value::Array(items) => items.iter().find_map(selection_in),
        _ => None,
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
    // The same list again changes nothing, so it writes no selection detail.
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
    let changes: Vec<Value> = records.iter().filter_map(selection_in).cloned().collect();
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

/// The bearer a permissive API key holds in [`the_other_scopes_cannot_widen_the_selection`].
const OPEN_KEY: &str = "sel-open-key";

/// All three tool scopes must permit a call, and none widens another: a
/// global `tool_policy.allow` of `sel:*` and an API key whose own
/// `allowed_tools` is `*` still leave `write_b` absent on the direct route
/// and through meta `gateway_invoke`, with no upstream call.
#[tokio::test]
async fn the_other_scopes_cannot_widen_the_selection() {
    let upstream = Arc::new(Upstream::default());
    let url = stub(Arc::clone(&upstream)).await;
    let fixture = fixture_with(|state| {
        // The router judges under the published generation's policy.
        let mut config = (*state.live_config.get()).clone();
        config.security.tool_policy = mcp_gateway::security::ToolPolicyConfig {
            allow: vec!["sel:*".to_string()],
            ..mcp_gateway::security::ToolPolicyConfig::default()
        };
        state.live_config.set(config);
        let open = mcp_gateway::config::ApiKeyConfig {
            key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                OPEN_KEY.as_bytes(),
            )),
            name: "open".to_string(),
            backends: vec!["*".to_string()],
            allowed_tools: Some(vec!["*".to_string()]),
            ..Default::default()
        };
        let auth = AuthConfig {
            api_keys: vec![open],
            ..super::admin_auth_config()
        };
        {
            state.live_config =
                std::sync::Arc::new(mcp_gateway::gateway::test_helpers::live_config(
                    (*state.live_config.get()).clone(),
                    Arc::new(mcp_gateway::gateway::auth::ResolvedAuthConfig::from_config(
                        &auth,
                        crate::record_key::RECORD_KEY,
                    )),
                ));
        }
        state.meta_mcp_enabled = true;
    })
    .await;
    assert_eq!(
        add(&fixture, &url, json!(["read_a"])).await.0,
        StatusCode::CREATED
    );
    let answer = direct(
        &fixture.router,
        OPEN_KEY,
        "tools/call",
        json!({"name": "write_b", "arguments": {}}),
    )
    .await;
    assert!(
        absent_write_b(&answer),
        "direct, permissive key and policy: {answer}"
    );
    let read = direct(
        &fixture.router,
        OPEN_KEY,
        "tools/call",
        json!({"name": "read_a", "arguments": {}}),
    )
    .await;
    assert!(
        served(&read),
        "the key still reaches a selected tool: {read}"
    );
    let invoked = meta_invoke(&fixture.router, OPEN_KEY, "write_b").await;
    // The meta route wraps the backend's absent-tool answer in its own
    // isError result; it carries the same words, never the tool's output.
    assert_eq!(
        invoked["result"]["isError"], true,
        "meta gateway_invoke: {invoked}"
    );
    let wrapped = invoked["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        wrapped.contains("the backend does not list a tool named `write_b`"),
        "meta gateway_invoke: {invoked}"
    );
    assert_eq!(
        upstream.write_b.load(Ordering::SeqCst),
        0,
        "write_b reached the server"
    );
}

/// A modern meta `gateway_invoke` of `tool` on `sel`, as the holder of `token`.
async fn meta_invoke(router: &axum::Router, token: &str, tool: &str) -> Value {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.mcp-gateway/idempotency-key": format!("sel-{tool}"),
            },
            "arguments": {"server": "sel", "tool": tool, "arguments": {}},
        },
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}
