// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8838 (U6): `POST /ui/api/previews` starts a server once, lists
//! its tools with a read/write class, and stops. These cover the URL arm and
//! the route's contract; the command arm's sandbox is MIK-8905's (ADR-027),
//! and until it lands a command preview is refused.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{HeaderMap, Uri};
use axum::response::{IntoResponse, Response};

use super::*;

const PREVIEW: &str = "/ui/api/previews";

/// One request the stub saw: path with query, and its header names.
#[derive(Clone, Debug)]
struct Seen {
    target: String,
    headers: Vec<String>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// How a stub answers one JSON-RPC request.
type Reply = fn(&Value) -> Response;

/// A Streamable HTTP MCP server on loopback that records every request.
/// `list_notes` is a read by name; `delete_all` is a write by name; `stamp` declares
/// `readOnlyHint: true` itself.
async fn stub(log: &Log) -> String {
    stub_with(log, answer).await
}

/// [`stub`] answering every request with `reply`.
async fn stub_with(log: &Log, reply: Reply) -> String {
    let log = Arc::clone(log);
    let app = axum::Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let log = Arc::clone(&log);
        async move {
            log.lock().unwrap().push(Seen {
                target: uri
                    .path_and_query()
                    .map_or_else(String::new, ToString::to_string),
                headers: headers.keys().map(ToString::to_string).collect(),
            });
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            reply(&request)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/mcp")
}

fn answer(request: &Value) -> Response {
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "stub", "version": "0"},
        }),
        Some("tools/list") => json!({"tools": [
            {"name": "list_notes", "description": "lists notes", "inputSchema": {"type": "object"}},
            {"name": "delete_all", "description": "deletes", "inputSchema": {"type": "object"}},
            {"name": "stamp", "description": "stamps", "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": true}},
        ]}),
        _ => {
            return Json(json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"}}))
            .into_response();
        }
    };
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

/// A request to the preview route, as admin when `token` is the admin token,
/// anonymous when `None`.
async fn preview_as(router: &Router, token: Option<&str>, body: &Value) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(PREVIEW)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!(null)),
    )
}

/// The two-step preview: describe, then confirm with the returned token.
async fn confirmed(router: &Router, body: &Value) -> (StatusCode, Value) {
    let (status, described) = preview_as(router, Some(ADMIN_TOKEN), body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "describe step: {described}");
    let token = described["confirm"]
        .as_str()
        .expect("a confirm token")
        .to_string();
    let mut body = body.clone();
    body["confirm"] = json!(token);
    preview_as(router, Some(ADMIN_TOKEN), &body).await
}

/// The router over a state whose `security.ssrf_protection` is `ssrf`.
async fn router_with(ssrf: bool) -> (Router, TempDir) {
    let (mut state, store_dir) = make_app_state(None, None).await;
    Arc::get_mut(&mut state)
        .expect("test AppState should be uniquely owned")
        .ssrf_protection = ssrf;
    (create_router(state), store_dir)
}

/// T7: an unconfirmed preview starts nothing and returns a token.
#[tokio::test]
async fn an_unconfirmed_preview_starts_nothing_and_returns_a_token() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    let (status, body) = preview_as(
        &router,
        Some(ADMIN_TOKEN),
        &json!({"name": "stub", "url": url}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(
        body["confirm"].as_str().is_some_and(|t| !t.is_empty()),
        "{body}"
    );
    assert_eq!(body["preview"]["transport"], "http", "{body}");
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing may start before confirm"
    );
}

/// T7: a token is single-use, and bound to the body it was issued for.
#[tokio::test]
async fn a_token_is_single_use_and_bound_to_its_body() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    let body = json!({"name": "stub", "url": url});
    let (_, described) = preview_as(&router, Some(ADMIN_TOKEN), &body).await;
    let token = described["confirm"].as_str().unwrap().to_string();

    let mut other = json!({"name": "other", "url": url});
    other["confirm"] = json!(token);
    let (status, _) = preview_as(&router, Some(ADMIN_TOKEN), &other).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a token for another body is refused"
    );

    let mut same = body.clone();
    same["confirm"] = json!(token);
    let (first, answer) = preview_as(&router, Some(ADMIN_TOKEN), &same).await;
    assert_eq!(first, StatusCode::OK, "{answer}");
    let (again, _) = preview_as(&router, Some(ADMIN_TOKEN), &same).await;
    assert_eq!(again, StatusCode::CONFLICT, "a spent token is refused");
}

/// T1, T5b, T9: a confirmed URL preview lists tools with class and its source,
/// names the publisher unverified, and says it stopped.
#[tokio::test]
async fn a_confirmed_url_preview_lists_tools_with_class() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    let (status, body) = confirmed(&router, &json!({"name": "stub", "url": url})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tools = body["tools"].as_array().expect("tools");
    let tool = |name: &str| {
        tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("{name} listed: {body}"))
            .clone()
    };
    assert_eq!(tool("list_notes")["class"], "read");
    assert_eq!(tool("list_notes")["class_source"], "inferred");
    assert_eq!(tool("delete_all")["class"], "write");
    assert_eq!(tool("stamp")["class"], "read");
    assert_eq!(tool("stamp")["class_source"], "declared");
    assert_eq!(
        body["preview"]["publisher"],
        json!({"verified": false, "source": null})
    );
    assert!(!log.lock().unwrap().is_empty(), "the stub was reached");
}

/// T6: a caller without admin gets 403 and nothing starts.
#[tokio::test]
async fn a_non_admin_caller_is_refused_and_nothing_starts() {
    const VIEWER_KEY: &str = "u6-viewer-key";
    let log = Log::default();
    let url = stub(&log).await;
    // A valid key without admin: it passes authentication, so only the
    // handler's own admin check can refuse it.
    let viewer = mcp_gateway::config::ApiKeyConfig {
        key: None,
        key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
            VIEWER_KEY.as_bytes(),
        )),
        expires_at: None,
        name: "viewer".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: mcp_gateway::config::ApiKeyKind::Shared,
    };
    let auth = AuthConfig {
        api_keys: vec![viewer],
        ..admin_auth_config()
    };
    let (state, _store) = make_app_state_with_auth_config(&auth).await;
    let router = create_router(state);
    let body = json!({"name": "stub", "url": url});
    let (anonymous, _) = preview_as(&router, None, &body).await;
    assert!(
        matches!(anonymous, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "anonymous got {anonymous}"
    );
    let (viewer, refused) = preview_as(&router, Some(VIEWER_KEY), &body).await;
    assert_eq!(viewer, StatusCode::FORBIDDEN, "a non-admin key: {refused}");
    assert!(log.lock().unwrap().is_empty());
}

/// T3: with SSRF protection on, a loopback URL is refused and never reached.
#[tokio::test]
async fn ssrf_protection_refuses_a_loopback_url() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(true).await;
    let (status, body) = confirmed(&router, &json!({"name": "stub", "url": url})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        log.lock().unwrap().is_empty(),
        "the guard refuses before connecting"
    );
}

/// T3c: a URL carrying userinfo or a query is refused, never rewritten.
#[tokio::test]
async fn a_url_with_credentials_is_refused_not_rewritten() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    for bad in [
        format!("{url}?token=s3cr3t"),
        url.replacen("http://", "http://user:pw@", 1),
    ] {
        let (status, body) = preview_as(
            &router,
            Some(ADMIN_TOKEN),
            &json!({"name": "stub", "url": bad}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
        assert!(!body.to_string().contains("s3cr3t"), "never echoed: {body}");
    }
    assert!(log.lock().unwrap().is_empty());
}

/// T2: an env secret is never sent, echoed or logged; its key is named.
#[tokio::test]
async fn an_env_secret_is_withheld_and_named() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    let body = json!({"name": "stub", "url": url, "env": {"SECRET": "s3cr3t-value"}});
    let (status, answer) = confirmed(&router, &body).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(!answer.to_string().contains("s3cr3t-value"), "{answer}");
    assert_eq!(answer["preview"]["withheld"]["env"], json!(["SECRET"]));
    let seen = log.lock().unwrap().clone();
    assert!(!seen.is_empty(), "the stub was reached");
    for request in &seen {
        assert!(!request.target.contains("s3cr3t-value"), "{request:?}");
        assert!(
            !request
                .headers
                .iter()
                .any(|h| h == "authorization" || h == "cookie"),
            "no credential header reaches the server: {request:?}"
        );
    }
}

/// T12: before MIK-8905's sandbox launcher lands, a command preview is refused,
/// naming why, and nothing is started.
#[tokio::test]
async fn a_command_preview_is_refused_until_the_sandbox_lands() {
    let (router, _store) = router_with(false).await;
    let marker = std::env::temp_dir().join(format!("u6-never-{}", std::process::id()));
    let command = format!("touch {}", marker.display());
    // Refused at the describe step: there is nothing to confirm.
    let (status, body) = preview_as(
        &router,
        Some(ADMIN_TOKEN),
        &json!({"name": "cmd", "command": command}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body.to_string().to_lowercase().contains("sandbox"),
        "the refusal names the sandbox: {body}"
    );
    assert!(!marker.exists(), "the command never ran");
}

/// T9 also holds for the WebSocket refusal: 422, nothing reached.
#[tokio::test]
async fn a_websocket_url_is_refused() {
    let (router, _store) = router_with(false).await;
    let (status, body) = preview_as(
        &router,
        Some(ADMIN_TOKEN),
        &json!({"name": "ws", "url": "ws://127.0.0.1:9/mcp"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

/// The preview route cannot shadow a backend: one named `preview` answers GET,
/// PATCH and DELETE on `/ui/api/backends/{name}` exactly as any other name does.
#[tokio::test]
async fn a_backend_named_preview_keeps_its_routes() {
    let (state, _store) = make_app_state(None, None).await;
    register_http_backend(&state, "preview");
    register_http_backend(&state, "docs");
    let router = create_router(state);
    for method in [Method::GET, Method::PATCH, Method::DELETE] {
        let body = (method == Method::PATCH).then(|| json!({"description": "x"}));
        let (preview, _) = send_json(
            &router,
            method.clone(),
            "/ui/api/backends/preview",
            body.clone(),
        )
        .await;
        let (docs, _) = send_json(&router, method.clone(), "/ui/api/backends/docs", body).await;
        assert_eq!(preview, docs, "{method} on a backend named preview");
    }
}

/// A JSON-RPC result for `request` whose `tools/list` page carries one tool
/// with a `pad`-byte description, and `next` as its next page token.
fn padded_page(request: &Value, pad: usize, next: Option<&str>) -> Response {
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    if request.get("method").and_then(Value::as_str) != Some("tools/list") {
        return answer(request);
    }
    let page = request["params"]["cursor"]
        .as_str()
        .unwrap_or("p0")
        .to_owned();
    let mut result = json!({"tools": [{
        "name": format!("list_{page}"),
        "description": "x".repeat(pad),
        "inputSchema": {"type": "object"},
    }]});
    if let Some(next) = next {
        result["nextCursor"] = json!(next);
    }
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

/// One `tools/list` answer just over the 4 MiB response budget.
fn oversized_list(request: &Value) -> Response {
    padded_page(request, 4 * 1024 * 1024 + 1, None)
}

/// The same oversized answer, sent as one SSE event.
fn oversized_sse(request: &Value) -> Response {
    if request.get("method").and_then(Value::as_str) != Some("tools/list") {
        return answer(request);
    }
    let pad = "x".repeat(4 * 1024 * 1024 + 1);
    let id = request["id"].clone();
    let event = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [
        {"name": "list_big", "description": pad, "inputSchema": {"type": "object"}}]}});
    (
        [("content-type", "text/event-stream")],
        format!("event: message\ndata: {event}\n\n"),
    )
        .into_response()
}

/// Three pages of 3 MiB each: every response is under 4 MiB, the preview
/// together is over 8 MiB.
fn three_large_pages(request: &Value) -> Response {
    let next = match request["params"]["cursor"].as_str() {
        None => Some("p1"),
        Some("p1") => Some("p2"),
        _ => None,
    };
    padded_page(request, 3 * 1024 * 1024, next)
}

/// An `initialize` refusal whose error body is over the 4 MiB budget.
fn oversized_error(request: &Value) -> Response {
    if request.get("method").and_then(Value::as_str) == Some("initialize") {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "e".repeat(4 * 1024 * 1024 + 1),
        )
            .into_response();
    }
    answer(request)
}

/// Fires when [`hanging_list`] has been asked for the tools, so a test knows
/// the preview is inside its listing (and holds the guard) without a timer.
static LIST_ARRIVED: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// A `tools/list` answer whose body never ends.
fn hanging_list(request: &Value) -> Response {
    if request.get("method").and_then(Value::as_str) != Some("tools/list") {
        return answer(request);
    }
    LIST_ARRIVED.notify_one();
    (
        [("content-type", "application/json")],
        Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>()),
    )
        .into_response()
}

/// T11: each over-budget shape is a 502 naming the budget it broke.
#[tokio::test]
async fn an_over_budget_preview_is_a_502_naming_the_budget() {
    let cases: [(&str, Reply, &str); 4] = [
        ("one response", oversized_list, "4 MiB"),
        ("one SSE response", oversized_sse, "4 MiB"),
        ("an error body", oversized_error, "4 MiB"),
        ("the whole preview", three_large_pages, "8 MiB"),
    ];
    for (shape, reply, budget) in cases {
        let log = Log::default();
        let url = stub_with(&log, reply).await;
        let (router, _store) = router_with(false).await;
        let (status, body) = confirmed(&router, &json!({"name": "big", "url": url})).await;
        let message = body["error"].as_str().unwrap_or_default();
        let shown: String = message.chars().take(200).collect();
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{shape}: {shown}");
        assert!(
            message.contains(budget) && message.contains("budget"),
            "{shape} names the {budget} budget: {shown}"
        );
    }
}

/// T11 positive control: pages just under both budgets list in full.
#[tokio::test]
async fn a_preview_under_both_budgets_lists_every_page() {
    fn two_pages(request: &Value) -> Response {
        let next = request["params"]["cursor"]
            .as_str()
            .is_none()
            .then_some("p1");
        padded_page(request, 3 * 1024 * 1024, next)
    }
    let log = Log::default();
    let url = stub_with(&log, two_pages).await;
    let (router, _store) = router_with(false).await;
    let (status, body) = confirmed(&router, &json!({"name": "big", "url": url})).await;
    assert_eq!(status, StatusCode::OK, "{}", body["error"]);
    let names: Vec<&str> = body["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, ["list_p0", "list_p1"]);
}

/// T13: a failed redeem frees the busy guard at once.
#[tokio::test]
async fn a_failed_redeem_frees_the_guard_for_the_next_preview() {
    let log = Log::default();
    let url = stub(&log).await;
    let (router, _store) = router_with(false).await;
    let body = json!({"name": "stub", "url": url, "confirm": "not-a-token"});
    let (status, answer) = preview_as(&router, Some(ADMIN_TOKEN), &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    let (status, answer) = confirmed(&router, &json!({"name": "stub", "url": url})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the next preview is admitted: {answer}"
    );
}

/// T8b: a client that disconnects mid-preview frees the guard; the next
/// preview is admitted.
#[tokio::test]
async fn a_disconnected_preview_frees_the_guard() {
    let log = Log::default();
    let hanging = stub_with(&log, hanging_list).await;
    let (router, _store) = router_with(false).await;
    // The first preview is dropped, as a disconnect drops it, once the
    // server has been asked for its tools: from then on it holds the guard.
    let slow = json!({"name": "slow", "url": hanging});
    tokio::select! {
        (status, body) = confirmed(&router, &slow) => {
            panic!("the hanging preview answered: {status} {body}");
        }
        () = LIST_ARRIVED.notified() => {}
    }
    let url = stub(&log).await;
    let (status, answer) = confirmed(&router, &json!({"name": "stub", "url": url})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admitted after the disconnect: {answer}"
    );
}
