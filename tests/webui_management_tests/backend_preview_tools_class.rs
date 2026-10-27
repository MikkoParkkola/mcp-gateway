// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/tools` carries the same read/write `class` and
//! `class_source` the preview shows, and a successful preview closes its
//! session before it answers.

use super::{
    Arc, Backend, BackendConfig, FailsafeConfig, IntoResponse, Json, Log, Method, Response,
    StatusCode, TransportConfig, Value, confirmed, create_router, json, make_app_state,
    router_with, send_json, serve,
};

/// Four tools, one per corner: declared read, declared write on a
/// read-looking name, inferred read, inferred write. Every `initialize`
/// answer opens a session, so a close has something to delete.
fn corners(request: &Value) -> Response {
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "corners", "version": "0"},
        }),
        Some("tools/list") => json!({"tools": [
            {"name": "stamp", "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": true}},
            {"name": "list_and_purge", "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": false}},
            {"name": "list_notes", "inputSchema": {"type": "object"}},
            {"name": "delete_all", "inputSchema": {"type": "object"}},
        ]}),
        _ => {
            return Json(json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"}}))
            .into_response();
        }
    };
    let mut response = Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response();
    if request.get("method").and_then(Value::as_str) == Some("initialize") {
        response
            .headers_mut()
            .insert("mcp-session-id", "s-1".parse().unwrap());
    }
    response
}

const CORNERS: [(&str, &str, &str); 4] = [
    ("stamp", "read", "declared"),
    ("list_and_purge", "write", "declared"),
    ("list_notes", "read", "inferred"),
    ("delete_all", "write", "inferred"),
];

/// `(class, class_source)` of `name` in a `tools` array.
fn class_of(tools: &Value, name: &str) -> (String, String) {
    let tool = tools
        .as_array()
        .expect("tools")
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("{name} listed: {tools}"));
    (
        tool["class"].as_str().unwrap_or_default().to_string(),
        tool["class_source"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// The tools list classes every cached tool as the preview does: an explicit
/// hint either way is `declared`, an omitted one is `inferred` from the name.
#[tokio::test]
async fn the_tools_list_carries_the_preview_class_per_tool() {
    let log = Log::default();
    let url = serve(&log, corners).await;
    let (state, _store) = make_app_state(None, None).await;
    let config = BackendConfig {
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.clone(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    assert!(state.backends.register(Arc::new(Backend::new(
        "corners",
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))));
    let router = create_router(state);
    let (status, listed) = send_json(&router, Method::GET, "/ui/api/tools", None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let (status, previewed) = confirmed(&router, &json!({"name": "probe", "url": url})).await;
    assert_eq!(status, StatusCode::OK, "{previewed}");
    for (name, class, source) in CORNERS {
        let expected = (class.to_string(), source.to_string());
        assert_eq!(class_of(&listed["tools"], name), expected, "tools list");
        assert_eq!(class_of(&previewed["tools"], name), expected, "preview");
    }
}

/// A preview that lists its tools closes its session (DELETE) before it
/// answers 200, as the capped and disconnected paths do.
#[tokio::test]
async fn a_successful_preview_closes_its_session_before_answering() {
    let log = Log::default();
    let url = serve(&log, corners).await;
    let (router, _store) = router_with(false).await;
    let (status, body) = confirmed(&router, &json!({"name": "closes", "url": url})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = log.lock().unwrap().clone();
    let deleted = seen.iter().any(|request| request.method == Method::DELETE);
    assert!(deleted, "no session teardown before the 200: {seen:?}");
}
