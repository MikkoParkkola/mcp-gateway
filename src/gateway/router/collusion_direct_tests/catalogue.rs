// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 x MIK-7765: `prompts/get` arguments and `resources/read` results
//! are inside relay detection. Content one caller received through
//! `resources/read` or `prompts/get` cannot be relayed by another through
//! `prompts/get` arguments, a `resources/read` URI or a `tools/call`, on both
//! the meta route (`/mcp`) and the direct route (`/mcp/alpha`).

use super::meta::meta_fixture;
use super::*;

/// POST one JSON-RPC `method` to `path` as bearer `who`; the status and body.
async fn rpc(fx: &Fixture, path: &str, who: &str, method: &str, params: &Value) -> (u16, String) {
    rpc_with(fx, (path, who, None), method, (params, &json!({}))).await
}

/// [`rpc`] on `session`, with `extra` merged into the request's `_meta`.
async fn rpc_with(
    fx: &Fixture,
    (path, who, session): (&str, &str, Option<&str>),
    method: &str,
    (params, extra_meta): (&Value, &Value),
) -> (u16, String) {
    let name = params
        .get("name")
        .or_else(|| params.get("uri"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut body_params = params.clone();
    body_params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                  "io.modelcontextprotocol/clientCapabilities": {}});
    if let (Some(meta), Some(extra)) =
        (body_params["_meta"].as_object_mut(), extra_meta.as_object())
    {
        meta.extend(extra.clone());
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": body_params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .header("authorization", format!("Bearer {who}"));
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The route under test: meta (`/mcp`, names carry the backend) or direct
/// (`/mcp/alpha`, bare names).
#[derive(Clone, Copy)]
enum Route {
    Meta,
    Direct,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Self::Meta => "/mcp",
            Self::Direct => "/mcp/alpha",
        }
    }

    fn prompt(self) -> &'static str {
        match self {
            Self::Meta => "alpha/orchard",
            Self::Direct => "orchard",
        }
    }
}

/// `who` reads the resource; a delivered result.
async fn read_resource(fx: &Fixture, route: Route, who: &str) {
    let params = json!({"uri": "res://orchard"});
    let (status, body) = rpc(fx, route.path(), who, "resources/read", &params).await;
    let answer = envelope(&body);
    assert_eq!(status, 200, "{body}");
    assert!(
        answer["result"]["contents"].is_array(),
        "not delivered: {body}"
    );
}

/// `who` gets the prompt; a delivered result.
async fn get_prompt(fx: &Fixture, route: Route, who: &str) {
    let params = json!({"name": route.prompt()});
    let (status, body) = rpc(fx, route.path(), who, "prompts/get", &params).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        envelope(&body)["result"]["messages"].is_array(),
        "not delivered: {body}"
    );
}

/// `who` sends `text` as `prompts/get` arguments.
async fn prompt_with(fx: &Fixture, route: Route, who: &str, text: &str) -> (u16, String) {
    let params = json!({"name": route.prompt(), "arguments": {"topic": text}});
    rpc(fx, route.path(), who, "prompts/get", &params).await
}

fn assert_catalogue_refused(fx: &Fixture, (_, body): &(u16, String), forwarded: usize) {
    let answer = envelope(body);
    assert_eq!(answer["error"]["code"], -32002, "relay not refused: {body}");
    assert!(answer.get("result").is_none(), "{body}");
    assert_eq!(fx.catalogue(), forwarded, "the backend was called: {body}");
}

fn assert_catalogue_sent(fx: &Fixture, (status, body): &(u16, String), forwarded: usize) {
    let answer = envelope(body);
    assert_eq!(*status, 200, "{body}");
    assert!(answer.get("error").is_none(), "refused: {body}");
    assert_eq!(fx.catalogue(), forwarded, "{body}");
}

fn setup() -> Setup {
    Setup {
        sources: vec!["alpha:*".to_string()],
        ..Setup::default()
    }
}

/// The fixture for `route`: the meta route needs its Meta-MCP to hold the
/// firewall too.
async fn fixture_for(route: Route) -> Fixture {
    match route {
        Route::Meta => meta_fixture(setup(), None).await,
        Route::Direct => fixture(setup()).await,
    }
}

/// A reads a resource; B sends its text as `prompts/get` arguments.
async fn resource_read_then_prompt_argument(route: Route) {
    let fx = fixture_for(route).await;
    read_resource(&fx, route, "a").await;
    let forwarded = fx.catalogue();
    // Control: A's own copy excuses A.
    assert_catalogue_sent(
        &fx,
        &prompt_with(&fx, route, "a", PROSE).await,
        forwarded + 1,
    );
    assert_catalogue_refused(
        &fx,
        &prompt_with(&fx, route, "b", PROSE).await,
        forwarded + 1,
    );
    // Control: unrelated arguments pass.
    assert_catalogue_sent(
        &fx,
        &prompt_with(&fx, route, "b", "harbour").await,
        forwarded + 2,
    );
}

/// A gets a prompt; B sends its text through a `tools/call`.
async fn prompt_result_then_tool_call(route: Route) {
    let fx = fixture_for(route).await;
    get_prompt(&fx, route, "a").await;
    let relay = call("send", &json!({"text": PROSE}), None, None);
    let (status, body) = fx.call(Some("b"), &relay).await;
    let _ = status;
    assert_eq!(
        envelope(&body)["error"]["code"],
        -32002,
        "relay not refused: {body}"
    );
    assert_eq!(fx.sends(), 0, "the relay reached the backend");
}

/// A reads a resource; B sends its text as the `uri` of `resources/read`. Only
/// the direct route forwards a URI no backend lists: the meta route resolves the
/// URI against the backends' catalogues first, so it cannot carry content.
async fn resource_read_then_uri() {
    let fx = fixture(setup()).await;
    read_resource(&fx, Route::Direct, "a").await;
    let forwarded = fx.catalogue();
    let params = json!({"uri": format!("res://orchard?q={PROSE}")});
    let (_, body) = rpc(&fx, Route::Direct.path(), "b", "resources/read", &params).await;
    let code = envelope(&body)["error"]["code"].clone();
    assert_eq!(code, -32002, "relay not refused: {body}");
    assert_eq!(fx.catalogue(), forwarded, "the backend was called");
}

#[tokio::test]
async fn meta_resource_read_then_prompt_argument_is_refused() {
    resource_read_then_prompt_argument(Route::Meta).await;
}

#[tokio::test]
async fn direct_resource_read_then_prompt_argument_is_refused() {
    resource_read_then_prompt_argument(Route::Direct).await;
}

#[tokio::test]
async fn meta_prompt_result_then_tool_call_is_refused() {
    prompt_result_then_tool_call(Route::Meta).await;
}

#[tokio::test]
async fn direct_prompt_result_then_tool_call_is_refused() {
    prompt_result_then_tool_call(Route::Direct).await;
}

#[tokio::test]
async fn direct_resource_read_then_uri_is_refused() {
    resource_read_then_uri().await;
}

/// With no `sources` glob, content the gateway classifies as personal data is
/// still a relay source: A reads a resource carrying an email address; B sends
/// that text as `prompts/get` arguments.
async fn classified_read_is_a_relay_source(route: Route) {
    let setup = Setup {
        sources: Vec::new(),
        ..Setup::default()
    };
    let fx = match route {
        Route::Meta => meta_fixture(setup, None).await,
        Route::Direct => fixture(setup).await,
    };
    let text = format!("{PROSE} Contact: keeper@orchardcoop.fi");
    fx.answer_read(Read::Text(text.clone()));
    read_resource(&fx, route, "a").await;
    let forwarded = fx.catalogue();
    assert_catalogue_refused(&fx, &prompt_with(&fx, route, "b", &text).await, forwarded);
}

#[tokio::test]
async fn meta_classified_read_is_a_relay_source() {
    classified_read_is_a_relay_source(Route::Meta).await;
}

#[tokio::test]
async fn direct_classified_read_is_a_relay_source() {
    classified_read_is_a_relay_source(Route::Direct).await;
}

/// MIK-7832.RELAY.1: under `observe` a relayed `prompts/get` argument goes
/// through and is audited; two sessions must not share one audit session
/// fingerprint, and each names its own.
#[tokio::test]
async fn meta_catalogue_relay_audit_names_the_callers_session() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("firewall-audit.ndjson");
    let observe = Setup {
        action: CollusionAction::Observe,
        audit_log: Some(log.clone()),
        ..setup()
    };
    let fx = meta_fixture(observe, None).await;
    read_resource(&fx, Route::Meta, "a").await;
    let params = json!({"name": Route::Meta.prompt(), "arguments": {"topic": PROSE}});
    // Legacy requests: each one mints its own session (a modern request has
    // none), so the two calls below are two sessions.
    let mut minted = Vec::new();
    for _ in 0..2 {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": params});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", "Bearer b")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = create_router(Arc::clone(&fx.state))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "observe lets the relay through");
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        minted.push(session.expect("a legacy request mints a session"));
    }
    assert_ne!(minted[0], minted[1], "two sessions");
    let entries: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry.to_string().contains("collusion_relay"))
        .collect();
    let sessions: Vec<&Value> = entries.iter().map(|e| &e["session_id"]).collect();
    let expected = [
        json!(crate::gateway::session_id::session_fp(&minted[0])),
        json!(crate::gateway::session_id::session_fp(&minted[1])),
    ];
    assert_eq!(sessions, expected.iter().collect::<Vec<_>>(), "{entries:?}");
}

/// MIK-7832.RELAY.2: a catalogue relay refusal on the meta route answers with
/// the status a `tools/call` refusal does (403), not 200.
#[tokio::test]
async fn meta_catalogue_relay_refusal_carries_the_refusal_status() {
    let fx = fixture_for(Route::Meta).await;
    read_resource(&fx, Route::Meta, "a").await;
    let relay = prompt_with(&fx, Route::Meta, "b", PROSE).await;
    assert_catalogue_refused(&fx, &relay, 1);
    assert_eq!(relay.0, 403, "{}", relay.1);
}

/// MIK-7832.RELAY.6: the direct route's relay scan skips the progress token,
/// which the gateway substitutes and the caller did not send as content: a
/// token equal to a delivered text is not a relay.
#[tokio::test]
async fn direct_relay_scan_skips_the_progress_token() {
    let fx = fixture_for(Route::Direct).await;
    read_resource(&fx, Route::Direct, "a").await;
    let forwarded = fx.catalogue();
    let params = json!({"name": Route::Direct.prompt(), "arguments": {"topic": "harbour"}});
    let route = ("/mcp/alpha", "b", None);
    let token = json!({"progressToken": PROSE});
    let sent = rpc_with(&fx, route, "prompts/get", (&params, &token)).await;
    assert_catalogue_sent(&fx, &sent, forwarded + 1);
    // Why skipping it is safe: the backend is never handed the caller's own
    // token, the gateway substitutes its own, so no caller text rides in it.
    let seen = fx.catalogue_params.lock().unwrap().last().cloned();
    let reached = seen.expect("the backend saw the call");
    assert!(
        !reached.to_string().contains("orchard ledger"),
        "the caller's progress token reached the backend: {reached}"
    );
}
