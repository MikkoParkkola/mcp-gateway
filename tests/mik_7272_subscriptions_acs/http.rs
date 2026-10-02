// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Through the transport: the gateway serves the subscription model.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, auth_state, create_router, open_runtime,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The gateway state, plus the directory its task store leases.
///
/// The store holds that directory for as long as the service lives, and the
/// cases here keep listen streams open across several steps, so the caller
/// binds the `TempDir` for the whole test rather than dropping it here.
async fn state(modern: bool) -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = Config::default();
    config.server.modern_protocol = modern;
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let agent_registry = Arc::new(AgentRegistry::new());

    // One registry, shared between the state the router reads and the
    // executor that publishes: these cases assert on what a listener sees,
    // and two registries would strand every task notification.
    let subscriptions = Arc::new(SubscriptionRegistry::new(64, auth_state(&config.auth)));
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let (tasks, task_executor) = open_runtime(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("the fixture task store opens");

    let state = Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        session_lifecycle: None,
        env: None,
        meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
        backends,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
        key_server: None,
        tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(100)),
        agent_auth: AgentAuthState::new(false, agent_registry),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        control_plane_base: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

async fn post(modern: bool, body: Value, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    // `_store_dir` stays bound until this helper returns, which is after the
    // response body has been read: the store's directory outlives the request.
    let (app, _store_dir) = state(modern).await;
    let response = create_router(app)
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).expect("body")))
                .expect("request"),
        )
        .await
        .expect("router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn modern_call(method: &str, params: Value) -> (Value, Vec<(&'static str, String)>) {
    let mut full = params;
    if let Some(object) = full.as_object_mut() {
        object.insert(
            "_meta".to_string(),
            json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }),
        );
    }
    (
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": full }),
        vec![
            ("mcp-protocol-version", "2026-07-28".to_string()),
            ("mcp-method", method.to_string()),
        ],
    )
}

async fn post_modern(method: &str, params: Value) -> (StatusCode, Value) {
    let (body, owned) = modern_call(method, params);
    let borrowed: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    post(true, body, &borrowed).await
}

/// Open a `subscriptions/listen` stream and hold it.
///
/// Reads the body FRAME BY FRAME. `to_bytes` waits for the end of the
/// body, and the whole point of this response is that there is no end —
/// a test written that way hangs rather than fails.
async fn open_listen(
    state: &Arc<AppState>,
    params: Value,
) -> (StatusCode, Option<String>, axum::body::BodyDataStream) {
    // Built by the same helper every other modern call uses, so an
    // envelope change cannot make these tests pass while real clients fail.
    let (body, headers) = modern_call("subscriptions/listen", params);
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    for (name, value) in &headers {
        builder = builder.header(*name, value.as_str());
    }
    let response = create_router(Arc::clone(state))
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).expect("body")))
                .expect("request"),
        )
        .await
        .expect("router must answer");

    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    (
        status,
        content_type,
        response.into_body().into_data_stream(),
    )
}

/// The next SSE payload, or `None` if none arrives in time.
///
/// Bounded on purpose: a stream that stays open cannot be drained, so
/// "nothing arrived" has to be an answer the test can assert on.
async fn next_data(stream: &mut axum::body::BodyDataStream) -> Option<Value> {
    use futures::StreamExt;

    let deadline = std::time::Duration::from_secs(2);
    loop {
        let chunk = tokio::time::timeout(deadline, stream.next()).await.ok()??;
        let text = String::from_utf8(chunk.expect("chunk").to_vec()).expect("utf-8");
        // Keep-alive comments carry no data line; skip them rather than
        // failing, since their timing is not what these tests are about.
        if let Some(line) = text.lines().find_map(|l| l.strip_prefix("data: ")) {
            return Some(serde_json::from_str(line).expect("each event is JSON"));
        }
    }
}

#[tokio::test]
async fn ac_sub_1_the_gateway_serves_subscriptions_listen() {
    let (state, _store_dir) = state(true).await;
    let (status, content_type, mut stream) = open_listen(
        &state,
        json!({ "notifications": { "toolsListChanged": true } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        content_type.as_deref(),
        Some("text/event-stream"),
        "the response to a listen request is the stream itself, not an \
         acknowledgement that closes"
    );

    let ack = next_data(&mut stream)
        .await
        .expect("the ack opens the stream");
    // MIK-7766: a notification, never a response. A JSON-RPC response to the
    // listen request is how a server ENDS a subscription, so a client reading
    // one first sees its stream close as it opens.
    assert_eq!(
        ack["method"], "notifications/subscriptions/acknowledged",
        "the first message is the acknowledgement notification: {ack}"
    );
    assert!(
        ack.get("id").is_none() && ack.get("result").is_none(),
        "a response on the stream signals the end of the subscription: {ack}"
    );
    assert_eq!(
        ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        json!(1),
        "the subscription id is the request's own id, so the client can \
         correlate every notification with the subscription that asked for \
         it: {ack}"
    );
    assert_eq!(
        ack["params"]["notifications"],
        json!({ "toolsListChanged": true }),
        "the acknowledgement names the filter the server honours: {ack}"
    );
}

/// MIK-7766: a listener that fell behind lost updates, so its stream closes
/// without the success response that would call the subscription complete.
#[tokio::test]
async fn ac_sub_1_a_lagged_listener_is_closed_without_a_graceful_end() {
    let (state, _store_dir) = state(true).await;
    let (status, _, mut stream) = open_listen(
        &state,
        json!({ "notifications": { "toolsListChanged": true } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    next_data(&mut stream)
        .await
        .expect("the ack opens the stream");
    // More than the registry's channel holds, published while unread.
    for _ in 0..300 {
        state.announce_tools_changed("any").await;
    }
    assert_eq!(
        next_data(&mut stream).await,
        None,
        "a lagged stream closes with no response"
    );
    assert!(
        matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                futures::StreamExt::next(&mut stream)
            )
            .await,
            Ok(None)
        ),
        "the body ended, not merely went quiet"
    );
}

/// MIK-7766: the honoured filter names only what the gateway delivers, and
/// drops what it does not recognise.
#[tokio::test]
async fn ac_sub_1_the_acknowledgement_names_the_honoured_filter() {
    let (state, _store_dir) = state(true).await;
    let (status, _, mut stream) = open_listen(
        &state,
        json!({ "notifications": {
            "toolsListChanged": true,
            "promptsListChanged": true,
            "resourcesListChanged": false,
            "resourceSubscriptions": ["file:///project/config.json"],
            "someFutureKind": true,
        } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ack = next_data(&mut stream)
        .await
        .expect("the ack opens the stream");
    assert_eq!(
        ack["params"]["notifications"],
        json!({ "toolsListChanged": true }),
        "only what the gateway delivers is acknowledged; prompt and resource \
         changes are never published, so they are not promised: {ack}"
    );
}

#[tokio::test]
async fn ac_sub_1_a_notification_reaches_a_listener_tagged_with_its_subscription() {
    let (state, _store_dir) = state(true).await;
    let (status, _, mut stream) = open_listen(
        &state,
        json!({ "notifications": { "toolsListChanged": true } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let ack = next_data(&mut stream)
        .await
        .expect("the ack opens the stream");
    let subscription = ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"].clone();

    state.announce_tools_changed("any").await;

    let event = next_data(&mut stream)
        .await
        .expect("a subscribed notification must reach the open stream");
    assert_eq!(event["method"], "notifications/tools/list_changed");
    assert_eq!(
        event["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], subscription,
        "a notification is tagged with the subscription that asked for it, \
         which is how a client with two subscriptions tells them apart: \
         {event}"
    );
}

#[tokio::test]
async fn ac_sub_1_a_listener_is_not_sent_what_it_did_not_ask_for() {
    let (state, _store_dir) = state(true).await;
    // An empty filter is a valid request and opens a quiet stream.
    let (status, _, mut stream) = open_listen(&state, json!({ "notifications": {} })).await;
    assert_eq!(status, StatusCode::OK);
    next_data(&mut stream)
        .await
        .expect("the ack opens the stream");

    state.announce_tools_changed("any").await;

    assert!(
        next_data(&mut stream).await.is_none(),
        "opting in is per notification type: a listener that asked for \
         nothing receives nothing"
    );
}

#[tokio::test]
async fn ac_sub_1_the_open_stream_count_has_a_ceiling() {
    // A client may open a stream and walk away, so the ceiling is what
    // makes an abandoned stream cost something finite.
    let (state, _store_dir) = state(true).await;
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(
            state
                .subscriptions
                .subscribe()
                .expect("the registry admits up to its capacity"),
        );
    }

    let (status, _, stream) = open_listen(
        &state,
        json!({ "notifications": { "toolsListChanged": true } }),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // A refusal is an ordinary body that ends, so it is read to the end;
    // only the accepted case returns a stream that does not.
    let bytes = axum::body::to_bytes(Body::from_stream(stream), usize::MAX)
        .await
        .expect("a refusal body ends");
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(body["error"]["code"], -32003, "{body}");
}

#[tokio::test]
async fn ac_sub_1_a_listen_without_a_filter_is_refused() {
    // A request that never said what it wanted. An *empty* filter is a
    // different thing and is accepted.
    let (status, body) = post_modern("subscriptions/listen", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
}

#[tokio::test]
async fn ac_sub_1_resources_subscribe_is_refused_on_the_modern_path() {
    // Replaced, not merely deprecated. A client that can still reach the old
    // method has no reason to move to the new one.
    let (status, body) = post_modern("resources/subscribe", json!({ "uri": "file:///x" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], -32601, "{body}");
}

#[tokio::test]
async fn ac_sub_1_resources_subscribe_is_refused_on_the_legacy_path_too() {
    // F24: the gateway never delivers `resources/updated`, so a legacy
    // subscription it accepted would wait forever. Refused on both eras.
    let (_status, body) = post(
        false,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/subscribe",
                "params": { "uri": "file:///x" } }),
        &[],
    )
    .await;
    assert_eq!(body["error"]["code"], -32601, "{body}");
}

#[tokio::test]
async fn ac_task_1_tasks_get_reports_an_unknown_handle() {
    let (mut request, mut headers) = modern_call("tasks/get", json!({ "taskId": "task-unknown" }));
    request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
        json!({ "extensions": { "io.modelcontextprotocol/tasks": {} } });
    headers.push(("mcp-name", "task-unknown".to_string()));
    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let (status, body) = post(true, request, &borrowed).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(body["error"]["message"], "no such task", "{body}");
    assert!(
        body.get("result").is_none(),
        "a missing task is not success: {body}"
    );
    assert!(body["error"].get("data").is_none(), "{body}");
}

#[tokio::test]
async fn ac_task_1_tasks_get_is_not_reachable_on_the_legacy_path() {
    // The extension belongs to a revision the legacy client does not speak.
    let (status, body) = post(
        false,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tasks/get",
                "params": { "taskId": "task-x" } }),
        &[],
    )
    .await;
    assert!(
        body.get("error").is_some() || status != StatusCode::OK,
        "a 2025 client has no tasks extension: {body}"
    );
}

/// A GET on /mcp, with whatever era headers the caller sent.
///
/// The SSE body is deliberately never read: it is an open stream, so a test
/// that read it to completion would hang rather than fail. The stream's
/// identity is its status and content type, which is what SUB.1.3 asserts.
async fn get_mcp(
    state: &Arc<AppState>,
    headers: &[(&str, &str)],
) -> (StatusCode, Option<String>, Option<String>, Option<Value>) {
    let mut builder = Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = create_router(Arc::clone(state))
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("router must answer");
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let allow = response
        .headers()
        .get(axum::http::header::ALLOW)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let streaming = content_type
        .as_deref()
        .is_some_and(|ct| ct.contains("text/event-stream"));
    if streaming {
        return (status, content_type, allow, None);
    }
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (
        status,
        content_type,
        allow,
        Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null)),
    )
}

/// MIK-7272.SUB.1.1 -- the 2026 revision deleted GET /mcp, so a caller
/// declaring that era is refused and told which method replaced it.
#[tokio::test]
async fn ac_sub_1_1_modern_get_is_refused_and_names_the_replacement() {
    let (state, _store_dir) = state(true).await;
    let (status, content_type, allow, body) =
        get_mcp(&state, &[("mcp-protocol-version", "2026-07-28")]).await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "modern GET must be refused"
    );
    assert!(
        !content_type
            .as_deref()
            .unwrap_or("")
            .contains("text/event-stream"),
        "a refusal must not look like a stream: {content_type:?}"
    );
    assert_eq!(
        allow.as_deref(),
        Some("POST"),
        "RFC 9110 requires a 405 to name the methods that do work"
    );
    let body = body.expect("a refusal carries a JSON-RPC body");
    assert_eq!(body["error"]["code"], json!(-32600), "body: {body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("subscriptions/listen"),
        "the refusal must name the replacement: {message}"
    );
}

/// MIK-7272.SUB.1.2 -- with the modern era switched off, the same caller
/// gets the unsupported-version answer the POST path already gives it.
#[tokio::test]
async fn ac_sub_1_2_modern_get_is_unsupported_when_modern_is_off() {
    let (state, _store_dir) = state(false).await;
    let (status, _, _, body) = get_mcp(&state, &[("mcp-protocol-version", "2026-07-28")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body = body.expect("a refusal carries a JSON-RPC body");
    assert_eq!(body["error"]["code"], json!(-32022), "body: {body}");
    assert_eq!(
        body["error"]["data"]["supportedVersions"],
        json!([]),
        "a gateway serving no modern version supports none: {body}"
    );
}

/// MIK-7272.SUB.1.2b -- a 2026 revision this build does not serve is
/// stateless, so it is refused, but naming `subscriptions/listen` would
/// send it to a method that refuses that same version.
#[tokio::test]
async fn ac_sub_1_2b_unserved_2026_revision_is_not_told_to_use_listen() {
    let (state, _store_dir) = state(true).await;
    let (status, _, _, body) = get_mcp(&state, &[("mcp-protocol-version", "2026-11-01")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body = body.expect("a refusal carries a JSON-RPC body");
    assert_eq!(body["error"]["code"], json!(-32022), "body: {body}");
    assert_eq!(
        body["error"]["data"]["supportedVersions"],
        json!(["2026-07-28"]),
        "the answer must say what this build does serve: {body}"
    );
    assert!(
        !body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("subscriptions/listen"),
        "an unserved revision must not be sent to a method it cannot call: {body}"
    );
}

/// MIK-7272.SUB.1.3 -- the negative control. A caller that declared nothing,
/// or declared a 2025 revision, still gets its stream; without this row,
/// "refuse every GET" would satisfy every other row here.
#[tokio::test]
async fn ac_sub_1_3_legacy_get_still_opens_the_stream() {
    let (state, _store_dir) = state(true).await;
    for headers in [
        &[][..],
        &[("mcp-protocol-version", "2025-06-18")][..],
        &[("mcp-protocol-version", "2025-11-25")][..],
    ] {
        let (status, content_type, _, _) = get_mcp(&state, headers).await;
        assert_eq!(status, StatusCode::OK, "legacy GET {headers:?} must stream");
        assert!(
            content_type
                .as_deref()
                .unwrap_or("")
                .contains("text/event-stream"),
            "legacy GET {headers:?} must stream: {content_type:?}"
        );
    }
}

/// MIK-7272.SUB.3.1 -- the refusal must happen before any session work. A
/// gate placed after `get_or_create_session_for` would mint an entry per
/// refused caller, and `create_sse_response` would overwrite the event id
/// the owner is resuming from.
#[tokio::test]
async fn ac_sub_3_1_refused_modern_get_leaves_resumption_state_alone() {
    let (state, _store_dir) = state(true).await;

    // Seeded through the real legacy path, not a fixture: the same handler
    // under test is what stores the id; the probe is the id it mints (F9).
    let seed = Request::get("/mcp").header("accept", "text/event-stream");
    let seed = seed.header("last-event-id", "seed-1").body(Body::empty());
    let router = create_router(Arc::clone(&state));
    let seeding = router
        .oneshot(seed.expect("request"))
        .await
        .expect("answer");
    assert_eq!(seeding.status(), StatusCode::OK, "seeding GET must stream");
    let probe = seeding.headers()["mcp-session-id"].to_str().expect("id");
    assert_eq!(
        state.multiplexer.last_event_id(probe),
        Some("seed-1".to_string()),
        "seeding failed, so the assertion below would pass vacuously"
    );
    let sessions_before = state.multiplexer.session_count();

    let (status, _, _, _) = get_mcp(
        &state,
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-session-id", probe),
            ("last-event-id", "seed-2"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "modern GET must be refused"
    );
    assert_eq!(
        state.multiplexer.last_event_id(probe),
        Some("seed-1".to_string()),
        "a refused caller must not move the owner's resumption point"
    );
    assert_eq!(
        state.multiplexer.session_count(),
        sessions_before,
        "a refused caller must not mint a session"
    );

    // A session id the multiplexer has never seen. With the seeded id above,
    // a gate moved below `get_or_create_session_for` would find that entry
    // already present and mint nothing, so the count assertion would pass on
    // a misplaced gate. This row is what makes it sensitive to that move.
    let (status, _, _, _) = get_mcp(
        &state,
        &[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-session-id", "sub3-never-seen"),
            ("last-event-id", "seed-3"),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "modern GET must be refused"
    );
    assert_eq!(
        state.multiplexer.session_count(),
        sessions_before,
        "a refused caller must not mint a session for an unseen id"
    );
    assert_eq!(
        state.multiplexer.last_event_id("sub3-never-seen"),
        None,
        "a refused caller must not create resumption state"
    );
}

/// MIK-7272.SUB.1.4 -- an intermediary may fold two field lines into one
/// comma-separated value, so the modern token can arrive in either position.
/// Wherever it sits, it decides.
#[tokio::test]
async fn ac_sub_1_4_a_modern_token_decides_wherever_it_sits() {
    let (state, _store_dir) = state(true).await;
    for headers in [
        &[
            ("mcp-protocol-version", "2025-06-18"),
            ("mcp-protocol-version", "2026-07-28"),
        ][..],
        &[("mcp-protocol-version", "2025-06-18, 2026-07-28")][..],
        &[("mcp-protocol-version", "2026-07-28, 2025-06-18")][..],
    ] {
        let (status, content_type, allow, body) = get_mcp(&state, headers).await;
        assert_eq!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "a modern token in {headers:?} must be refused"
        );
        assert!(
            !content_type
                .as_deref()
                .unwrap_or("")
                .contains("text/event-stream"),
            "{headers:?} must not stream"
        );
        assert_eq!(allow.as_deref(), Some("POST"), "headers: {headers:?}");
        let body = body.expect("a refusal carries a JSON-RPC body");
        assert_eq!(body["error"]["code"], json!(-32600), "body: {body}");
    }
}

/// A legacy caller that repeats its own version is still a legacy caller.
/// Refusing every repeat as ambiguous would take the stream away from a path
/// this change does not own.
#[tokio::test]
async fn ac_sub_1_4_a_repeated_legacy_version_still_streams() {
    let (state, _store_dir) = state(true).await;
    for headers in [
        &[
            ("mcp-protocol-version", "2025-06-18"),
            ("mcp-protocol-version", "2025-06-18"),
        ][..],
        &[("mcp-protocol-version", "2025-06-18, 2025-03-26")][..],
    ] {
        let (status, content_type, _, _) = get_mcp(&state, headers).await;
        assert_eq!(status, StatusCode::OK, "legacy {headers:?} must stream");
        assert!(
            content_type
                .as_deref()
                .unwrap_or("")
                .contains("text/event-stream"),
            "legacy {headers:?} must stream: {content_type:?}"
        );
    }
}

/// A GET on /mcp built from raw parts, for the two cases the `&str` helper
/// cannot express: a header value carrying a byte above 0x7F, and no
/// `Accept` header at all.
async fn get_mcp_raw(state: &Arc<AppState>, request: Request<Body>) -> StatusCode {
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer")
        .status()
}

/// MIK-7272.SUB.1.1 -- `HeaderValue::to_str` refuses a whole value that
/// carries `obs-text`, so decoding before tokenising would discard a modern
/// token along with the high byte hiding it, and serve the legacy stream.
#[tokio::test]
async fn ac_sub_1_1_a_high_byte_cannot_hide_a_modern_token() {
    let request = Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .header(
            "mcp-protocol-version",
            axum::http::HeaderValue::from_bytes(b"\xff, 2026-07-28")
                .expect("obs-text is a legal header value"),
        )
        .body(Body::empty())
        .expect("request");
    let (state, _store_dir) = state(true).await;
    assert_eq!(
        get_mcp_raw(&state, request).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "an undecodable neighbouring token must not save a modern caller"
    );
}

/// MIK-7272.SUB.1.1 -- every other row sends `Accept: text/event-stream`, so
/// a gate slid below the `Accept` negotiation would keep them all green
/// while answering 406 here.
#[tokio::test]
async fn ac_sub_1_1_the_refusal_precedes_the_accept_check() {
    let request = Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("mcp-protocol-version", "2026-07-28")
        .body(Body::empty())
        .expect("request");
    let (state, _store_dir) = state(true).await;
    assert_eq!(
        get_mcp_raw(&state, request).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "the era refusal must not depend on what the caller accepts"
    );
}
