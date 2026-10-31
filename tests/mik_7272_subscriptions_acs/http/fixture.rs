// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixtures for the subscription HTTP tests.

use super::{
    AgentAuthState, AgentRegistry, AppState, Arc, BackendRegistry, Body, Config, GatewayKeyPair,
    MetaMcp, MtlsConfig, MtlsPolicy, NotificationMultiplexer, ProxyManager, Request,
    ResolvedAuthConfig, ServiceExt, StatusCode, StoreLimits, SubscriptionRegistry, ToolPolicy,
    ToolPolicyConfig, Value, auth_state, create_router, json, open_runtime,
};

/// The gateway state, plus the directory its task store leases.
///
/// The store holds that directory for as long as the service lives, and the
/// cases here keep listen streams open across several steps, so the caller
/// binds the `TempDir` for the whole test rather than dropping it here.
pub(crate) async fn state(modern: bool) -> (Arc<AppState>, tempfile::TempDir) {
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
    let subscriptions = Arc::new(SubscriptionRegistry::new(
        64,
        auth_state(&config.auth, crate::record_key::RECORD_KEY),
    ));
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
        process: std::sync::Arc::default(),
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        session_lifecycle: None,
        env: None,
        meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
        backends,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        key_server: None,
        tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
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
        live_config: Arc::new(mcp_gateway::gateway::test_helpers::live_config(
            mcp_gateway::gateway::test_helpers::flags_off(config.clone()),
            Arc::new(ResolvedAuthConfig::from_config(
                &config.auth,
                crate::record_key::RECORD_KEY,
            )),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

pub(super) async fn post(
    modern: bool,
    body: Value,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
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

pub(super) fn modern_call(method: &str, params: Value) -> (Value, Vec<(&'static str, String)>) {
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

pub(super) async fn post_modern(method: &str, params: Value) -> (StatusCode, Value) {
    let (body, owned) = modern_call(method, params);
    let borrowed: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    post(true, body, &borrowed).await
}

/// Open a `subscriptions/listen` stream and hold it.
///
/// Reads the body FRAME BY FRAME. `to_bytes` waits for the end of the
/// body, and the whole point of this response is that there is no end —
/// a test written that way hangs rather than fails.
pub(crate) async fn open_listen(
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
pub(crate) async fn next_data(stream: &mut axum::body::BodyDataStream) -> Option<Value> {
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
