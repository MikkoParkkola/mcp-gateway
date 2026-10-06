// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6: no delivered `cacheScope` is `public`.
//!
//! Design: `docs/design/2026-09-30-parent-6-cache-scope-type-guard.md`. Every
//! wire case here has a stub backend answer `"cacheScope": "public"` and asserts
//! a successful response carrying exactly `"private"`.

use std::path::Path;

mod source_checks {
    use super::*;

    const CACHEABLE: &str = include_str!("../src/protocol/cacheable.rs");
    const MESSAGES: &str = include_str!("../src/protocol/messages.rs");
    const TASKS: &str = include_str!("../src/protocol/tasks.rs");
    const ATTRIBUTE: &str =
        "serialize_with = \"crate::protocol::cacheable::serialize_delivered_result\"";

    /// Test 6. A source check, not behaviour: the construction half of the
    /// closing record.
    #[test]
    fn public_variant_carries_an_uninhabited_payload() {
        assert!(
            CACHEABLE.contains("Public(std::convert::Infallible)"),
            "CacheScope::Public must be uninhabited"
        );
        assert!(!CACHEABLE.contains("fn for_list"), "for_list is removed");
    }

    /// Test 7 (a). Both wire result slots carry the clamping serializer.
    #[test]
    fn both_result_slots_carry_the_clamping_serializer() {
        assert!(MESSAGES.contains(ATTRIBUTE), "JsonRpcResponse.result");
        assert!(
            MESSAGES.contains(
                "serialize_with = \"crate::protocol::cacheable::serialize_delivered_error_data\""
            ),
            "JsonRpcError.data (MIK-7702)"
        );
        assert!(TASKS.contains(ATTRIBUTE), "task snapshot result");
    }

    fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("source dir reads") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Whether `text` names the key outside a line comment, full-line or
    /// trailing. Nothing else is stripped: test code counts too, so a file is
    /// excused only by name.
    fn writes_the_key(text: &str) -> bool {
        text.lines()
            .any(|l| code_part(l).contains("\"cacheScope\""))
    }

    /// `line` up to a `//` comment, if one starts outside a string literal
    /// (so a URL in a string does not cut the line short).
    fn code_part(line: &str) -> &str {
        // `escaped`: the previous char was an unescaped `\` inside a string,
        // so `"C:\\"` closes its string (escape parity, not the prior char).
        let (mut in_string, mut escaped, mut prev) = (false, false, '\0');
        for (i, c) in line.char_indices() {
            match c {
                '\\' if in_string && !escaped => {
                    escaped = true;
                    prev = c;
                    continue;
                }
                '"' if !escaped => in_string = !in_string,
                '/' if !in_string && prev == '/' => return &line[..i - 1],
                _ => {}
            }
            escaped = false;
            prev = c;
        }
        line
    }

    /// Cutting a file at its first `#[cfg(test)]` hid every production writer
    /// after a test-gated item. The check reads whole files now.
    #[test]
    fn a_writer_after_a_test_gated_item_is_still_seen() {
        let text = concat!(
            "#[cfg(test)]\n",
            "mod t {}\n",
            "fn b() { let _ = \"cacheScope\"; }\n",
        );
        assert!(writes_the_key(text));
        assert!(!writes_the_key("// \"cacheScope\" in a comment\n"));
    }

    /// MIK-7860: a trailing comment naming the key is a comment, and a `//`
    /// inside a string literal does not hide the key after it.
    #[test]
    fn a_trailing_comment_is_not_a_writer() {
        assert!(!writes_the_key("let x = 1; // sets \"cacheScope\"\n"));
        assert!(writes_the_key(
            "let u = \"https://a.example\"; let _ = \"cacheScope\";\n"
        ));
        // An escaped backslash closes its string: the comment after it is cut,
        // and a key after a URL that follows it still counts.
        assert!(!writes_the_key("let p = \"C:\\\\\"; // \"cacheScope\"\n"));
        assert!(writes_the_key(
            "let p = \"C:\\\\\"; let u = \"https://a\"; let _ = \"cacheScope\";\n"
        ));
    }

    /// Test 7 (b). A drift check, and labelled as one: `"cacheScope"` is
    /// written only by `shape_modern_response` and the clamp.
    #[test]
    fn only_the_shaper_and_the_clamp_name_the_key() {
        let mut files = Vec::new();
        rust_files(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        // The two production writers, then every test file that names the key.
        // Fails closed: a new file naming it fails here until it is reviewed
        // and listed. Not caught: a new writer inside a listed file, or a key
        // built without the literal; the wire tests below cover delivery.
        let allowed = [
            "src/gateway/router/handlers.rs",
            "src/gateway/router/handlers/modern_response.rs",
            "src/protocol/cacheable.rs",
            "src/gateway/meta_mcp/chain_emission_tests.rs",
            // MIK-7910: pins that a bridged prompt reaches the client with its
            // scope clamped; it writes the key only into a test prompt.
            "src/gateway/meta_mcp/invoke/relay_tests.rs",
            // MIK-7887.RECEIPT.4 rows: they write the key only into backend
            // fixtures.
            "src/gateway/meta_mcp/invoke/relay_delivery_tests.rs",
            "src/gateway/router/tests/task_execution_adapter/relay_upstream.rs",
            "src/gateway/server/tests/collusion_stdio_delivered.rs",
            "src/gateway/meta_mcp/response_delivery_scope_tests.rs",
            "src/gateway/meta_mcp/signing_delivery_scope_tests.rs",
            "src/gateway/outbound/tests.rs",
            "src/gateway/router/handlers/tasks/scope_tests.rs",
            "src/gateway/server/tests/stdio_cache_scope.rs",
            "src/gateway/task_service/execution/scope_tests.rs",
            "src/gateway/webhooks/message_clamp_tests.rs",
            "src/protocol/cacheable/clamp_tests.rs",
            "src/protocol/tasks/scope_clamp_tests.rs",
        ];
        let mut offenders = Vec::new();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for path in files {
            let relative = path.strip_prefix(root).expect("under the crate root");
            let shown = relative.to_string_lossy().replace('\\', "/");
            if allowed.contains(&shown.as_str()) {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source reads");
            if writes_the_key(&text) {
                offenders.push(shown);
            }
        }
        assert!(
            offenders.is_empty(),
            "other writers of cacheScope: {offenders:?}"
        );
    }
}

/// A loopback backend that claims `public` on every successful answer, plus the
/// smallest gateway around it.
mod fixture {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use mcp_gateway::backend::{Backend, BackendRegistry};
    use mcp_gateway::config::{
        BackendConfig, Config, FailsafeConfig, SurfacedToolConfig, TransportConfig,
    };
    use mcp_gateway::gateway::auth::ResolvedAuthConfig;
    use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
    use mcp_gateway::gateway::proxy::ProxyManager;
    use mcp_gateway::gateway::streaming::NotificationMultiplexer;
    use mcp_gateway::gateway::test_helpers::{
        AppState, MetaMcp, StoreLimits, create_router, open_runtime,
    };
    use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
    use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    pub const BACKEND: &str = "backend";
    pub const TOOL: &str = "tool";
    pub const URI: &str = "file:///doc";

    /// What the backend answers to `method`: always a `public` claim.
    pub fn public_result(method: &str, calls: &AtomicUsize) -> Value {
        match method {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {}, "resources": {} },
                "serverInfo": { "name": "fixture", "version": "0" }
            }),
            "tools/list" => json!({ "tools": [
                { "name": TOOL, "description": "d", "inputSchema": { "type": "object" } }
            ]}),
            "resources/read" => json!({
                "contents": [{ "uri": URI, "text": "body" }],
                "cacheScope": "public"
            }),
            "tools/call" => {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                json!({
                    "content": [{ "type": "text", "text": format!("call-{n}") }],
                    "cacheScope": "public"
                })
            }
            _ => json!({}),
        }
    }

    /// The fixture claims `public`; a test that starts from a private fixture
    /// proves nothing.
    pub fn assert_fixture_is_public() {
        let calls = AtomicUsize::new(0);
        for method in ["tools/call", "resources/read"] {
            assert_eq!(public_result(method, &calls)["cacheScope"], "public");
        }
    }

    pub async fn spawn_backend(calls: Arc<AtomicUsize>) -> String {
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
                let calls = Arc::clone(&calls);
                async move {
                    let method = request["method"].as_str().unwrap_or_default().to_owned();
                    axum::Json(json!({
                        "jsonrpc": "2.0",
                        "id": request.get("id").cloned().unwrap_or(Value::Null),
                        "result": public_result(&method, &calls)
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the fixture backend binds a loopback port");
        let address = listener.local_addr().expect("the bound port is known");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{address}/")
    }

    /// Register the backend under [`BACKEND`]; `passthrough` skips sanitizing.
    pub fn register(state: &Arc<AppState>, url: &str, passthrough: bool) {
        let config = BackendConfig {
            enabled: true,
            passthrough,
            transport: TransportConfig::Http {
                http_url: url.to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::default()
        };
        let backend = Backend::new(
            BACKEND,
            config,
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        );
        assert!(state.backends.register(Arc::new(backend)));
    }

    /// One gateway with idempotency on and, optionally, [`TOOL`] surfaced.
    pub async fn state(surfaced: bool) -> (Arc<AppState>, tempfile::TempDir) {
        let config = Config::default();
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&backends),
            config.streaming.clone(),
        ));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        let mut meta = MetaMcp::new(Arc::clone(&backends));
        meta.enable_idempotency(
            Arc::new(mcp_gateway::idempotency::IdempotencyCache::new()),
            mcp_gateway::idempotency::CLEANUP_INTERVAL,
        );
        if surfaced {
            meta = meta.with_surfaced_tools(vec![SurfacedToolConfig {
                server: BACKEND.to_string(),
                tool: TOOL.to_string(),
            }]);
        }
        let meta_mcp = Arc::new(meta);
        let continuation = meta_mcp.continuation();
        let subscriptions = Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(
                64,
                mcp_gateway::gateway::test_helpers::auth_state(&config.auth),
            ),
        );
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
            session_lifecycle: None,
            env: None,
            meta_mcp,
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
            agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
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
            continuation,
        });
        (state, store_dir)
    }

    /// POST `body` to `uri` and return the status and parsed body.
    pub async fn post(state: &Arc<AppState>, uri: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = create_router(Arc::clone(state))
            .oneshot(request)
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
}

mod routes {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::StatusCode;
    use mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META;
    use serde_json::{Value, json};

    use super::fixture::{
        self, BACKEND, TOOL, URI, assert_fixture_is_public, register, spawn_backend,
    };

    fn direct() -> String {
        format!("/mcp/{BACKEND}")
    }

    fn tool_call(id: u32, key: Option<&str>) -> Value {
        let mut params = json!({ "name": TOOL, "arguments": { "a": 1 } });
        if let Some(key) = key {
            params["_meta"] = json!({ IDEMPOTENCY_KEY_META: key });
        }
        json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params })
    }

    fn assert_private_success(status: StatusCode, body: &Value) {
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("error").is_none(), "must be a success: {body}");
        assert_eq!(body["result"]["cacheScope"], "private", "{body}");
    }

    async fn direct_tool_call(passthrough: bool) -> (StatusCode, Value) {
        assert_fixture_is_public();
        let url = spawn_backend(Arc::new(AtomicUsize::new(0))).await;
        let (state, _dir) = fixture::state(false).await;
        register(&state, &url, passthrough);
        fixture::post(&state, &direct(), tool_call(1, None)).await
    }

    /// Test 1 (a): the sanitized-dispatch arm.
    #[tokio::test]
    async fn direct_sanitized_tools_call_is_delivered_private() {
        let (status, body) = direct_tool_call(false).await;
        assert_private_success(status, &body);
    }

    /// Test 1 (b): the passthrough arm.
    #[tokio::test]
    async fn direct_passthrough_tools_call_is_delivered_private() {
        let (status, body) = direct_tool_call(true).await;
        assert_private_success(status, &body);
    }

    /// Test 1 (c) and test 10: a replay of a stored public result, with no
    /// second dispatch.
    #[tokio::test]
    async fn direct_idempotency_replay_is_delivered_private() {
        assert_fixture_is_public();
        let calls = Arc::new(AtomicUsize::new(0));
        let url = spawn_backend(Arc::clone(&calls)).await;
        let (state, _dir) = fixture::state(false).await;
        register(&state, &url, false);

        let (first_status, first) = fixture::post(&state, &direct(), tool_call(1, Some("k"))).await;
        let (status, replay) = fixture::post(&state, &direct(), tool_call(2, Some("k"))).await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the replay must not dispatch"
        );
        assert_private_success(first_status, &first);
        assert_private_success(status, &replay);
        assert_eq!(replay["result"]["content"], first["result"]["content"]);
    }

    /// Test 2: direct `resources/read`, which a backend answers itself.
    #[tokio::test]
    async fn direct_resources_read_is_delivered_private() {
        assert_fixture_is_public();
        let url = spawn_backend(Arc::new(AtomicUsize::new(0))).await;
        let (state, _dir) = fixture::state(false).await;
        register(&state, &url, false);
        let request = json!({
            "jsonrpc": "2.0", "id": 5, "method": "resources/read", "params": { "uri": URI }
        });

        let (status, body) = fixture::post(&state, &direct(), request).await;

        assert_private_success(status, &body);
        assert_eq!(body["result"]["contents"][0]["uri"], URI, "{body}");
    }

    /// Test 3 (HTTP leg): a surfaced backend tool on the meta route returns the
    /// backend's envelope directly.
    #[tokio::test]
    async fn meta_route_surfaced_tool_is_delivered_private() {
        assert_fixture_is_public();
        let url = spawn_backend(Arc::new(AtomicUsize::new(0))).await;
        let (state, _dir) = fixture::state(true).await;
        register(&state, &url, false);

        let (status, body) = fixture::post(&state, "/mcp", tool_call(6, None)).await;

        assert_private_success(status, &body);
        assert_eq!(body["result"]["content"][0]["text"], "call-1", "{body}");
    }
}
