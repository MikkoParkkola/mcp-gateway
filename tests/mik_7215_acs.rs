// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7215 — stateless request handling, the
//! second increment of MCP revision 2026-07-28 support.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 2".
//!
//! Request frames here are transcribed from the specification's examples, not
//! built from the gateway's own types. Increment 1 shipped a nonconforming
//! discovery document that every test passed, because the tests asserted the
//! same invented field names. Once was enough.

use mcp_gateway::protocol::meta::{RequestShape, classify_request};
use serde_json::json;

/// A modern request, as the specification writes one.
fn modern_params() -> serde_json::Value {
    json!({
        "name": "get_weather",
        "arguments": { "location": "Helsinki" },
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "ExampleClient",
                "version": "1.0.0"
            }
        }
    })
}

// ===========================================================================
// MIK-7215.STATELESS.1 — a request carrying its own protocol version is served
// with no prior handshake, and dispatch is per request.
// ===========================================================================

#[test]
fn ac_stateless_1_a_request_carrying_its_own_version_is_modern() {
    match classify_request(Some(&modern_params()), None) {
        RequestShape::Modern(fields) => {
            assert_eq!(fields.protocol_version, "2026-07-28");
            assert_eq!(
                fields.client_info_name.as_deref(),
                Some("ExampleClient"),
                "clientInfo travels as context, and is read — but never trusted for authorization"
            );
        }
        other => panic!("a request carrying the protocol fields is modern, got {other:?}"),
    }
}

#[test]
fn ac_stateless_1_each_request_carries_its_own_version() {
    // Per REQUEST, not per connection. Two requests declaring different
    // versions are each classified under their own; an implementation that
    // remembered the first would serve the second wrongly, which is exactly
    // what the removal of the handshake is meant to prevent.
    let mut first = modern_params();
    first["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
    let mut second = modern_params();
    second["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2027-01-01");

    let a = classify_request(Some(&first), None);
    let b = classify_request(Some(&second), None);

    match (a, b) {
        (RequestShape::Modern(x), RequestShape::Modern(y)) => {
            assert_eq!(x.protocol_version, "2026-07-28");
            assert_eq!(y.protocol_version, "2027-01-01");
        }
        other => panic!("both are modern requests, got {other:?}"),
    }
}

// ===========================================================================
// MIK-7215.STATELESS.9 — both protocol fields are required. A request missing
// either is malformed: -32602, HTTP 400.
// ===========================================================================

#[test]
fn ac_stateless_9_missing_protocol_version_is_malformed() {
    let mut params = modern_params();
    params["_meta"]
        .as_object_mut()
        .expect("_meta is an object")
        .remove("io.modelcontextprotocol/protocolVersion");

    match classify_request(Some(&params), None) {
        RequestShape::Malformed { missing } => assert!(
            missing.contains(&"io.modelcontextprotocol/protocolVersion"),
            "the error must name what was missing, got {missing:?}"
        ),
        other => panic!("a modern request without its version is malformed, got {other:?}"),
    }
}

#[test]
fn ac_stateless_9_missing_client_capabilities_is_malformed() {
    // The one an implementer skips, because the field looks optional and
    // nothing appears to break without it. The specification lists it as
    // Required: Yes, alongside the version.
    let mut params = modern_params();
    params["_meta"]
        .as_object_mut()
        .expect("_meta is an object")
        .remove("io.modelcontextprotocol/clientCapabilities");

    match classify_request(Some(&params), None) {
        RequestShape::Malformed { missing } => assert!(
            missing.contains(&"io.modelcontextprotocol/clientCapabilities"),
            "the error must name what was missing, got {missing:?}"
        ),
        other => {
            panic!("a modern request without declared capabilities is malformed, got {other:?}")
        }
    }
}

#[test]
fn ac_stateless_9_a_request_with_no_protocol_meta_is_legacy_not_malformed() {
    // THE ROW THAT DECIDES THE DESIGN.
    //
    // A 2025 client sends no `_meta` protocol fields at all — and so does a
    // 2026 client that forgot a required one. One must be served and the other
    // refused, so absence alone cannot be the discriminator.
    //
    // Resolution: malformed means "declared itself modern and then omitted
    // something". A request that declares nothing has not declared itself
    // modern, so it is legacy. Refusing it would break every 2025 client, which
    // is a worse error than telling a broken 2026 client its method is unknown.
    let legacy = json!({ "name": "get_weather", "arguments": {} });
    assert!(
        matches!(classify_request(Some(&legacy), None), RequestShape::Legacy),
        "a request with no protocol metadata is a 2025 client, not a broken 2026 one"
    );

    // Including the shape with an empty `_meta` — `_meta` is a general-purpose
    // extension field and its mere presence declares nothing about the era.
    let empty_meta = json!({ "name": "get_weather", "_meta": {} });
    assert!(
        matches!(classify_request(Some(&empty_meta), None), RequestShape::Legacy),
        "`_meta` carries more than protocol fields; an empty one declares no era"
    );

    // And no params at all.
    assert!(matches!(classify_request(None, None), RequestShape::Legacy));
}

#[test]
fn ac_stateless_9_a_partially_declared_request_is_malformed_not_legacy() {
    // The complement of the row above, and the reason it is not circular: a
    // request carrying ONE protocol field has declared itself modern, so the
    // missing one is an error rather than an absence.
    let params = json!({
        "name": "get_weather",
        "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" }
    });
    assert!(
        matches!(
            classify_request(Some(&params), None),
            RequestShape::Malformed { .. }
        ),
        "declaring a version and omitting capabilities is a broken modern request"
    );
}

#[test]
fn ac_stateless_9_other_meta_keys_do_not_make_a_request_modern() {
    // `_meta` is shared with tracing, extensions and anything else. A request
    // carrying only a trace context is a 2025 client with a tracing header, and
    // reading it as a broken modern request would refuse a working client.
    let params = json!({
        "name": "get_weather",
        "_meta": { "traceparent": "00-abc-def-01", "vendor.example/thing": 1 }
    });
    assert!(
        matches!(classify_request(Some(&params), None), RequestShape::Legacy),
        "unrelated _meta keys declare no era"
    );
}

// ===========================================================================
// Integration: the modern request as it arrives over Streamable HTTP.
//
// STATELESS.2 (serverInfo on every result), STATELESS.3 (no Mcp-Session-Id on
// the modern path, still there on the legacy one) and STATELESS.9 (a malformed
// modern request is refused) are all properties of one seam — what a modern
// response looks like — so they are exercised together against the real router.
// ===========================================================================

mod http {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use mcp_gateway::backend::BackendRegistry;
    use mcp_gateway::config::Config;
    use mcp_gateway::gateway::auth::ResolvedAuthConfig;
    use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
    use mcp_gateway::gateway::proxy::ProxyManager;
    use mcp_gateway::gateway::streaming::NotificationMultiplexer;
    use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
    use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
    use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn state() -> Arc<AppState> {
        state_with_modern(true)
    }

    fn state_with_modern(modern: bool) -> Arc<AppState> {
        let mut config = Config::default();
        config.server.modern_protocol = modern;
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&backends),
            config.streaming.clone(),
        ));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        let agent_registry = Arc::new(AgentRegistry::new());
        Arc::new(AppState {
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
            live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
            export_status: None,
            transparency_log: None,
            dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        })
    }

    /// POST to `/mcp`, returning status, the session header if any, and the body.
    async fn post_mcp(body: Value) -> (StatusCode, Option<String>, Value) {
        post_mcp_against(state(), body).await
    }

    async fn post_mcp_against(
        state: Arc<AppState>,
        body: Value,
    ) -> (StatusCode, Option<String>, Value) {
        let router = create_router(state);
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");

        // A conforming modern client mirrors its body into the standard
        // headers. Derived from the body here rather than hard-coded, so these
        // tests always send what they claim to send; increment 3 sends
        // deliberately disagreeing headers of its own.
        if let Some(version) = body
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str)
        {
            builder = builder.header("mcp-protocol-version", version);
            if let Some(method) = body.get("method").and_then(Value::as_str) {
                builder = builder.header("mcp-method", method);
                if matches!(method, "tools/call" | "resources/read" | "prompts/get")
                    && let Some(name) = body
                        .pointer("/params/name")
                        .or_else(|| body.pointer("/params/uri"))
                        .and_then(Value::as_str)
                {
                    builder = builder.header("mcp-name", name);
                }
            }
        }

        let request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = router.oneshot(request).await.expect("router must answer");
        let status = response.status();
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body must read");
        (
            status,
            session,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// A modern `tools/list`, transcribed from the specification's shape.
    fn modern_tools_list(id: i64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient", "version": "1.0.0"
                    }
                }
            }
        })
    }

    #[tokio::test]
    async fn ac_stateless_3_a_modern_response_carries_no_session_header() {
        let (status, session, body) = post_mcp(modern_tools_list(1)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            session, None,
            "2026-07-28 removed protocol sessions and the Mcp-Session-Id header; \
             emitting one tells a modern client to carry state that no longer exists"
        );
    }

    #[tokio::test]
    async fn ac_stateless_3_a_legacy_response_still_carries_the_session_header() {
        // The regression that matters. A change that strips the header
        // unconditionally satisfies the row above and breaks every 2025 client.
        let (status, session, body) = post_mcp(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list"
        }))
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            session.is_some(),
            "a 2025 client must keep the session header it has always received"
        );
    }

    #[tokio::test]
    async fn ac_stateless_2_a_modern_result_identifies_the_server() {
        let (_, _, body) = post_mcp(modern_tools_list(3)).await;

        let info = &body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"];
        assert!(
            info["name"].is_string() && info["version"].is_string(),
            "a stateless client has no handshake to learn who it is talking to, \
             so every result identifies the server: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_2_a_legacy_result_is_unchanged() {
        // The mirror. Adding serverInfo to the shared result builder would
        // change the 2025 wire format for every existing client.
        let (_, _, body) = post_mcp(json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/list"
        }))
        .await;

        assert!(
            body["result"].get("_meta").is_none(),
            "a 2025 result gains no fields: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_9_a_malformed_modern_request_is_refused() {
        // Declared a version, omitted the capabilities. Refused, not served.
        let (status, _, body) = post_mcp(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/list",
            "params": {
                "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" }
            }
        }))
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the specification requires 400 for a malformed request: {body}"
        );
        assert_eq!(body["error"]["code"], -32602, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("clientCapabilities"),
            "the error names the field that was missing: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_4_an_unsupported_version_is_refused_with_its_own_error() {
        // A modern client naming a revision this gateway cannot serve gets a
        // recognised modern error listing what it can serve — which is what
        // lets the client retry on a shared version instead of guessing.
        let mut request = modern_tools_list(6);
        request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
        let (status, _, body) = post_mcp(request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["error"]["code"], -32022,
            "UnsupportedProtocolVersion, renumbered from -32004 by this revision: {body}"
        );
        let supported = &body["error"]["data"]["supportedVersions"];
        assert!(
            supported.is_array() && !supported.as_array().expect("array").is_empty(),
            "the error must list what the server does support: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_6_ping_is_refused_on_the_modern_path() {
        // `ping` was removed by this revision. A modern peer that can still
        // call it is not speaking this revision, whatever its version string
        // claims.
        let mut request = modern_tools_list(7);
        request["method"] = json!("ping");
        let (_, _, body) = post_mcp(request).await;

        assert!(
            body.get("error").is_some(),
            "ping is removed in 2026-07-28 and must be refused: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_6_ping_still_works_on_the_legacy_path() {
        // The regression. A version-blind removal satisfies the row above and
        // breaks every 2025 client's health check — and this gateway's own
        // backend health probe is a `ping`.
        let (status, _, body) = post_mcp(json!({
            "jsonrpc": "2.0", "id": 8, "method": "ping"
        }))
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.get("error").is_none(),
            "a 2025 client keeps the ping it has always had: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_8_one_endpoint_serves_both_eras() {
        // The dual-era claim, end to end: the same URL answers a 2025 client
        // and a 2026 client, and each gets its own era's treatment.
        let (legacy_status, legacy_session, legacy_body) = post_mcp(json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/list"
        }))
        .await;
        let (modern_status, modern_session, modern_body) = post_mcp(modern_tools_list(10)).await;

        assert_eq!(legacy_status, StatusCode::OK, "{legacy_body}");
        assert_eq!(modern_status, StatusCode::OK, "{modern_body}");
        assert!(
            legacy_session.is_some(),
            "the 2025 caller keeps its session"
        );
        assert_eq!(modern_session, None, "the 2026 caller is given none");
        assert!(
            legacy_body["result"]["tools"].is_array() && modern_body["result"]["tools"].is_array(),
            "both are served the tools, whatever era they speak"
        );
    }

    #[tokio::test]
    async fn ac_stateless_8_modern_serving_is_off_unless_switched_on() {
        // The default an operator inherits on upgrade. Until the revision is
        // served completely, a client that asks for it is refused with an
        // answer it can act on — not served half a revision, where the working
        // half hides the missing one.
        let (status, _, body) =
            post_mcp_against(state_with_modern(false), modern_tools_list(11)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32022, "{body}");
        assert_eq!(
            body["error"]["data"]["supportedVersions"],
            json!([]),
            "with the switch off the gateway claims no modern revision at all: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_8_a_legacy_client_is_unaffected_by_the_switch() {
        // The switch governs the modern path and nothing else. A 2025 client
        // sees the same gateway either way.
        for modern in [false, true] {
            let (status, session, body) = post_mcp_against(
                state_with_modern(modern),
                json!({ "jsonrpc": "2.0", "id": 12, "method": "tools/list" }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "modern={modern}: {body}");
            assert!(session.is_some(), "modern={modern}: {body}");
        }
    }

    #[tokio::test]
    async fn ac_stateless_5_an_unknown_method_is_404_with_a_json_rpc_body() {
        // The status distinguishes this from a legacy HTTP+SSE server that does
        // not host the modern endpoint at all: that 404 has no JSON-RPC body,
        // and a client uses the difference to decide whether to fall back.
        let mut request = modern_tools_list(13);
        request["method"] = json!("does/not/exist");
        let (status, _, body) = post_mcp(request).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], -32601, "{body}");
        assert_eq!(
            body["jsonrpc"], "2.0",
            "the body is what tells this apart from a transport-level 404: {body}"
        );
    }

    #[tokio::test]
    async fn ac_stateless_10_an_undeclared_capability_is_named_in_the_refusal() {
        // The gateway must not rely on a capability the client did not declare.
        // When it needs one, the refusal says which — a client cannot fix what
        // it is not told.
        let mut request = modern_tools_list(14);
        request["method"] = json!("sampling/createMessage");
        let (status, _, body) = post_mcp(request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        let required = &body["error"]["data"]["requiredCapabilities"];
        assert!(
            required
                .as_array()
                .is_some_and(|c| c.iter().any(|v| v == "sampling")),
            "the refusal must name the capability that was missing: {body}"
        );
    }
}

// ===========================================================================
// MIK-7215.STATELESS.7 — the gateway MUST NOT emit `notifications/message` for
// a request that carried no `io.modelcontextprotocol/logLevel`.
//
// Satisfied by absence: the gateway emits no log notifications at all today
// (searched 2026-08-29 — the only occurrence of the method name in `src/` is a
// doc comment). An absence is a fine way to satisfy a MUST NOT, and a terrible
// way to keep satisfying it, because the day someone adds emission nothing
// says the rule exists.
//
// So the absence is pinned rather than assumed. When log notifications are
// implemented, this test fails — and the fix is not to delete it but to replace
// it with one that asserts the gate at the emission site.
// ===========================================================================

#[test]
fn ac_stateless_7_the_gateway_emits_no_log_notifications() {
    use std::path::Path;

    fn scan(dir: &Path, hits: &mut Vec<String>) {
        let entries = std::fs::read_dir(dir).expect("source tree must be readable");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, hits);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                for (n, line) in text.lines().enumerate() {
                    // The emission shape, not the mention: a doc comment naming
                    // the method is not an emission, and this test is about
                    // what the gateway sends.
                    if line.contains("\"notifications/message\"") {
                        hits.push(format!("{}:{}", path.display(), n + 1));
                    }
                }
            }
        }
    }

    let mut hits = Vec::new();
    scan(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut hits,
    );

    assert!(
        hits.is_empty(),
        "the gateway now emits log notifications at {hits:?} — MIK-7215.STATELESS.7 \
         requires that none is sent for a request carrying no \
         `io.modelcontextprotocol/logLevel`. Enforce it at that site and replace \
         this test with one that asserts the gate."
    );
}
