// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7214 — the standard request headers of
//! MCP 2026-07-28, and the validation that must happen before the gateway acts
//! on them.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 3".
//!
//! The encoding table below is transcribed from the specification, not produced
//! by our own encoder. A round-trip through our encoder would prove that our
//! encoder agrees with our decoder — a property that was already worth nothing
//! once this release, when a whole increment passed against an invented wire
//! format.

use mcp_gateway::protocol::headers::{HeaderCheck, decode_header_value, mcp_name_required};

// ===========================================================================
// MIK-7214.HEADER.4 — sentinel encoding.
//
// Every row here is copied from the specification's "Encoding examples" table,
// read 2026-08-29. Original value on the left, header value on the right.
// ===========================================================================

/// The specification's own table. Transcribed, not generated.
const SPEC_ENCODING_TABLE: &[(&str, &str)] = &[
    // Plain ASCII passes through untouched.
    ("us-west1", "us-west1"),
    // Non-ASCII.
    ("Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="),
    // Leading and trailing whitespace.
    (" padded ", "=?base64?IHBhZGRlZCA=?="),
    // Embedded newline.
    ("line1\nline2", "=?base64?bGluZTEKbGluZTI=?="),
    // A plain-ASCII value that happens to look like the sentinel. The
    // specification requires clients to encode this one precisely so a server
    // cannot mistake it for an encoded value.
    ("=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="),
];

#[test]
fn ac_header_4_the_specifications_encoding_table_decodes() {
    for (original, header_value) in SPEC_ENCODING_TABLE {
        assert_eq!(
            decode_header_value(header_value).as_deref(),
            Some(*original),
            "the specification's own example must decode: {header_value}"
        );
    }
}

#[test]
fn ac_header_4_a_sentinel_value_is_not_taken_literally() {
    // The ambiguity the specification calls out by name. `=?base64?literal?=`
    // arrives Base64-encoded; a server that compared the raw header against the
    // body would see the sentinel wrapper and reject a valid request.
    let encoded = "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=";
    assert_eq!(
        decode_header_value(encoded).as_deref(),
        Some("=?base64?literal?="),
        "an encoded sentinel decodes to the literal, not to itself"
    );
}

#[test]
fn ac_header_4_a_malformed_sentinel_is_rejected_not_guessed() {
    // An attacker writes this string. Every shape below must produce a refusal:
    // not a panic, and not a silent pass that compares something else.
    for malformed in [
        "=?base64?not-valid-base64!!!?=",
        "=?base64?",
        "=?base64??=",   // empty payload
        "=?base64?SGk=", // opens like a sentinel and never closes
    ] {
        assert_eq!(
            decode_header_value(malformed),
            None,
            "a malformed sentinel must be refused, not guessed: {malformed}"
        );
    }
}

#[test]
fn ac_header_4_the_markers_are_case_sensitive() {
    // The specification: the markers "MUST appear exactly as shown
    // (lowercase)". So `=?BASE64?…?=` is not a sentinel — it is a plain value
    // that resembles one, and a client may send it literally. Refusing it would
    // reject a valid request, and decoding it would decode something the client
    // meant as text.
    //
    // The client's own obligation to encode ambiguous values is defined against
    // the lowercase pattern, so the uppercase form is never ambiguous.
    assert_eq!(
        decode_header_value("=?BASE64?SGk=?=").as_deref(),
        Some("=?BASE64?SGk=?="),
        "an uppercase marker is text, not an encoding"
    );
}

#[test]
fn ac_header_4_decoding_rejects_a_value_that_is_not_utf8() {
    // Valid Base64 whose bytes are not UTF-8. Decoding must refuse rather than
    // lossily substitute, because the result is compared against a body string
    // and a substitution would compare something the client never sent.
    // 0xFF 0xFE is not valid UTF-8.
    assert_eq!(decode_header_value("=?base64?//4=?="), None);
}

// ===========================================================================
// MIK-7214.HEADER.2 — `Mcp-Name` is required for three methods, and for no
// others. Treating it as universal rejects valid requests.
// ===========================================================================

#[test]
fn ac_header_2_mcp_name_is_required_for_exactly_three_methods() {
    for method in ["tools/call", "resources/read", "prompts/get"] {
        assert!(
            mcp_name_required(method),
            "the specification's table requires Mcp-Name for {method}"
        );
    }
    for method in [
        "tools/list",
        "prompts/list",
        "resources/list",
        "server/discover",
        "resources/templates/list",
        "completion/complete",
    ] {
        assert!(
            !mcp_name_required(method),
            "requiring Mcp-Name for {method} rejects a valid request"
        );
    }
}

// ===========================================================================
// MIK-7214.HEADER.1, .3 — the comparison itself. One function, because doing
// this in three places is how two of them end up subtly different, and the
// difference is a bypass rather than a bug.
// ===========================================================================

#[test]
fn ac_header_1_matching_header_and_body_pass() {
    let check = HeaderCheck {
        header_protocol_version: Some("2026-07-28"),
        body_protocol_version: Some("2026-07-28"),
        header_method: Some("tools/call"),
        body_method: "tools/call",
        header_name: Some("get_weather"),
        body_name: Some("get_weather"),
    };
    assert_eq!(check.validate(), Ok(()));
}

#[test]
fn ac_header_1_a_disagreeing_protocol_version_is_a_mismatch() {
    // The vulnerability row. An intermediary routing on the header and a server
    // executing on the body must not be able to disagree — the specification's
    // stated reason for requiring this check.
    let check = HeaderCheck {
        header_protocol_version: Some("2026-07-28"),
        body_protocol_version: Some("2025-11-25"),
        header_method: Some("tools/list"),
        body_method: "tools/list",
        header_name: None,
        body_name: None,
    };
    assert!(
        check.validate().is_err(),
        "a header and body naming different revisions must be refused"
    );
}

#[test]
fn ac_header_2_a_disagreeing_method_is_a_mismatch() {
    let check = HeaderCheck {
        header_protocol_version: Some("2026-07-28"),
        body_protocol_version: Some("2026-07-28"),
        header_method: Some("tools/list"),
        body_method: "tools/call",
        header_name: Some("get_weather"),
        body_name: Some("get_weather"),
    };
    assert!(
        check.validate().is_err(),
        "routing on tools/list while executing tools/call is the exact split \
         the specification names"
    );
}

#[test]
fn ac_header_2_a_disagreeing_name_is_a_mismatch() {
    let check = HeaderCheck {
        header_protocol_version: Some("2026-07-28"),
        body_protocol_version: Some("2026-07-28"),
        header_method: Some("tools/call"),
        body_method: "tools/call",
        header_name: Some("read_file"),
        body_name: Some("delete_everything"),
    };
    assert!(
        check.validate().is_err(),
        "a permitted name in the header must not carry a different call in the body"
    );
}

#[test]
fn ac_header_1_a_missing_protocol_version_header_is_a_mismatch() {
    // Required on every modern POST. Absent is not "unconstrained".
    let check = HeaderCheck {
        header_protocol_version: None,
        body_protocol_version: Some("2026-07-28"),
        header_method: Some("tools/list"),
        body_method: "tools/list",
        header_name: None,
        body_name: None,
    };
    assert!(check.validate().is_err());
}

#[test]
fn ac_header_2_a_missing_required_name_header_is_a_mismatch() {
    let check = HeaderCheck {
        header_protocol_version: Some("2026-07-28"),
        body_protocol_version: Some("2026-07-28"),
        header_method: Some("tools/call"),
        body_method: "tools/call",
        header_name: None,
        body_name: Some("get_weather"),
    };
    assert!(
        check.validate().is_err(),
        "Mcp-Name is required for tools/call, so its absence is a mismatch"
    );
}

#[test]
fn ac_header_2_an_unrequired_name_header_may_be_absent() {
    // The boundary. `tools/list` carries no name, and demanding one would
    // reject every valid listing.
    let check = HeaderCheck {
        header_protocol_version: Some("2026-07-28"),
        body_protocol_version: Some("2026-07-28"),
        header_method: Some("tools/list"),
        body_method: "tools/list",
        header_name: None,
        body_name: None,
    };
    assert_eq!(check.validate(), Ok(()));
}

// ===========================================================================
// Through the transport. The rows above prove the comparison; these prove the
// gateway performs it — on the real router, before anything acts on either
// source of truth.
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
        let mut config = Config::default();
        config.server.modern_protocol = true;
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
            subscriptions: Arc::new(
                mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
            ),
        })
    }

    /// POST with explicitly chosen headers, so a test can make them disagree.
    async fn post_with_headers(body: Value, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = create_router(state())
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

    /// As `post_against`, and also returns the parsed body for diagnosis.
    async fn post_against_json(
        app_state: &Arc<AppState>,
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
        let request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = create_router(Arc::clone(app_state))
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

    /// POST against a caller-supplied state, so several requests share one
    /// gateway and its accumulated state can be observed.
    async fn post_against(
        app_state: &Arc<AppState>,
        body: Value,
        headers: &[(&str, &str)],
    ) -> (StatusCode, axum::http::HeaderMap) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = create_router(Arc::clone(app_state))
            .oneshot(request)
            .await
            .expect("router must answer");
        (response.status(), response.headers().clone())
    }

    #[tokio::test]
    async fn a_modern_error_response_carries_no_session_header() {
        // The success path never emitted one. The *error* paths did: they use
        // the builders written for 2025, which attach the session header on
        // their way out. So a modern client that got anything wrong was handed
        // state the revision deleted, and an intermediary a value to route on.
        //
        // Driven through a mirrored-header mismatch because that is an early
        // refusal — the exact shape of response that carried it.
        let app_state = state();
        let (status, headers) = post_against(
            &app_state,
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "server/discover"),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the request must be refused"
        );
        assert!(
            !headers.contains_key("mcp-session-id"),
            "a modern refusal must not carry a session header: {headers:?}"
        );
    }

    #[tokio::test]
    async fn an_unsupported_modern_version_still_gets_no_session() {
        // A client naming a 2026 revision this build does not serve is still a
        // stateless client. Recognising only an exactly-supported version meant
        // it was handed a session its own revision deleted, and grew the table
        // on behalf of a caller about to be refused anyway.
        let app_state = state();
        let (_, headers) = post_against(
            &app_state,
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2026-99-99"),
                ("mcp-method", "tools/list"),
            ],
        )
        .await;

        assert!(
            !headers.contains_key("mcp-session-id"),
            "an unsupported modern revision must not be given a session: {headers:?}"
        );
        assert_eq!(
            app_state.multiplexer.session_count(),
            0,
            "and must not leave one behind"
        );
    }

    #[tokio::test]
    async fn a_duplicated_protocol_version_header_cannot_hide_a_modern_declaration() {
        // The bypass, stated precisely. Send the header twice - legacy first,
        // modern second - with a body carrying NO protocol metadata. Reading
        // only the first value classifies the request legacy, and the legacy
        // path never reaches the mirrored-header comparison that would have
        // noticed the duplicate, so an intermediary reading the second value
        // routes one thing while the gateway serves another.
        //
        // The body must be metadata-free for this to test anything: with modern
        // metadata the request is refused by the duplicate-header check inside
        // the modern block, and the row passes whether or not classification
        // was fixed. Verified by running it against the unfixed classifier.
        let app_state = state();
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });

        let (status, response) = post_against_json(
            &app_state,
            body,
            &[
                ("mcp-protocol-version", "2025-11-25"),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a repeated protocol-version header must be refused, never resolved: {response}"
        );
    }

    #[tokio::test]
    async fn a_legacy_error_response_still_carries_its_session_header() {
        // The regression that matters: 2025 clients track the session across a
        // refusal too.
        let app_state = state();
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "no/such/method"});
        let (_, headers) = post_against(&app_state, body, &[]).await;

        assert!(
            headers.contains_key("mcp-session-id"),
            "a legacy refusal must still carry its session header"
        );
    }

    #[tokio::test]
    async fn a_legacy_response_still_carries_its_session_header() {
        // The regression that matters: 2025 clients depend on it.
        let app_state = state();
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let (_, headers) = post_against(&app_state, body, &[]).await;

        assert!(
            headers.contains_key("mcp-session-id"),
            "a legacy response must still carry its session header"
        );
    }

    #[tokio::test]
    async fn modern_requests_do_not_accumulate_sessions() {
        // A stateless client sends no session id, so every request minted a new
        // multiplexer session nothing could ever reach: unbounded growth, and a
        // per-request identity that makes sequence anomaly detection see a first
        // call every time — a control that keeps running and stops protecting.
        let app_state = state();
        for _ in 0..5 {
            let (_, _) = post_against(
                &app_state,
                modern_body("tools/list"),
                &[
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-method", "tools/list"),
                ],
            )
            .await;
        }

        assert_eq!(
            app_state.multiplexer.session_count(),
            0,
            "a stateless request must not leave a session behind"
        );
    }

    #[tokio::test]
    async fn legacy_requests_still_get_a_session() {
        let app_state = state();
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let (_, _) = post_against(&app_state, body, &[]).await;

        assert_eq!(
            app_state.multiplexer.session_count(),
            1,
            "a legacy request must still get its session"
        );
    }

    fn modern_body(method: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
    }

    /// A `resources/read` body carrying both a `uri` and a decoy `name`.
    fn resources_read_with_decoy(uri: &str, decoy_name: &str) -> Value {
        let mut body = modern_body("resources/read");
        body["params"]["uri"] = json!(uri);
        body["params"]["name"] = json!(decoy_name);
        body
    }

    #[tokio::test]
    async fn a_decoy_name_cannot_authorise_a_different_uri_over_http() {
        // The bypass, end to end. `resources/read` executes on `uri`. While the
        // check read `name` with a fallback to `uri`, a caller could attach a
        // permitted-looking `name`, mirror THAT in the header, and have the
        // gateway read the `uri` beside it — an intermediary routing on the
        // header would have authorised a resource the gateway never fetched.
        //
        // Driven through the real router rather than the helper: a unit test of
        // the field-selection function passes even if the handler stops calling
        // it, which is the defect class this branch has already shipped once.
        let (status, body) = post_with_headers(
            resources_read_with_decoy("file:///etc/shadow", "public-readme"),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "resources/read"),
                ("mcp-name", "public-readme"),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a header agreeing with a decoy name must not authorise the uri: {body}"
        );
        assert_eq!(body["error"]["code"], -32020, "{body}");
    }

    #[tokio::test]
    async fn a_modern_notification_is_validated_before_it_is_accepted() {
        // A notification carries no id and gets no response body, but "no body"
        // is not "no checks". While 202 was returned before the mirrored-header
        // comparison ran, a notification whose header named one method and whose
        // body carried another was accepted as though it had been honoured —
        // the same header/body split the check exists to close, on the one
        // message shape that skipped it.
        let mut body = modern_body("notifications/tools/list_changed");
        body.as_object_mut().expect("object").remove("id");

        let (status, _) = post_with_headers(
            body,
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "notifications/resources/updated"),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a notification whose header disagrees with its body must be refused, not accepted"
        );
    }

    #[tokio::test]
    async fn a_valid_modern_notification_is_still_accepted() {
        // Validation must not turn into refusal: a well-formed modern
        // notification still gets its 202.
        let mut body = modern_body("notifications/tools/list_changed");
        body.as_object_mut().expect("object").remove("id");

        let (status, _) = post_with_headers(
            body,
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "notifications/tools/list_changed"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn a_legacy_notification_is_still_accepted() {
        // The regression that matters: 2025 clients send notifications and must
        // keep getting 202 for them.
        let body = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        let (status, _) = post_with_headers(body, &[]).await;

        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "a legacy notification must still be accepted"
        );
    }

    #[tokio::test]
    async fn a_header_declared_modern_request_cannot_slip_through_as_legacy() {
        // The bypass end to end: 2026-07-28 declared in the header an upstream
        // routes on, with no body metadata at all. Classifying on the body alone
        // answered Legacy and walked past the feature gate.
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        });

        let (status, response) = post_with_headers(
            body,
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a header-declared modern request with no body metadata must be refused: {response}"
        );
        assert_eq!(response["error"]["code"], -32602, "{response}");
    }

    #[tokio::test]
    async fn a_repeated_mirrored_header_is_refused_over_http() {
        // Two lines of one header let one intermediary route on the first and
        // another act on the second. The disagreement between them is the
        // bypass, arriving through the header list rather than past it.
        let (status, body) = post_with_headers(
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
                ("mcp-method", "server/discover"),
            ],
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a repeated mirrored header must be refused: {body}"
        );
        assert_eq!(body["error"]["code"], -32020, "{body}");
    }

    #[tokio::test]
    async fn ac_header_3_a_disagreeing_method_header_is_refused_over_http() {
        // The vulnerability, end to end: a header naming one method and a body
        // carrying another. An intermediary that routed on the header would
        // have permitted this call under the wrong name.
        let (status, body) = post_with_headers(
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "server/discover"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32020, "HeaderMismatch: {body}");
    }

    #[tokio::test]
    async fn ac_header_1_a_disagreeing_version_header_is_refused_over_http() {
        let (status, body) = post_with_headers(
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2025-11-25"),
                ("mcp-method", "tools/list"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32020, "{body}");
    }

    #[tokio::test]
    async fn ac_header_1_a_missing_version_header_is_refused_over_http() {
        let (status, body) =
            post_with_headers(modern_body("tools/list"), &[("mcp-method", "tools/list")]).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32020, "{body}");
    }

    #[tokio::test]
    async fn ac_header_1_matching_headers_are_served() {
        let (status, body) = post_with_headers(
            modern_body("tools/list"),
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
            ],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["result"]["tools"].is_array(), "{body}");
    }

    #[tokio::test]
    async fn ac_header_2_a_legacy_request_needs_no_headers() {
        // The regression. A version-blind header requirement would refuse every
        // 2025 client, none of which has ever sent one.
        let (status, body) = post_with_headers(
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
            &[],
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("error").is_none(), "{body}");
    }
}
