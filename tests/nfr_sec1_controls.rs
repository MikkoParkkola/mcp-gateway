// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refusal tests for the controls named in
//! `docs/requirements/nfr-sec1-control-inventory.md`.
//!
//! NFR.SEC.1 says EACH control that constrained a caller under 3.5.0 must have
//! a test asserting refusal when its input is absent. The four tests the
//! release ledger cited all cover controls 4.0.0 *introduced*; none covered a
//! 3.5.0 one. These do, and they do it through the only route a modern caller
//! has — a policy nothing consults refuses nothing, so calling the gate
//! function directly would be a weaker claim than the criterion makes.

mod common;
use common::*;
// Control 5 is the only test here that builds a breaker config, so these stay
// local rather than in the shared module every target compiles.
use mcp_gateway::config::CircuitBreakerConfig;
use std::time::Duration;

// ============================================================================
// NFR.SEC.1 control 3 — authentication
// A modern caller with no credential is refused before the handler runs.
// ============================================================================
#[tokio::test]
async fn control_3_a_modern_request_without_a_credential_is_refused() {
    let app = state(Fixture {
        auth: auth_with(Vec::new(), Some("secret-bearer")),
        ..Default::default()
    });
    let (status, _) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "removing the handshake must not remove the credential requirement"
    );
    // Falsifier: with the credential present the same frame is served, so the
    // refusal above is this gate's and not something refusing unconditionally.
    let (served, _) = post(
        &app,
        modern("tools/list", json!({})),
        &[("authorization", "Bearer secret-bearer")],
    )
    .await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 4 — per-client rate limit
// The second call inside the window is refused; the budget is the input.
// ============================================================================
#[tokio::test]
async fn control_4_a_modern_caller_over_its_rate_limit_is_refused() {
    let app = state(Fixture {
        auth: auth_with(vec![api_key("k", 1, None)], None),
        ..Default::default()
    });
    let header = [("authorization", "Bearer k")];
    let (first, _) = post(&app, modern("tools/list", json!({})), &header).await;
    assert_eq!(first, StatusCode::OK, "the first call is inside the budget");
    let (second, _) = post(&app, modern("tools/list", json!({})), &header).await;
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "the rate limit must still bind a caller who never handshook"
    );
}

// ============================================================================
// NFR.SEC.1 control 6 — agent identity
// `require_id` with no `X-Agent-ID` header.
// ============================================================================
#[tokio::test]
async fn control_6_a_modern_request_without_an_agent_id_is_refused() {
    let identity = mcp_gateway::config::AgentIdentityConfig {
        enabled: true,
        require_id: true,
        ..Default::default()
    };
    let app = state(Fixture {
        agent_identity: identity,
        ..Default::default()
    });
    let (status, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], -32600, "body: {body}");
    // Falsifier: the same frame carrying an agent ID is served.
    let (served, _) = post(
        &app,
        modern("tools/list", json!({})),
        &[("x-agent-id", "agent-1")],
    )
    .await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 9 — the Meta-MCP surface can be switched off
// ============================================================================
#[tokio::test]
async fn control_9_a_modern_request_to_a_disabled_surface_is_refused() {
    let app = state(Fixture {
        meta_mcp_enabled: false,
        ..Default::default()
    });
    let (status, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], -32600, "body: {body}");
    // Falsifier: the identical frame against an enabled surface is served.
    let enabled = state(Fixture::default());
    let (served, _) = post(&enabled, modern("tools/list", json!({})), &[]).await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 13 — API-key tool scope
// The existing coverage calls `authorize_tool_target` directly. This crosses
// the handler branch that consults it, by the only route a modern caller has.
// ============================================================================
fn invoke() -> Value {
    modern(
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": "some_backend", "tool": "forbidden_tool" }
        }),
    )
}

#[tokio::test]
async fn control_13_a_modern_caller_outside_its_tool_scope_is_refused() {
    let app = state(Fixture {
        auth: auth_with(
            vec![api_key("k", 0, Some(vec!["allowed_tool".to_string()]))],
            None,
        ),
        ..Default::default()
    });
    let (status, body) = post(&app, invoke(), &[("authorization", "Bearer k")]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "tool scope must still bind a modern caller; body: {body}"
    );
    // Falsifier: a key whose scope covers the target reaches past this gate, so
    // the refusal above is the scope check and not the call failing anyway.
    let in_scope = state(Fixture {
        auth: auth_with(
            vec![api_key("k", 0, Some(vec!["forbidden_tool".to_string()]))],
            None,
        ),
        ..Default::default()
    });
    let (served, body) = post(&in_scope, invoke(), &[("authorization", "Bearer k")]).await;
    assert_ne!(
        served,
        StatusCode::FORBIDDEN,
        "an in-scope key must clear the scope gate; body: {body}"
    );
}

// ============================================================================
// NFR.SEC.1 control 8 — JSON well-formedness
// `-32700` from `serde_json::from_slice` at `handlers.rs:526`. The inventory
// recorded this as "covered by 10" and it was not: a body that fails here
// never reaches `parse_request`, and the `-32700` assertions that existed
// call `build_http_error_response`, the constructor, rather than the gate.
// ============================================================================
#[tokio::test]
async fn control_8_a_modern_request_with_unparseable_json_is_refused() {
    let app = state(Fixture::default());
    let (status, body) = post_raw(&app, b"{\"jsonrpc\": \"2.0\", ".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["error"]["code"], -32700,
        "the refusal must be this gate's parse error, not a later envelope \
         check or an earlier header check; body: {body}"
    );
    // Falsifier: the same route, same headers, parseable body — served. A test
    // that refused both halves would be measuring some gate ahead of this one.
    let (served, _) = post_raw(
        &app,
        serde_json::to_vec(&modern("tools/list", json!({}))).expect("body"),
    )
    .await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 7 — request body ceiling (10 MiB)
// `axum::body::to_bytes` at `handlers.rs:513`. Built in memory rather than
// shipped as a fixture, which is what the inventory priced as too expensive.
// ============================================================================
#[tokio::test]
async fn control_7_a_modern_request_over_the_body_ceiling_is_refused() {
    let app = state(Fixture::default());
    let over = modern(
        "tools/list",
        json!({ "padding": "x".repeat(11 * 1024 * 1024) }),
    );
    let (status, _) = post(&app, over, &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the 10 MiB ceiling must still bind a caller who never handshook"
    );
    // Falsifier: the SAME shape under the ceiling is served, so the refusal is
    // the size and not the padded frame being rejected on its own account.
    let under = modern("tools/list", json!({ "padding": "x".repeat(1024 * 1024) }));
    let (served, body) = post(&app, under, &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
}

// ============================================================================
// NFR.SEC.1 control 11 — input sanitization
// The inventory excused this row as "off by default". It is not:
// `SecurityConfig::default()` sets it ON (`src/config/features/security.rs:472`)
// and the gateway reads that field into `AppState`
// (`src/gateway/server/mod.rs:1187`). What the row actually needed was a
// rejection shape that is not a moving target — a null byte, which
// `sanitize_string` refuses by contract.
// ============================================================================
#[tokio::test]
async fn control_11_a_modern_request_carrying_a_null_byte_is_refused() {
    let app = state(Fixture {
        sanitize_input: true,
        ..Default::default()
    });
    let (status, body) = post(&app, modern("tools/list", json!({ "q": "a\u{0}b" })), &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["error"]["code"], -32600,
        "the refusal must be the sanitizer's, not the JSON parser's; body: {body}"
    );
    // Falsifier one: the same frame without the null byte is served.
    let (served, body) = post(&app, modern("tools/list", json!({ "q": "ab" })), &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
    // Falsifier two: with the control off, the null byte itself is served — so
    // the refusal above is this control and not the shape being rejected
    // somewhere else on the path.
    let off = state(Fixture::default());
    let (unguarded, _) = post(&off, modern("tools/list", json!({ "q": "a\u{0}b" })), &[]).await;
    assert_eq!(
        unguarded,
        StatusCode::OK,
        "with sanitization off nothing else on the path rejects a null byte"
    );
}

// Row 2 — agent JWT validity. The inventory recorded this as open because
// driving it "needs an agent registry and a signed token". Only the second
// half is true: the absent input is *a JWT that validates*, and removing it
// needs no valid token to exist. Both refusal arms are reachable with an
// empty registry, which is what these two assert.

#[tokio::test]
async fn control_2_a_modern_request_with_an_unverifiable_agent_token_is_refused() {
    let state = state(Fixture {
        agent_auth_enabled: true,
        ..Fixture::default()
    });
    let (status, body) = post(
        &state,
        modern("tools/list", json!({})),
        &[("authorization", "Bearer not-a-jwt")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"]["code"], json!(-32000), "body: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .expect("message")
            .contains("Invalid or expired token"),
        "body: {body}"
    );
}

#[tokio::test]
async fn control_2_a_modern_request_with_no_agent_token_is_refused() {
    let app = state(Fixture {
        agent_auth_enabled: true,
        ..Fixture::default()
    });
    let (status, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"]["code"], json!(-32000), "body: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .expect("message")
            .contains("Missing Authorization header"),
        "body: {body}"
    );
    // Falsifier, and this one is load-bearing: the client-credential gate
    // refuses through the same helper, with the same status and the same
    // -32000, so a headerless request refused by *that* gate would satisfy
    // every assertion above while this control never ran. With the control
    // off the identical request is served, which leaves the agent gate as
    // the only party that can have refused it.
    let off = state(Fixture {
        agent_auth_enabled: false,
        ..Fixture::default()
    });
    let (served, body) = post(&off, modern("tools/list", json!({})), &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
}

// ============================================================================
// NFR.SEC.1 control 5 — per-client circuit breaker
// The breaker trips on a client's own failure count, so a modern caller whose
// circuit is open is refused before the handler runs — and the refusal is
// keyed to that client, not to the gateway.
// ============================================================================
#[tokio::test]
async fn control_5_a_modern_caller_whose_circuit_is_open_is_refused() {
    let app = state(Fixture {
        auth: AuthConfig {
            client_circuit_breaker: Some(CircuitBreakerConfig {
                enabled: true,
                failure_threshold: 2,
                // Long enough that the open circuit cannot half-open under us
                // mid-test and turn a refusal back into a 200.
                reset_timeout: Duration::from_secs(300),
                ..CircuitBreakerConfig::default()
            }),
            ..auth_with(
                vec![
                    api_key("k", 0, None),
                    ApiKeyConfig {
                        name: "second".to_string(),
                        ..api_key("k2", 0, None)
                    },
                ],
                None,
            )
        },
        ..Default::default()
    });
    let tripped = [("authorization", "Bearer k")];
    let other = [("authorization", "Bearer k2")];

    // Falsifier: both clients are served while their circuits are closed, so
    // the refusal below cannot be a request the gateway was rejecting anyway.
    let (before, body) = post(&app, modern("tools/list", json!({})), &tripped).await;
    assert_eq!(before, StatusCode::OK, "body: {body}");
    let (peer, body) = post(&app, modern("tools/list", json!({})), &other).await;
    assert_eq!(peer, StatusCode::OK, "body: {body}");

    // The trip, driven rather than staged. `record_client_failure` sits below
    // the method-dispatch match in `handle_jsonrpc_request`, so the `_` arm's
    // -32601 reaches it while anything refused earlier — auth, the parser, the
    // rate limiter — does not. Each call asserts its own -32601: a build where
    // the trip silently stops erroring fails here, at the staging step, instead
    // of passing the claim below for the wrong reason.
    //
    // The client's `rate_limit` is 0 on purpose. Zero disarms row 4's limiter
    // twice over (no bucket is pre-created, and the check returns *allowed*
    // before consulting one) while leaving this breaker armed, because the
    // breaker's per-client entry is created lazily off the circuit-breaker
    // config alone and never reads `rate_limit`.
    for _ in 0..2 {
        let (staged, body) = post(&app, modern("no/such/method", json!({})), &tripped).await;
        assert_eq!(body["error"]["code"], json!(-32601), "body: {body}");
        assert_ne!(staged, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    }

    let (status, body) = post(&app, modern("tools/list", json!({})), &tripped).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    assert_eq!(body["error"]["code"], json!(-32003), "body: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .expect("message")
            .contains("circuit breaker is open"),
        "body: {body}"
    );
    // The gate itself refuses, not only the route that consults it.
    assert!(
        !app.auth_config.check_client_circuit_breaker("client"),
        "the breaker must refuse the client whose failures tripped it"
    );

    // Per-client keying: a global breaker would refuse this one too, so this
    // is the assertion that separates the control from a gateway-wide fuse.
    let (unaffected, body) = post(&app, modern("tools/list", json!({})), &other).await;
    assert_eq!(unaffected, StatusCode::OK, "body: {body}");
}

// ============================================================================
// NFR.SEC.1 control 15 — the security firewall's request gate
// The existing firewall tests all call `check_request` directly, so a build
// that stops consulting the firewall on the `tools/call` path passes every one
// of them. This drives the route instead, and asserts the pair the route emits.
// ============================================================================
#[cfg(feature = "firewall")]
#[tokio::test]
async fn control_15_a_modern_tools_call_the_firewall_blocks_is_refused() {
    use mcp_gateway::security::firewall::{Firewall, FirewallConfig};

    // The scan runs inside the loop over the targets the call resolves
    // (`handlers.rs:1249`), so a tool no backend serves is answered by the
    // dispatcher before the firewall ever sees it. `gateway_invoke` carries its
    // own target in its arguments (`target_from_invoke_arguments`), which is
    // how this reaches the gate against the empty `BackendRegistry` every
    // router fixture builds.
    let blocked = || {
        modern(
            "tools/call",
            json!({
                "name": "gateway_invoke",
                "arguments": {
                    "server": "backend",
                    "tool": "echo",
                    "arguments": { "cmd": "ls; rm -rf /" }
                }
            }),
        )
    };

    let app = state(Fixture {
        firewall: Some(Arc::new(Firewall::from_config(
            FirewallConfig::default(),
            None,
        ))),
        ..Default::default()
    });
    let (status, body) = post(&app, blocked(), &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    // -32600 is the non-anomaly block; -32002 is the anomaly one. Asserting the
    // code and not only the status is what separates this refusal from every
    // other 400 the route can emit.
    assert_eq!(body["error"]["code"], json!(-32600), "body: {body}");

    // Falsifier: the same frame against the state seven router fixtures already
    // build. Whatever answers it, it is not this gate.
    let off = state(Fixture::default());
    let (_, body) = post(&off, blocked(), &[]).await;
    assert_ne!(body["error"]["code"], json!(-32600), "body: {body}");
}
