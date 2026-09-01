// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7213 and MIK-7272 — results, renumbered
//! errors, and the cacheability fields of MCP 2026-07-28.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 4".
//!
//! `cacheScope` is the reason this increment is not mechanical. `public` means
//! any intermediary may serve this response across authorization contexts — a
//! statement about every future caller, made by a server that has seen one.

use mcp_gateway::protocol::cacheable::{CacheScope, result_type_of};
use mcp_gateway::protocol::era::{
    HEADER_MISMATCH, MISSING_REQUIRED_CLIENT_CAPABILITY, UNSUPPORTED_PROTOCOL_VERSION,
};
use serde_json::json;

// ===========================================================================
// MIK-7272.ERROR.1 / .2 — the renumbered codes.
//
// Pinned as literals, transcribed from the specification's error-code
// allocation policy. Asserting `X == X` against our own constant would pass
// however wrong the constant is.
// ===========================================================================

#[test]
fn ac_error_1_the_renumbered_codes_are_at_their_new_numbers() {
    // -32000..=-32019 stays implementation-defined; -32020..=-32099 is reserved
    // for the specification, which is why these three moved.
    assert_eq!(HEADER_MISMATCH, -32020, "HeaderMismatch, was -32001");
    assert_eq!(
        MISSING_REQUIRED_CLIENT_CAPABILITY, -32021,
        "MissingRequiredClientCapability, was -32003"
    );
    assert_eq!(
        UNSUPPORTED_PROTOCOL_VERSION, -32022,
        "UnsupportedProtocolVersion, was -32004"
    );
}

#[test]
fn ac_error_1_no_renumbered_code_sits_in_the_implementation_defined_range() {
    // The renumbering exists because the old numbers were in the range the
    // specification left to implementations. A code that drifted back would
    // collide with whatever an SDK already put there.
    for code in [
        HEADER_MISMATCH,
        MISSING_REQUIRED_CLIENT_CAPABILITY,
        UNSUPPORTED_PROTOCOL_VERSION,
    ] {
        assert!(
            (-32099..=-32020).contains(&code),
            "{code} must sit in the specification's reserved range, not the \
             implementation-defined one"
        );
    }
}

// ===========================================================================
// MIK-7272.RESULT.2 — as a client, a result from an earlier-protocol server
// omits `resultType`, and the client MUST read it as "complete".
// ===========================================================================

#[test]
fn ac_result_2_a_missing_result_type_reads_as_complete() {
    // Every pre-2026 backend answers this way. Reading the absence as unknown
    // would make every legacy backend's answer unusable.
    assert_eq!(result_type_of(&json!({ "tools": [] })), "complete");
}

#[test]
fn ac_result_2_an_explicit_result_type_is_honoured() {
    assert_eq!(
        result_type_of(&json!({ "resultType": "input_required" })),
        "input_required",
        "an interim result must not be flattened into a completed one"
    );
    assert_eq!(
        result_type_of(&json!({ "resultType": "complete", "tools": [] })),
        "complete"
    );
}

// ===========================================================================
// MIK-7213.CACHE.2 / .3 — the scope of a cached response.
// ===========================================================================

#[test]
fn ac_cache_3_a_filtered_list_is_never_public() {
    // The ticket's stop-the-line, as a rule the code holds: no `public` from a
    // scoped assembly, anywhere. `filtered` here means the response depended on
    // who asked.
    assert_eq!(CacheScope::for_list(true), CacheScope::Private);
}

#[test]
fn ac_cache_2_this_gateways_list_is_private() {
    // This gateway's `tools/list` varies by the credential presented — legally,
    // since credentials are per-request input rather than connection state. A
    // response that varies by caller is private by construction. Asked of the
    // table, because the table is what the emitting code asks.
    assert_eq!(
        mcp_gateway::protocol::cacheable::scope_for_method("tools/list"),
        CacheScope::Private
    );
}

#[test]
fn ac_cache_3_public_requires_proof_not_a_default() {
    // The burden runs the other way round: `public` says any intermediary may
    // serve this to a caller the server has never seen. It is available only
    // where the response provably does not depend on who asked.
    assert_eq!(CacheScope::for_list(false), CacheScope::Public);
    assert_eq!(CacheScope::Private.as_str(), "private");
    assert_eq!(CacheScope::Public.as_str(), "public");
}

// ===========================================================================
// Through the transport. The rows above prove the rules; these prove the
// gateway applies them to what it actually sends.
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
            continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
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
            live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
            export_status: None,
            transparency_log: None,
            dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
            subscriptions: Arc::new(
                mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
            ),
        })
    }

    async fn post(body: Value, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = create_router(state())
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

    fn modern(method: &str, id: i64) -> Value {
        json!({
            "jsonrpc": "2.0", "id": id, "method": method,
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        })
    }

    fn modern_headers(method: &str) -> Vec<(&'static str, String)> {
        vec![
            ("mcp-protocol-version", "2026-07-28".to_string()),
            ("mcp-method", method.to_string()),
        ]
    }

    async fn post_modern(method: &str, id: i64) -> (StatusCode, Value) {
        let owned = modern_headers(method);
        let borrowed: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        post(modern(method, id), &borrowed).await
    }

    #[tokio::test]
    async fn ac_result_1_every_modern_result_carries_result_type() {
        let (status, body) = post_modern("tools/list", 1).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["resultType"], "complete", "{body}");
    }

    #[tokio::test]
    async fn ac_result_1_a_legacy_result_carries_none() {
        // The mirror. Adding the field in the shared builder would change the
        // 2025 wire format for every existing client.
        let (_, body) = post(
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
            &[],
        )
        .await;
        assert!(
            body["result"].get("resultType").is_none(),
            "a 2025 result gains no fields: {body}"
        );
    }

    #[tokio::test]
    async fn ac_cache_1_a_cacheable_result_carries_ttl_and_scope() {
        let (_, body) = post_modern("tools/list", 3).await;
        assert!(
            body["result"]["ttlMs"].as_u64().is_some_and(|t| t > 0),
            "ttlMs is a freshness hint the client uses to stop re-listing: {body}"
        );
        assert_eq!(body["result"]["cacheScope"], "private", "{body}");
    }

    #[tokio::test]
    async fn ac_cache_3_no_response_from_this_gateway_claims_public() {
        // The stop-the-line, asserted across every cacheable method rather than
        // the one that was convenient to write.
        for (i, method) in [
            "tools/list",
            "prompts/list",
            "resources/list",
            "resources/templates/list",
        ]
        .iter()
        .enumerate()
        {
            let id = 100 + i64::try_from(i).expect("a four-element index fits");
            let (_, body) = post_modern(method, id).await;
            let scope = &body["result"]["cacheScope"];
            assert_ne!(
                scope, "public",
                "{method} must not tell a shared cache it may serve this across \
                 authorization contexts: {body}"
            );
        }
    }

    #[tokio::test]
    async fn ac_cache_1_a_non_cacheable_result_carries_no_cache_fields() {
        // The fields belong to five results. Putting them on everything would
        // tell a client it may cache a tool call.
        let (_, body) = post_modern("server/discover", 4).await;
        assert!(
            body["result"].get("ttlMs").is_none(),
            "discovery's cache scope is decided with its own document, not here: {body}"
        );
    }

    #[tokio::test]
    async fn ac_order_1_the_tool_order_is_stable_across_callers() {
        // A `HashMap` iteration order passes a same-caller repeat and fails
        // this: two independent gateways assembling the same set must agree, or
        // no client can cache the list and no prompt cache can hit.
        let (_, first) = post_modern("tools/list", 5).await;
        let (_, second) = post_modern("tools/list", 6).await;

        let names = |body: &Value| -> Vec<String> {
            body["result"]["tools"]
                .as_array()
                .expect("tools array")
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_string))
                .collect()
        };
        assert!(!names(&first).is_empty(), "{first}");
        assert_eq!(
            names(&first),
            names(&second),
            "the order must not depend on who asked or when"
        );
    }
}

// ===========================================================================
// MIK-7213.CACHE.3 — the decision table itself.
//
// The rules above prove `for_list` decides correctly once someone has answered
// "did this depend on the caller?". The criterion asks for the artifact that
// answers it per method, and for that artifact to be what the emitting code
// consults — not a document beside code that decides on its own.
// ===========================================================================

#[test]
fn ac_cache_3_every_cacheable_method_has_an_assessed_row() {
    // Five methods carry `cacheScope` on the wire. A table missing one of them
    // is a method whose scope was defaulted rather than decided — and asking
    // `scope_for_method` cannot tell the two apart, since the fallback returns
    // what every row returns. So ask the table for its membership, not the
    // lookup for its answer.
    let assessed = mcp_gateway::protocol::cacheable::assessed_methods();
    for method in [
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
    ] {
        assert!(
            assessed.iter().any(|(name, _)| *name == method),
            "{method} is emitted with a `cacheScope` but has no assessed row, \
             so its scope is a default wearing a decision's clothes"
        );
        assert_eq!(
            mcp_gateway::protocol::cacheable::scope_for_method(method),
            CacheScope::Private,
            "{method} is served from a caller-scoped assembly"
        );
    }
}

// ===========================================================================
// MIK-7213.CACHE.4 — one row per response-varying input.
// Test plan row 4.b. The rest of CACHE.4 (backend pair 4.a, behavioural
// identity pair 4.c, routing profile 4.d, protocol revision 4.e, policy epoch
// 4.f.1-4.f.3) is not covered here and is not claimed to be.
// ===========================================================================

#[test]
fn ac_cache_4_two_principals_do_not_share_an_entry() {
    use mcp_gateway::cache::ResponseCache;
    let arguments = serde_json::json!({ "query": "quarterly numbers" });
    let key =
        |principal| ResponseCache::response_key("memory", "search", &arguments, "", principal);

    // Every other input is equal by construction, so a difference can only come
    // from the principal. Identity propagation is off in this case — the
    // shipped default — which is exactly when the two used to collide.
    assert_ne!(
        key(Some("oidc:11:https://idp:1:alice")),
        key(Some("oidc:11:https://idp:1:bob")),
        "two authorization identities sharing one key means one caller is \
         served the other's body"
    );

    // Determinism control: without it the assertion above passes for a key
    // that is merely different every time, which would be a broken cache
    // rather than an isolated one.
    assert_eq!(
        key(Some("oidc:11:https://idp:1:alice")),
        key(Some("oidc:11:https://idp:1:alice"))
    );

    // Two callers the gateway could not identify are one caller as far as the
    // cache can tell. Splitting them would be a key that cannot ever hit.
    assert_eq!(key(None), key(None));
}

#[test]
fn ac_cache_3_an_unlisted_method_is_private() {
    // Fail closed. A method nobody has assessed is exactly the case where
    // `public` would be a claim about callers the gateway has never seen.
    assert_eq!(
        mcp_gateway::protocol::cacheable::scope_for_method("tools/call"),
        CacheScope::Private
    );
    assert_eq!(
        mcp_gateway::protocol::cacheable::scope_for_method(""),
        CacheScope::Private
    );
}

// ===========================================================================
// The second clause: the table is referenced from the emitting code. Source
// lints, and named as such — prose of the same shape keeps them green, so
// these bound the drift rather than proving the reference is meaningful.
// ===========================================================================

fn source(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn ac_cache_3_the_deciding_function_names_the_table() {
    let text = source("src/protocol/cacheable.rs");
    let signature = "pub const fn for_list(";
    let doc = text
        .split(signature)
        .next()
        .expect("a split always yields a first part");
    // The contiguous run, not a line count: a neighbour's doc satisfying this
    // assertion is the failure mode it exists to catch.
    let block = doc
        .rsplit("\n\n")
        .next()
        .expect("a split always yields a first part");
    assert!(
        block.contains("scope_for_method"),
        "the doc above `{signature}` must send a reader to the table that \
         decides per method, or the table is a document beside the code"
    );
}

#[test]
fn ac_cache_3_the_wire_field_is_filled_from_the_table() {
    let text = source("src/gateway/router/handlers.rs");
    assert!(
        text.contains("scope_for_method(method)"),
        "the `cacheScope` a client receives must come from the table, not from \
         one method's answer applied to five"
    );
}
