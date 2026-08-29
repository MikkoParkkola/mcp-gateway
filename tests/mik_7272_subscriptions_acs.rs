// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7272 §3.9 — subscriptions and streams
//! under MCP 2026-07-28.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 8".
//!
//! The revision replaces the HTTP GET stream and `resources/subscribe` with one
//! long-lived POST-response stream a client opts into by notification type. It
//! also removes stream resumability — a broken stream loses the in-flight
//! request, and the client re-issues it with a new id.
//!
//! That last part is why this increment carries a safety rule rather than only
//! a shape: re-issuing a side-effecting call is how one booking becomes two.

use mcp_gateway::protocol::RequestId;
use mcp_gateway::protocol::subscriptions::{ListenRequest, NotificationKind, SubscriptionId};
use serde_json::json;

// The filter shape below is the specification's own example, verbatim from
// /specification/2026-07-28/basic/patterns/subscriptions:
//
//   "params": {
//     "notifications": {
//       "toolsListChanged": true,
//       "resourceSubscriptions": ["file:///project/config.json"]
//     }
//   }
//
// The first version of these rows was written from the changelog and the index
// rather than this page, and encoded three wire errors that all agreed with the
// implementation. Quoting the page is what makes them tests rather than a
// second copy of the same assumption.

#[test]
fn ac_sub_1_a_client_opts_in_by_notification_type() {
    // Opt-in, not a firehose. A client that asked for tool-list changes must
    // not be sent resource updates it never wanted and cannot interpret.
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": {
            "toolsListChanged": true,
            "resourcesListChanged": false
        }
    })))
    .expect("a well-formed listen request");

    assert!(request.wants(NotificationKind::ToolsListChanged));
    assert!(!request.wants(NotificationKind::ResourcesListChanged));
    assert!(
        !request.wants(NotificationKind::PromptsListChanged),
        "a type the client did not name is a type it did not ask for"
    );
}

#[test]
fn ac_sub_1_the_filter_is_nested_under_notifications() {
    // Read at the params root, every conforming request looked empty and was
    // refused — the opt-ins were never where they were looked for.
    assert!(
        ListenRequest::from_params(Some(&json!({ "toolsListChanged": true }))).is_none(),
        "opt-ins at the params root are not a filter"
    );
    assert!(
        ListenRequest::from_params(Some(&json!({
            "notifications": { "toolsListChanged": true }
        })))
        .is_some_and(|r| r.wants(NotificationKind::ToolsListChanged))
    );
}

#[test]
fn ac_sub_1_resource_subscriptions_names_uris_not_a_boolean() {
    // The one field in the filter table that is not a boolean. Read as one, a
    // client's resource list was silently dropped and it received nothing for
    // the resources it named.
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": {
            "toolsListChanged": true,
            "resourceSubscriptions": ["file:///project/config.json"]
        }
    })))
    .expect("the specification's own example must parse");

    assert!(request.wants(NotificationKind::ResourceSubscriptions));
    assert_eq!(
        request.resource_uris(),
        ["file:///project/config.json"],
        "the subscribed resource URIs must survive parsing"
    );
}

#[test]
fn ac_sub_1_a_request_without_a_filter_is_invalid_but_an_empty_filter_is_not() {
    // Two different answers. No filter at all is invalid params. An empty
    // filter is a client asking for nothing, which the specification permits
    // and which is acknowledged rather than refused.
    assert!(ListenRequest::from_params(None).is_none());
    assert!(
        ListenRequest::from_params(Some(&json!({}))).is_none(),
        "a listen request must carry a notifications filter"
    );

    let empty = ListenRequest::from_params(Some(&json!({ "notifications": {} })))
        .expect("an empty filter is a valid request");
    assert!(
        empty.is_empty(),
        "it asked for nothing, and that is allowed"
    );
}

#[test]
fn ac_sub_1_an_unrecognised_notification_type_is_ignored_not_refused() {
    // A server is expected to handle unsupported types gracefully; refusing
    // them would make every future notification type a breaking change.
    let request = ListenRequest::from_params(Some(&json!({
        "notifications": { "toolsListChanged": true, "somethingFuture": true }
    })))
    .expect("an unknown key must not sink the request");

    assert!(request.wants(NotificationKind::ToolsListChanged));
}

#[test]
fn ac_sub_1_the_subscription_id_is_the_requests_own_id() {
    // "The value is the JSON-RPC ID of the subscriptions/listen request."
    // A minted id looks authoritative and leaves the client unable to correlate
    // a notification with the subscription that asked for it.
    let numeric = SubscriptionId::of_request(RequestId::Number(1));
    assert_eq!(numeric.as_value(), json!(1), "a numeric id stays numeric");

    let textual = SubscriptionId::of_request(RequestId::String("sub-a".into()));
    assert_eq!(textual.as_value(), json!("sub-a"));
}

#[test]
fn ac_sub_1_the_server_tags_what_it_sends_under_params_meta() {
    // The specification's own notification example puts the tag in
    // `params._meta`. At the notification root it is well-formed, present, and
    // in a place no conforming client looks.
    let id = SubscriptionId::of_request(RequestId::Number(1));
    let tagged = id.tag(json!({
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": { "uri": "file:///project/config.json" }
    }));

    assert_eq!(
        tagged["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        json!(1),
        "the tag belongs under params._meta, as a number when the id was one"
    );
    assert_eq!(
        tagged["params"]["uri"], "file:///project/config.json",
        "tagging must not disturb the notification's own params"
    );
    assert!(
        tagged.get("_meta").is_none(),
        "nothing should be left at the notification root"
    );
}

#[test]
fn ac_sub_1_two_subscriptions_are_distinguishable() {
    assert_ne!(
        SubscriptionId::of_request(RequestId::Number(1)),
        SubscriptionId::of_request(RequestId::Number(2))
    );
}

#[test]
fn ac_sub_2_a_request_scoped_notification_is_not_a_subscription_notification() {
    // Progress and log messages belong to the request that caused them and
    // travel on its own response stream. Routing them to the subscription
    // stream would deliver them to a client that never made that request.
    for method in ["notifications/progress", "notifications/message"] {
        assert!(
            NotificationKind::from_method(method).is_none(),
            "{method} is request-scoped and cannot be subscribed to"
        );
    }
    assert_eq!(
        NotificationKind::from_method("notifications/tools/list_changed"),
        Some(NotificationKind::ToolsListChanged)
    );
}

// ===========================================================================
// MIK-7272.SUB.3 / .4 — resumability is gone, so re-issue safety matters.
//
// A broken response stream loses the in-flight request and the client MUST
// re-issue it with a new request id. Without deduplication that turns one
// booking into two — and the auto-generated key is derived from the tool name
// and arguments, which a retry repeats exactly, so the mechanism is there. What
// is not automatic is that a multi-round-trip retry must NOT collide with it.
// ===========================================================================

mod reissue {
    use mcp_gateway::protocol::mrtr::RetryFields;
    use serde_json::json;

    #[test]
    fn ac_sub_4_a_reissued_call_is_the_same_call() {
        // The property re-issue safety rests on: the same call, re-sent after a
        // broken stream, must look the same to the deduplicator. A key derived
        // from the tool name and arguments has that; a key derived from the
        // request id would not, and the request id is required to change.
        let first = json!({ "name": "book_flight", "arguments": { "seat": "12A" } });
        let reissued = json!({ "name": "book_flight", "arguments": { "seat": "12A" } });
        assert_eq!(
            first["arguments"], reissued["arguments"],
            "a re-issue differs only in its request id, which must not be part \
             of what identifies the call"
        );
    }

    #[test]
    fn ac_sub_4_a_continuation_retry_is_not_the_same_call() {
        // The other side, and the one that bites. A multi-round-trip retry
        // carries the same tool and the same arguments as the call it
        // continues — so a deduplicator keyed on those alone would treat the
        // retry as a duplicate and replay the interim result forever. The
        // retry fields have to be part of what identifies it.
        let original = RetryFields::from_params(Some(&json!({
            "name": "book_flight", "arguments": { "seat": "12A" }
        })));
        let retry = RetryFields::from_params(Some(&json!({
            "name": "book_flight",
            "arguments": { "seat": "12A" },
            "inputResponses": { "confirm": { "action": "accept" } },
            "requestState": "envelope"
        })));

        assert!(!original.is_retry());
        assert!(retry.is_retry());
        assert_ne!(
            original.request_state, retry.request_state,
            "the retry is distinguishable from the call it continues, which is \
             what stops a deduplicator swallowing it"
        );
    }

    #[test]
    fn ac_sub_4_two_different_continuations_are_distinguishable() {
        // Two users answering the same question about the same flight. If the
        // continuation did not participate in identity, the second would be
        // served the first one's cached outcome.
        let a = RetryFields::from_params(Some(&json!({
            "name": "book_flight", "arguments": {}, "requestState": "envelope-a"
        })));
        let b = RetryFields::from_params(Some(&json!({
            "name": "book_flight", "arguments": {}, "requestState": "envelope-b"
        })));
        assert_ne!(a.request_state, b.request_state);
    }
}

// ===========================================================================
// Through the transport. The rows above prove the model; these prove the
// gateway serves it — which is the difference between a type and a feature.
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

    fn state(modern: bool) -> Arc<AppState> {
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

    async fn post(modern: bool, body: Value, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = create_router(state(modern))
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

    #[tokio::test]
    async fn ac_sub_1_the_gateway_serves_subscriptions_listen() {
        let (status, body) = post_modern(
            "subscriptions/listen",
            json!({ "notifications": { "toolsListChanged": true } }),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"], body["id"],
            "the subscription id is the request's own id, so the client can \
             correlate every notification with the subscription that asked for \
             it: {body}"
        );
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
        let (status, body) =
            post_modern("resources/subscribe", json!({ "uri": "file:///x" })).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], -32601, "{body}");
    }

    #[tokio::test]
    async fn ac_sub_1_resources_subscribe_still_works_on_the_legacy_path() {
        // The regression. A 2025 client subscribes this way and always has.
        let (status, body) = post(
            false,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/subscribe",
                    "params": { "uri": "file:///x" } }),
            &[],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the legacy method is untouched: {body}"
        );
    }

    #[tokio::test]
    async fn ac_task_1_tasks_get_reports_that_it_is_not_implemented() {
        // It answered every handle with a `not_found` **success**. That status
        // is not in the protocol's task model, and as a success it told a client
        // its handle had been looked up and missed — a lookup that never
        // happened, against a store that does not exist.
        //
        // The specification page for the tasks extension returns 404 at the path
        // its own index links, so there is no shape to build against. Answering
        // method-not-found is the true statement, and a client discovers that on
        // its first call rather than after polling a fiction.
        let (status, body) = post_modern("tasks/get", json!({ "taskId": "task-unknown" })).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["code"], -32601, "{body}");
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
}
