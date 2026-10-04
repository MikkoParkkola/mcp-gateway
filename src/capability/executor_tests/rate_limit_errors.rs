// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Typed 429 and untyped 500 errors from a live loopback backend.

use super::*;

/// A loopback backend answering 429 on `/throttled` and 500 on `/broken`, with
/// an executor whose HTTP client can actually reach it.
///
/// The sibling REST test above reaches its server with the production client
/// because `handle_response` is called directly, past every guard. The protocol
/// executors are entered at `execute()`, which runs the guards first: an IP
/// literal is rejected outright (`security/ssrf/mod.rs:164`) and a domain name,
/// which does pass (`security/ssrf/mod.rs:185`), is then stopped at DNS by the
/// production client's `PinningResolver` (`executor/mod.rs:175`). A plain
/// client plus a domain host clears both.
///
/// LIMIT: swapping the client means the production client's own SSRF and
/// redirect posture is not exercised here. What the two tests below pin is
/// their format site and the classification of what it produces — nothing more.
async fn loopback_status_backend() -> (CapabilityExecutor, String) {
    // Same body on both routes: the status line is the only discriminator.
    async fn throttled() -> AxumResponse {
        AxumResponse::builder()
            .status(429)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }
    async fn broken() -> AxumResponse {
        AxumResponse::builder()
            .status(500)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/throttled", post(throttled))
                .route("/broken", post(broken)),
        )
        .await
        .unwrap();
    });

    let mut executor = CapabilityExecutor::new();
    executor.client = reqwest::Client::new();
    (executor, format!("http://localhost:{port}"))
}

/// A capability the protocol executors will dispatch without prerequisites:
/// not `personal`, so the identity check passes, and no auth to inject.
fn unauthenticated_capability() -> CapabilityDefinition {
    crate::capability::parse_capability(
        r"
name: throttled_backend
description: Backend used to observe a real 429
providers:
  primary:
    service: rest
    config:
      base_url: https://backend.invalid
      path: /
      method: POST
",
    )
    .unwrap()
}

/// Drive the same predicate the sibling REST test drives: `errors[0]` came from
/// the 429 route and must not trip the breaker, `errors[1]` from the 500 route
/// and must.
fn assert_only_the_500_trips_the_breaker(errors: &[String]) {
    use crate::config::{CircuitBreakerConfig, FailsafeConfig};
    use crate::failsafe::Failsafe;
    use std::time::Duration;

    let failsafe_config = FailsafeConfig {
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let latency = Duration::from_millis(1);

    let throttled_backend = Failsafe::new("throttled-capability", &failsafe_config);
    throttled_backend.record_dispatch_failure(&errors[0], latency);
    assert!(
        throttled_backend.circuit_breaker.can_proceed(),
        "a real 429 must not trip the breaker; error text was: {}",
        errors[0]
    );

    let broken_backend = Failsafe::new("broken-capability", &failsafe_config);
    broken_backend.record_dispatch_failure(&errors[1], latency);
    assert!(
        !broken_backend.circuit_breaker.can_proceed(),
        "the control must still trip: same body, only the status differs; error text was: {}",
        errors[1]
    );
}

/// The JSON-RPC half of the site pinned by
/// `a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate`,
/// which that test names as NOT PINNED.
///
/// The error text is produced by the production formatter at
/// `executor/jsonrpc.rs` (`"JSON-RPC endpoint returned {}: {}"`), not composed
/// here — a test writing its own status string pins a copy of the format and
/// stays green when the format changes.
///
/// FALSIFIER: a mutation probe. Dropping the status from that literal
/// (`"JSON-RPC endpoint returned: {}", error_text`) makes the throttled case
/// count as an ordinary failure and this test fails on its first assertion.
#[tokio::test]
async fn a_real_jsonrpc_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::capability::{ExecutionContext, JsonRpcConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    let (executor, base) = loopback_status_backend().await;
    let capability = unauthenticated_capability();

    let mut errors = Vec::new();
    for route in ["/throttled", "/broken"] {
        let config = ProtocolConfig::Jsonrpc(JsonRpcConfig {
            endpoint: format!("{base}{route}"),
            method: "eth_blockNumber".to_string(),
            ..Default::default()
        });
        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        errors.push(
            jsonrpc::JsonRpcExecutor {
                executor: &executor,
            }
            .execute(&config, serde_json::json!({}), &ctx)
            .await
            .unwrap_err()
            .to_string(),
        );
    }

    assert_only_the_500_trips_the_breaker(&errors);
}

/// The GraphQL half of the site pinned by
/// `a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate`,
/// which that test names as NOT PINNED.
///
/// The error text is produced by the production formatter at
/// `executor/graphql.rs` (`"GraphQL endpoint returned {}: {}"`), not composed
/// here, for the same reason.
///
/// FALSIFIER: a mutation probe. Dropping the status from that literal
/// (`"GraphQL endpoint returned: {}", error_text`) makes the throttled case
/// count as an ordinary failure and this test fails on its first assertion.
#[tokio::test]
async fn a_real_graphql_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::capability::{ExecutionContext, GraphqlConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    let (executor, base) = loopback_status_backend().await;
    let capability = unauthenticated_capability();

    let mut errors = Vec::new();
    for route in ["/throttled", "/broken"] {
        let config = ProtocolConfig::Graphql(GraphqlConfig {
            endpoint: format!("{base}{route}"),
            query: Some("query { viewer { login } }".to_string()),
            ..Default::default()
        });
        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        errors.push(
            graphql::GraphqlExecutor {
                executor: &executor,
            }
            .execute(&config, serde_json::json!({}), &ctx)
            .await
            .unwrap_err()
            .to_string(),
        );
    }

    assert_only_the_500_trips_the_breaker(&errors);
}

/// RL.10 — the rate-limit outcome is TYPED, and every other status is not.
///
/// The three sibling tests above prove a 429 is *recognised*; they do it by
/// reading a formatted string, so the property they pin is "the status text
/// survives formatting", not "a rate limit has a type". This one pins the
/// type: `Error::Http` carrying `StatusCode::TOO_MANY_REQUESTS`, which
/// `BudgetOutcome::of` can match without reading a byte of prose.
///
/// THE CONTROL IS THE OTHER HALF OF THE TEST: 500 must still arrive as
/// `Error::Protocol` with its status and its body fragment intact. The gate is
/// `status == 429` alone — not `error_for_status_ref()`'s `Err`, which would
/// flatten 504 into a typed error and change how the dispatch classifier reads
/// it.
///
/// URL CANARY: the REST leg is driven through a query string carrying
/// `api_key=CANARY`. A `reqwest::Error` prints its URL by default, so the typed
/// error is stripped with `without_url()` before it is wrapped; the assertions
/// below fail if either the credential, the host or the path reaches `Display`.
///
/// STILL NOT PINNED here: that the relocated body reaches the `warn!` record —
/// only that it leaves the error. Capturing a tracing event needs a subscriber
/// this module does not install.
/// A typed 429 must still reach the caller as a backend fault (GH475.RL.10).
///
/// `to_rpc_code` reported `Error::Protocol` as `-32600` and every other variant
/// as `-32603`. Making a 429 typed moved it from the first bucket to the
/// second, which tells a JSON-RPC client the *gateway* failed. The guarded arm
/// puts it in `-32000` beside the other backend-side refusals; the 500 control
/// proves the move is scoped to 429 and did not drag the untyped path with it.
#[tokio::test]
async fn a_typed_429_reports_a_backend_fault_rpc_code() {
    let (executor, base) = loopback_status_backend().await;
    let rest_config = RestConfig::default();

    let mut codes = Vec::new();
    for route in ["/throttled", "/broken"] {
        let response = executor
            .client
            .post(format!("{base}{route}"))
            .send()
            .await
            .unwrap();
        codes.push(
            executor
                .handle_response(response, &rest_config)
                .await
                .unwrap_err()
                .to_rpc_code(),
        );
    }

    assert_eq!(
        codes[0], -32000,
        "a throttled backend is a backend fault, not a gateway one"
    );
    assert_eq!(
        codes[1], -32600,
        "the untyped 500 must keep the code it always had"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_capability_429_is_a_typed_http_error_at_every_protocol_site() {
    use crate::capability::{ExecutionContext, GraphqlConfig, JsonRpcConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    fn assert_typed_429(error: &Error, site: &str) {
        match error {
            Error::Http(inner) => assert_eq!(
                inner.status(),
                Some(reqwest::StatusCode::TOO_MANY_REQUESTS),
                "{site}: the typed error must carry the throttling status"
            ),
            other => panic!("{site}: a 429 must be a typed Http error, got: {other}"),
        }
    }

    fn assert_untyped_500(error: &Error, site: &str) {
        match error {
            Error::Protocol(text) => {
                assert!(
                    text.contains("500"),
                    "{site}: the control must keep its status in the message: {text}"
                );
                assert!(
                    text.contains("slow down"),
                    "{site}: the control must keep its body fragment: {text}"
                );
            }
            other => panic!("{site}: only 429 is typed; 500 must stay Protocol, got: {other}"),
        }
    }

    let (executor, base) = loopback_status_backend().await;
    let capability = unauthenticated_capability();

    // REST — driven at `handle_response`, the production formatter, with a
    // credential in the query string as the leak canary.
    let rest_config = RestConfig::default();
    let mut rest = Vec::new();
    for route in ["/throttled", "/broken"] {
        let response = executor
            .client
            .post(format!("{base}{route}?api_key=CANARY"))
            .send()
            .await
            .unwrap();
        rest.push(
            executor
                .handle_response(response, &rest_config)
                .await
                .unwrap_err(),
        );
    }
    assert_typed_429(&rest[0], "REST");
    assert_untyped_500(&rest[1], "REST");

    let leaked = rest[0].to_string();
    for secret in ["CANARY", "api_key", "localhost", "/throttled", "slow down"] {
        assert!(
            !leaked.contains(secret),
            "the typed error leaked {secret:?}: {leaked}"
        );
    }
    match &rest[0] {
        Error::Http(inner) => assert!(
            inner.url().is_none(),
            "the URL must be stripped from the error, not merely absent from its Display"
        ),
        other => panic!("expected a typed Http error, got: {other}"),
    }

    // JSON-RPC and GraphQL — driven through `execute`, as their sibling
    // detection tests are.
    let mut jsonrpc = Vec::new();
    let mut graphql = Vec::new();
    for route in ["/throttled", "/broken"] {
        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        jsonrpc.push(
            jsonrpc::JsonRpcExecutor {
                executor: &executor,
            }
            .execute(
                &ProtocolConfig::Jsonrpc(JsonRpcConfig {
                    endpoint: format!("{base}{route}"),
                    method: "eth_blockNumber".to_string(),
                    ..Default::default()
                }),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap_err(),
        );

        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        graphql.push(
            graphql::GraphqlExecutor {
                executor: &executor,
            }
            .execute(
                &ProtocolConfig::Graphql(GraphqlConfig {
                    endpoint: format!("{base}{route}"),
                    query: Some("query { viewer { login } }".to_string()),
                    ..Default::default()
                }),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap_err(),
        );
    }
    assert_typed_429(&jsonrpc[0], "JSON-RPC");
    assert_untyped_500(&jsonrpc[1], "JSON-RPC");
    assert_typed_429(&graphql[0], "GraphQL");
    assert_untyped_500(&graphql[1], "GraphQL");
}
