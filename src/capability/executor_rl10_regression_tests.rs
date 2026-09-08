// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Inherited real-response/shared-predicate controls for GH475.RL.10.
//! These exercise Failsafe's predicate; the sibling invoke tests pin both actual budgets.

use super::*;
use axum::{
    Router,
    body::Body,
    response::Response as AxumResponse,
    routing::{get, post},
};

struct ServerTask(tokio::task::JoinHandle<()>);
impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// GH475.RL.10: compatibility of a real capability Http429 Display with the
/// shared text predicate consumed by Failsafe. Equal bodies and different status
/// lines ensure this checks the real error formatter, not a fabricated message.
///
/// This is a compatibility control, not proof of typed classification. Removing
/// the typed carrier can leave matching Protocol text and this test still green.
/// The sibling typed-carrier assertions and required429-to430 mechanism probes
/// discriminate that defect. The actual capability budget windows are asserted
/// separately through BudgetOutcome and record_error_budget in invoke_rl10_tests.
///
/// Capability dispatch does not call Failsafe; the public Failsafe recorder here
/// exercises the shared predicate with the production Error::Http Display. A
/// formatter change that loses its rate-limit token would trip this circuit,
/// while the real500 control must still open it. JSON-RPC and GraphQL have their
/// own production-executor compatibility controls below.
#[tokio::test]
async fn a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::config::{CircuitBreakerConfig, FailsafeConfig};
    use crate::failsafe::Failsafe;
    use std::time::Duration;

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
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/throttled", get(throttled))
                .route("/broken", get(broken)),
        )
        .await
        .unwrap();
    });

    let _server = ServerTask(server);
    let executor = CapabilityExecutor::new();
    let config = RestConfig::default();
    let mut errors = Vec::new();
    for route in ["/throttled", "/broken"] {
        let response = executor
            .client
            .get(format!("http://{addr}{route}"))
            .send()
            .await
            .unwrap();
        errors.push(
            executor
                .handle_response(response, &config)
                .await
                .unwrap_err()
                .to_string(),
        );
    }

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
async fn loopback_status_backend() -> (CapabilityExecutor, String, ServerTask) {
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
    let server = tokio::spawn(async move {
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
    (
        executor,
        format!("http://localhost:{port}"),
        ServerTask(server),
    )
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

/// Real JSON-RPC Http429 Display compatibility with the shared Failsafe
/// predicate, alongside a real500 control. These cases use production execute,
/// but do not discriminate the typed carrier from matching legacy Protocol text.
/// Sibling carrier assertions and429-to430 probes pin that mechanism separately.
#[tokio::test]
async fn a_real_jsonrpc_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::capability::{ExecutionContext, JsonRpcConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    let (executor, base, _server) = loopback_status_backend().await;
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

/// Real GraphQL Http429 Display compatibility with the shared Failsafe
/// predicate, alongside a real500 control. These cases use production execute,
/// but do not discriminate the typed carrier from matching legacy Protocol text.
/// Sibling carrier assertions and429-to430 probes pin that mechanism separately.
#[tokio::test]
async fn a_real_graphql_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::capability::{ExecutionContext, GraphqlConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    let (executor, base, _server) = loopback_status_backend().await;
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
