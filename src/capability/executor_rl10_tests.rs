// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH475.RL.10: actual executor boundaries, diagnostics and RPC conversion.
//! Loopback fixtures replace only the HTTP client resolver, not response handling.
//! Production SSRF/reachability is outside these component tests.

use super::rest::{ExecutionContext, ProtocolExecutor};
use super::*;
use crate::capability::{GraphqlConfig, JsonRpcConfig, ProtocolConfig};
use axum::{Router, body::Body, response::Response, routing::post};
use std::sync::{Arc, Mutex};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

const QUERY_SECRET: &str = "RL10_QUERY_SECRET_5e8d2c";
const BODY_SECRET: &str = "RL10_BODY_SECRET_9c3a71";
const FIXTURE_PATH: &str = "/rl10-private-endpoint";

pub(crate) struct ReasonOutcome {
    pub(crate) error: Error,
    pub(crate) reflected_url: String,
    pub(crate) query_secret: &'static str,
    pub(crate) warn_fields: String,
}

struct StatusServer {
    base: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for StatusServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StatusServer {
    async fn start(status: u16, body: &str) -> Self {
        let body = body.to_owned();
        let router = Router::new().route(
            FIXTURE_PATH,
            post(move || {
                let body = body.clone();
                async move {
                    Response::builder()
                        .status(status)
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://localhost:{}", listener.local_addr().unwrap().port());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { base, task }
    }

    /// C12/C14 use the same raw reason phrase and deliberately incomplete body.
    async fn start_reason_with_pending_body() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://localhost:{}", listener.local_addr().unwrap().port());
        let reason = format!("{base}{FIXTURE_PATH}?api_key={QUERY_SECRET}");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut headers = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0, "fixture request closed before headers");
                    headers.extend_from_slice(&chunk[..read]);
                    assert!(
                        headers.len() <= 16 * 1024,
                        "bounded fixture request headers"
                    );
                }
            })
            .await
            .expect("fixture request headers must arrive");
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 429 {reason}\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            // Keep this socket open without supplying any of the promised body.
            // StatusServer::drop aborts the task, including this owned socket.
            std::future::pending::<()>().await;
            drop(stream);
        });
        Self { base, task }
    }

    fn endpoint(&self) -> String {
        format!("{}{FIXTURE_PATH}?api_key={QUERY_SECRET}", self.base)
    }
}

fn capability() -> CapabilityDefinition {
    crate::capability::parse_capability(
        r"
name: rl10_fixture
description: Synthetic capability HTTP response fixture
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

impl CapabilityExecutor {
    /// Test-only bridge to private downstream classifiers. Every protocol enters
    /// its production execute method; this fixture never constructs error text.
    pub(crate) async fn rl10_test_error(protocol: &str, status: u16, body: &str) -> Error {
        let server = StatusServer::start(status, body).await;
        Self::rl10_error_from_server(protocol, &server).await
    }

    /// Test-only real executor entry for the C12/C13/C14 raw wire fixture.
    pub(crate) async fn rl10_test_pending_reason_error(protocol: &str) -> ReasonOutcome {
        use tracing::instrument::WithSubscriber;

        let server = StatusServer::start_reason_with_pending_body().await;
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let error = async {
            tracing::warn!(rl10_capture_canary = true, "capture is active");
            tokio::time::timeout(
                Duration::from_secs(2),
                Self::rl10_error_from_server(protocol, &server),
            )
            .await
            .expect("429 handling must return without waiting for the unfinished body")
        }
        .with_subscriber(subscriber)
        .await;
        ReasonOutcome {
            error,
            reflected_url: server.endpoint(),
            query_secret: QUERY_SECRET,
            warn_fields: events.verified_metadata(protocol),
        }
    }

    async fn rl10_error_from_server(protocol: &str, server: &StatusServer) -> Error {
        let mut executor = Self::new();
        executor.client = Client::builder().no_proxy().build().unwrap();
        let capability = capability();
        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        let params = serde_json::json!({});
        match protocol {
            "rest" => {
                rest::RestExecutor {
                    executor: &executor,
                }
                .execute(
                    &ProtocolConfig::Rest(Box::new(RestConfig {
                        base_url: server.base.clone(),
                        path: format!("{FIXTURE_PATH}?api_key={QUERY_SECRET}"),
                        method: "POST".into(),
                        ..Default::default()
                    })),
                    params,
                    &ctx,
                )
                .await
            }
            "jsonrpc" => {
                jsonrpc::JsonRpcExecutor {
                    executor: &executor,
                }
                .execute(
                    &ProtocolConfig::Jsonrpc(JsonRpcConfig {
                        endpoint: server.endpoint(),
                        method: "fixture.read".into(),
                        ..Default::default()
                    }),
                    params,
                    &ctx,
                )
                .await
            }
            "graphql" => {
                graphql::GraphqlExecutor {
                    executor: &executor,
                }
                .execute(
                    &ProtocolConfig::Graphql(GraphqlConfig {
                        endpoint: server.endpoint(),
                        query: Some("query { fixture }".into()),
                        ..Default::default()
                    }),
                    params,
                    &ctx,
                )
                .await
            }
            other => panic!("unknown fixture protocol {other}"),
        }
        .unwrap_err()
    }

    /// Independent typed negative control: bypass the production response helper
    /// so its possible over-broad status guard cannot contaminate this oracle.
    pub(crate) async fn rl10_test_http_error(status: u16) -> Error {
        let server = StatusServer::start(status, "synthetic ordinary failure").await;
        let error = Client::new()
            .post(server.endpoint())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err();
        Error::Http(error.without_url())
    }

    /// A peer closes a real TCP connection without sending any HTTP response.
    pub(crate) async fn rl10_test_transport_error() -> Error {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let error = Client::new()
            .post(format!("http://{address}/"))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .unwrap_err();
        task.await.unwrap();
        assert!(error.status().is_none(), "fixture must have no HTTP status");
        Error::Http(error.without_url())
    }
}

fn secret_body() -> String {
    // An upstream can echo the request URL, so redacting only reqwest's URL
    // while logging its response body still fails the privacy contract.
    format!("{BODY_SECRET}: http://localhost{FIXTURE_PATH}?api_key={QUERY_SECRET}")
}

async fn assert_typed_and_redacted(protocol: &str) {
    let error = CapabilityExecutor::rl10_test_error(protocol, 429, &secret_body()).await;
    let Error::Http(inner) = &error else {
        panic!("{protocol}: 429 must retain typed HTTP status, got {error:?}");
    };
    assert_eq!(inner.status(), Some(reqwest::StatusCode::TOO_MANY_REQUESTS));
    assert!(
        inner.url().is_none(),
        "{protocol}: remove URL from the carrier"
    );
    for secret in [
        QUERY_SECRET,
        BODY_SECRET,
        "localhost",
        FIXTURE_PATH,
        "api_key",
    ] {
        assert!(
            !error.to_string().contains(secret),
            "{protocol}: leaked {secret}"
        );
    }
}

#[tokio::test]
async fn rl10_rest_retains_typed_429_without_url_or_body() {
    assert_typed_and_redacted("rest").await;
}

#[tokio::test]
async fn rl10_jsonrpc_retains_typed_429_without_url_or_body() {
    assert_typed_and_redacted("jsonrpc").await;
}

#[tokio::test]
async fn rl10_graphql_retains_typed_429_without_url_or_body() {
    assert_typed_and_redacted("graphql").await;
}

async fn assert_non_429_contract(protocol: &str, prefix: &str) {
    // The 500th character occupies three UTF-8 bytes. A byte cutoff or a changed
    // prefix fails full equality; trailing text must not survive truncation.
    let body = format!("{}€MUST_BE_TRUNCATED", "x".repeat(499));
    for status in [403, 500, 504] {
        let error = CapabilityExecutor::rl10_test_error(protocol, status, &body).await;
        let Error::Protocol(actual) = error else {
            panic!("{protocol}: non-429 {status} must remain Protocol, got {error:?}");
        };
        let expected = format!(
            "{prefix} {}: {}€",
            reqwest::StatusCode::from_u16(status).unwrap(),
            "x".repeat(499)
        );
        assert_eq!(
            actual, expected,
            "{protocol}: status {status} compatibility"
        );
    }
}

#[tokio::test]
async fn rl10_rest_preserves_exact_non_429_errors() {
    assert_non_429_contract("rest", "API returned").await;
}

#[tokio::test]
async fn rl10_jsonrpc_preserves_exact_non_429_errors() {
    assert_non_429_contract("jsonrpc", "JSON-RPC endpoint returned").await;
}

#[tokio::test]
async fn rl10_graphql_preserves_exact_non_429_errors() {
    assert_non_429_contract("graphql", "GraphQL endpoint returned").await;
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<(tracing::Level, Vec<(String, String)>)>>>);

#[derive(Default)]
struct Fields(Vec<(String, String)>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }
}

impl<S: Subscriber> Layer<S> for Events {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // The contract covers the new WARN. Existing request DEBUG events are
        // outside this increment and are not relabeled as safe by this test.
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), fields.0));
    }
}

impl Events {
    fn verified_metadata(&self, protocol: &str) -> String {
        let recorded = self.0.lock().unwrap();
        assert!(
            recorded.iter().any(|(_, fields)| fields
                .iter()
                .any(|(k, v)| k == "rl10_capture_canary" && v == "true")),
            "positive capture control"
        );
        assert!(
            recorded.iter().any(|(level, fields)| {
                *level == tracing::Level::WARN
                    && fields.iter().any(|(key, value)| {
                        key == "protocol" && value.trim_matches('"') == protocol
                    })
                    && fields
                        .iter()
                        .any(|(key, value)| key == "status" && value == "429")
            }),
            "{protocol}: WARN must carry protocol and numeric status; got {recorded:?}"
        );
        format!("{recorded:?}")
    }
}

async fn assert_safe_diagnostics(protocol: &str) {
    use tracing::instrument::WithSubscriber;

    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let error = async {
        tracing::warn!(rl10_capture_canary = true, "capture is active");
        CapabilityExecutor::rl10_test_error(protocol, 429, &secret_body()).await
    }
    .with_subscriber(subscriber)
    .await;
    let diagnostic = format!("{error} {}", events.verified_metadata(protocol));
    for secret in [
        QUERY_SECRET,
        BODY_SECRET,
        "localhost",
        FIXTURE_PATH,
        "api_key",
    ] {
        assert!(
            !diagnostic.contains(secret),
            "{protocol}: error/log leaked {secret}"
        );
    }
}

#[tokio::test]
async fn rl10_rest_warn_contains_only_safe_response_metadata() {
    assert_safe_diagnostics("rest").await;
}

#[tokio::test]
async fn rl10_jsonrpc_warn_contains_only_safe_response_metadata() {
    assert_safe_diagnostics("jsonrpc").await;
}

#[tokio::test]
async fn rl10_graphql_warn_contains_only_safe_response_metadata() {
    assert_safe_diagnostics("graphql").await;
}

async fn assert_backend_rpc_code(protocol: &str) {
    let error = CapabilityExecutor::rl10_test_error(protocol, 429, "synthetic").await;
    assert_eq!(error.to_rpc_code(), -32000, "{protocol}");
}

#[tokio::test]
async fn rl10_rest_429_keeps_backend_rpc_code() {
    assert_backend_rpc_code("rest").await;
}

#[tokio::test]
async fn rl10_jsonrpc_429_keeps_backend_rpc_code() {
    assert_backend_rpc_code("jsonrpc").await;
}

#[tokio::test]
async fn rl10_graphql_429_keeps_backend_rpc_code() {
    assert_backend_rpc_code("graphql").await;
}

#[tokio::test]
async fn rl10_other_typed_status_and_statusless_http_keep_internal_rpc_code() {
    for status in [403, 500] {
        let error = CapabilityExecutor::rl10_test_http_error(status).await;
        assert!(
            matches!(&error, Error::Http(inner) if inner.status().map(|s| s.as_u16()) == Some(status))
        );
        assert_eq!(error.to_rpc_code(), -32603, "typed {status}");
    }
    let error = CapabilityExecutor::rl10_test_transport_error().await;
    assert!(matches!(&error, Error::Http(inner) if inner.status().is_none()));
    assert_eq!(error.to_rpc_code(), -32603);
}

/// GH475.RL10.C12: without_url removes the URL field, but reqwest still keeps
/// the same endpoint in an independently parsed HTTP reason phrase.
#[tokio::test]
async fn rl10_raw_reason_control_survives_without_url_and_has_pending_body() {
    let server = StatusServer::start_reason_with_pending_body().await;
    let error = tokio::time::timeout(Duration::from_secs(2), async {
        Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(server.endpoint())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err()
            .without_url()
    })
    .await
    .expect("headers and status error must not require a completed body");
    assert_eq!(error.status(), Some(reqwest::StatusCode::TOO_MANY_REQUESTS));
    assert!(
        error.url().is_none(),
        "control must remove the separate URL field"
    );
    assert!(error.to_string().contains(&server.endpoint()));
    assert!(error.to_string().contains(QUERY_SECRET));
}
