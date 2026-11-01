// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! LOG.1: requests that log still complete while stderr never drains. Each
//! refused request logs one warning through the production text layer; the
//! writer's sink is parked, so the lines past the queue are dropped and
//! counted, and the requests are never held by the log.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth_and_key_server;
use crate::config::AuthConfig;
use crate::log_writer::NoticeFormat;
use crate::log_writer::test_sinks::{notices, parked};

/// A request to an authenticated path with no credential: 401, and one
/// `warn!(path, "Missing credential")` from the auth middleware.
fn unauthenticated() -> Request<Body> {
    Request::builder()
        .uri("/mcp")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_348))))
        .body(Body::empty())
        .expect("request builds")
}

#[tokio::test]
async fn l1_requests_that_log_complete_while_stderr_never_drains() {
    crate::test_log_capture::keep_interest_open();
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some("lossy-bearer".to_string()),
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (state, _dir) = test_router_app_state_with_auth_and_key_server(&auth, None).await;
    // Eight queued lines; the auth middleware's warnings only, so the count is exact.
    let (w, _flush, gate, out) = parked(8, 1 << 20);
    let subscriber = tracing_subscriber::registry()
        .with(Targets::new().with_target("mcp_gateway::gateway::auth", Level::WARN))
        .with(crate::log_layer(NoticeFormat::Text, w.clone()));
    let _default = tracing::subscriber::set_default(subscriber);

    let send = || async {
        create_router(Arc::clone(&state))
            .oneshot(unauthenticated())
            .await
            .expect("the router is infallible")
            .status()
    };
    assert_eq!(send().await, StatusCode::UNAUTHORIZED);
    // The writer holds the first line in its parked write: one in flight.
    assert!(gate.wait_entered(), "the writer never took the first line");
    for _ in 0..19 {
        assert_eq!(send().await, StatusCode::UNAUTHORIZED);
    }
    assert!(!gate.fired(), "a request waited on the log");
    assert_eq!(w.dropped_lines(), 20 - 1 - 8);

    gate.open();
    assert!(
        out.wait_for(|t| t.matches("Missing credential").count() == 9),
        "{}",
        out.text()
    );
    let lines = out.lines();
    assert!(lines[0].contains("Missing credential"), "{lines:?}");
    assert_eq!(
        notices(&lines[1..2]),
        [11],
        "the notice follows the first written line: {lines:?}"
    );
    assert_eq!(
        lines[2..]
            .iter()
            .filter(|l| l.contains("Missing credential"))
            .count(),
        8,
        "{lines:?}"
    );
}
