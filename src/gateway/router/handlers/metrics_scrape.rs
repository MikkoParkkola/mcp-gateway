// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /metrics`.

use std::sync::Arc;

use crate::gateway::health_metrics::process;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

/// What `/metrics` needs: the scrape token, and the multiplexer whose session
/// count is read at scrape time.
#[derive(Clone)]
pub(in crate::gateway::router) struct MetricsState {
    pub(in crate::gateway::router) token: Option<Arc<str>>,
    pub(in crate::gateway::router) multiplexer:
        Arc<crate::gateway::streaming::NotificationMultiplexer>,
}

/// GET /metrics — Prometheus text exposition format scrape endpoint.
///
/// Answers only `Authorization: Bearer <server.metrics_token>`. Everything
/// else, the admin bearer included, gets 401 with `WWW-Authenticate: Bearer`,
/// and with no token configured nobody is admitted. The route sits outside the
/// main auth middleware on purpose: two credentials, two surfaces, and neither
/// opens the other. Returns an empty 200 when the recorder is not installed.
pub(in crate::gateway::router) async fn metrics_handler(
    State(state): State<MetricsState>,
    headers: HeaderMap,
) -> axum::response::Response {
    use axum::http::{HeaderValue, header};
    use subtle::ConstantTimeEq;
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let admitted = match (state.token.as_deref(), presented) {
        (Some(expected), Some(presented)) => {
            bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
        }
        _ => false,
    };
    if !admitted {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
        )
            .into_response();
    }
    // Set after the token check, so only an admitted scrape reads the count.
    process::record_sessions(state.multiplexer.session_count());
    let mut text = crate::metrics::render();
    text.push_str(&process::resident_memory_exposition());
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        text,
    )
        .into_response()
}
