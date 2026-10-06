// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `/accounts/v1` router's shell (design §4.3, §6.4): one header layer and
//! one trace span over every route under the prefix, including 404 and 405.

use crate::gateway::routes;
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::any;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use super::super::AppState;

/// The browser pages' policy (§4.3): no third-party content, no framing.
const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; \
                   form-action 'self'; frame-ancestors 'none'";
/// Where the provider redirects back; routed in `accounts::router`.
pub(crate) const CALLBACK: &str = routes::ACCOUNTS_CALLBACK;

/// `owner` (already authenticated) plus the unauthenticated browser routes,
/// wrapped so no response under the prefix leaves without the three headers.
pub(super) fn shell(owner: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    owner
        .route(
            routes::ACCOUNTS_UNROUTED,
            any(|| async { StatusCode::NOT_FOUND }),
        )
        .route(
            routes::ACCOUNTS_ROOT,
            any(|| async { StatusCode::NOT_FOUND }),
        )
        .layer(axum::middleware::map_response(harden))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http().make_span_with(super::super::trace_span::span_for))
}

async fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    response
}
