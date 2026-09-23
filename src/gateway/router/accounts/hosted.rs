// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `/accounts/v1` router's shell (design §4.3, §6.4): one header layer and
//! one trace span over every route under the prefix, including 404 and 405.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::response::Response;
use axum::routing::any;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;

use super::super::AppState;

/// The browser pages' policy (§4.3): no third-party content, no framing.
const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; \
                   form-action 'self'; frame-ancestors 'none'";
/// Where the provider redirects back; routed in `accounts::router`.
pub(crate) const CALLBACK: &str = "/accounts/v1/callback";
/// Every path under the prefix that no route claims.
const UNROUTED: &str = "/accounts/v1/{*rest}";
/// The bare prefix, which the catch-all does not match; claimed here so it
/// never reaches the main router's full-URI trace span.
const PREFIX_ROOT: &str = "/accounts/v1";

/// `owner` (already authenticated) plus the unauthenticated browser routes,
/// wrapped so no response under the prefix leaves without the three headers.
pub(super) fn shell(owner: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    owner
        .route(UNROUTED, any(|| async { StatusCode::NOT_FOUND }))
        .route(PREFIX_ROOT, any(|| async { StatusCode::NOT_FOUND }))
        .layer(axum::middleware::map_response(harden))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http().make_span_with(span_for))
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

/// Method and matched route only: the raw URI carries the callback's code
/// and state, and headers carry the Open `WebUI` session cookie.
fn span_for(request: &Request<Body>) -> tracing::Span {
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str);
    tracing::info_span!("accounts_request", method = %request.method(), path)
}
