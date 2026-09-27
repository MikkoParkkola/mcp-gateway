// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one span shape every traced router records (#1529).

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::Request;

/// Method and matched route template only. The raw URI can carry a session
/// id, a dashboard bootstrap value or an OAuth code in its query, and
/// headers carry credentials and cookies, so neither is recorded. Same level
/// and target as tower-http's own span, so `RUST_LOG=tower_http=debug` still
/// shows it.
pub(super) fn span_for(request: &Request<Body>) -> tracing::Span {
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str);
    tracing::span!(
        target: "tower_http::trace",
        tracing::Level::DEBUG,
        "request",
        method = %request.method(),
        path
    )
}
