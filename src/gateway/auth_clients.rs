// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The client identities the middleware assigns, and the credential and
//! session readers it uses to pick one.

use super::{
    AuthenticatedClient, Body, InternalPrincipal, QuotaPrincipal, Request, Response,
    SESSION_COOKIE, bearer_unauthorized_response, session_cookie,
};

/// The answer to a dashboard session that has ended: its own message and a
/// clearing cookie, rather than a "Missing credential" that sends the operator
/// looking for a header a browser cannot send.
pub(super) fn session_ended_response(secure: bool) -> Response {
    let mut response = bearer_unauthorized_response(
        "Dashboard session expired or ended; run `mcp-gateway dashboard-link` for a new link.",
    );
    if let Ok(value) = session_cookie("", 0, secure).parse() {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
    response
}

/// The dashboard's own background refreshes: the `/ui` interval sends the
/// header, and the `/dashboard` meta refresh targets `?poll=1`. Such a request
/// is checked but never extends a session. The marker can only fail to extend
/// one, so a forged or stripped marker cannot lengthen a session.
pub(super) fn is_poll(request: &Request<Body>) -> bool {
    request.headers().contains_key("x-mcp-gateway-poll")
        || (request.uri().path() == "/dashboard"
            && request
                .uri()
                .query()
                .is_some_and(|q| q.split('&').any(|p| p == "poll=1")))
}

/// The live UI stream, matched on the route the router chose, not the raw
/// path. A stream is the server pushing, never operator activity: opening it or
/// reconnecting must not keep an idle session alive (ADR-020).
pub(super) fn is_ui_stream(request: &Request<Body>) -> bool {
    request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .is_some_and(|p| p.as_str() == crate::gateway::routes::UI_STREAM)
}

/// The identity a validated dashboard session carries.
pub(super) fn dashboard_client() -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: Some(QuotaPrincipal::dashboard_session()),
        name: "dashboard".to_string(),
        principal: InternalPrincipal::new("dashboard-session".to_string()),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: true,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::DashboardSession,
    }
}

/// The credential a request presents, from the session cookie or a bearer header.
pub(super) fn presented_credential(headers: &axum::http::HeaderMap) -> Option<String> {
    // The session cookie is NOT a credential: it is an opaque handle checked
    // against this process's store, above.
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(ToString::to_string)
}

/// The SHA-256 of the bearer a request presents, for a binding that must
/// tell two bearers apart (the 12-hex principal is only a log fingerprint).
pub(crate) fn presented_bearer_sha256(headers: &axum::http::HeaderMap) -> Option<String> {
    presented_credential(headers).map(|token| crate::hashing::sha256_hex(token.as_bytes()))
}

/// Read the session cookie from a request's headers, if present.
#[must_use]
pub fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

/// The identity every caller holds when authentication is disabled.
///
/// Reaches ordinary tools, so a local MCP client works out of the box, and
/// holds no admin. Admin is an explicit grant that requires a credential
/// (`auth.enabled = true` with a bearer token): an auth-disabled gateway
/// cannot tell its operator apart from a web page that rebound a hostname to
/// loopback, or from any other process running as the same user.
///
/// `backends` is `["*"]` because an empty list reaches no backend: with auth
/// off there is no scope to narrow, so every backend stays reachable.
#[must_use]
pub fn anonymous_client() -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: None,
        name: "anonymous".to_string(),
        principal: InternalPrincipal::new(String::new()),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: false,
        credential_kind: crate::security::audit::CredentialKind::None,
    }
}

/// The identity a public path gives a caller no gateway credential
/// authenticates. One constructor, because delivery gives a validated agent
/// token the same one and compares principals against what ingress stored.
pub(super) fn public_client() -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: None,
        name: "public".to_string(),
        principal: InternalPrincipal::new(String::new()),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: false,
        credential_kind: crate::security::audit::CredentialKind::None,
    }
}
