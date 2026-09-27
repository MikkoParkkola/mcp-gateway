// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dashboard logout and re-entry (MIK-7570.SESSION.1, E5).
//!
//! Logout lives on its own router, merged outside authentication and outside
//! the E1-f audit layer. An expired session must still be able to log out, and
//! an audit outage must never block a revocation. Re-entry is an ordinary
//! audited admin route inside [`super::api_router`].

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;

use super::errors::{admin_auth_required, flat_error};
use crate::gateway::auth::{
    AuthenticatedClient, cookies_are_secure, session_cookie, session_cookie_value,
};
use crate::gateway::router::AppState;
use crate::security::audit::{AuditEnvelope, AuditWho, CredentialKind};

/// Path of the logout route.
pub const LOGOUT_PATH: &str = "/dashboard/logout";

/// `POST /dashboard/logout`, unauthenticated by design: holding a handle is
/// the right to revoke it. POST only, so a link or an image cannot log anyone
/// out; the origin guard and `SameSite=Strict` keep it same-site.
pub fn logout_router() -> Router<Arc<AppState>> {
    Router::new().route(LOGOUT_PATH, post(logout))
}

/// Revoke the presented session server-side and clear the cookie. Idempotent:
/// an unknown, expired or absent handle gets the same answer.
pub(super) async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let ended = session_cookie_value(&headers)
        .is_some_and(|handle| state.dashboard_bootstrap.revoke(&handle));
    // The one audit write that does not fail closed: refusing to revoke a
    // session because the log is down is worse than a missing record.
    if let Some(log) = &state.transparency_log {
        let mut fields = serde_json::Map::new();
        fields.insert("route".into(), LOGOUT_PATH.into());
        fields.insert("method".into(), "POST".into());
        fields.insert("session_ended".into(), ended.into());
        let envelope = AuditEnvelope::ok(AuditWho::from_request(None, None));
        if let Err(error) = log.append_admin_action("admin_ui", fields, &envelope) {
            tracing::warn!(%error, "Dashboard logout not recorded; the session was still revoked");
        }
    }
    let secure = cookies_are_secure(&state.live_config.get());
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/dashboard".to_string()),
            (header::SET_COOKIE, session_cookie("", 0, secure)),
        ],
    )
        .into_response()
}

/// `POST /ui/api/dashboard-link`: re-arm a fresh single-use link.
///
/// Only a credential the link's redemption also accepts may mint one: the
/// static bearer or an admin API key. A dashboard session may not (it would
/// renew itself past the absolute limit), and neither may an SSO admin, whose
/// link would be refused at redemption. Replaces any unused value.
pub(super) async fn dashboard_link(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> Response {
    let may_mint = client.is_some_and(|Extension(c)| {
        c.admin
            && matches!(
                c.credential_kind,
                CredentialKind::StaticBearer | CredentialKind::ApiKey
            )
    });
    if !may_mint {
        return admin_auth_required().into_response();
    }
    let config = state.live_config.get();
    if cookies_are_secure(&config) && !config.mtls.enabled {
        // The session cookie would be `Secure` over a plain-HTTP loopback
        // listener, and a browser discards it: the link would be spent for
        // nothing. Same refusal as the startup banner's.
        return flat_error(
            StatusCode::CONFLICT,
            "server.public_url is HTTPS but this listener is plain HTTP, so the \
             session cookie would be discarded. Enable mtls or remove public_url.",
        )
        .into_response();
    }
    let host = config.server.host.as_str();
    let wildcard = matches!(host, "0.0.0.0" | "::" | "");
    if !wildcard && !crate::gateway::router::is_loopback_bind(host) {
        // Redemption accepts only a loopback peer, and a browser reaching a
        // concrete network address is not one: the link could never open.
        return flat_error(
            StatusCode::CONFLICT,
            "server.host is a network address, and a dashboard link opens only from \
             a loopback connection. Bind loopback or a wildcard address to use it.",
        )
        .into_response();
    }
    let value = state.dashboard_bootstrap.rearm();
    let scheme = if config.mtls.enabled { "https" } else { "http" };
    let authority = loopback_authority(&config.server.host, config.server.port);
    Json(json!({ "link": format!("{scheme}://{authority}/dashboard?bootstrap={value}") }))
        .into_response()
}

/// An address a browser on this machine can open. Redemption is loopback
/// only, so a wildcard bind becomes the loopback address.
fn loopback_authority(host: &str, port: u16) -> String {
    let host = match host {
        "0.0.0.0" | "" => "127.0.0.1",
        "::" => "::1",
        other => other,
    };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
