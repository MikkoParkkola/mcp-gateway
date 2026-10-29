// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dashboard logout and re-entry (MIK-7570.SESSION.1, E5).
//!
//! Logout lives on its own router, merged outside authentication and outside
//! the E1-f audit layer. An expired session must still be able to log out, and
//! an audit outage must never block a revocation. Re-entry is an ordinary
//! audited admin route inside [`super::api_router`].

use crate::gateway::routes;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use super::errors::{admin_auth_required, flat_error};
use super::guard::Guard;
use crate::gateway::auth::{
    Now, SessionLimits, cookies_are_secure, dashboard_session_who, session_cookie,
    session_cookie_value,
};
use crate::gateway::router::AppState;
use crate::security::audit::AuditEnvelope;

/// Path of the logout route.
pub const LOGOUT_PATH: &str = routes::DASHBOARD_LOGOUT;

/// `POST /dashboard/logout`, unauthenticated by design: holding a handle is
/// the right to revoke it. POST only, so a link or an image cannot log anyone
/// out; the origin guard and `SameSite=Strict` keep it same-site.
///
/// It also carries the dashboard handoff (#2130), unauthenticated for the same
/// reason: the posted code is the credential, and a session cookie the browser
/// already holds, live or dead, must not decide it.
pub fn logout_router() -> Router<Arc<AppState>> {
    // Every answer on the handoff path, including a router 405 or an
    // extractor 413, is neither cached nor sent onward as a `Referer`.
    let handoff = Router::new()
        .route(
            routes::DASHBOARD_HANDOFF,
            get(handoff_form).post(handoff_code),
        )
        .layer(axum::middleware::map_response(handoff_private));
    Router::new()
        .route(routes::DASHBOARD_LOGOUT, post(logout))
        .merge(handoff)
}

async fn handoff_private(response: Response) -> Response {
    crate::gateway::auth::handoff_private(response)
}

async fn handoff_form() -> Response {
    crate::gateway::auth::handoff_form()
}

/// The body is read by the extractor, under the router's configured limit.
async fn handoff_code(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    crate::gateway::auth::redeem_handoff(
        &state.dashboard_bootstrap,
        &state.live_config,
        origin,
        &body,
        crate::gateway::auth::Navigation::of(&headers),
    )
}

/// Revoke the presented session server-side, clear the cookie and send the
/// browser to `/ui`. Idempotent: an unknown, expired or absent handle gets the
/// same answer.
async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let limits = SessionLimits::from(&state.live_config.get().auth.dashboard_session);
    let ended = session_cookie_value(&headers).is_some_and(|handle| {
        state
            .dashboard_bootstrap
            .revoke(&handle, Now::read(), &limits)
    });
    // The one audit write that does not fail closed: refusing to revoke a
    // session because the log is down is worse than a missing record. Written
    // only when a live session actually ended: the route is unauthenticated,
    // so recording every attempt would let anyone fill the log.
    // Through the bounded append, so a stuck audit write cannot hold the answer.
    if ended && let Some(log) = &state.transparency_log {
        let mut fields = serde_json::Map::new();
        fields.insert("route".into(), LOGOUT_PATH.into());
        fields.insert("method".into(), "POST".into());
        let envelope = AuditEnvelope::ok(dashboard_session_who(state.auth_config.record_key()));
        let written = log
            .append_bounded(move |l| {
                l.append_admin_action("admin_ui", fields, &envelope)
                    .map_err(std::io::Error::other)
            })
            .await;
        if let Err(error) = written {
            tracing::warn!(%error, "Dashboard logout not recorded; the session was still revoked");
        }
    }
    let secure = cookies_are_secure(&state.live_config);
    (
        StatusCode::SEE_OTHER,
        [
            // `/ui` needs no session; `/dashboard` would answer 401 now.
            (header::LOCATION, "/ui".to_string()),
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
pub(super) async fn dashboard_link(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    // Admitted: an admin holding the static bearer or an API key.
    let Some(client) = guard.client else {
        return admin_auth_required().into_response();
    };
    // A session opened by this link ends no later than the key that minted
    // it: otherwise a key used minutes before its expiry would buy a full
    // absolute limit of access after it.
    // The expiry comes from the resolved key that authenticated this request,
    // not the live file, so a reload cannot split them. A key that is not
    // found cannot prove its expiry, so it may not mint: fail closed.
    let not_after = if client.api_key_identity().is_some() {
        let keys = state.auth_config.api_keys();
        let Some(key) = keys
            .iter()
            // By the credential, not the name: two keys may share a name
            // when a config skipped load validation (MIK-8489).
            .find(|k| k.principal() == client.principal)
        else {
            return admin_auth_required().into_response();
        };
        key.expires_at.map(std::time::SystemTime::from)
    } else {
        None
    };
    // Host, port and TLS are restart-only: the running listener's values, not
    // a reloaded file's, say where a browser can reach this process.
    let running = state.live_config.running();
    let host = running.server.host.as_str();
    if !is_wildcard(host) && !crate::gateway::router::is_loopback_bind(host) {
        // Redemption accepts only a loopback peer, and a browser reaching a
        // concrete network address is not one: the link could never open.
        return flat_error(
            StatusCode::CONFLICT,
            "server.host is a network address, and a dashboard link opens only from \
             a loopback connection. Bind loopback or a wildcard address to use it.",
        )
        .into_response();
    }
    let value = state.dashboard_bootstrap.rearm_until(not_after);
    let scheme = if running.mtls.enabled {
        "https"
    } else {
        "http"
    };
    // `server.port: 0` binds an OS-chosen port; the link names that one.
    let port = state
        .dashboard_bootstrap
        .bound_port()
        .unwrap_or(running.server.port);
    let authority = loopback_authority(host, port);
    Json(json!({ "link": format!("{scheme}://{authority}/dashboard?bootstrap={value}") }))
        .into_response()
}

/// An address a browser on this machine can open. Redemption is loopback
/// only, so a wildcard bind becomes the loopback address.
fn loopback_authority(host: &str, port: u16) -> String {
    let host = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) if ip.is_unspecified() => "::1",
        _ if is_wildcard(host) => "127.0.0.1",
        _ => host,
    };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A bind on every interface, in any spelling (`0.0.0.0`, `::`,
/// `0:0:0:0:0:0:0:0`), or none given.
fn is_wildcard(host: &str) -> bool {
    host.is_empty()
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_unspecified())
}

#[cfg(test)]
mod mik_8659_dashboard_tests {
    async fn t1f_app_state(
        auth_config: &std::sync::Arc<crate::gateway::auth::ResolvedAuthConfig>,
        store_dir: &std::path::Path,
    ) -> std::sync::Arc<super::super::super::router::AppState> {
        use std::sync::Arc;
        let backends = Arc::new(crate::backend::BackendRegistry::new());
        let meta_mcp = Arc::new(crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(
            &backends,
        )));
        let streaming_config = crate::config::StreamingConfig::default();
        let multiplexer = Arc::new(crate::gateway::streaming::NotificationMultiplexer::new(
            Arc::clone(&backends),
            streaming_config.clone(),
        ));
        let proxy_manager = Arc::new(crate::gateway::proxy::ProxyManager::new(Arc::clone(
            &multiplexer,
        )));
        let agent_auth = crate::gateway::oauth::AgentAuthState::new(
            false,
            Arc::new(crate::gateway::oauth::AgentRegistry::new()),
        );
        let gateway_key_pair =
            Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("gateway key"));
        let authorizer = crate::gateway::auth::AuthState {
            auth_config: Arc::clone(auth_config),
            key_server: None,
            dashboard_bootstrap: Arc::default(),
            tls_enabled: false,
            live_config: Arc::new(crate::config_reload::LiveConfig::new(
                crate::config_reload::flags_off(crate::config::Config::default()),
            )),
            agent_auth: agent_auth.clone(),
        };
        let subscriptions = Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64, authorizer),
        );
        let (task_service, task_executor) =
            crate::gateway::task_service::open_runtime_with_admission(
                &store_dir.join("tasks"),
                crate::config::TasksConfig::default().max_workers,
                crate::gateway::task_service::StoreLimits::default(),
                Arc::clone(&subscriptions),
                Arc::clone(meta_mcp.execution_admission()),
            )
            .await
            .expect("task store opens");
        Arc::new(super::super::super::router::AppState {
            process: std::sync::Arc::default(),
            session_lifecycle: None,
            continuation: Arc::new(crate::protocol::continuation::ContinuationState::new()),
            env: None,
            backends,
            meta_mcp,
            meta_mcp_enabled: true,
            multiplexer,
            proxy_manager,
            streaming_config,
            auth_config: Arc::clone(auth_config),
            key_server: None,
            tool_policy: Arc::new(crate::security::ToolPolicy::default()),
            mtls_policy: Arc::new(crate::mtls::MtlsPolicy::from_config(
                &crate::mtls::MtlsConfig::default(),
            )),
            trust_configured_backends: false,
            inflight: Arc::new(tokio::sync::Semaphore::new(8)),
            agent_auth,
            gateway_key_pair,
            capability_dirs: Vec::new(),
            config_path: None,
            #[cfg(feature = "firewall")]
            firewall: None,
            agent_identity_config: crate::config::AgentIdentityConfig::default(),
            control_plane_store: None,
            control_plane_base: None,
            live_config: Arc::new(crate::config_reload::LiveConfig::new(
                crate::config_reload::flags_off(crate::config::Config::default()),
            )),
            export_status: None,
            transparency_log: None,
            dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
            tasks: task_service,
            task_executor,
            subscriptions,
        })
    }

    /// MIK-8659 T1f unauthenticated (RED): the same admin API key with
    /// `authenticated: false` is refused by the auth check alone. Host is
    /// loopback and the key is found with no expiry, so only the missing
    /// `authenticated` conjunct can refuse it. Today copy 7 does not check
    /// it, so a link is minted and this fails.
    #[tokio::test]
    async fn t1f_unauthenticated_admin_key_is_refused() {
        use std::sync::Arc;
        let secret = "mik-8659-t1f-unauth-secret";
        let auth = crate::config::AuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![crate::config::ApiKeyConfig {
                key: None,
                key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
                expires_at: None,
                name: "k".to_owned(),
                rate_limit: 0,
                backends: vec!["*".to_owned()],
                allowed_tools: None,
                denied_tools: None,
                admin: true,
                kind: crate::config::ApiKeyKind::Shared,
                ..Default::default()
            }],
            ..crate::config::AuthConfig::default()
        };
        let auth_config = Arc::new(
            crate::gateway::auth::ResolvedAuthConfig::try_from_config(
                &auth,
                &crate::config::EnvOverlay::none(),
                crate::gateway::record_principal::TEST_RECORD_KEY,
            )
            .expect("fixture auth resolves"),
        );
        let real = auth_config
            .validate_token(secret)
            .expect("admin key validates");
        let unauthenticated = crate::gateway::auth::AuthenticatedClient {
            authenticated: false,
            // MIK-6704.IDENT.1a: the validated client's own principal, copied so
            // only the authenticated flag differs.
            principal: real.principal.clone(),
            ..real
        };
        let store_dir = tempfile::tempdir().expect("task store dir");
        let state = t1f_app_state(&auth_config, store_dir.path()).await;
        let response = super::dashboard_link(
            axum::extract::State(Arc::clone(&state)),
            super::super::guard::Guard::for_route(
                crate::gateway::routes::UI_DASHBOARD_LINK,
                &axum::http::Method::POST,
                Some(unauthenticated),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "unauthenticated admin key is refused by the auth check"
        );
    }
}
