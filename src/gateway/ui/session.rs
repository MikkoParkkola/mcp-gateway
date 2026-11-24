// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dashboard logout, sign-in and re-entry (E5).
//!
//! Logout and sign-in live on their own router, merged outside authentication
//! and outside the E1-f audit layer. An expired session must still be able to
//! log out, and an audit outage must never block a revocation. Sign-in writes
//! its own audit records. Re-entry is an ordinary audited admin route inside
//! [`super::api_router`].

use crate::gateway::routes;
use std::sync::Arc;

use axum::extract::{Extension, FromRequest, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use super::errors::{admin_auth_required, flat_error};
use super::guard::Guard;
use crate::gateway::auth::{
    AuthenticatedClient, Bound, MintingKey, NamedApiKey, Navigation, Now, SessionLimits,
    cookies_are_secure, dashboard_session_who, is_gateway_admin, refused_sign_in, session_cookie,
    session_cookie_value, signed_in,
};
use crate::gateway::router::AppState;
use crate::security::audit::AuditEnvelope;

/// Path of the logout route.
pub const LOGOUT_PATH: &str = routes::DASHBOARD_LOGOUT;

/// Where a refused sign-in form returns a browser. Fixed: nothing in the
/// request chooses it.
const SIGNIN_REFUSED_TARGET: &str = "/ui/overview/status#signin-refused";

/// Audit surface of `POST /ui/signin`. This router is outside the E1-f layer,
/// so the route writes the record itself.
const SIGNIN_SURFACE: &str = "ui_signin";

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
    // Sign-in shares the handoff's private layer, so a router 405 and an
    // extractor 413 or 415 are `no-store` too.
    let handoff = Router::new()
        .route(
            routes::DASHBOARD_HANDOFF,
            get(handoff_form).post(handoff_code),
        )
        .route(routes::UI_SIGNIN, post(signin))
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
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    crate::gateway::auth::redeem_handoff(
        &state.dashboard_bootstrap,
        (&state.live_config, generation.auth()),
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
        let envelope = AuditEnvelope::ok(dashboard_session_who(
            state.live_config.generation().auth().record_key(),
        ));
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

/// `POST /ui/signin`: one form field, `key`, for a session cookie.
///
/// Origin is decided before the body is read. A refused origin, a bad body
/// and an extra field never check the key. The presented key is not logged
/// and is not written into the audit record.
async fn signin(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    request: axum::http::Request<axum::body::Body>,
) -> Response {
    let headers = request.headers().clone();
    if !signin_origin_ok(&state, header_str(&headers, header::ORIGIN)) {
        tracing::warn!("sign-in refused: Origin is absent or is not this gateway");
        return crate::gateway::middleware::bearer_unauthorized_response(
            "Sign in from this gateway's own page.",
        );
    }
    if !is_form(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let body = match axum::body::Bytes::from_request(request, &()).await {
        Ok(body) => body,
        Err(rejection) => return rejection.into_response(),
    };
    let Some(presented) = single_key(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let navigation = Navigation::of(&headers);
    let presented_session = session_cookie_value(&headers);
    let resolved = generation.auth().validate_token_with_origin(&presented);
    drop(presented);
    let Some((client, named)) = resolved else {
        return signin_refused(&state, navigation).await;
    };
    if !is_gateway_admin(Some(&client)) {
        return signin_refused(&state, navigation).await;
    }
    let Some(bound) = bound_for(generation.auth(), &client, named.as_ref()) else {
        return signin_refused(&state, navigation).await;
    };
    let who = crate::security::audit::AuditWho::from_request(
        Some(&client),
        None,
        generation.auth().record_key(),
    );
    if signin_audit(&state, crate::security::audit::AuditEnvelope::ok(who))
        .await
        .is_err()
    {
        return signin_withheld();
    }
    let limits = SessionLimits::from(&state.live_config.get().auth.dashboard_session);
    let now = Now::read();
    if let Some(handle) = presented_session {
        state.dashboard_bootstrap.revoke(&handle, now, &limits);
    }
    signed_in(
        &state.dashboard_bootstrap,
        &state.live_config,
        bound,
        now,
        cookies_are_secure(&state.live_config),
    )
}

/// The gateway's own origin, as [`crate::gateway::router::admits_signin`]
/// decides it. An absent Origin is not one.
fn signin_origin_ok(state: &AppState, origin: Option<&str>) -> bool {
    origin.is_some_and(|origin| crate::gateway::router::admits_signin(&state.live_config, origin))
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn is_form(headers: &HeaderMap) -> bool {
    header_str(headers, header::CONTENT_TYPE)
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// The body is exactly one field named `key`. Any other shape is `None`, and
/// the value is not checked.
fn single_key(body: &[u8]) -> Option<String> {
    let mut pairs = url::form_urlencoded::parse(body);
    let (name, value) = pairs.next()?;
    if name != "key" || pairs.next().is_some() {
        return None;
    }
    Some(value.into_owned())
}

/// A key that does not resolve, or resolves but is not an admin key this
/// route can bind. Counted once, recorded once, and answered by the fixed
/// refusal. The key is not part of the record.
async fn signin_refused(state: &AppState, navigation: Navigation) -> Response {
    crate::security::security_metrics::auth_failure(
        crate::security::security_metrics::AuthFailureKind::InvalidCredential,
    );
    tracing::warn!("sign-in refused: the key is not an admin key for this gateway");
    let envelope = crate::security::audit::AuditEnvelope {
        outcome: crate::security::audit::AuditOutcome::Denied(
            crate::error::rpc_codes::INVALID_REQUEST,
        ),
        ..crate::security::audit::AuditEnvelope::ok(refusal_who())
    };
    if signin_audit(state, envelope).await.is_err() {
        return signin_withheld();
    }
    refused_sign_in(
        navigation,
        crate::gateway::middleware::bearer_unauthorized_response("Invalid token"),
        SIGNIN_REFUSED_TARGET,
    )
}

/// No principal and no account: a refusal names nobody.
fn refusal_who() -> crate::security::audit::AuditWho {
    crate::security::audit::AuditWho {
        credential_kind: None,
        principal: crate::gateway::record_principal::RecordPrincipal::none(),
        account: String::new(),
        authority: None,
        subject: None,
    }
}

/// What a session minted by this credential is bound to, by a dashboard link
/// or by the sign-in form. It ends no later than the minting key's expiry
/// (otherwise a key used minutes before it expires would buy a full absolute
/// limit of access), with that key on a reload, by its quota identity, and
/// with the secret this request matched, by its fingerprint. The expiry comes
/// from `auth`, the table that authenticated this request, so a reload cannot
/// split them; the key is found by its credential, not its name, since two keys
/// may share a name when a config skipped load validation. The static bearer
/// binds nothing: it is restart-only. An API key that cannot be bound (not
/// found, or no quota identity or fingerprint) may not mint: `None`.
fn bound_for(
    auth: &crate::gateway::auth::ResolvedAuthConfig,
    client: &AuthenticatedClient,
    named: Option<&NamedApiKey>,
) -> Option<Bound> {
    if client.api_key_identity().is_none() {
        return Some(Bound {
            not_after: None,
            key: None,
        });
    }
    let not_after = auth
        .api_keys()
        .iter()
        .find(|key| key.principal() == client.principal)
        .map(|key| key.expires_at.map(std::time::SystemTime::from))?;
    Some(Bound {
        not_after,
        key: Some(MintingKey {
            quota: client.quota_principal.clone()?,
            digest_tag: named?.digest_tag().to_owned(),
        }),
    })
}

/// One `ui_signin` record with an empty domain map. No log skips the write.
/// A fail-closed failure withholds the answer; a best-effort failure does not.
async fn signin_audit(
    state: &AppState,
    envelope: crate::security::audit::AuditEnvelope,
) -> Result<(), ()> {
    let Some(log) = &state.transparency_log else {
        return Ok(());
    };
    let fail_closed =
        log.failure_policy() == crate::security::audit::AuditFailurePolicy::FailClosed;
    let written = log
        .append_bounded(move |logger| {
            logger
                .append_admin_action(SIGNIN_SURFACE, serde_json::Map::new(), &envelope)
                .map_err(std::io::Error::other)
        })
        .await;
    match written {
        Ok(()) => Ok(()),
        Err(error) if fail_closed => {
            tracing::warn!(%error, "sign-in was not recorded; no session was opened");
            Err(())
        }
        Err(error) => {
            tracing::warn!(%error, "sign-in was not recorded; the answer was still sent");
            Ok(())
        }
    }
}

fn signin_withheld() -> Response {
    crate::gateway::http_error::json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        crate::gateway::http_error::jsonrpc_error_body(
            crate::error::rpc_codes::INTERNAL_ERROR,
            "Sign-in was not recorded, so no session was opened.",
        ),
    )
}

/// `POST /ui/api/dashboard-link`: re-arm a fresh single-use link.
///
/// Only a credential the link's redemption also accepts may mint one: the
/// static bearer or an admin API key. A dashboard session may not (it would
/// renew itself past the absolute limit), and neither may an SSO admin, whose
/// link would be refused at redemption. Replaces any unused value.
pub(super) async fn dashboard_link(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    named: Option<Extension<crate::gateway::auth::NamedApiKey>>,
    guard: Guard,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    // Admitted: an admin holding the static bearer or an API key.
    let Some(client) = guard.client else {
        return admin_auth_required().into_response();
    };
    let Some(bound) = bound_for(
        generation.auth(),
        &client,
        named.as_ref().map(|Extension(key)| key),
    ) else {
        return admin_auth_required().into_response();
    };
    // Host, port and TLS are restart-only: the running listener's values, not
    // a reloaded file's, say where a browser can reach this process.
    let running = state.live_config.running();
    let host = running.server.host.as_str();
    if !crate::gateway::router::is_wildcard_bind(host)
        && !crate::gateway::router::is_loopback_bind(host)
    {
        // Redemption accepts only a loopback peer, and a browser reaching a
        // concrete network address is not one: the link could never open.
        return flat_error(
            StatusCode::CONFLICT,
            "server.host is a network address, and a dashboard link opens only from \
             a loopback connection. Bind loopback or a wildcard address to use it.",
        )
        .into_response();
    }
    let value = state.dashboard_bootstrap.rearm_bound(bound);
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
    // A bracketed bind host (`[::]`) is judged as its address, as the
    // wildcard test judges it.
    let bare = crate::gateway::router::strip_brackets(host);
    let host = match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) if ip.is_unspecified() => "::1",
        _ if crate::gateway::router::is_wildcard_bind(bare) => "127.0.0.1",
        _ => bare,
    };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(tp3)]
#[cfg(test)]
mod mik_8659_dashboard_tests {
    pub(super) async fn t1f_app_state(
        auth_config: &std::sync::Arc<crate::gateway::auth::ResolvedAuthConfig>,
        store_dir: &std::path::Path,
        config: crate::config::Config,
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
            key_server: None,
            dashboard_bootstrap: Arc::default(),
            tls_enabled: false,
            live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
                crate::config_reload::flags_off(config.clone()),
                Arc::clone(auth_config),
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
            key_server: None,
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
            live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
                crate::config_reload::flags_off(config),
                Arc::clone(auth_config),
            )),
            export_status: None,
            transparency_log: None,
            governance_log: None,
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
        let state = t1f_app_state(
            &auth_config,
            store_dir.path(),
            crate::config::Config::default(),
        )
        .await;
        let response = super::dashboard_link(
            axum::extract::State(Arc::clone(&state)),
            axum::extract::Extension(state.live_config.generation()),
            None,
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

    #[tokio::test]
    async fn an_api_key_client_with_no_bindable_identity_mints_no_link() {
        use std::sync::Arc;
        let secret = "k13-unbindable-admin-secret";
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
        let (real, named) = auth_config
            .validate_token_with_origin(secret)
            .expect("admin key validates");
        // K13: an API-key client with no quota identity cannot bind the link
        // to its key, so the mint fails closed rather than minting a link no
        // reload can end.
        let mut unbindable = real;
        unbindable.quota_principal = None;
        let store_dir = tempfile::tempdir().expect("task store dir");
        let state = t1f_app_state(
            &auth_config,
            store_dir.path(),
            crate::config::Config::default(),
        )
        .await;
        // Premise: the access table admits this client, so a 403 below is
        // the mint's own refusal, not the guard's.
        assert!(
            super::super::guard::decide(
                super::super::access_table::Need::AdminKeyLink,
                Some(&unbindable)
            )
            .is_ok(),
            "premise: the guard admits an admin API key"
        );
        let response = super::dashboard_link(
            axum::extract::State(Arc::clone(&state)),
            axum::extract::Extension(state.live_config.generation()),
            // The match's own record, so the refusal is the missing quota
            // identity's, not a missing secret binding's.
            named.clone().map(axum::extract::Extension),
            super::super::guard::Guard::for_route(
                crate::gateway::routes::UI_DASHBOARD_LINK,
                &axum::http::Method::POST,
                Some(unbindable),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "an unbindable API-key client minted a link"
        );
        // A client with its quota identity but no record of which secret it
        // matched cannot be bound to that secret either: fail closed.
        let response = super::dashboard_link(
            axum::extract::State(Arc::clone(&state)),
            axum::extract::Extension(state.live_config.generation()),
            None,
            super::super::guard::Guard::for_route(
                crate::gateway::routes::UI_DASHBOARD_LINK,
                &axum::http::Method::POST,
                Some(
                    auth_config
                        .validate_token(secret)
                        .expect("admin key validates"),
                ),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "an API-key client with no matched secret minted a link"
        );
    }
}

/// The dashboard link's binding order, and the session bound it shares with
/// the sign-in form.
#[cfg(tp3)]
#[cfg(test)]
#[path = "session_bound_tests.rs"]
mod bound_tests;
