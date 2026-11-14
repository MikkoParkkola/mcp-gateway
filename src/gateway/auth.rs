// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Authentication middleware for MCP Gateway
//!
//! Supports:
//! - Bearer token authentication
//! - API key authentication with per-key restrictions
//! - Rate limiting per client
//! - Public paths that bypass authentication

use std::sync::Arc;

use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use tracing::{debug, warn};

use super::middleware::{
    bearer_unauthorized_response, circuit_open_response, rate_limited_response,
};
use crate::config::CircuitBreakerConfig;
use crate::gateway::record_principal::InternalPrincipal;
use crate::key_server::KeyServer;

#[path = "auth_live.rs"]
pub(crate) mod live;

#[path = "auth_runtime.rs"]
pub(crate) mod runtime;
use live::key_server_credential;
#[path = "auth_quota.rs"]
mod quota;
pub use quota::QuotaPrincipal;
#[path = "auth_api_key.rs"]
mod api_key;
pub use api_key::ResolvedApiKey;
#[cfg(test)]
pub(crate) use api_key::secret_tag;
pub(crate) use api_key::{
    PreviousDigest, digest_tag_of, presented_digest, refuse_shared_digests, tag_still_valid,
};
#[path = "auth_dashboard.rs"]
mod dashboard;
pub use dashboard::DashboardBootstrap;
pub(crate) use dashboard::{
    Bound, MintingKey, Now, Redeem, Redemption, SessionCheck, SessionLimits, Touch,
};

/// Retains the minting key's identity when a cookie authenticates a dashboard request.
#[cfg(feature = "webui")]
#[derive(Debug, Clone)]
pub(crate) struct SessionMintedBy(pub(crate) MintingKey);

#[path = "auth_bootstrap.rs"]
mod bootstrap;
#[path = "auth_handoff.rs"]
mod handoff;
use crate::security::security_metrics::{AuthFailureKind, auth_failure};
#[cfg(feature = "webui")]
pub(crate) use bootstrap::Navigation;
use bootstrap::{bootstrap_param, try_dashboard_bootstrap};
#[cfg(feature = "webui")]
pub(crate) use handoff::{handoff_form, private as handoff_private, redeem_handoff};

/// The `tracing` target of the events this module raises, its `resolved`
/// child included: code moved into a child module keeps the target a log
/// filter already names.
const AUTH_TARGET: &str = module_path!();

/// Short, non-reversible fingerprint of a secret for log correlation (CWE-532).
///
/// Returns the first 12 hex chars of the SHA-256 digest — enough to correlate
/// which credential is active across logs, useless as a credential itself.
pub(crate) fn principal_of(token: &str) -> InternalPrincipal {
    InternalPrincipal::new(bearer_token_fingerprint(token))
}

fn bearer_token_fingerprint(token: &str) -> String {
    crate::hashing::sha256_hex(token.as_bytes())[..12].to_string()
}

/// A configured API key's principal: the first 48 bits of its digest, as hex.
///
/// Persisted as the key of sessions, grants, journals and task owners, so it
/// is never lengthened; two credentials that share one are refused instead
/// ([`refuse_shared_principals`], MIK-7973).
fn principal_of_digest(digest: &[u8; 32]) -> InternalPrincipal {
    InternalPrincipal::new(hex::encode(&digest[..6]))
}

/// A configured key's principal (ADR-022): `explicit` when the key records
/// one, written at its first rotation, otherwise derived from `digest`, its
/// current digest. The only way any code outside this file turns a configured
/// key into a principal.
pub(crate) fn configured_key_principal(
    explicit: Option<&str>,
    digest: &[u8; 32],
) -> InternalPrincipal {
    explicit.map_or_else(
        || principal_of_digest(digest),
        |principal| InternalPrincipal::new(principal.to_owned()),
    )
}

/// The prefix of a credential caller's owner key, `credential:<principal>`: a
/// task's recorded owner and the key of its MCP child (MIK-7825).
pub(crate) const CREDENTIAL_OWNER_PREFIX: &str = "credential:";

/// MIK-7973: refuse a configuration where two credentials resolve to one
/// principal, since each would then own the other's sessions, grants and tasks.
///
/// Covers the bearer and API keys configured together. Identities issued at
/// runtime (key-server tokens, delegated OIDC bearers) need no check: their
/// principals are tagged and cannot fall in this space (MIK-8006). A principal
/// that a removed credential once held is not checked either.
///
/// The error names the two credentials, never a secret, digest or principal.
pub(crate) fn refuse_shared_principals<'a>(
    bearer: Option<&str>,
    keys: impl IntoIterator<Item = (&'a str, InternalPrincipal)>,
) -> crate::Result<()> {
    let bearer = bearer.map(|token| ("auth.bearer_token".to_owned(), principal_of(token)));
    let keys = keys
        .into_iter()
        .map(|(name, principal)| (format!("auth.api_keys['{name}']"), principal));
    let mut seen = std::collections::HashMap::new();
    for (label, principal) in bearer.into_iter().chain(keys) {
        if let Some(first) = seen.insert(principal, label.clone()) {
            return Err(crate::Error::ConfigValidation(format!(
                "{first} and {label} resolve to the same credential principal (the first 48 \
                 bits of the SHA-256 digest, or an explicit principal), so the gateway could \
                 not tell their callers apart; replace one of the two credentials or remove \
                 the duplicate entry"
            )));
        }
    }
    Ok(())
}

/// Resolved authentication configuration (tokens expanded)
pub struct ResolvedAuthConfig {
    /// Whether auth is enabled
    pub enabled: bool,
    /// Resolved bearer token
    pub bearer_token: Option<String>,
    /// Precomputed full digest, published only after validating the bearer.
    bearer_quota_principal: Option<QuotaPrincipal>,
    /// Resolved API keys. Read through [`Self::api_keys`], never directly, so
    /// every reader sees one snapshot of the list.
    api_keys: Vec<ResolvedApiKey>,
    /// Public paths
    pub public_paths: Vec<String>,
    /// Optional client circuit-breaker policy shared across per-client breaker instances.
    client_circuit_breaker: Option<CircuitBreakerConfig>,
    /// Per-client rate-limit buckets and circuit breakers, keyed by credential
    /// (`client_state_key`): one store shared by every config built over it.
    runtime: Arc<runtime::AuthRuntime>,
    /// The record key every client minted here computes its record principal
    /// with (MIK-8697 §16): resolved once at startup and injected, never picked.
    record_key: Arc<crate::gateway::record_principal::RecordPrincipalKey>,
}

// Manual `Debug` that redacts resolved secrets (CWE-532, mirrors MIK-6733).
// A derived `Debug` would print the bearer token / API key verbatim into any
// trace or error context. Only a non-reversible fingerprint is shown.
impl std::fmt::Debug for ResolvedAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedAuthConfig")
            .field("enabled", &self.enabled)
            .field(
                "bearer_token",
                &self.bearer_token.as_deref().map(|_| "<redacted>"),
            )
            .field("api_keys", &self.api_keys)
            .field("public_paths", &self.public_paths)
            .field("record_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Proof that THIS request authenticated with a configured API key, naming
/// which one.
///
/// Deliberately not constructible outside this module (private field, no public
/// constructor): the only mint site is
/// [`ResolvedAuthConfig::validate_token_with_origin`], the one place that
/// compares a presented secret against `api_keys`. An adapter allow-list is
/// written against these names, so if any other code could build one — from a
/// header, from `AuthenticatedClient::name`, from an OIDC subject — the
/// allow-list would be satisfiable by an identity that never presented the key.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NamedApiKey {
    name: String,
    personal: bool,
    /// The key's previous digest matched, not its current one (ADR-022).
    matched_previous_digest: bool,
    /// The fingerprint ([`digest_tag_of`]) of the digest that matched,
    /// current or previous: what a watch or session opened by this request is bound to,
    /// so it ends when that secret stops being valid. Never the digest.
    digest_tag: String,
}

// The tag fingerprints a secret: redacted, as `ApiKeyRef` redacts it.
impl std::fmt::Debug for NamedApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedApiKey")
            .field("name", &self.name)
            .field("personal", &self.personal)
            .field("matched_previous_digest", &self.matched_previous_digest)
            .field("digest_tag", &"<redacted>")
            .finish()
    }
}

impl NamedApiKey {
    /// The configured `name` of the API key that authenticated this request.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Whether the key is configured `kind: personal`: held by one person,
    /// so it is a per-caller identity on its own.
    pub(crate) fn is_personal(&self) -> bool {
        self.personal
    }

    /// Whether the request presented the key's previous secret, inside its
    /// grace (ADR-022): the caller still holds the secret a rotation replaced.
    pub(crate) fn matched_previous_digest(&self) -> bool {
        self.matched_previous_digest
    }

    /// The fingerprint of the digest this request matched, taken at the
    /// match: a holder this request opens is bound to it, never to a later
    /// read of the key table.
    pub(crate) fn digest_tag(&self) -> &str {
        &self.digest_tag
    }
}

#[path = "auth_resolved.rs"]
mod resolved;
pub(crate) use resolved::KeyBinding;

/// Carries the matched key's provenance with the request, so downstream checks
/// read it rather than re-derive it. A request that presented a rotated key's
/// previous secret is logged at DEBUG, naming only the key (ADR-022).
fn attach_api_key(request: &mut Request<Body>, api_key: Option<NamedApiKey>) {
    let Some(api_key) = api_key else {
        return;
    };
    if api_key.matched_previous_digest() {
        debug!(key = %api_key.name(), "API key authenticated with its previous secret");
    }
    request.extensions_mut().insert(api_key);
}

pub use crate::security::audit::CredentialKind;

#[path = "auth_caller.rs"]
mod caller;
pub use caller::AuthenticatedClient;
pub(in crate::gateway) use caller::{api_key_name, authenticated_principal, is_gateway_admin};
#[path = "auth_cookies.rs"]
mod cookies;
pub use cookies::SESSION_COOKIE;
pub(super) use cookies::session_limits;
pub(crate) use cookies::{cookie_secure, is_https_url, session_cookie};
// Outside this module only the web UI asks; `cookie_secure` asks it inside.
#[cfg(feature = "webui")]
pub(crate) use cookies::cookies_are_secure;

/// Who a dashboard-session action is attributed to in the audit log: the same
/// identity the middleware gives a valid session.
#[cfg(feature = "webui")]
pub(crate) fn dashboard_session_who(
    key: &crate::gateway::record_principal::RecordPrincipalKey,
) -> crate::security::audit::AuditWho {
    crate::security::audit::AuditWho::from_request(Some(&dashboard_client()), None, key)
}

#[path = "auth_clients.rs"]
mod clients;
pub(crate) use clients::presented_bearer_sha256;
pub use clients::{anonymous_client, session_cookie_value};
use clients::{
    dashboard_client, is_poll, is_ui_stream, presented_credential, public_client,
    session_ended_response,
};

/// Combined auth state: static config + optional key server.
#[derive(Clone)]
pub struct AuthState {
    /// Key server for OIDC-issued temporary tokens (optional).
    pub key_server: Option<Arc<KeyServer>>,
    /// Single-use value that opens the dashboard from a printed link.
    pub dashboard_bootstrap: Arc<DashboardBootstrap>,
    /// Whether this listener speaks TLS, so the session cookie is `Secure`.
    /// A live HTTPS `public_url` also makes it `Secure` (`cookie_secure`).
    pub tls_enabled: bool,
    /// The live config: its generations hold the API key table and the
    /// running `auth` settings, and its `control_plane.role_mapping` confers
    /// admin per request (E1-a). A request is judged by the generation the
    /// router pinned on it; a held credential by the one current at delivery.
    pub live_config: Arc<crate::config_reload::LiveConfig>,
    /// Agent authentication, holding the same registry the agent middleware
    /// validates against at ingress, so a held agent token is re-judged by
    /// the one validator.
    pub agent_auth: crate::gateway::oauth::AgentAuthState,
}

/// Authentication middleware
///
/// Validation order (for performance and backward compatibility):
/// 1. Static auth (existing `ResolvedAuthConfig`) — O(n) comparison.
/// 2. Key server credential — temporary token (`DashMap` lookup, O(1)), then a
///    delegated OIDC bearer when enabled.
/// 3. Reject.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(pinned) = live::pinned_auth(&request) else {
        return live::unpinned();
    };
    let auth_config = &*pinned;

    // If auth is disabled, pass through with anonymous client
    if !auth_config.enabled {
        request.extensions_mut().insert(anonymous_client());
        return next.run(request).await;
    }

    // An opaque dashboard session, validated against this process's store
    // rather than treated as a credential.
    //
    // A presented `Authorization` header decides the request alone: a live
    // cookie beside it neither overrides it (an admin key must not be read
    // as the weaker session) nor stands in for it when it is wrong (no
    // fallback). The cookie is still checked, so a dead one is cleared.
    let has_authorization = request
        .headers()
        .contains_key(axum::http::header::AUTHORIZATION);
    // A link being redeemed is decided by the exchange, never by a cookie the
    // browser holds: a live one must not leave the link unspent (#2130).
    let is_bootstrap = request.uri().path() == "/dashboard"
        && request.uri().query().and_then(bootstrap_param).is_some();
    // The kind a dead cookie is refused as, when it is refused on its own.
    let mut dead_session = None;
    // A session refused on a clock before 1970 keeps its cookie: it may be
    // live once the clock reads (MIK-8202).
    let mut keep_cookie = false;
    if let Some(handle) = session_cookie_value(request.headers()) {
        let touch = if has_authorization || is_poll(&request) || is_ui_stream(&request) {
            Touch::No
        } else {
            Touch::Yes
        };
        let limits = session_limits(&state);
        // Judged by the request's pinned key table: a session whose minting
        // key a reload removed, demoted or expired ends here (K13).
        let checked_session = state.dashboard_bootstrap.check_session_with_origin(
            &handle,
            Now::read(),
            &limits,
            touch,
            auth_config,
        );
        match checked_session.0 {
            SessionCheck::Valid if !has_authorization && !is_bootstrap => {
                request.extensions_mut().insert(dashboard_client());
                #[cfg(feature = "webui")]
                if let Some(key) = checked_session.1 {
                    request.extensions_mut().insert(SessionMintedBy(key));
                }
                return next.run(request).await;
            }
            SessionCheck::Valid => {}
            SessionCheck::Expired => dead_session = Some(AuthFailureKind::SessionExpired),
            SessionCheck::Unknown => dead_session = Some(AuthFailureKind::InvalidCredential),
            SessionCheck::ClockUnreadable => {
                dead_session = Some(AuthFailureKind::SessionExpired);
                keep_cookie = true;
            }
        }
    }
    if let Some(kind) = dead_session {
        // A dead handle answers for itself, unless the request carries
        // something else to decide it: a bearer beside a stale cookie (an API
        // client must not be locked out by it), a fresh bootstrap link (the
        // operator is re-entering, exactly when a stale cookie is present), or
        // a public path, which needs no credential at all.
        let has_bearer = presented_credential(request.headers()).is_some();
        if !has_bearer && !is_bootstrap && !auth_config.is_public_path(request.uri().path()) {
            auth_failure(kind);
            if keep_cookie {
                return bearer_unauthorized_response(
                    "The gateway clock reads before 1970; the dashboard session resumes once it is set.",
                );
            }
            return session_ended_response(cookie_secure(&state));
        }
    }
    let secure = cookie_secure(&state);
    let mut response = authenticate_request(state, request, next).await;
    // The browser drops the dead handle instead of presenting it forever,
    // unless this response already set a fresh one (a redeemed link): a
    // second `Set-Cookie` for the same name would delete the new session.
    let sets_session = response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .any(|v| {
            v.as_bytes()
                .strip_prefix(SESSION_COOKIE.as_bytes())
                .is_some_and(|rest| rest.starts_with(b"="))
        });
    if dead_session.is_some()
        && !keep_cookie
        && !sets_session
        && let Ok(value) = session_cookie("", 0, secure).parse()
    {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
    response
}

/// The middleware past the session cookie: public paths, the bootstrap link
/// and presented credentials.
async fn authenticate_request(
    state: AuthState,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // One generation judges the request: its keys, its `auth` settings and
    // the role mapping a key-server caller's admin flag comes from.
    let Some(generation) = crate::gateway::router::pinned_generation(request.extensions()) else {
        return live::unpinned();
    };
    let auth_config = &**generation.auth();
    let path = request.uri().path();

    // A public path skips the credential REQUIREMENT, not the credential. An
    // operator who presents their admin token to `/mcp` — a public path on the
    // starter config, so ordinary tools stay open — was handed the public
    // identity and lost the management tools their token pays for.
    if auth_config.is_public_path(path)
        && let Some(presented) = presented_credential(request.headers())
    {
        if let Some((client, api_key)) = auth_config.validate_token_with_origin(&presented) {
            // The adapter allow-list is checked downstream against this, so the
            // provenance has to travel with the request rather than be re-derived.
            attach_api_key(&mut request, api_key);
            request.extensions_mut().insert(client);
            return next.run(request).await;
        }
        // A gateway-issued temporary token and a verified delegated bearer are
        // credentials here for the same reason a configured key is: the caller
        // proved who they are, and a public path that ignores that hands them
        // the anonymous identity — and with it the anonymous quota, which any
        // unauthenticated flood can exhaust. Unrecognised input still falls
        // through to the anonymous identity below, exactly as before.
        match key_server_credential(&state, &generation, &presented).await {
            live::KsCredential::Credential(found) => {
                let (client, identity, via) = *found;
                debug!(client = %client.name, path = %path, "Public path authenticated via {via}");
                identity.insert_into(request.extensions_mut());
                request.extensions_mut().insert(client);
                return next.run(request).await;
            }
            // A credential this gateway recognises whose identity names no
            // one is refused here too, never handed the anonymous identity
            // below (MIK-8286).
            live::KsCredential::Refused => {
                auth_failure(AuthFailureKind::InvalidCredential);
                warn!(path = %path, "Invalid token");
                return bearer_unauthorized_response("Invalid token");
            }
            live::KsCredential::NotOurs => {}
        }
    }

    // Check if path is public
    if auth_config.is_public_path(path) {
        debug!(path = %path, "Public path, skipping auth");
        request.extensions_mut().insert(public_client());
        return next.run(request).await;
    }

    // A browser navigation carries no Authorization header, so the dashboard
    // session cookie is accepted as an equivalent credential. It is HttpOnly and
    // SameSite=Strict, so script cannot read it and it is not sent cross-site.
    // The dashboard bootstrap link. A browser navigation carries no header and
    // no cookie yet, so this is the one path where a credential arrives in the
    // URL — which is why the value is single-use and is not the admin token.
    if let Some(response) = try_dashboard_bootstrap(&state, auth_config, &request) {
        return handoff::private(response);
    }

    let token = presented_credential(request.headers());

    let Some(token) = token else {
        auth_failure(AuthFailureKind::MissingCredential);
        warn!(path = %path, "Missing credential");
        return bearer_unauthorized_response(
            "Missing Authorization header. Use: Authorization: Bearer <token>",
        );
    };
    let token = token.as_str();

    // 1. Try static auth (existing behavior)
    if let Some((client, api_key)) = auth_config.validate_token_with_origin(token) {
        if let Some(deny) = client_preflight(auth_config, &client, path) {
            return deny;
        }
        debug!(client = %client.name, path = %path, "Authenticated via static key");
        attach_api_key(&mut request, api_key);
        request.extensions_mut().insert(client);
        return next.run(request).await;
    }

    // 2. Try the key server: temporary token, then delegated OIDC bearer. The
    //    verified subject is bound into request extensions so downstream grant
    //    evaluation can scope capabilities to the caller identity.
    if let live::KsCredential::Credential(found) =
        key_server_credential(&state, &generation, token).await
    {
        let (client, identity, via) = *found;
        if let Some(deny) = client_preflight(auth_config, &client, path) {
            return deny;
        }
        debug!(client = %client.name, path = %path, "Authenticated via {via}");
        identity.insert_into(request.extensions_mut());
        request.extensions_mut().insert(client);
        return next.run(request).await;
    }

    // 3. Reject. An expired key was matched and refused above, so it is
    // counted as its own kind rather than as a wrong credential.
    auth_failure(if auth_config.is_expired_key(token) {
        AuthFailureKind::ExpiredApiKey
    } else {
        AuthFailureKind::InvalidCredential
    });
    warn!(path = %path, "Invalid token");
    bearer_unauthorized_response("Invalid token")
}

/// Per-client rate-limit + circuit-breaker preflight shared by every auth path.
/// Returns `Some(response)` to short-circuit with an error, `None` to proceed.
fn client_preflight(
    auth_config: &ResolvedAuthConfig,
    client: &AuthenticatedClient,
    path: &str,
) -> Option<Response> {
    if !auth_config.check_authenticated_client_rate_limit(client) {
        warn!(client = %client.name, path = %path, "Rate limit exceeded");
        return Some(rate_limited_response(format!(
            "Rate limit exceeded for client '{}'. Try again later.",
            client.name
        )));
    }
    if !auth_config.check_client_circuit_breaker(client) {
        warn!(client = %client.name, path = %path, "Client circuit breaker open");
        return Some(circuit_open_response(format!(
            "Client '{}' circuit breaker is open. Try again later.",
            client.name
        )));
    }
    None
}

/// Cheap structural check: a JWT is three non-empty base64url segments joined
/// by `.`. Used to avoid running OIDC/JWKS verification on opaque static keys
/// or exchanged tokens, which never have this shape.
fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !h.is_empty()
        && !p.is_empty()
        && !s.is_empty()
        && [h, p, s].iter().all(|seg| {
            seg.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
#[path = "auth_backend_grant_tests.rs"]
mod backend_grant_tests;

#[cfg(test)]
#[path = "auth_api_key_digest_tests.rs"]
mod api_key_digest_tests;

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "auth_clock_tests.rs"]
mod clock_tests;

#[cfg(test)]
#[path = "auth_client_state_tests.rs"]
mod client_state_tests;

#[cfg(test)]
#[path = "auth_rotation_tests.rs"]
mod rotation_tests;

#[cfg(test)]
#[path = "auth_limit_state_tests.rs"]
mod limit_state_tests;

#[cfg(test)]
#[path = "auth_approval_binding_tests.rs"]
mod approval_binding_tests;

#[cfg(test)]
#[path = "auth_session_origin_tests.rs"]
mod session_origin_tests;

/// SIGNING.5 row 44: which nonce-quota authority a dashboard session carries.
///
/// Every identity here is produced by [`auth_middleware`] itself, from a handle
/// [`DashboardBootstrap::issue_session`] actually issued. Copying
/// [`dashboard_client`] would assert what this file already says; only the
/// middleware can say what a presented cookie is worth. The last two cases
/// carry that identity into a real [`NonceStore`], because the quota claim is
/// about admission, not about a struct field.
#[cfg(test)]
#[path = "auth_signing_dashboard_quota_tests.rs"]
mod signing_dashboard_quota_tests;

#[cfg(test)]
#[path = "auth_caller_agreement_tests.rs"]
mod caller_agreement_tests;
#[cfg(test)]
pub(crate) use caller_agreement_tests::{expected_api_key, mints};
