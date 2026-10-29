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
pub(crate) use api_key::{PreviousDigest, refuse_shared_digests};
#[path = "auth_dashboard.rs"]
mod dashboard;
pub use dashboard::DashboardBootstrap;
pub(crate) use dashboard::{Now, Redeem, Redemption, SessionCheck, SessionLimits, Touch};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedApiKey {
    name: String,
    personal: bool,
    /// The key's previous digest matched, not its current one (ADR-022).
    matched_previous_digest: bool,
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
}

#[path = "auth_resolved.rs"]
mod resolved;

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

/// The one API-key predicate (MIK-8659): a caller's API-key name iff it authenticated with an API key.
pub(in crate::gateway) fn api_key_name(
    authenticated: bool,
    kind: CredentialKind,
    name: Option<&str>,
) -> Option<&str> {
    if authenticated && kind == CredentialKind::ApiKey {
        name
    } else {
        None
    }
}

/// What the caller-principal predicate needs of a principal: whether it is
/// the empty one. Implemented by the opaque [`InternalPrincipal`] (so its bytes
/// never leave through the predicate, MIK-8697 §16.6) and by the `&str` the
/// caller contexts carry.
pub(in crate::gateway) trait Principal {
    /// Whether this is the empty principal of a caller with no credential.
    fn is_empty(&self) -> bool;
}

impl Principal for str {
    fn is_empty(&self) -> bool {
        str::is_empty(self)
    }
}

impl Principal for InternalPrincipal {
    fn is_empty(&self) -> bool {
        InternalPrincipal::is_empty(self)
    }
}

/// The one caller-principal predicate (MIK-8659): the principal iff the caller authenticated and it is non-empty.
pub(in crate::gateway) fn authenticated_principal<P: Principal + ?Sized>(
    authenticated: bool,
    principal: Option<&P>,
) -> Option<&P> {
    if authenticated {
        principal.filter(|p| !p.is_empty())
    } else {
        None
    }
}

/// Information about an authenticated client
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// Client name
    pub name: String,
    /// Rate limit (0 = unlimited)
    pub rate_limit: u32,
    /// Allowed backends (`["*"]` = all; empty = none)
    pub backends: Vec<String>,
    /// Allowed tools (allowlist if Some): exact names or a trailing `prefix*`.
    pub allowed_tools: Option<Vec<String>>,
    /// Denied tools (blocklist if Some): exact names or a trailing `prefix*`.
    pub denied_tools: Option<Vec<String>>,
    /// Admin-level UI and management tool access.
    pub admin: bool,
    /// Stable identifier for the principal behind this identity.
    ///
    /// A digest of the validated secret, not the display name: `name` is
    /// operator-chosen and two API keys may share one, which would let them
    /// attach to each other's sessions. Empty for an identity that presented
    /// no credential.
    pub(crate) principal: InternalPrincipal,
    /// Authenticated nonce-quota authority; never derived from audit labels.
    pub quota_principal: Option<QuotaPrincipal>,
    /// Whether a credential was actually presented and validated.
    ///
    /// False for the anonymous identity used when authentication is disabled,
    /// and for the identity given to a public path. Authorization must test
    /// this rather than compare `name` against `"public"` or `"anonymous"`: a
    /// name is data, and a rule written against one silently admits any client
    /// configured with a different name.
    pub authenticated: bool,
    /// How the credential was presented, for the audit record's `who`
    /// (4.0.0 item D1-c). Set at each mint site; it has no `Default`.
    // ci-allow-secret-debug: an enum naming how a credential was presented; it holds no secret bytes.
    pub credential_kind: CredentialKind,
}

impl AuthenticatedClient {
    /// Check if this client can access a backend
    #[must_use]
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.iter().any(|b| b == "*" || b == backend)
    }

    /// The API key's name when this client authenticated with an API key,
    /// else `None`: the identity-grant fallback subject (MIK-8518).
    #[must_use]
    pub(crate) fn api_key_identity(&self) -> Option<&str> {
        api_key_name(self.authenticated, self.credential_kind, Some(&self.name))
    }

    /// The record principal of `client`, keyed (MIK-8697 §16.11): what a record
    /// of its request writes as `who.principal`. No client is no credential.
    pub(crate) fn record_principal_of(
        client: Option<&Self>,
        key: &crate::gateway::record_principal::RecordPrincipalKey,
    ) -> crate::gateway::record_principal::RecordPrincipal {
        client.map_or_else(
            || InternalPrincipal::default().record_form(key),
            |c| c.principal.record_form(key),
        )
    }

    /// The validated credential principal iff this client authenticated with a non-empty one (MIK-8659).
    #[must_use]
    pub(in crate::gateway) fn credential_principal(&self) -> Option<&InternalPrincipal> {
        authenticated_principal(self.authenticated, Some(&self.principal))
    }

    /// The refusal text when this client may not reach `backend`.
    ///
    /// An empty grant names that cause and not the backend, so the answer is
    /// the same whether or not the backend exists.
    pub(crate) fn backend_refusal(&self, backend: &str) -> String {
        if self.backends.is_empty() {
            format!(
                "Client '{}' has no backends granted: an empty `backends` list reaches none \
                 (docs/UPGRADING-4.0.md section 32)",
                self.name
            )
        } else {
            format!(
                "Client '{}' not authorized for backend '{backend}'",
                self.name
            )
        }
    }

    /// Check if this client can access a tool (per-client scope).
    ///
    /// Logic:
    /// - If `allowed_tools` is Some, only tools matching the allowlist are permitted.
    /// - If `denied_tools` is Some, tools matching the denylist are blocked.
    /// - If both are None, fall back to global policy (caller's responsibility).
    ///
    /// Returns `Ok(())` if allowed, `Err(message)` if denied.
    pub fn check_tool_scope(&self, server: &str, tool: &str) -> std::result::Result<(), String> {
        let qualified = format!("{server}:{tool}");

        // If allowlist is set, ONLY tools in the list are permitted
        if let Some(ref allowed) = self.allowed_tools
            && !crate::config::tool_pattern_matches(allowed, tool, &qualified)
        {
            return Err(format!(
                "Tool '{tool}' on server '{server}' is not in the allowlist for client '{}'",
                self.name
            ));
        }

        // If denylist is set, tools in the list are blocked
        if let Some(ref denied) = self.denied_tools
            && crate::config::tool_pattern_matches(denied, tool, &qualified)
        {
            return Err(format!(
                "Tool '{tool}' on server '{server}' is blocked by client '{}' policy",
                self.name
            ));
        }

        Ok(())
    }
}

/// Name of the browser session cookie the dashboard bootstrap sets.
///
/// A browser cannot attach an `Authorization` header to a navigation, so a
/// bearer token alone leaves the dashboard unusable however correct the
/// credential is. The gateway prints a one-time link; opening it exchanges the
/// credential for this cookie and redirects, so the token never lingers in the
/// address bar, the history, or a `Referer`.
pub const SESSION_COOKIE: &str = "mcp_gateway_session";

/// The session limits in force now: read from the live config, so a reload
/// applies to sessions already open.
pub(super) fn session_limits(state: &AuthState) -> SessionLimits {
    SessionLimits::from(&state.live_config.get().auth.dashboard_session)
}

/// The `Set-Cookie` value for `handle`; an empty handle with `max_age` 0
/// clears it.
///
/// `Secure` whenever this listener speaks TLS, or a proxy terminates it in
/// front. Without it a downgrade puts the cookie on the wire; with a
/// plain-HTTP loopback listener the attribute would stop the cookie being sent
/// at all, so it is conditional rather than unconditional.
pub(crate) fn session_cookie(handle: &str, max_age: u64, secure: bool) -> String {
    let secure = if secure { " Secure;" } else { "" };
    format!(
        "{SESSION_COOKIE}={handle}; HttpOnly;{secure} SameSite=Strict; Path=/; Max-Age={max_age}"
    )
}

/// Whether browsers reach this gateway over HTTPS, so its cookies must be
/// `Secure`: a TLS listener, or a `public_url` behind a TLS-terminating proxy.
///
/// TLS is read from the RUNNING listener (restart-only); `public_url` from the
/// live config, which a reload applies.
pub(crate) fn cookies_are_secure(live: &crate::config_reload::LiveConfig) -> bool {
    live.running().mtls.enabled
        || live
            .get()
            .server
            .public_url
            .as_deref()
            .is_some_and(is_https_url)
}

/// `true` for a URL whose scheme is `https`, in any letter case.
///
/// Parses with the same WHATWG URL parser `origin_guard::public_url_parts` and
/// `cleartext::public_url_host` already use, rather than a byte prefix: the
/// scheme is case-insensitive (RFC 3986 section 3.1) and the parser also
/// trims leading and trailing spaces and C0 controls, so `url.starts_with("https://")` rejects
/// values the rest of the gateway accepts — leaving cookies without `Secure`
/// behind a front end this parser agrees is HTTPS. Shared by the cookie
/// security check, the startup-banner link refusal and the OIDC
/// issuer/`jwks_uri` checks, so one fix covers all of them.
pub(crate) fn is_https_url(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| u.scheme() == "https")
}

/// Whether a session cookie set or cleared now must be `Secure`: the listener
/// speaks TLS, or the live config names an HTTPS `public_url` (a reload may add
/// or remove one, so it is read per response, never snapshotted).
pub(crate) fn cookie_secure(state: &AuthState) -> bool {
    state.tls_enabled || cookies_are_secure(&state.live_config)
}

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
    /// Static key / bearer token configuration.
    pub auth_config: Arc<ResolvedAuthConfig>,
    /// Key server for OIDC-issued temporary tokens (optional).
    pub key_server: Option<Arc<KeyServer>>,
    /// Single-use value that opens the dashboard from a printed link.
    pub dashboard_bootstrap: Arc<DashboardBootstrap>,
    /// Whether this listener speaks TLS, so the session cookie is `Secure`.
    /// A live HTTPS `public_url` also makes it `Secure` (`cookie_secure`).
    pub tls_enabled: bool,
    /// The live config, whose `control_plane.role_mapping` confers admin per
    /// request (E1-a).
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
    let auth_config = &state.auth_config;

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
        match state
            .dashboard_bootstrap
            .check_session(&handle, Now::read(), &limits, touch)
        {
            SessionCheck::Valid if !has_authorization && !is_bootstrap => {
                request.extensions_mut().insert(dashboard_client());
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
    let auth_config = &state.auth_config;
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
        match key_server_credential(&state, &presented).await {
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
    if let Some(response) = try_dashboard_bootstrap(&state, &request) {
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
    if let live::KsCredential::Credential(found) = key_server_credential(&state, token).await {
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
