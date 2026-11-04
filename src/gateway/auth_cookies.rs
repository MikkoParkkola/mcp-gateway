// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard session cookie: its name, its `Set-Cookie` value, and when it
//! must be `Secure`. Re-exported at `gateway::auth`.

use super::{AuthState, SessionLimits};

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
pub(in crate::gateway) fn session_limits(state: &AuthState) -> SessionLimits {
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
