// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! RFC 9728 OAuth Protected Resource Metadata endpoint.
//!
//! `GET /.well-known/oauth-protected-resource` lets an MCP client discover,
//! *before* it holds a token, that this gateway is a protected resource. Per
//! RFC 9728 §3.1 the endpoint is unauthenticated — a client fetches it in
//! response to a `401` carrying `WWW-Authenticate: Bearer resource_metadata="…"`.
//!
//! # Where `resource` comes from
//!
//! The document is built from the gateway's own configuration, never from the
//! request `Host` header — reflecting an attacker-controlled `Host` into a
//! security-relevant discovery document would let a caller advertise a rogue
//! origin. The `resource` identifier is resolved, in order:
//!
//! 1. `server.public_url` when set and a valid origin — the only value that
//!    reliably names the real external origin behind a TLS-terminating proxy.
//!    It is validated with a real URL parser and reduced to a scheme+authority
//!    origin (no path/query/fragment/userinfo), because the endpoint is mounted
//!    at the root and RFC 9728 §3.1 pairs a root well-known path with a resource
//!    that has no path component. Per RFC 9728 §1.2 the scheme must be `https`,
//!    except for a loopback host where `http` is legal (the OAuth loopback
//!    exception).
//! 2. Otherwise the *startup* bind address — but only when it is a loopback
//!    host, for which advertising `http` is RFC-legal (the OAuth loopback
//!    exception) and the bind address genuinely *is* the reachable origin.
//! 3. Otherwise nothing: a non-loopback bind without a `public_url` cannot be
//!    named honestly — the bind address (`0.0.0.0`) is not a resource
//!    identifier and the external scheme behind a proxy is unknown. The
//!    endpoint returns `503` rather than publish a guess or leak the bind
//!    address.
//!
//! The bind fallback is captured once at router construction from the startup
//! config, not read from the hot-reloadable `LiveConfig`: `server.host`/`port`
//! are restart-required (a `/reload` does not move the TCP listener), so the
//! advertised origin must not change on a host/port edit that has not taken
//! effect. `public_url` *is* read live, so a `public_url`-only reload is
//! reflected immediately.
//!
//! `authorization_servers` names the OIDC issuers of an enabled key server with
//! `delegated_bearer` on: those are the authorization servers whose tokens the
//! MCP routes accept, so a standards-following client learns
//! where to sign in. When no issuer token is accepted the endpoint answers
//! `404` (MIK-8158): the gateway itself serves no RFC 8414 authorization-server
//! metadata, so there is no server to name, and a document naming none would
//! send a client into an OAuth sign-in that cannot complete.

use std::sync::Arc;

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::config::Config;
use crate::oauth::ProtectedResourceMetadata;

use super::AppState;

/// `true` when `host` names the loopback interface, for which advertising an
/// `http` origin is RFC-legal (OAuth loopback exception).
pub(super) fn is_loopback_host(host: &str) -> bool {
    // Strip an IPv6 literal's brackets before parsing (`[::1]` -> `::1`).
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    // Case-insensitive: DNS names are case-insensitive, and the URL parser
    // lowercases the host on the `public_url` path, so the bind-fallback path
    // must classify `LOCALHOST` the same way rather than reject it.
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bare.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// The startup bind address as an RFC 9728 resource origin, or `None` when it
/// cannot be named honestly.
///
/// Returns `Some(http://host[:port])` only for a loopback bind (the address a
/// local client actually reaches). A non-loopback bind returns `None`: its
/// address is not a resource identifier and its external scheme is unknown, so
/// the operator must set `server.public_url` instead. IPv6 literals are
/// bracketed so the result is a well-formed URL.
#[must_use]
pub fn bind_fallback_origin(host: &str, port: u16) -> Option<String> {
    if !is_loopback_host(host) {
        return None;
    }
    let bracketed = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Some(format!("http://{bracketed}:{port}"))
}

/// Validate an operator-supplied `public_url` and reduce it to a bare origin.
///
/// Accepts `https` for any host, and `http` only for a loopback host (the OAuth
/// loopback exception; RFC 9728 §1.2 otherwise requires `https`). Returns the
/// canonical `scheme://host[:port]` origin (default ports and trailing slash
/// dropped), else `None`.
///
/// The value is validated *structurally on the raw string* before the URL
/// parser runs. The WHATWG parser silently rewrites malformed input: it strips
/// whitespace/controls, turns `\` into `/`, accepts a missing authority slash,
/// collapses `..` path segments, and re-encodes alternate-IPv4 / IDNA hosts.
/// Any such rewrite could canonicalize a hostile config value into a *different*
/// origin than was written. So this rejects up front: whitespace, control
/// chars, backslashes; a missing / case-wrong `http(s)://` prefix; any path,
/// query, fragment, userinfo. It then parses a reconstructed `scheme://authority`
/// only for host classification and port, and finally requires the parsed host
/// to equal the raw host (ASCII case and IPv6 bracket form aside), so no parser
/// host rewrite is ever published.
fn sanitize_public_url(raw: &str) -> Option<String> {
    // 1. Reject bytes the parser would strip / rewrite (whitespace, C0
    //    controls, backslash) rather than publish the rewritten origin.
    if raw
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return None;
    }
    // 2. Require an explicit `http://` / `https://` prefix (case-insensitive)
    //    and slice off exactly the authority. A missing authority slash
    //    (`https:/host`) fails the prefix; an embedded path, dot-segments,
    //    query, fragment, userinfo all fail the authority check below. None can
    //    be canonicalized into a different origin because they never reach the
    //    parser as structure. `get(..N)` keeps the slice on a char boundary.
    let (scheme, rest) = if raw
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
    {
        ("https", &raw[8..])
    } else if raw
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
    {
        ("http", &raw[7..])
    } else {
        return None;
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return None;
    }
    // 3. Parse the reconstructed origin for validated host/port handling.
    let parsed = url::Url::parse(&format!("{scheme}://{authority}")).ok()?;
    let host = parsed.host_str()?;
    // RFC 9728 §1.2: a protected-resource identifier uses `https`. The sole
    // exception is a loopback host, where `http` is legitimate and reachable.
    if scheme == "http" && !is_loopback_host(host) {
        return None;
    }
    // Belt-and-suspenders: the structural check already forbids these; keep the
    // origin path/query/fragment/userinfo-free regardless of parser quirks.
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return None;
    }
    // 4. Faithful-host guard: reject any value whose host the parser rewrote
    //    into a different form (alternate/decimal IPv4, IDNA/punycode, percent-
    //    encoding). ASCII case folding of a domain and the IPv6 bracket form are
    //    the only canonicalizations allowed through.
    let raw_host = if let Some(after_bracket) = authority.strip_prefix('[') {
        // `[v6]` and `[v6]:port` -> keep the bracketed literal for comparison.
        let end = after_bracket.as_bytes().iter().position(|&b| b == b']')?;
        &authority[..=end + 1]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if !raw_host.eq_ignore_ascii_case(host) {
        return None;
    }
    let mut origin = format!("{scheme}://{host}");
    if let Some(port) = parsed.port() {
        // `port()` is `None` for the scheme's default port, so this omits
        // `:443`/`:80` and keeps the origin canonical.
        origin = format!("{origin}:{port}");
    }
    Some(origin)
}

/// Resolve the gateway's externally reachable origin: validated `public_url`,
/// else the startup loopback bind origin, else `None`.
fn resolve_resource_origin(config: &Config, bind_origin: Option<&str>) -> Option<String> {
    if let Some(raw) = config.server.public_url.as_deref() {
        if let Some(origin) = sanitize_public_url(raw) {
            return Some(origin);
        }
        tracing::warn!(
            public_url = %raw,
            "server.public_url is not a valid http(s) origin (scheme://host[:port], no path/query/fragment/userinfo); \
             not published as the protected-resource identifier"
        );
    }
    bind_origin.map(ToString::to_string)
}

/// The authorization servers whose tokens this gateway accepts as bearers
/// (RFC 9728 section 2): the OIDC issuers of an enabled key server with
/// `delegated_bearer` on, behind enabled auth and no agent auth, in configured
/// order, blank, repeated and unpublishable ones dropped. Empty otherwise, and then omitted
/// from the document: an exchange-only key server accepts no issuer token on
/// the MCP routes, auth off accepts no token at all, and the gateway itself
/// serves no authorization-server metadata.
///
/// `running` is the configuration this process started with: `auth` and
/// `key_server` apply only on restart, so a pending reload must not change
/// which issuers are named.
fn authorization_servers(running: &Config) -> Vec<String> {
    // Once per process: the running config never changes, and the endpoint
    // needs no sign-in, so a per-request warning would let anyone flood the log.
    static WARNED: std::sync::Once = std::sync::Once::new();
    let key_server = &running.key_server;
    // Agent auth refuses every bearer that is not a registered agent's token,
    // an OIDC ID token included.
    if !(running.auth.enabled
        && !running.agent_auth.enabled
        && key_server.enabled
        && key_server.delegated_bearer)
    {
        return Vec::new();
    }
    let mut issuers: Vec<String> = Vec::new();
    let mut skipped: Vec<usize> = Vec::new();
    for (idx, provider) in key_server.oidc.iter().enumerate() {
        // Exactly as configured: the token check compares the `iss` claim to
        // this string, so a client must be sent the same identifier.
        let issuer = provider.issuer.as_str();
        if issuer.trim().is_empty() || issuers.iter().any(|seen| seen == issuer) {
            continue;
        }
        if is_publishable_issuer(issuer) {
            issuers.push(issuer.to_string());
        } else {
            skipped.push(idx);
        }
    }
    if !skipped.is_empty() {
        WARNED.call_once(|| {
            for idx in &skipped {
                // The issuer is not echoed: it may carry a credential.
                tracing::warn!(
                    "key_server.oidc[{idx}] issuer is not an http(s) URL free of userinfo, \
                     query and fragment; not advertised in protected-resource metadata"
                );
            }
        });
    }
    issuers
}

/// `true` when `issuer` may be published on the unauthenticated metadata
/// endpoint: an http(s) URL with a host and no userinfo, query or fragment
/// (the RFC 8414 issuer shape). Anything else either may leak a credential or
/// names nothing a client can fetch metadata from, and redacting it would send
/// clients an identifier the token check refuses.
fn is_publishable_issuer(issuer: &str) -> bool {
    // Published verbatim, so refuse what the parser would silently rewrite.
    if issuer
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return false;
    }
    // The parser repairs `https:host`, `https:///host` and empty userinfo
    // (`https://@host`), so the raw text must already be `scheme://authority`
    // with no `@` in the authority, which ends at the first `/`, `?` or `#`.
    let Some(rest) = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    url::Url::parse(issuer)
        .is_ok_and(|parsed| parsed.query().is_none() && parsed.fragment().is_none())
}

/// Build RFC 9728 protected-resource metadata, or `None` when no honest
/// `resource` identifier is available (see module docs). `config` is the live
/// snapshot (`public_url` is re-read per request); `running` is the config
/// the process started with, which decides the advertised issuers.
#[must_use]
pub fn build_protected_resource_metadata(
    config: &Config,
    running: &Config,
    bind_origin: Option<&str>,
) -> Option<ProtectedResourceMetadata> {
    let resource = resolve_resource_origin(config, bind_origin)?;
    Some(ProtectedResourceMetadata {
        resource,
        authorization_servers: authorization_servers(running),
        bearer_methods_supported: vec!["header".to_string()],
        scopes_supported: Vec::new(),
    })
}

/// `GET /.well-known/oauth-protected-resource` — unauthenticated (RFC 9728).
///
/// `bind_origin` is the startup loopback bind origin captured at router
/// construction (`None` for a non-loopback bind); `public_url` is read live so
/// a reload is reflected without a restart, the restart-only issuers are not.
pub async fn oauth_protected_resource_handler(
    state: Arc<AppState>,
    bind_origin: Option<String>,
) -> Response {
    // MIK-8158: no authorization server, nothing to discover. A document
    // naming none tells a client this is an OAuth resource it can never sign
    // in to; without one it uses the credential it was given.
    if authorization_servers(state.live_config.running()).is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let config = state.live_config.get();
    let json_header = (
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    match build_protected_resource_metadata(
        &config,
        state.live_config.running(),
        bind_origin.as_deref(),
    ) {
        Some(metadata) => (StatusCode::OK, [json_header], Json(metadata)).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [json_header],
            Json(serde_json::json!({
                "error": "protected_resource_metadata_unavailable",
                "error_description":
                    "server.public_url is not configured with a valid http(s) origin",
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_host(host: &str, port: u16) -> Config {
        Config {
            server: crate::config::ServerConfig {
                host: host.to_string(),
                port,
                ..Config::default().server
            },
            ..Config::default()
        }
    }

    #[test]
    fn resource_is_public_url_not_request_host() {
        let mut config = config_with_host("0.0.0.0", 8080);
        config.server.public_url = Some("https://gateway.internal".to_string());
        // Even with a non-loopback bind, the advertised resource is the
        // configured public origin — never the request host or bind address.
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert_eq!(meta.resource, "https://gateway.internal");
    }

    #[test]
    fn loopback_bind_origin_advertises_http_and_brackets_ipv6() {
        // http is RFC-legal only for loopback (OAuth loopback exception); a
        // bare IPv6 host must be bracketed to stay a valid URL.
        assert_eq!(
            bind_fallback_origin("127.0.0.1", 39400).as_deref(),
            Some("http://127.0.0.1:39400")
        );
        assert_eq!(
            bind_fallback_origin("localhost", 39400).as_deref(),
            Some("http://localhost:39400")
        );
        assert_eq!(
            bind_fallback_origin("::1", 39400).as_deref(),
            Some("http://[::1]:39400")
        );
        // Uppercase localhost must classify as loopback too, so the bind path
        // agrees with the `public_url` path (the URL parser lowercases hosts).
        assert_eq!(
            bind_fallback_origin("LOCALHOST", 39400).as_deref(),
            Some("http://LOCALHOST:39400")
        );
    }

    #[test]
    fn non_loopback_bind_without_public_url_is_unavailable() {
        // No public_url + a non-loopback bind cannot be named honestly: no
        // bind fallback, so metadata is unavailable (handler returns 503)
        // rather than leaking `0.0.0.0` or guessing a scheme.
        for host in ["0.0.0.0", "gateway.internal", "203.0.113.7"] {
            assert_eq!(
                bind_fallback_origin(host, 8080),
                None,
                "{host} is not loopback"
            );
            let config = config_with_host(host, 8080);
            assert!(
                build_protected_resource_metadata(&config, &config, None).is_none(),
                "{host} without public_url must not publish a resource"
            );
        }
    }

    #[test]
    fn public_url_overrides_bind_origin() {
        let config = {
            let mut c = config_with_host("127.0.0.1", 39400);
            c.server.public_url = Some("https://mcp.acme.internal/".to_string());
            c
        };
        // public_url wins over the loopback bind fallback; trailing slash dropped.
        let meta =
            build_protected_resource_metadata(&config, &config, Some("http://127.0.0.1:39400"))
                .unwrap();
        assert_eq!(meta.resource, "https://mcp.acme.internal");
        assert!(!meta.resource.contains("127.0.0.1"));
    }

    #[test]
    fn authorization_servers_empty_without_a_delegated_issuer() {
        let mut config = config_with_host("gw.internal", 9000);
        config.server.public_url = Some("https://gw.internal:9000".to_string());
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert!(
            meta.authorization_servers.is_empty(),
            "the default config accepts no issuer token and the gateway serves no authorization-server metadata of its own, so it names none"
        );
    }

    fn config_with_issuers(enabled: bool, delegated: bool, issuers: &[&str]) -> Config {
        let mut config = config_with_host("gw.internal", 9000);
        config.server.public_url = Some("https://gw.internal:9000".to_string());
        config.auth.enabled = true;
        config.key_server.enabled = enabled;
        config.key_server.delegated_bearer = delegated;
        config.key_server.oidc = issuers
            .iter()
            .map(|issuer| {
                serde_json::from_value(serde_json::json!({
                    "issuer": issuer,
                    "audiences": ["gateway-client"],
                }))
                .unwrap()
            })
            .collect();
        config
    }

    /// RFC 9728 section 2: the metadata names the authorization servers whose
    /// tokens the resource accepts. A gateway that takes an OIDC issuer's
    /// bearer tokens (`key_server.delegated_bearer`) names that issuer.
    #[test]
    fn configured_delegated_issuers_are_advertised() {
        let config = config_with_issuers(
            true,
            true,
            &[
                "https://idp.corp.internal",
                "https://login.corp.internal/tenant",
            ],
        );
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert_eq!(
            meta.authorization_servers,
            [
                "https://idp.corp.internal",
                "https://login.corp.internal/tenant"
            ],
            "a client must be able to find where to sign in"
        );
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(
            json["authorization_servers"][0],
            "https://idp.corp.internal"
        );
    }

    /// The issuer is named only when its tokens are accepted as bearers: an
    /// exchange-only key server (`delegated_bearer: false`) or a disabled one
    /// accepts none, so naming it would send clients to a dead end.
    #[test]
    fn issuers_are_not_advertised_unless_their_tokens_are_accepted() {
        for (enabled, delegated) in [(true, false), (false, true), (false, false)] {
            let config = config_with_issuers(enabled, delegated, &["https://idp.corp.internal"]);
            let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
            assert!(
                meta.authorization_servers.is_empty(),
                "enabled={enabled} delegated_bearer={delegated}"
            );
        }
    }

    /// `auth` and `key_server` apply only on restart, so the issuers named are
    /// the ones the running process accepts, while `public_url` is read live
    /// (MIK-7941 findings 1, 2 and 5).
    #[test]
    fn issuers_come_from_the_running_config_not_a_pending_reload() {
        let running = config_with_issuers(true, true, &["https://idp.running.internal"]);
        let mut pending = config_with_issuers(true, true, &["https://idp.pending.internal"]);
        pending.server.public_url = Some("https://gw.reloaded.internal".to_string());
        let meta = build_protected_resource_metadata(&pending, &running, None).unwrap();
        assert_eq!(meta.resource, "https://gw.reloaded.internal");
        assert_eq!(meta.authorization_servers, ["https://idp.running.internal"]);

        let off = config_with_issuers(false, true, &["https://idp.running.internal"]);
        let meta = build_protected_resource_metadata(&pending, &off, None).unwrap();
        assert!(
            meta.authorization_servers.is_empty(),
            "a key server enabled only in a pending reload accepts no token yet"
        );
    }

    /// With `auth.enabled: false` every caller is anonymous and no issuer
    /// token is ever checked, so none is advertised (MIK-7941 finding 4).
    #[test]
    fn issuers_are_not_advertised_when_auth_is_off() {
        let mut config = config_with_issuers(true, true, &["https://idp.corp.internal"]);
        config.auth.enabled = false;
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert!(meta.authorization_servers.is_empty());
    }

    /// The endpoint is unauthenticated: an issuer carrying userinfo, a query
    /// or a fragment is never published, and neither is an opaque one a
    /// client cannot fetch metadata from (MIK-7941 finding 3).
    #[test]
    fn credential_bearing_or_opaque_issuers_are_not_advertised() {
        let config = config_with_issuers(
            true,
            true,
            &[
                "https://user:pw@idp.corp.internal/tenant",
                "https://token@idp.corp.internal",
                "https://idp.corp.internal/tenant?k=secret",
                "https://idp.corp.internal/tenant#frag",
                "mcp-gateway",
                "https://idp.corp.internal/tenant\n",
                "https://idp.corp.internal/tenant",
            ],
        );
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert_eq!(
            meta.authorization_servers,
            ["https://idp.corp.internal/tenant"]
        );
        let json = serde_json::to_string(&meta).unwrap();
        for leaked in ["pw", "token@", "secret", "frag", "mcp-gateway"] {
            assert!(!json.contains(leaked), "leaked {leaked:?}: {json}");
        }
    }

    /// Review follow-up to MIK-7941: empty userinfo is stripped by the URL
    /// parser but published verbatim, so the raw authority is checked; an `@`
    /// in the path is fine.
    #[test]
    fn issuers_with_empty_userinfo_are_not_advertised() {
        let config = config_with_issuers(
            true,
            true,
            &[
                "https://@idp.corp.internal",
                "https://:@idp.corp.internal/tenant",
                // No `//`: the parser still reads userinfo here.
                "https:user@idp.corp.internal",
                "https::pw@idp.corp.internal",
                "ftp://idp.corp.internal",
                // The parser reads `\` as `/`; published verbatim it would differ.
                "https://idp.corp.internal\\tenant",
                "https://idp.corp.internal/t@nant",
            ],
        );
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert_eq!(
            meta.authorization_servers,
            ["https://idp.corp.internal/t@nant"]
        );
    }

    /// Second review follow-up to MIK-7941: an issuer without exactly
    /// `scheme://authority` is refused; the parser repairs both of these.
    #[test]
    fn issuers_without_a_plain_authority_are_not_advertised() {
        let config = config_with_issuers(
            true,
            true,
            &[
                "https:@idp.corp.internal",
                "https:///@idp.corp.internal",
                "https://idp.corp.internal",
            ],
        );
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert_eq!(meta.authorization_servers, ["https://idp.corp.internal"]);
    }

    /// Agent auth refuses every bearer that is not a registered agent's
    /// token, an OIDC ID token included, so no issuer is named while it is on.
    #[test]
    fn issuers_are_not_advertised_under_agent_auth() {
        let mut agent = config_with_issuers(true, true, &["https://idp.corp.internal"]);
        agent.agent_auth.enabled = true;
        let meta = build_protected_resource_metadata(&agent, &agent, None).unwrap();
        assert!(meta.authorization_servers.is_empty());
    }

    #[test]
    fn advertised_issuers_are_unique_and_never_blank() {
        let config = config_with_issuers(
            true,
            true,
            &[
                "https://idp.corp.internal",
                "  ",
                "https://idp.corp.internal",
            ],
        );
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        assert_eq!(meta.authorization_servers, ["https://idp.corp.internal"]);
    }

    #[test]
    fn empty_arrays_are_omitted_not_serialized_as_empty() {
        // RFC 9728 §3.2: zero-value parameters are omitted, not sent as `[]`.
        let mut config = config_with_host("gw.internal", 9000);
        config.server.public_url = Some("https://gw.internal:9000".to_string());
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("authorization_servers"));
        assert!(!json.contains("scopes_supported"));
    }

    #[test]
    fn serializes_rfc9728_shaped_json() {
        let mut config = config_with_host("gw.internal", 9000);
        config.server.public_url = Some("https://gw.internal:9000".to_string());
        let meta = build_protected_resource_metadata(&config, &config, None).unwrap();
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"resource\":\"https://gw.internal:9000\""));
        assert!(json.contains("\"bearer_methods_supported\":[\"header\"]"));
    }

    #[test]
    fn invalid_public_url_falls_back_to_loopback_bind_but_never_publishes_garbage() {
        // A malformed public_url is never published; with a loopback bind
        // available the resource falls back to it, otherwise it is unavailable.
        for bad in [
            "gateway.example",              // no scheme
            "ftp://gw.internal",            // wrong scheme
            "https://user@gw.internal",     // userinfo
            "https://user:pw@gw.internal",  // userinfo w/ password
            "https://gw.internal/base",     // non-root path
            "https://gw.internal/path?x=1", // query
            "https://gw.internal#frag",     // fragment
            "https://",                     // no host
            "https://gw.internal:abc",      // bad port
            "https://[::1",                 // malformed IPv6
        ] {
            let mut config = config_with_host("127.0.0.1", 39400);
            config.server.public_url = Some(bad.to_string());
            let meta =
                build_protected_resource_metadata(&config, &config, Some("http://127.0.0.1:39400"))
                    .unwrap();
            assert_eq!(
                meta.resource, "http://127.0.0.1:39400",
                "malformed public_url {bad:?} must fall back to the bind origin, never be published"
            );
        }
    }

    #[test]
    fn sanitize_public_url_accepts_wellformed_and_canonicalizes() {
        // Trailing slash dropped.
        assert_eq!(
            sanitize_public_url("https://mcp.acme.internal/").as_deref(),
            Some("https://mcp.acme.internal")
        );
        // Explicit non-default port retained (loopback http is RFC-legal).
        assert_eq!(
            sanitize_public_url("http://127.0.0.1:8080").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        // Default port normalized away.
        assert_eq!(
            sanitize_public_url("https://gw.internal:443").as_deref(),
            Some("https://gw.internal")
        );
        // IPv6 literal stays bracketed.
        assert_eq!(
            sanitize_public_url("https://[2001:db8::1]:8443").as_deref(),
            Some("https://[2001:db8::1]:8443")
        );
        // Rejections.
        assert_eq!(sanitize_public_url("https://gw.internal#f"), None);
        assert_eq!(sanitize_public_url("https://gw.internal/p"), None);
        assert_eq!(sanitize_public_url("https://gw.internal:abc"), None);
    }

    #[test]
    fn sanitize_public_url_requires_https_except_loopback() {
        // RFC 9728 §1.2: a non-loopback resource identifier must be https.
        assert_eq!(sanitize_public_url("http://gw.internal"), None);
        assert_eq!(sanitize_public_url("http://gw.internal:8080"), None);
        assert_eq!(sanitize_public_url("http://203.0.113.7"), None);
        // Loopback http is the legitimate OAuth loopback exception.
        assert_eq!(
            sanitize_public_url("http://localhost").as_deref(),
            Some("http://localhost")
        );
        assert_eq!(
            sanitize_public_url("http://[::1]:8080").as_deref(),
            Some("http://[::1]:8080")
        );
        // https is accepted for any host.
        assert_eq!(
            sanitize_public_url("https://gw.internal").as_deref(),
            Some("https://gw.internal")
        );
    }

    #[test]
    fn sanitize_public_url_rejects_parser_rewritten_inputs() {
        // The URL parser silently strips whitespace/controls and rewrites `\`;
        // such raw inputs must be rejected, not canonicalized into an origin.
        assert_eq!(sanitize_public_url(" https://gw.internal"), None);
        assert_eq!(sanitize_public_url("https://gw.internal "), None);
        assert_eq!(sanitize_public_url("https://gw.\tinternal"), None);
        assert_eq!(sanitize_public_url("https://gw.internal\n"), None);
        assert_eq!(sanitize_public_url("https:\\\\gw.internal"), None);
        assert_eq!(sanitize_public_url("https://gw.internal\u{0000}"), None);
    }

    #[test]
    fn sanitize_public_url_rejects_structural_and_host_rewrites() {
        // Missing authority slash: parser would read `https:/host` as host.
        assert_eq!(sanitize_public_url("https:/gw.internal"), None);
        assert_eq!(sanitize_public_url("https:gw.internal"), None);
        // Dot-segment path that normalizes to root must not sneak through.
        assert_eq!(sanitize_public_url("https://gw.internal/../evil"), None);
        assert_eq!(sanitize_public_url("https://gw.internal/./"), None);
        // Alternate / decimal IPv4 the parser rewrites to 127.0.0.1.
        assert_eq!(sanitize_public_url("http://0x7f.0.0.1"), None);
        assert_eq!(sanitize_public_url("https://2130706433"), None);
        assert_eq!(sanitize_public_url("http://127.1"), None);
        // Case folding of a domain is faithful and stays accepted.
        assert_eq!(
            sanitize_public_url("https://GW.Internal").as_deref(),
            Some("https://gw.internal")
        );
    }
}
