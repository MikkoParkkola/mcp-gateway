// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Origin and Host validation for the gateway's HTTP surface (CWE-346).
//!
//! The gateway binds loopback, which stops remote callers and nothing else. A
//! web page reaches a loopback port two ways: by rebinding a hostname to
//! 127.0.0.1, or by a cross-origin POST that skips preflight because the MCP
//! handler reads its body without requiring a JSON content type.
//!
//! The asymmetry this gate rests on: a browser always attaches `Origin` to a
//! scripted request, and a non-browser MCP client never does. So an absent
//! `Origin` is allowed and a present one must be known. `Host` is checked the
//! same way, which is what refuses a rebound name when the browser suppresses
//! `Origin`.
//!
//! This gate stops browsers. It does nothing about a process running as the
//! same user, which needs a credential to stop; see [`super::super::auth::anonymous_client`].

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::well_known::is_loopback_host;

/// Paths exempt from the gate because they carry no authority.
const EXEMPT_PATHS: &[&str] = &["/health"];

/// Origins and hosts this gateway answers to, snapshotted at startup.
///
/// `server.host`/`port` are restart-required, so a snapshot cannot drift from
/// the live listener.
///
/// There is deliberately no operator allow-list of extra browser origins. A
/// cross-origin browser client needs CORS preflight responses to work at all,
/// which this gate does not serve, so an allow-list would name origins that
/// still could not call the gateway. Serve the page from the gateway's own
/// origin, or use a non-browser client.
#[derive(Clone)]
pub struct OriginPolicy {
    allowed_origins: Vec<String>,
    /// Live config, read per request for `server.public_url`.
    ///
    /// `public_url` is hot-reloadable and the RFC 9728 metadata handler already
    /// reads it live, so snapshotting it here would refuse the very origin the
    /// gateway advertises after an operator reloads a changed value.
    live_config: Arc<crate::config_reload::LiveConfig>,
    /// Whether `Host` can be judged at all.
    ///
    /// False for a non-loopback bind with no declared public host: such a
    /// gateway is reached by a name this process cannot predict, so gating on
    /// it would refuse every request. DNS rebinding needs a loopback bind to be
    /// worth mounting, so nothing is lost where the threat actually lives.
    gate_host: bool,
}

impl OriginPolicy {
    /// Build the policy from the live config.
    ///
    /// The only constructor, deliberately. Bind host and port are snapshotted
    /// because they are restart-required; `public_url` is read per request
    /// because it is not. A second constructor taking a bare `ServerConfig`
    /// would have to drop the live view, and silently lose `public_url` with it.
    #[must_use]
    pub fn from_live(live_config: &Arc<crate::config_reload::LiveConfig>) -> Self {
        let config = &live_config.get().server;
        let port = config.port;
        // Every spelling of the loopback bind a browser could legitimately use.
        let allowed_origins: Vec<String> = if is_loopback_host(&config.host) {
            // Every spelling a browser could legitimately use to reach a
            // loopback bind, including the configured address itself: a bind on
            // 127.0.0.2 is served at 127.0.0.2, and its own page is same-origin
            // only there.
            let mut origins = vec![
                format!("http://127.0.0.1:{port}"),
                format!("http://localhost:{port}"),
                format!("http://[::1]:{port}"),
            ];
            let bracketed = if config.host.contains(':') && !config.host.starts_with('[') {
                format!("[{}]", config.host)
            } else {
                config.host.clone()
            };
            let configured = format!("http://{bracketed}:{port}").to_ascii_lowercase();
            if !origins.contains(&configured) {
                origins.push(configured);
            }
            origins
        } else {
            Vec::new()
        };

        let gate_host = is_loopback_host(&config.host) || config.public_url.is_some();

        Self {
            allowed_origins,
            live_config: Arc::clone(live_config),
            gate_host,
        }
    }

    /// Host and origin of `server.public_url` as it stands right now.
    fn public_url_parts(&self) -> Option<(String, String)> {
        let config = self.live_config.get();
        let url = config.server.public_url.as_deref()?;
        let parsed = url::Url::parse(url).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        Some((
            host,
            parsed.origin().ascii_serialization().to_ascii_lowercase(),
        ))
    }

    /// `true` when a browser-supplied `Origin` value is one this gateway answers to.
    #[must_use]
    fn origin_allowed(&self, origin: &str) -> bool {
        let candidate = origin.trim_end_matches('/').to_ascii_lowercase();
        if self.allowed_origins.contains(&candidate) {
            return true;
        }
        self.public_url_parts()
            .is_some_and(|(_, public_origin)| public_origin == candidate)
    }

    /// `true` when a `Host` value names this gateway.
    ///
    /// A rebound name arrives here as the attacker's hostname, which is neither
    /// loopback nor the configured public host.
    #[must_use]
    fn host_allowed(&self, host: &str) -> bool {
        let bare = strip_port(host);

        // A public_url set after startup turns full gating back on: it names a
        // host we can now judge, so the "cannot know the name" allowance lapses.
        if !self.gate_host && self.public_url_parts().is_none() {
            // A non-loopback bind answers to an address this process cannot
            // predict, so the name itself cannot be checked. The numeric form
            // still can be, and that is enough: DNS rebinding requires a
            // hostname to rebind, while a client reaching a bare gateway over
            // the network dials an address. Refusing names therefore closes the
            // rebinding path without refusing legitimate callers, and rebinding
            // is not a loopback-only threat — it reaches any address the
            // victim's browser can.
            return is_numeric_host(bare);
        }

        if is_loopback_host(bare) {
            return true;
        }
        self.public_url_parts()
            .is_some_and(|(public_host, _)| public_host.eq_ignore_ascii_case(bare))
    }

    /// `true` when a browser's `Sec-Fetch-Site` value describes a request this
    /// gateway should answer.
    ///
    /// Browsers attach Fetch Metadata to every request, including the no-CORS
    /// GET that the Fetch standard omits `Origin` from. That GET is how a
    /// hostile page would otherwise slip through the absent-Origin allowance
    /// and open an SSE session on `/mcp`.
    ///
    /// `none` is a user-initiated navigation, which cannot carry a payload
    /// from another site. `same-origin` is the gateway's own page.
    #[must_use]
    fn fetch_site_allowed(site: &str) -> bool {
        matches!(site, "same-origin" | "none")
    }
}

/// `true` when `host` is a bare IP address rather than a name.
///
/// An IPv6 literal arrives bracketed and parses only once the brackets are off.
fn is_numeric_host(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>().is_ok()
}

/// Strip a `:port` suffix, leaving an IPv6 literal's brackets intact.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // `[::1]:39400` -> `[::1]`
        return host.find(']').map_or(host, |i| &host[..=i]);
    }
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

/// Refuse a request whose `Origin` or `Host` does not name this gateway.
pub async fn origin_guard_middleware(
    State(policy): State<Arc<OriginPolicy>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if EXEMPT_PATHS.contains(&request.uri().path()) {
        return next.run(request).await;
    }

    let headers = request.headers();

    // A header that is not valid UTF-8 cannot be compared, so it is refused
    // rather than skipped: an unreadable value must not read as absent.
    if let Some(origin) = headers.get(axum::http::header::ORIGIN) {
        match origin.to_str() {
            Ok(value) if policy.origin_allowed(value) => {}
            _ => return forbidden("Origin not allowed").into_response(),
        }
    }

    if let Some(site) = headers.get("sec-fetch-site") {
        match site.to_str() {
            Ok(value) if OriginPolicy::fetch_site_allowed(value) => {}
            _ => return forbidden("Cross-site request not allowed").into_response(),
        }
    }

    // HTTP/2 carries the target in the `:authority` pseudo-header, which hyper
    // surfaces on the URI; HTTP/1.1 carries it in `Host`. Reading only `Host`
    // would leave the gate inert over HTTP/2, which is the protocol a browser
    // prefers. Both are absent only in synthetic requests: hyper rejects an
    // HTTP/1.1 request with no `Host` and an HTTP/2 one with no `:authority`.
    let target = request
        .uri()
        .authority()
        .map(|a| Ok(a.as_str().to_string()))
        .or_else(|| {
            headers
                .get(axum::http::header::HOST)
                .map(|h| h.to_str().map(ToString::to_string).map_err(|_| ()))
        });

    match target {
        None => {}
        Some(Ok(value)) if policy.host_allowed(&value) => {}
        _ => return forbidden("Host not allowed").into_response(),
    }

    next.run(request).await
}

/// JSON-RPC shaped refusal, so an MCP client sees a protocol error not HTML.
fn forbidden(message: &str) -> impl IntoResponse + use<> {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32600, "message": message },
            "id": serde_json::Value::Null,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    fn policy_for(server: ServerConfig) -> OriginPolicy {
        let config = crate::config::Config {
            server,
            ..crate::config::Config::default()
        };
        OriginPolicy::from_live(&Arc::new(crate::config_reload::LiveConfig::new(config)))
    }

    fn policy() -> OriginPolicy {
        policy_for(ServerConfig::default())
    }

    #[test]
    fn allows_loopback_host_spellings() {
        let p = policy();
        for host in [
            "127.0.0.1",
            "127.0.0.1:39400",
            "localhost",
            "localhost:39400",
            "LOCALHOST",
            "[::1]",
            "[::1]:39400",
            "127.0.0.2:39400",
        ] {
            assert!(p.host_allowed(host), "{host} names the loopback interface");
        }
    }

    #[test]
    fn rejects_rebound_host() {
        let p = policy();
        for host in ["attacker.example", "attacker.example:39400", "10.0.0.5"] {
            assert!(!p.host_allowed(host), "{host} is not this gateway");
        }
    }

    #[test]
    fn strip_port_keeps_ipv6_brackets() {
        assert_eq!(strip_port("[::1]:39400"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("127.0.0.1:39400"), "127.0.0.1");
        assert_eq!(strip_port("localhost"), "localhost");
    }

    #[test]
    fn non_loopback_bind_stays_reachable() {
        // A gateway bound to a wildcard address is reached at an address this
        // process cannot predict, so the numeric form is what can be checked.
        // A name requires `public_url`; see `non_loopback_bind_refuses_a_named_host`.
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            ..ServerConfig::default()
        };
        let p = policy_for(config);
        for host in ["192.168.1.5:39400", "10.0.0.5:39400", "172.16.0.1"] {
            assert!(p.host_allowed(host), "{host} must reach a wildcard bind");
        }
    }

    #[test]
    fn non_loopback_bind_refuses_a_named_host() {
        // DNS rebinding works against any address a victim's browser can reach,
        // a LAN address included, so a wildcard bind is not exempt. A rebound
        // request necessarily carries a NAME; a direct client on the LAN carries
        // the numeric address it dialled. Refusing names costs nothing and
        // removes the rebinding path.
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            ..ServerConfig::default()
        };
        let p = policy_for(config);
        for host in ["attacker.example", "attacker.example:39400"] {
            assert!(!p.host_allowed(host), "{host} is a name, not this gateway");
        }
        for host in ["192.168.1.5:39400", "10.0.0.5", "[fd00::1]:39400"] {
            assert!(
                p.host_allowed(host),
                "{host} is a numeric address a client dialled"
            );
        }
    }

    #[test]
    fn non_loopback_bind_with_public_url_gates_host() {
        // Once the operator names the public host, an unknown Host is refused
        // again: we now have a basis to judge.
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            public_url: Some("https://mcp.example.com".to_string()),
            ..ServerConfig::default()
        };
        let p = policy_for(config);
        assert!(p.host_allowed("mcp.example.com"));
        assert!(!p.host_allowed("attacker.example"));
    }

    #[test]
    fn browser_metadata_refuses_cross_site() {
        // Fetch Metadata is sent on EVERY browser request including a no-CORS
        // GET, which the Fetch standard omits `Origin` from. Without this, a
        // hostile page opens `/mcp` SSE sessions through the absent-Origin path.
        assert!(!OriginPolicy::fetch_site_allowed("cross-site"));
        assert!(!OriginPolicy::fetch_site_allowed("same-site"));
        assert!(OriginPolicy::fetch_site_allowed("same-origin"));
        assert!(OriginPolicy::fetch_site_allowed("none"));
    }

    #[test]
    fn bind_address_origin_is_always_allowed() {
        // A gateway bound to a nonstandard loopback address is reached at that
        // address, so its own page is same-origin there. Allowing only the
        // three canonical spellings refuses the gateway's own dashboard.
        let config = ServerConfig {
            host: "127.0.0.2".to_string(),
            port: 39400,
            ..ServerConfig::default()
        };
        let p = policy_for(config);
        assert!(
            p.origin_allowed("http://127.0.0.2:39400"),
            "the configured bind address must name an allowed origin"
        );
    }

    #[test]
    fn public_url_change_is_picked_up_without_a_restart() {
        // `public_url` is hot-reloadable: the RFC 9728 metadata handler reads it
        // from the live config per request (config_reload/mod.rs:343-349). A gate
        // that snapshots it at startup refuses the very origin the gateway
        // advertises, as soon as an operator reloads a changed value.
        let live = Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        ));
        let p = OriginPolicy::from_live(&live);
        assert!(!p.host_allowed("mcp.example.com"));

        let mut changed = crate::config::Config::default();
        changed.server.public_url = Some("https://mcp.example.com".to_string());
        live.set(changed);

        assert!(
            p.host_allowed("mcp.example.com"),
            "a reloaded public_url must be honored without a restart"
        );
    }

    #[test]
    fn origin_matching_is_case_and_slash_insensitive() {
        let p = policy();
        assert!(p.origin_allowed("http://127.0.0.1:39400"));
        assert!(p.origin_allowed("HTTP://127.0.0.1:39400/"));
        assert!(!p.origin_allowed("http://127.0.0.1:39401"));
        assert!(!p.origin_allowed("http://attacker.example"));
    }
}
