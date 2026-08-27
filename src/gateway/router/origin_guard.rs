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

use tracing::warn;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::well_known::is_loopback_host;

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
    /// Whether the bind address is loopback. Restart-required, so a snapshot
    /// cannot drift from the listener.
    ///
    /// Whether `Host` can be judged at all is derived from this AND the current
    /// `public_url`, per request, never snapshotted. A gateway that started with
    /// a `public_url` and had it removed by a reload would otherwise keep gating
    /// with nothing left to gate against, and refuse every request.
    bind_is_loopback: bool,
    /// Scheme this listener speaks, so an Origin is compared as a full origin
    /// rather than only an authority.
    listener_scheme: &'static str,
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
        let full = live_config.get();
        let tls = full.mtls.enabled;
        let config = &full.server;
        let port = config.port;
        // Every spelling of the loopback bind a browser could legitimately use.
        let allowed_origins: Vec<String> = if is_loopback_host(&config.host) {
            // Every spelling a browser could legitimately use to reach a
            // loopback bind, including the configured address itself: a bind on
            // 127.0.0.2 is served at 127.0.0.2, and its own page is same-origin
            // only there.
            // One scheme: the one this listener actually speaks. Listing both
            // would admit an origin nothing can serve.
            let scheme = if tls { "https" } else { "http" };
            let mut origins = vec![
                format!("{scheme}://127.0.0.1:{port}"),
                format!("{scheme}://localhost:{port}"),
                format!("{scheme}://[::1]:{port}"),
            ];
            let bracketed = if config.host.contains(':') && !config.host.starts_with('[') {
                format!("[{}]", config.host)
            } else {
                config.host.clone()
            };
            let configured = format!("{scheme}://{bracketed}:{port}").to_ascii_lowercase();
            if !origins.contains(&configured) {
                origins.push(configured);
            }
            origins
        } else {
            Vec::new()
        };

        Self {
            allowed_origins,
            live_config: Arc::clone(live_config),
            bind_is_loopback: is_loopback_host(&config.host),
            listener_scheme: if tls { "https" } else { "http" },
        }
    }

    /// Host and origin of `server.public_url` in one live snapshot.
    ///
    /// Taken ONCE per request and handed to both checks. Reading it separately
    /// per check lets a reload land between them, so `Origin` would be judged
    /// against the old value and `Host` against the new — a window in which
    /// neither answer describes a configuration that ever existed.
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
    fn origin_allowed(
        &self,
        origin: &str,
        public: Option<&(String, String)>,
        request_authority: Option<&str>,
    ) -> bool {
        let candidate = origin.trim_end_matches('/').to_ascii_lowercase();
        // Canonical, not string equality: a browser omits the port when it is
        // the scheme default, so a gateway on port 80 or 443 would refuse its
        // own page against an allow-list entry that spells the port out. Used
        // for BOTH allow-list paths — the configured origins and `public_url` —
        // because one decision reached by two comparison rules is a decision
        // that can come out two ways.
        if self
            .allowed_origins
            .iter()
            .any(|allowed| same_origin(allowed, &candidate))
        {
            return true;
        }
        if public.is_some_and(|(_, public_origin)| same_origin(public_origin, &candidate)) {
            return true;
        }

        // A page served by this gateway on a non-loopback bind carries an Origin
        // naming the address it was fetched from, which no startup list can
        // enumerate. Admit a numeric one ONLY when it names the gateway this
        // request is addressed to.
        //
        // Admitting any numeric Origin does not work: an attacker can serve the
        // page from a public IP address, and the browser then sends that address
        // as the Origin. Matching it against the request's own authority is what
        // makes "the page this gateway served" checkable.
        if self.bind_is_loopback {
            return false;
        }
        let Some(authority) = request_authority else {
            return false;
        };
        let Ok(parsed) = url::Url::parse(&candidate) else {
            return false;
        };
        // Scheme must be the one this listener speaks. Same-socket cross-scheme
        // cannot really occur, but comparing it costs nothing and keeps the
        // check a full origin comparison rather than an authority one.
        if parsed.scheme() != self.listener_scheme {
            return false;
        }
        let Some(origin_host) = parsed.host_str() else {
            return false;
        };
        if !is_numeric_host(strip_brackets(origin_host)) {
            return false;
        }
        let default_port = if parsed.scheme() == "https" { 443 } else { 80 };
        let origin = canonical_authority(
            &format!("{}:{}", origin_host, parsed.port().unwrap_or(default_port)),
            default_port,
        );
        canonical_authority(authority, default_port) == origin
    }

    /// `true` when a `Host` value names this gateway.
    ///
    /// A rebound name arrives here as the attacker's hostname, which is neither
    /// loopback nor the configured public host.
    #[must_use]
    fn host_allowed(&self, host: &str, public: Option<&(String, String)>) -> bool {
        let bare = strip_port(host);

        // A numeric host always reaches a non-loopback bind, whether or not a
        // public name is declared. An orchestrator probes a pod by address, and
        // a pod it cannot probe gets drained. Rebinding needs a NAME, so
        // admitting addresses costs nothing the gate was built to stop.
        if !self.bind_is_loopback && is_numeric_host(bare) {
            return true;
        }

        // Derived per request, never snapshotted: a public_url added by a
        // reload turns full gating on, and one removed returns to the numeric
        // rule rather than refusing everything.
        if !self.bind_is_loopback && public.is_none() {
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
        public.is_some_and(|(public_host, _)| public_host.eq_ignore_ascii_case(bare))
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

/// `true` when two origin strings name the same origin.
///
/// Compares scheme, host and effective port after parsing, so an omitted
/// default port and an explicit one are equal and IPv6 spellings agree.
fn same_origin(a: &str, b: &str) -> bool {
    let parts = |o: &str| {
        let u = url::Url::parse(o).ok()?;
        let host = u.host_str()?.to_string();
        let default = if u.scheme() == "https" { 443 } else { 80 };
        let host = strip_brackets(&host)
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| host.to_ascii_lowercase(), |ip| ip.to_string());
        Some((u.scheme().to_string(), host, u.port().unwrap_or(default)))
    };
    match (parts(a), parts(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Canonical (host, port) of an authority, for comparison.
///
/// The host is normalised through `IpAddr` when it parses as one, so bracketed
/// and unbracketed IPv6, and long-hand and compressed forms of the same
/// address, compare equal. A hand-rolled string comparison got all three wrong.
fn canonical_authority(authority: &str, default_port: u16) -> (String, u16) {
    let bare = strip_brackets(strip_port(authority));
    let host = bare
        .parse::<std::net::IpAddr>()
        .map_or_else(|_| bare.to_ascii_lowercase(), |ip| ip.to_string());
    let port = authority
        .rsplit_once(':')
        .filter(|(head, _)| !head.ends_with(':') && !authority.ends_with(']'))
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(default_port);
    (host, port)
}

/// Strip the brackets from an IPv6 literal, leaving anything else alone.
fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
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
    let headers = request.headers();

    // A header that is not valid UTF-8 cannot be compared, so it is refused
    // rather than skipped: an unreadable value must not read as absent.
    let path = request.uri().path().to_string();
    // One snapshot for the whole request. See `public_url_parts`.
    let public = policy.public_url_parts();

    // The authority this request is addressed to: HTTP/2 carries it on the URI,
    // HTTP/1.1 in `Host`. Needed by the Origin check, so it is resolved first.
    let request_authority: Option<String> = request
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            headers
                .get(axum::http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(ToString::to_string)
        });

    if let Some(origin) = headers.get(axum::http::header::ORIGIN) {
        match origin.to_str() {
            Ok(value)
                if policy.origin_allowed(value, public.as_ref(), request_authority.as_deref()) => {}
            other => {
                // Logged because a silent refusal is indistinguishable from a
                // broken client: an operator seeing 403 needs the reason, and a
                // real cross-site attempt should leave a trace. Header values
                // are attacker-supplied but carry no secret.
                warn!(
                    path = %path,
                    origin = other.unwrap_or("<invalid utf-8>"),
                    "Request blocked: Origin does not name this gateway"
                );
                return forbidden("Origin not allowed").into_response();
            }
        }
    }

    if let Some(site) = headers.get("sec-fetch-site") {
        match site.to_str() {
            Ok(value) if OriginPolicy::fetch_site_allowed(value) => {}
            other => {
                warn!(
                    path = %path,
                    sec_fetch_site = other.unwrap_or("<invalid utf-8>"),
                    "Request blocked: browser reports a cross-site request"
                );
                return forbidden("Cross-site request not allowed").into_response();
            }
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
        Some(Ok(value)) if policy.host_allowed(&value, public.as_ref()) => {}
        other => {
            warn!(
                path = %path,
                host = other.and_then(Result::ok).unwrap_or_else(|| "<invalid utf-8>".to_string()),
                "Request blocked: Host does not name this gateway"
            );
            return forbidden("Host not allowed").into_response();
        }
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

    /// Test shim: take the live snapshot the middleware would take.
    impl OriginPolicy {
        fn host_ok(&self, host: &str) -> bool {
            self.host_allowed(host, self.public_url_parts().as_ref())
        }
        fn origin_ok(&self, origin: &str) -> bool {
            self.origin_allowed(origin, self.public_url_parts().as_ref(), None)
        }
        fn origin_ok_at(&self, origin: &str, authority: &str) -> bool {
            self.origin_allowed(origin, self.public_url_parts().as_ref(), Some(authority))
        }
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
            assert!(p.host_ok(host), "{host} names the loopback interface");
        }
    }

    #[test]
    fn rejects_rebound_host() {
        let p = policy();
        for host in ["attacker.example", "attacker.example:39400", "10.0.0.5"] {
            assert!(!p.host_ok(host), "{host} is not this gateway");
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
            assert!(p.host_ok(host), "{host} must reach a wildcard bind");
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
            assert!(!p.host_ok(host), "{host} is a name, not this gateway");
        }
        for host in ["192.168.1.5:39400", "10.0.0.5", "[fd00::1]:39400"] {
            assert!(
                p.host_ok(host),
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
        assert!(p.host_ok("mcp.example.com"));
        assert!(!p.host_ok("attacker.example"));
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
            p.origin_ok("http://127.0.0.2:39400"),
            "the configured bind address must name an allowed origin"
        );
    }

    #[test]
    fn an_https_listener_admits_its_own_https_page() {
        // The mirror of the plain-HTTP case: with TLS on, the gateway's own
        // page carries an https Origin and the http spelling names nothing.
        let config = crate::config::Config {
            mtls: crate::mtls::MtlsConfig {
                enabled: true,
                ..crate::mtls::MtlsConfig::default()
            },
            ..crate::config::Config::default()
        };
        let p = OriginPolicy::from_live(&Arc::new(crate::config_reload::LiveConfig::new(config)));
        assert!(p.origin_ok("https://127.0.0.1:39400"));
        assert!(!p.origin_ok("http://127.0.0.1:39400"));
    }

    #[test]
    fn own_origin_matching_is_canonical() {
        // Three defects in one hand-rolled comparison: the scheme was ignored,
        // so an http page matched an https listener; an IPv6 authority carries
        // brackets while the parsed origin host does not, so the gateway's own
        // IPv6 page could never match; and a default port omitted from the
        // Origin compared unequal to an explicit one.
        let p = policy_for(ServerConfig {
            host: "0.0.0.0".to_string(),
            ..ServerConfig::default()
        });

        // IPv6: bracketed authority against an unbracketed parsed host.
        assert!(
            p.origin_ok_at("http://[fd00::1]:39400", "[fd00::1]:39400"),
            "the gateway's own IPv6 page"
        );
        // Alternate spellings of the same address must compare equal.
        assert!(
            p.origin_ok_at("http://[fd00:0:0:0:0:0:0:1]:39400", "[fd00::1]:39400"),
            "the same IPv6 address written long-hand"
        );
        // A different address must not.
        assert!(!p.origin_ok_at("http://[fd00::2]:39400", "[fd00::1]:39400"));
        // Default port omitted on one side only.
        assert!(p.origin_ok_at("http://192.168.1.5", "192.168.1.5:80"));
        // Cross-scheme on the same authority is a different origin.
        assert!(!p.origin_ok_at("https://192.168.1.5:39400", "192.168.1.5:39400"));
    }

    #[test]
    fn the_gateways_own_page_is_same_origin_on_any_bind() {
        // Two ways an operator gets refused by their own gateway: a LAN bind,
        // where the page is served from an address no allow-list names; and a
        // TLS listener, where the page's Origin is https and the list is built
        // with a hardcoded http scheme.
        let lan = policy_for(ServerConfig {
            host: "0.0.0.0".to_string(),
            ..ServerConfig::default()
        });
        assert!(
            lan.origin_ok_at("http://192.168.1.5:39400", "192.168.1.5:39400"),
            "the gateway's own LAN page"
        );
        assert!(!lan.origin_ok("http://attacker.example"), "still a name");
        assert!(
            !lan.origin_ok_at("http://203.0.113.5", "192.168.1.5:39400"),
            "an attacker page served from a public address is still numeric"
        );
        assert!(
            !lan.origin_ok_at("http://192.168.1.5:8080", "192.168.1.5:39400"),
            "a different port is a different origin"
        );

        // The listener speaks one scheme. On a plain-HTTP listener an https
        // origin names something nothing serves, so it is refused; the TLS case
        // is covered by `an_https_listener_admits_its_own_https_page`.
        let plain = policy_for(ServerConfig::default());
        assert!(plain.origin_ok("http://127.0.0.1:39400"));
        assert!(!plain.origin_ok("https://127.0.0.1:39400"));
    }

    #[test]
    fn a_numeric_probe_reaches_a_proxied_gateway() {
        // A gateway behind a reverse proxy declares public_url, and its
        // orchestrator still probes it by pod IP. Gating solely on the public
        // name refuses that probe, and an orchestrator that cannot health-check
        // a pod drains or restarts it.
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            public_url: Some("https://mcp.example.com".to_string()),
            ..ServerConfig::default()
        };
        let p = policy_for(config);
        assert!(p.host_ok("mcp.example.com"), "the declared name");
        assert!(p.host_ok("10.42.0.7:39400"), "the orchestrator's probe");
        assert!(
            !p.host_ok("attacker.example"),
            "a name that is neither is still refused"
        );
    }

    #[test]
    fn removing_public_url_by_reload_does_not_lock_everyone_out() {
        // gate_host was computed once at startup. A gateway that started WITH a
        // public_url and then had it removed kept gating, but had nothing left
        // to gate against, so every non-loopback host was refused.
        let config = crate::config::Config {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                public_url: Some("https://mcp.example.com".to_string()),
                ..ServerConfig::default()
            },
            ..crate::config::Config::default()
        };
        let live = Arc::new(crate::config_reload::LiveConfig::new(config));
        let p = OriginPolicy::from_live(&live);
        assert!(p.host_ok("mcp.example.com"));

        let mut without = crate::config::Config::default();
        without.server.host = "0.0.0.0".to_string();
        live.set(without);

        assert!(
            p.host_ok("192.168.1.5:39400"),
            "removing public_url must fall back to the numeric rule, not refuse everything"
        );
    }

    #[test]
    fn a_numeric_host_reaches_a_non_loopback_bind() {
        // What this case actually covers, renamed to say so. It was called
        // `ipv6_public_url_matches_a_bracketed_host` and claimed to lock in the
        // bracketed `public_url` comparison — which it never reached: with a
        // non-loopback bind, `host_allowed` returns true on the numeric-host
        // rule before `public_url` is consulted at all. Its assertions were
        // true and its stated purpose was not tested.
        let config = ServerConfig {
            host: "0.0.0.0".to_string(),
            public_url: Some("http://[fd00::1]:39400".to_string()),
            ..ServerConfig::default()
        };
        let p = policy_for(config);
        assert!(p.host_ok("[fd00::1]:39400"));
        assert!(p.host_ok("[fd00::1]"));
        // A DIFFERENT literal is admitted too, which is the point: every
        // numeric host reaches a non-loopback bind by design, because rebinding
        // needs a NAME. What `public_url` gates is names.
        assert!(p.host_ok("[fd00::2]"));
        assert!(!p.host_ok("attacker.example"));
    }

    #[test]
    fn ipv6_public_url_matches_a_bracketed_host() {
        // The comparison the case above claimed to cover, on a LOOPBACK bind so
        // the numeric short-circuit cannot fire and `public_url` is genuinely
        // consulted.
        //
        // This matters because a Host header carries an IPv6 literal in
        // brackets while `Url::host_str` does not necessarily return it that
        // way. If the two forms did not compare equal, every IPv6 operator who
        // set `public_url` would be locked out of their own gateway.
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            public_url: Some("http://[fd00::1]:39400".to_string()),
            ..ServerConfig::default()
        };
        let p = policy_for(config);

        assert!(
            p.host_ok("[fd00::1]:39400"),
            "the bracketed Host form must match a bracketed public_url"
        );
        assert!(
            !p.host_ok("[fd00::2]:39400"),
            "and a different literal must not — on a loopback bind the numeric \
             rule does not apply, so this is the public_url comparison itself"
        );
        assert!(!p.host_ok("attacker.example"));
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
        assert!(!p.host_ok("mcp.example.com"));

        let mut changed = crate::config::Config::default();
        changed.server.public_url = Some("https://mcp.example.com".to_string());
        live.set(changed);

        assert!(
            p.host_ok("mcp.example.com"),
            "a reloaded public_url must be honored without a restart"
        );
    }

    #[test]
    fn a_default_port_omitted_by_the_browser_still_matches() {
        // A gateway on port 80 is reached at `http://localhost`, with no port,
        // while the allow-list spells it out. String equality refuses the
        // gateway's own page.
        let p = policy_for(ServerConfig {
            port: 80,
            ..ServerConfig::default()
        });
        assert!(p.origin_ok("http://localhost"));
        assert!(p.origin_ok("http://127.0.0.1:80"));
        assert!(!p.origin_ok("http://localhost:8080"));
    }

    #[test]
    fn origin_matching_is_case_and_slash_insensitive() {
        let p = policy();
        assert!(p.origin_ok("http://127.0.0.1:39400"));
        assert!(p.origin_ok("HTTP://127.0.0.1:39400/"));
        assert!(!p.origin_ok("http://127.0.0.1:39401"));
        assert!(!p.origin_ok("http://attacker.example"));
    }
}
