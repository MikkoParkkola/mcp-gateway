// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for the origin guard's policy checks.

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
fn a_tunnel_hostname_is_admitted_once_declared() {
    // Inbound webhook deliveries arrive through a tunnel and carry its
    // hostname, which on a loopback bind is neither loopback nor known.
    // Declaring it as public_url admits them, and is read live so a reload
    // applies it.
    let live = Arc::new(crate::config_reload::LiveConfig::new(
        crate::config::Config::default(),
    ));
    let p = OriginPolicy::from_live(&live);
    assert!(
        !p.host_ok("your-tunnel.example.com"),
        "undeclared is refused"
    );

    let mut declared = crate::config::Config::default();
    declared.server.public_url = Some("https://your-tunnel.example.com".to_string());
    live.set(declared);
    assert!(
        p.host_ok("your-tunnel.example.com"),
        "a declared public_url must admit the provider's delivery"
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
