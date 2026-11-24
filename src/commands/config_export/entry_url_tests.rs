// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The exported URL, its notes and the Auto-mode probe address. Expected
//! values are literals, never built with the functions under test.

use mcp_gateway::{cli::ConnectionMode, config::Config};

use super::super::build_gateway_entry;
use super::{UrlNote, gateway_url, probe_addr};

/// `Config::default()` with a bind host, a port and whether TLS is on.
fn on(host: &str, port: u16, tls: bool) -> Config {
    let mut config = Config::default();
    config.server.host = host.to_string();
    config.server.port = port;
    config.mtls.enabled = tls;
    config.mtls.require_client_cert = false;
    config
}

/// [`on`] behind a declared `server.public_url`.
fn behind(public_url: &str, host: &str, tls: bool) -> Config {
    let mut config = on(host, 39400, tls);
    config.server.public_url = Some(public_url.to_string());
    config
}

/// A YAML text through serde, so its defaults apply: `mtls.require_client_cert`
/// is true when the text leaves it out.
fn file(text: &str) -> Config {
    crate::yaml::from_str(text).expect("fixture config")
}

fn url(config: &Config) -> String {
    gateway_url(config).expect("a usable URL")
}

const REFUSED: &str = "server.public_url is not a URL a client can use: it must be http or \
                       https, name a host a client can reach, and carry no user, password, \
                       query or fragment. Fix it or remove it.";

#[test]
fn u1_ipv6_binds_are_bracketed_and_wildcards_become_loopback() {
    assert_eq!(
        url(&on("fd00::2", 39400, false)),
        "http://[fd00::2]:39400/mcp"
    );
    assert_eq!(url(&on("[::1]", 39400, false)), "http://[::1]:39400/mcp");
    assert_eq!(url(&on("::1", 39400, false)), "http://[::1]:39400/mcp");
    // A mapped address that is no wildcard is an IPv6 host like any other.
    assert_eq!(
        url(&on("::ffff:127.0.0.1", 39400, false)),
        "http://[::ffff:127.0.0.1]:39400/mcp"
    );
    for wildcard in ["::0", "[::]", "::"] {
        assert_eq!(
            url(&on(wildcard, 39400, false)),
            "http://[::1]:39400/mcp",
            "{wildcard:?}"
        );
    }
}

#[test]
fn u1_ipv4_and_names_keep_their_host_and_take_the_served_scheme() {
    // A mapped IPv4 wildcard serves IPv4, so its loopback is IPv4's.
    for wildcard in ["", "0.0.0.0", "[0.0.0.0]", "::ffff:0.0.0.0"] {
        assert_eq!(
            url(&on(wildcard, 39400, false)),
            "http://127.0.0.1:39400/mcp",
            "{wildcard:?}"
        );
    }
    assert_eq!(
        url(&on("gw.internal", 39400, false)),
        "http://gw.internal:39400/mcp"
    );
    assert_eq!(
        url(&on("127.0.0.1", 39400, true)),
        "https://127.0.0.1:39400/mcp"
    );
    assert_eq!(
        url(&on("127.0.0.1", 8080, false)),
        "http://127.0.0.1:8080/mcp"
    );
    assert_eq!(url(&Config::default()), "http://127.0.0.1:39400/mcp");
}

#[test]
fn u1_a_declared_public_url_decides_scheme_host_and_port() {
    // Built from the parsed value: a stray space is not carried into the entry.
    assert_eq!(
        url(&behind("https://mcp.example.com ", "0.0.0.0", false)),
        "https://mcp.example.com/mcp"
    );
    assert_eq!(
        url(&behind("https://mcp.example.com/gw", "0.0.0.0", false)),
        "https://mcp.example.com/gw/mcp"
    );
    assert_eq!(
        url(&behind("https://mcp.example.com:8443", "0.0.0.0", false)),
        "https://mcp.example.com:8443/mcp"
    );
    assert_eq!(
        url(&behind("https://mcp.example.com/", "0.0.0.0", false)),
        "https://mcp.example.com/mcp"
    );
    assert_eq!(
        url(&behind("https://mcp.example.com", "0.0.0.0", false)),
        "https://mcp.example.com/mcp"
    );
    // TLS on the listener does not override the scheme the operator declared.
    assert_eq!(
        url(&behind("http://gw.internal:8080", "127.0.0.1", true)),
        "http://gw.internal:8080/mcp"
    );
}

#[test]
fn u1_a_public_url_no_client_can_use_is_refused() {
    for bad in [
        "http://[::]:39400",
        "http://[::ffff:0.0.0.0]:39400",
        "https://u:p@mcp.example.com",
        "https://u@mcp.example.com",
        "https://:p@mcp.example.com",
        "https://mcp.example.com/#x",
        "http://0.0.0.0:39400",
        "https://mcp.example.com/?a=1",
        "ftp://x",
        "not a url",
    ] {
        assert_eq!(
            gateway_url(&behind(bad, "127.0.0.1", false)),
            Err(REFUSED.to_string()),
            "{bad:?}"
        );
    }
}

fn notes(config: &Config, mode: ConnectionMode) -> Vec<UrlNote> {
    build_gateway_entry(config, None, mode)
        .expect("entry")
        .notes
}

fn tls_on(host: &str) -> UrlNote {
    UrlNote::TlsTrust {
        host: host.to_string(),
    }
}

#[test]
fn u2_each_note_appears_exactly_when_it_is_true() {
    let proxy = ConnectionMode::Proxy;
    // Client certificates required (the file leaves the field out).
    let wildcard_mtls = file("server:\n  host: 0.0.0.0\nmtls:\n  enabled: true\n");
    assert_eq!(
        notes(&wildcard_mtls, proxy),
        [
            UrlNote::WildcardBind,
            tls_on("127.0.0.1"),
            UrlNote::ClientCertificate
        ]
    );
    let mtls_file = file("mtls:\n  enabled: true\n");
    assert_eq!(
        notes(&mtls_file, proxy),
        [tls_on("127.0.0.1"), UrlNote::ClientCertificate]
    );
    // TLS without required certificates names the host written in the URL.
    assert_eq!(
        notes(&on("gw.internal", 39400, true), proxy),
        [tls_on("gw.internal")]
    );
    assert_eq!(
        notes(&on("127.0.0.1", 39400, true), proxy),
        [tls_on("127.0.0.1")]
    );
    for wildcard in ["0.0.0.0", "::ffff:0.0.0.0"] {
        assert_eq!(
            notes(&on(wildcard, 39400, false), proxy),
            [UrlNote::WildcardBind],
            "{wildcard:?}"
        );
    }
    assert_eq!(notes(&Config::default(), proxy), []);

    let mtls_behind =
        file("server:\n  public_url: https://mcp.example.com\nmtls:\n  enabled: true\n");
    assert_eq!(
        notes(&mtls_behind, proxy),
        [UrlNote::ClientCertificateIfDirect]
    );
    let entry = build_gateway_entry(
        &behind("https://mcp.example.com", "0.0.0.0", false),
        None,
        proxy,
    )
    .expect("entry");
    assert_eq!(entry.notes, []);
    assert_eq!(entry.url.as_deref(), Some("https://mcp.example.com/mcp"));
    assert_eq!(entry.value["url"], "https://mcp.example.com/mcp");

    // A stdio entry holds no URL: no notes, and a bad public_url is not read.
    let stdio = build_gateway_entry(&mtls_file, None, ConnectionMode::Stdio).expect("entry");
    assert_eq!((stdio.url, stdio.notes), (None, vec![]));
    assert!(
        build_gateway_entry(
            &behind("not a url", "127.0.0.1", false),
            None,
            ConnectionMode::Stdio
        )
        .is_ok()
    );
}

#[test]
fn u2_the_tls_line_names_the_written_host_not_the_bind_address() {
    let wildcard_mtls = file("server:\n  host: 0.0.0.0\nmtls:\n  enabled: true\n");
    let lines: Vec<String> = notes(&wildcard_mtls, ConnectionMode::Proxy)
        .iter()
        .map(UrlNote::line)
        .collect();
    let tls = lines
        .iter()
        .find(|l| l.contains("serves TLS"))
        .expect("the TLS line");
    assert!(tls.contains("127.0.0.1"), "{tls}");
    assert!(!tls.contains("0.0.0.0"), "{tls}");
}

#[test]
fn u2_each_note_has_its_own_sentence() {
    assert_eq!(
        UrlNote::ClientCertificateIfDirect.line(),
        "Note: the gateway's listener asks for a client certificate. If server.public_url \
         reaches that listener with no TLS-terminating proxy between, the client needs one too: \
         mcp-gateway tls issue-client (see docs/DEPLOYMENT.md, TLS / mTLS)."
    );
    assert_eq!(
        UrlNote::ClientCertificate.line(),
        "Note: this gateway asks every client for a certificate; issue one from its CA with \
         mcp-gateway tls issue-client (see docs/DEPLOYMENT.md, TLS / mTLS)."
    );
    assert_eq!(
        tls_on("HOST").line(),
        "Note: the gateway serves TLS. The client has to trust the gateway's CA, and the server \
         certificate has to name HOST; if it names another host, set server.public_url to that \
         name."
    );
    assert_eq!(
        UrlNote::WildcardBind.line(),
        "Note: the gateway listens on every address, so this entry points at loopback. A \
         client on another machine needs the address it can reach; set server.public_url to it."
    );
}

#[test]
fn u6a_the_probe_asks_this_machine_in_a_form_that_parses() {
    assert_eq!(
        probe_addr(&on("gw.internal", 8080, false)),
        "gw.internal:8080"
    );
    assert_eq!(probe_addr(&on("0.0.0.0", 39400, false)), "127.0.0.1:39400");
    assert_eq!(
        probe_addr(&on("::ffff:0.0.0.0", 39400, false)),
        "127.0.0.1:39400"
    );
    assert_eq!(probe_addr(&on("::", 39400, false)), "[::1]:39400");
    assert_eq!(probe_addr(&on("::1", 39400, false)), "[::1]:39400");
    // The probe asks whether a gateway runs here, so a public_url is not read.
    assert_eq!(
        probe_addr(&behind("https://mcp.example.com", "127.0.0.1", false)),
        "127.0.0.1:39400"
    );
}
