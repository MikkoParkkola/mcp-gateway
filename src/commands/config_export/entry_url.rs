// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The address `setup export` writes into a client's config, and the lines it
//! prints about what that address cannot tell the client.

use std::io::Write;
use std::net::IpAddr;

use serde_json::Value;

use crate::gateway::{is_wildcard_bind, strip_brackets};

use mcp_gateway::config::Config;

/// One thing the exported entry cannot show by itself, printed as one line.
/// Closed: each variant has exactly one sentence ([`UrlNote::line`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UrlNote {
    /// The bind address serves every interface, so the entry uses loopback.
    WildcardBind,
    /// The listener serves TLS: the client must trust it for `host`.
    TlsTrust { host: String },
    /// The listener asks every client for a certificate.
    ClientCertificate,
    /// The listener asks for a certificate, but `server.public_url` may name a
    /// proxy in front of it.
    ClientCertificateIfDirect,
}

impl UrlNote {
    /// The sentence printed for this note.
    pub(crate) fn line(&self) -> String {
        match self {
            Self::WildcardBind => "Note: the gateway listens on every address, so this entry \
                 points at loopback. A client on another machine needs the address it can \
                 reach; set server.public_url to it."
                .to_string(),
            Self::TlsTrust { host } => format!(
                "Note: the gateway serves TLS. The client has to trust the gateway's CA, and \
                 the server certificate has to name {host}; if it names another host, set \
                 server.public_url to that name."
            ),
            Self::ClientCertificate => "Note: this gateway asks every client for a \
                 certificate; issue one from its CA with mcp-gateway tls issue-client (see \
                 docs/DEPLOYMENT.md, TLS / mTLS)."
                .to_string(),
            Self::ClientCertificateIfDirect => "Note: the gateway's listener asks for a client \
                 certificate. If server.public_url reaches that listener with no \
                 TLS-terminating proxy between, the client needs one too: mcp-gateway tls \
                 issue-client (see docs/DEPLOYMENT.md, TLS / mTLS)."
                .to_string(),
        }
    }
}

/// The entry `setup export` writes, with the URL it holds (proxy mode only)
/// and the notes for that URL. Returned together, so a caller cannot print
/// notes for a different mode than the entry it writes.
#[derive(Debug, Clone)]
pub(crate) struct GatewayEntry {
    pub(crate) value: Value,
    pub(crate) url: Option<String>,
    pub(crate) notes: Vec<UrlNote>,
}

/// Why an export stops before writing anything: the declared address cannot
/// be handed to a client.
const PUBLIC_URL_REFUSED: &str = "server.public_url is not a URL a client can use: it must be \
     http or https, name a host a client can reach, and carry no user, password, query or \
     fragment. Fix it or remove it.";

/// The host a client on this machine connects to for a bind host: a wildcard
/// (the router's own test, so the two cannot drift apart) becomes its family's
/// loopback, an IPv6 address is bracketed once, and anything else (IPv4, a
/// name) is kept.
pub(crate) fn connect_host(host: &str) -> String {
    let bare = strip_brackets(host);
    if is_wildcard_bind(bare) {
        // The family the bind serves: an empty host and an IPv4-mapped
        // wildcard (`::ffff:0.0.0.0`) serve IPv4.
        let serves_v6 = bare
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_ipv6());
        let loopback = if serves_v6 { "[::1]" } else { "127.0.0.1" };
        return loopback.to_string();
    }
    if bare.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{bare}]")
    } else {
        bare.to_string()
    }
}

/// Whether a parsed `server.public_url` can be given to a client.
fn usable(url: &url::Url) -> bool {
    let reachable = match url.host() {
        Some(url::Host::Domain(_)) => true,
        Some(url::Host::Ipv4(ip)) => !ip.is_unspecified(),
        // An IPv4-mapped address is judged as the IPv4 address it carries.
        Some(url::Host::Ipv6(ip)) => !ip.to_canonical().is_unspecified(),
        None => false,
    };
    matches!(url.scheme(), "http" | "https")
        && reachable
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

/// The URL written into a proxy entry. A declared `server.public_url` decides
/// scheme, host and port; otherwise the scheme follows TLS on the listener and
/// the host is [`connect_host`] of the bind host.
///
/// # Errors
///
/// A `server.public_url` no client can use.
pub(crate) fn gateway_url(config: &Config) -> Result<String, String> {
    if let Some(declared) = &config.server.public_url {
        // From the parsed value, never the text as typed: the parser drops
        // surrounding spaces the text would carry into the entry.
        let parsed = url::Url::parse(declared)
            .ok()
            .filter(usable)
            .ok_or_else(|| PUBLIC_URL_REFUSED.to_string())?;
        return Ok(format!("{}/mcp", parsed.as_str().trim_end_matches('/')));
    }
    let scheme = if config.mtls.enabled { "https" } else { "http" };
    Ok(format!(
        "{scheme}://{}:{}/mcp",
        connect_host(&config.server.host),
        config.server.port
    ))
}

/// The notes for a proxy entry of `config`, in the enum's order.
pub(crate) fn url_notes(config: &Config) -> Vec<UrlNote> {
    let tls = config.mtls.enabled;
    let certificates = tls && config.mtls.require_client_cert;
    // With a declared address the export cannot see what stands there, so it
    // says only what holds if that address reaches the listener directly.
    if config.server.public_url.is_some() {
        return if certificates {
            vec![UrlNote::ClientCertificateIfDirect]
        } else {
            Vec::new()
        };
    }
    let mut notes = Vec::new();
    if is_wildcard_bind(&config.server.host) {
        notes.push(UrlNote::WildcardBind);
    }
    if tls {
        notes.push(UrlNote::TlsTrust {
            host: connect_host(&config.server.host),
        });
    }
    if certificates {
        notes.push(UrlNote::ClientCertificate);
    }
    notes
}

/// The `host:port` the Auto mode probes for a running gateway on this
/// machine. It never reads `server.public_url`, which may name a proxy.
pub(crate) fn probe_addr(config: &Config) -> String {
    format!(
        "{}:{}",
        connect_host(&config.server.host),
        config.server.port
    )
}

/// Print each note's line once, in order.
pub(crate) fn print_notes(entry: &GatewayEntry, out: &mut impl Write) {
    for note in &entry.notes {
        let _ = writeln!(out, "{}", note.line());
    }
}

#[cfg(tp1)]
#[cfg(test)]
#[path = "entry_url_tests.rs"]
mod tests;
