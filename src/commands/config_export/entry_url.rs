// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The address `setup export` writes into a client's config, and the lines it
//! prints about what that address cannot tell the client.

use std::io::Write;

use serde_json::Value;

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

/// The host a client on this machine connects to for a bind host.
pub(crate) fn connect_host(host: &str) -> String {
    host.to_string()
}

/// The URL written into a proxy entry.
///
/// # Errors
///
/// A `server.public_url` no client can use.
pub(crate) fn gateway_url(config: &Config) -> Result<String, String> {
    Ok(format!(
        "http://{}:{}/mcp",
        config.server.host, config.server.port
    ))
}

/// The notes for a proxy entry of `config`.
pub(crate) fn url_notes(_config: &Config) -> Vec<UrlNote> {
    Vec::new()
}

/// The `host:port` the Auto mode probes for a running gateway.
pub(crate) fn probe_addr(config: &Config) -> String {
    format!("{}:{}", config.server.host, config.server.port)
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
