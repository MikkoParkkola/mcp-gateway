// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TLS flags for `mcp-gateway dashboard-link` (#1832).

use std::path::PathBuf;

/// Where a remote command sends its request: the one destination flag of
/// the five commands that talk to a running gateway.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct GatewayArg {
    /// The gateway to send to, as a base URL. Order: this flag, then
    /// `MCP_GATEWAY_URL`, then the address in `--config` (`server.host` and
    /// `server.port`).
    // `--url` and `-u` are the old spellings: hidden aliases, so scripts
    // written for them keep working.
    #[arg(
        long = "gateway",
        alias = "url",
        short_alias = 'u',
        env = "MCP_GATEWAY_URL",
        value_name = "URL"
    )]
    pub url: Option<String>,
}

/// Arguments of `mcp-gateway dashboard-link`.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct DashboardLinkArgs {
    /// Where to send the request.
    #[command(flatten)]
    pub gateway: GatewayArg,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
    /// Print one JSON document on stdout (`url`); errors are the shared JSON error on stderr
    #[arg(long)]
    pub json: bool,
}

/// The TLS material `dashboard-link` presents and trusts.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct DashboardLinkTls {
    /// PEM client certificate for a listener that requires one
    /// (`mtls.require_client_cert`); pair with `--client-key`.
    #[arg(long, env = "MCP_GATEWAY_CLIENT_CERT", requires = "client_key")]
    pub client_cert: Option<PathBuf>,
    /// PEM private key for `--client-cert`.
    #[arg(long, env = "MCP_GATEWAY_CLIENT_KEY", requires = "client_cert")]
    pub client_key: Option<PathBuf>,
    /// PEM CA the gateway's server certificate must chain to; replaces the
    /// built-in roots. Without it, a config-derived URL on an mTLS listener
    /// trusts only `mtls.ca_cert`.
    #[arg(long, env = "MCP_GATEWAY_CA_CERT")]
    pub ca_cert: Option<PathBuf>,
}
