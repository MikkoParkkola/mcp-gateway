// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! TLS flags for `mcp-gateway dashboard-link` (#1832).

use std::path::PathBuf;

/// Arguments of `mcp-gateway dashboard-link`.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct DashboardLinkArgs {
    /// Gateway base URL (default as for `stats`).
    #[arg(short, long)]
    pub url: Option<String>,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
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
