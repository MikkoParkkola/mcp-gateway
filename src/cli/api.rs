// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Arguments of `mcp-gateway api`: one request to a running gateway's admin
//! API (`/ui/api/...`), authenticated by `MCP_GATEWAY_TOKEN`.

use super::dashboard_link::DashboardLinkTls;

/// The HTTP methods `mcp-gateway api` sends. Anything else is a usage error.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "UPPER")]
pub enum ApiMethod {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
}

/// Arguments of `mcp-gateway api`.
#[derive(clap::Args, Debug, Clone)]
pub struct ApiArgs {
    /// GET, POST, PUT, PATCH or DELETE.
    #[arg(value_enum, ignore_case = true)]
    pub method: ApiMethod,
    /// A path under `/ui/api/`, with an optional query string. A path that
    /// URL normalisation would rewrite (`..`, `.`, `\`, encoded dots or
    /// separators) is refused, so the credential never leaves the admin API.
    pub path: String,
    /// The JSON request body: inline, `@FILE`, or `-` for standard input.
    #[arg(long)]
    pub data: Option<String>,
    /// Gateway base URL (default as for `dashboard-link`).
    #[arg(short, long)]
    pub url: Option<String>,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
}
