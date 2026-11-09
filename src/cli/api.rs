// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Arguments of `mcp-gateway api`: one request to a running gateway's admin
//! API (`/ui/api/...`), authenticated by `MCP_GATEWAY_TOKEN`.

use super::dashboard_link::DashboardLinkTls;

/// The HTTP methods `mcp-gateway api` sends. Anything else is a usage error.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Retained so the API error renderer can report usage in either mode.
    Unsupported(String),
}

impl std::str::FromStr for ApiMethod {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            _ => Self::Unsupported(value.to_string()),
        })
    }
}

/// Arguments of `mcp-gateway api`.
#[derive(clap::Args, Debug, Clone)]
pub struct ApiArgs {
    /// GET, POST, PUT, PATCH or DELETE.
    #[arg(value_name = "METHOD")]
    pub method: ApiMethod,
    /// A path under `/ui/api/`, with an optional query string. A path that
    /// URL normalisation would rewrite (`..`, `.`, `\`, encoded dots or
    /// separators) is refused, so the credential never leaves the admin API.
    pub path: String,
    /// The JSON request body: inline, `@FILE`, or `-` for standard input.
    #[arg(long)]
    pub data: Option<String>,
    /// Require the gateway resource to match this `ETag`.
    #[arg(long, value_name = "VALUE")]
    pub if_match: Option<String>,
    /// Gateway base URL (default as for `dashboard-link`).
    #[arg(short, long)]
    pub url: Option<String>,
    /// Emit errors as one structured JSON object on stderr.
    /// Successful responses retain the gateway's native JSON or raw bytes.
    #[arg(long)]
    pub json: bool,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
}
