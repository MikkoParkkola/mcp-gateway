// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Arguments of `mcp-gateway api`: one request to a running gateway's admin
//! API (`/ui/api/...`), authenticated by `MCP_GATEWAY_TOKEN`.

use super::dashboard_link::{DashboardLinkTls, GatewayArg};

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
    /// The request body: inline, `@FILE`, or `-` for standard input. JSON,
    /// except a capability's save (PUT) and validate routes, which send it
    /// unchanged as YAML.
    #[arg(long)]
    pub data: Option<String>,
    /// Require the gateway resource to match this `ETag`.
    #[arg(hide = true, long, value_name = "VALUE")]
    pub if_match: Option<String>,
    /// The event stream (`/ui/api/stream`) only, and required there: print
    /// this many events, then close the stream and exit.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    pub limit: Option<u32>,
    /// Where to send the request.
    #[command(flatten)]
    pub gateway: GatewayArg,
    /// Emit errors as one structured JSON object on stderr.
    /// Successful responses retain the gateway's native JSON or raw bytes.
    #[arg(long)]
    pub json: bool,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
}
