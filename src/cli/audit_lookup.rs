// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Arguments of `mcp-gateway audit lookup-email`: an admin looks up the key
//! server's retained issuance rows by email. The email is read from stdin
//! only: an argument would land in shell history and in every process
//! listing on the machine.

use super::dashboard_link::DashboardLinkTls;

/// Arguments of `mcp-gateway audit lookup-email`.
#[derive(clap::Args, Debug, Clone)]
pub struct LookupEmailArgs {
    /// Read the email from standard input (one line). Required: the email is
    /// never an argument, so it stays out of shell history and process lists.
    /// The credential is read from `MCP_GATEWAY_TOKEN`.
    #[arg(long, required = true)]
    pub email_stdin: bool,
    /// Gateway base URL (default as for `dashboard-link`).
    #[arg(short, long)]
    pub url: Option<String>,
    /// Rows per page (1 to 200; the gateway's default is 50).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=200))]
    pub limit: Option<u32>,
    /// The `next_cursor` of the previous page.
    #[arg(long)]
    pub cursor: Option<String>,
    /// Only rows at or after this RFC 3339 time.
    #[arg(long)]
    pub from: Option<String>,
    /// Only rows at or before this RFC 3339 time.
    #[arg(long)]
    pub to: Option<String>,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
}
