// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Arguments of `mcp-gateway audit lookup-email`: an admin looks up the key
//! server's retained issuance rows by email. The email is read from stdin
//! only: an argument would land in shell history and in every process
//! listing on the machine.

use super::dashboard_link::DashboardLinkTls;

/// Arguments of `mcp-gateway audit lookup-email`.
///
/// Exactly one of `--email-stdin` (the first page) and `--cursor-stdin` (every
/// later page) is given. Page through a long answer by feeding each printed
/// `next_cursor` back in, for example
/// `jq -r .next_cursor < page1.json | mcp-gateway audit lookup-email --cursor-stdin`.
/// A page token is single use and lives five minutes: a throttled request
/// leaves it redeemable, a lost successful answer has already spent it. Treat
/// saved output as sensitive until its token is spent or has expired.
#[derive(clap::Args, Debug, Clone)]
#[command(group(
    clap::ArgGroup::new("source")
        .required(true)
        .args(["email_stdin", "cursor_stdin"])
))]
pub struct LookupEmailArgs {
    /// Read the email from standard input (one line): the first page. The
    /// email is never an argument, so it stays out of shell history and
    /// process lists. The credential is read from `MCP_GATEWAY_TOKEN`.
    #[arg(long, conflicts_with = "cursor_stdin")]
    pub email_stdin: bool,
    /// Read the previous page's `next_cursor` from standard input (one line):
    /// every later page. The token is never an argument either. It carries its
    /// own time window, so `--from` and `--to` are refused beside it.
    #[arg(long, conflicts_with_all = ["email_stdin", "from", "to"])]
    pub cursor_stdin: bool,
    /// Gateway base URL (default as for `dashboard-link`).
    #[arg(short, long)]
    pub url: Option<String>,
    /// Rows per page (1 to 200; the gateway's default is 50).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=200))]
    pub limit: Option<u32>,
    /// Only rows at or after this RFC 3339 time (first page only).
    #[arg(long)]
    pub from: Option<String>,
    /// Only rows at or before this RFC 3339 time (first page only).
    #[arg(long)]
    pub to: Option<String>,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
}
