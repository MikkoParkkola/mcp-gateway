// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway api METHOD PATH`: one request to a running gateway's admin
//! API, authenticated by `MCP_GATEWAY_TOKEN`, printing the gateway's JSON.

use std::process::ExitCode;

/// `mcp-gateway api ...`: resolve the gateway like `dashboard-link`, then send
/// the one request. Red stub: it sends nothing and exits 70 (unimplemented).
pub async fn run_api_command(
    args: mcp_gateway::cli::api::ApiArgs,
    load: impl FnOnce() -> Result<mcp_gateway::config::Config, String>,
    port_override: Option<u16>,
    host_override: Option<&str>,
) -> ExitCode {
    let _ = (args, load, port_override, host_override);
    eprintln!("api: not implemented yet");
    ExitCode::from(70)
}
