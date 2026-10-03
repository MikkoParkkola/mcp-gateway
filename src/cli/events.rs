// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Arguments of `mcp-gateway events dead-letters` (MIK-7630 I6).

use super::dashboard_link::DashboardLinkTls;

/// Arguments of `mcp-gateway events`.
#[derive(clap::Args, Debug, Clone)]
pub struct EventsArgs {
    /// What to administer.
    #[command(subcommand)]
    pub command: EventsCommand,
}

/// What `mcp-gateway events` administers.
#[derive(clap::Subcommand, Debug, Clone)]
pub enum EventsCommand {
    /// List or replay dead-lettered event deliveries; reads `MCP_GATEWAY_TOKEN`.
    DeadLetters(DeadLettersArgs),
}

/// What to do with the dead letters.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterAction {
    /// Print the dead letters (ids, reasons, times, sizes; no bodies).
    List,
    /// Replay one dead letter (`ID`), or with `--all` every one of
    /// `--subscription`.
    Replay,
}

/// Arguments of `mcp-gateway events dead-letters`.
#[derive(clap::Args, Debug, Clone)]
pub struct DeadLettersArgs {
    /// `list` or `replay`.
    #[arg(value_enum)]
    pub action: DeadLetterAction,
    /// The dead letter's event id (`replay` without `--all`).
    pub id: Option<String>,
    /// Replay every dead letter of `--subscription`.
    #[arg(long)]
    pub all: bool,
    /// Only this subscription's dead letters.
    #[arg(long)]
    pub subscription: Option<String>,
    /// Only dead letters with this reason (`list`).
    #[arg(long)]
    pub reason: Option<String>,
    /// Gateway base URL (default as for `dashboard-link`).
    #[arg(short, long)]
    pub url: Option<String>,
    /// TLS material to present and trust.
    #[command(flatten)]
    pub tls: DashboardLinkTls,
}
