// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! clap's own consistency checks pass on the whole CLI (MIK-8173).
//!
//! clap runs these only in debug builds, and only for the subcommand being
//! parsed, so a duplicate short flag on one rarely used subcommand panics a
//! debug binary there and is silently ambiguous in a release one. This
//! builds every subcommand at once.

use clap::CommandFactory;

#[test]
fn the_whole_cli_passes_clap_debug_asserts() {
    mcp_gateway::cli::Cli::command().debug_assert();
}
