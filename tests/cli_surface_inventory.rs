// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `## Surface: cli` table lists exactly the CLI clap builds (MIK-8170).
//!
//! Gated on every CLI-gating feature (Cargo.toml `[[test]]`), so CI's
//! `--all-features` run sees every subcommand and a default run skips it.

#[path = "common/cli_inventory_walker.rs"]
mod walker;

use clap::CommandFactory;

const DOC: &str = include_str!("../docs/design/surface-4.0.md");

#[test]
fn the_cli_inventory_lists_exactly_the_cli_clap_builds() {
    let w = walker::walk(&mcp_gateway::cli::Cli::command());
    let problems = walker::compare(&w, &walker::doc_rows(DOC));
    assert!(
        problems.is_empty(),
        "docs/design/surface-4.0.md `## Surface: cli` disagrees with clap ({} problems):\n{}",
        problems.len(),
        problems.join("\n")
    );
}
