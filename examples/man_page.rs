// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Writes the man page for the release build: `cargo run --release --example man_page > mcp-gateway.1`. It renders
//! through the same function the man page row checks.

#[path = "../src/cli/man_page_render.rs"]
mod man_page_render;

fn main() {
    use clap::CommandFactory;
    print!(
        "{}",
        man_page_render::render(mcp_gateway::cli::Cli::command())
    );
}
