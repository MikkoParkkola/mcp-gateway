// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MCP Gateway - Universal Model Context Protocol Gateway

#[macro_use]
mod mutant_macro;
mod mutant;
mod allocator;
mod main_stack;
mod parse_errors;

use std::process::ExitCode;

use clap::Parser;
use mcp_gateway::cli::{self, Cli};

use main_stack::on_main_stack;

fn main() -> ExitCode {
    // The preview sandbox's helpers run before the CLI parser, the main-stack
    // thread and any runtime: they change their own privileges, which must
    // happen while the process has one thread (ADR-027).
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if let Some(code) = mcp_gateway::preview_sandbox::dispatch_helper(&args) {
        return code;
    }
    on_main_stack(move || {
        // Parsing needs the main stack, especially on Windows debug builds.
        let cli = Cli::try_parse_from(&args)
            .unwrap_or_else(|error| parse_errors::quiet_for_secret_commands(&args, error).exit());
        cli::run(cli)
    })
}

#[cfg(test)]
#[path = "main_stack_tests.rs"]
mod main_stack_tests;
