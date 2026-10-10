// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway tool` subcommands (CLI bridge for direct tool invocation).

use std::process::ExitCode;

use mcp_gateway::cli::{
    ToolCommand,
    completion::{ShellTarget, generate_completion},
    invoke::{ToolCatalogue, build_completion_tool_names, execute_tool, resolve_args},
    output::{OutputFormat, print_tool_inspect, print_tool_list, print_tool_result},
};

/// Run `mcp-gateway tool` subcommands (CLI bridge for direct tool invocation).
pub async fn run_tool_command(cmd: ToolCommand) -> ExitCode {
    match cmd {
        ToolCommand::List {
            capabilities,
            format,
        } => tool_list(capabilities, format).await,
        ToolCommand::Inspect {
            tool,
            capabilities,
            format,
        } => tool_inspect(tool, capabilities, format).await,
        ToolCommand::Invoke {
            tool,
            capabilities,
            args,
            kv_args,
            format,
        } => tool_invoke(tool, capabilities, args, kv_args, format).await,
        ToolCommand::Completions {
            shell,
            capabilities,
        } => tool_completions(shell, capabilities).await,
    }
}

async fn tool_list(capabilities: std::path::PathBuf, format: OutputFormat) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    // `tool list` scans a *local* capability-YAML directory. It is independent
    // of the running gateway's `-c gateway.yaml` config (including
    // `capabilities.enabled`), which controls the server, not this CLI scan.
    // When the directory is absent, report an empty catalogue with a one-line
    // explanation rather than hard-failing (see issue #225); the `discover`
    // path already degrades this way for the same condition.
    if !capabilities.exists() {
        eprintln!(
            "No capability catalogue at '{dir}'. `tool list` scans a local directory of \
             capability YAML files (set -C/--capabilities or MCP_GATEWAY_CAPABILITIES) and is \
             independent of your server config. A configured gateway exposes its tools over MCP \
             at runtime, not via this command."
        );
        print_tool_list(&[], format);
        return ExitCode::SUCCESS;
    }
    match ToolCatalogue::load(&dir).await {
        Ok(cat) => {
            print_tool_list(&cat.list_entries(), format);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: Failed to load capabilities from '{dir}': {e}");
            ExitCode::FAILURE
        }
    }
}

async fn tool_inspect(
    tool: String,
    capabilities: std::path::PathBuf,
    format: OutputFormat,
) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    match ToolCatalogue::load(&dir).await {
        Ok(cat) => {
            if let Some(cap) = cat.find(&tool) {
                print_tool_inspect(&cap.name, &cap.description, &cap.schema.input, format);
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "Error: Tool '{tool}' not found. Run 'tool list' to see available tools."
                );
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("Error: Failed to load capabilities from '{dir}': {e}");
            ExitCode::FAILURE
        }
    }
}

async fn tool_invoke(
    tool: String,
    capabilities: std::path::PathBuf,
    args: Option<String>,
    kv_args: Vec<String>,
    format: OutputFormat,
) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    let catalogue = match ToolCatalogue::load(&dir).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load capabilities from '{dir}': {e}");
            return ExitCode::FAILURE;
        }
    };
    // `key=value` text is typed by the tool's own input schema (MIK-7943).
    let kv_schema = catalogue.find(&tool).map(|cap| &cap.schema.input);
    let resolved = match resolve_args(args.as_deref(), &kv_args, true, kv_schema) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match execute_tool(&catalogue, &tool, resolved).await {
        Ok(result) => {
            print_tool_result(&result, format);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn tool_completions(
    shell: clap_complete::Shell,
    capabilities: std::path::PathBuf,
) -> ExitCode {
    let dir = capabilities.to_string_lossy();
    let tool_names = build_completion_tool_names(&dir).await;
    let target = ShellTarget::from_shell(shell).unwrap_or(ShellTarget::Bash);
    let script = generate_completion(target, &tool_names);
    print!("{script}");
    ExitCode::SUCCESS
}
