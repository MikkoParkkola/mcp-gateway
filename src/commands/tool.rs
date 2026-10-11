// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway tool` subcommands (CLI bridge for direct tool invocation).
//!
//! The catalogue is the gateway's own: the loaded config's
//! `capabilities.directories`, unless `-C` or `MCP_GATEWAY_CAPABILITIES`
//! names a directory (MIK-8044, `super::capability_dirs`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mcp_gateway::cli::{
    ToolCommand,
    completion::{ShellTarget, generate_completion},
    invoke::{ToolCatalogue, execute_tool, resolve_args},
    output::{OutputFormat, print_tool_inspect, print_tool_list, print_tool_result},
};

use super::capability_dirs::{self, CapabilityDirs, NONE_FOUND};

pub async fn run_tool_command(cmd: ToolCommand, config: Option<&Path>) -> ExitCode {
    match cmd {
        ToolCommand::List {
            capabilities,
            format,
        } => tool_list(capabilities, config, format).await,
        ToolCommand::Inspect {
            tool,
            capabilities,
            format,
        } => tool_inspect(tool, capabilities, config, format).await,
        ToolCommand::Invoke {
            tool,
            capabilities,
            args,
            kv_args,
            format,
        } => tool_invoke(tool, capabilities, config, args, kv_args, format).await,
        ToolCommand::Completions {
            shell,
            capabilities,
        } => tool_completions(shell, capabilities, config).await,
    }
}

/// The catalogue the command reads, or the error already printed.
async fn catalogue(
    capabilities: Option<PathBuf>,
    config: Option<&Path>,
) -> Result<(ToolCatalogue, CapabilityDirs), ExitCode> {
    let dirs = capability_dirs::resolve(capabilities, config).map_err(|e| {
        eprintln!("Error: {e}");
        ExitCode::FAILURE
    })?;
    let cat = capability_dirs::load(&dirs).await.map_err(|e| {
        eprintln!("Error: {e}");
        ExitCode::FAILURE
    })?;
    Ok((cat, dirs))
}

/// Whether a catalogue read from the configured directories came back empty;
/// says so on stderr.
fn none_found(cat: &ToolCatalogue, dirs: &CapabilityDirs) -> bool {
    let empty = cat.all().is_empty() && matches!(dirs, CapabilityDirs::Configured(_));
    if empty {
        eprintln!("{NONE_FOUND}.");
    }
    empty
}

async fn tool_list(
    capabilities: Option<PathBuf>,
    config: Option<&Path>,
    format: OutputFormat,
) -> ExitCode {
    // A named directory that is absent reports an empty catalogue with one
    // line of explanation rather than failing (#225).
    if let Some(dir) = capabilities.as_ref().filter(|d| !d.exists()) {
        eprintln!(
            "No capability catalogue at '{}'. `tool list` scans the directory named by \
             -C/--capabilities or MCP_GATEWAY_CAPABILITIES; without either it reads the \
             gateway config's `capabilities.directories`.",
            dir.display()
        );
        print_tool_list(&[], format);
        return ExitCode::SUCCESS;
    }
    match catalogue(capabilities, config).await {
        Ok((cat, dirs)) => {
            none_found(&cat, &dirs);
            print_tool_list(&cat.list_entries(), format);
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

async fn tool_inspect(
    tool: String,
    capabilities: Option<PathBuf>,
    config: Option<&Path>,
    format: OutputFormat,
) -> ExitCode {
    let (cat, dirs) = match catalogue(capabilities, config).await {
        Ok(found) => found,
        Err(code) => return code,
    };
    if none_found(&cat, &dirs) {
        return ExitCode::FAILURE;
    }
    if let Some(cap) = cat.find(&tool) {
        print_tool_inspect(&cap.name, &cap.description, &cap.schema.input, format);
        ExitCode::SUCCESS
    } else {
        eprintln!("Error: Tool '{tool}' not found. Run 'tool list' to see available tools.");
        ExitCode::FAILURE
    }
}

async fn tool_invoke(
    tool: String,
    capabilities: Option<PathBuf>,
    config: Option<&Path>,
    args: Option<String>,
    kv_args: Vec<String>,
    format: OutputFormat,
) -> ExitCode {
    let (catalogue, dirs) = match catalogue(capabilities, config).await {
        Ok(found) => found,
        Err(code) => return code,
    };
    if none_found(&catalogue, &dirs) {
        return ExitCode::FAILURE;
    }
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
    capabilities: Option<PathBuf>,
    config: Option<&Path>,
) -> ExitCode {
    // A catalogue that cannot be read still yields a completion script, as
    // before, just without tool names.
    let tool_names: Vec<String> = match catalogue(capabilities, config).await {
        Ok((cat, _)) => cat.all().iter().map(|c| c.name.clone()).collect(),
        Err(_) => Vec::new(),
    };
    let target = ShellTarget::from_shell(shell).unwrap_or(ShellTarget::Bash);
    let script = generate_completion(target, &tool_names);
    print!("{script}");
    ExitCode::SUCCESS
}
