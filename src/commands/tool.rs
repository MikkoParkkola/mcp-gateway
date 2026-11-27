// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway tool` subcommands (CLI bridge for direct tool invocation).
//!
//! The catalogue is the gateway's own: the loaded config's
//! `capabilities.directories`, unless `-C` or `MCP_GATEWAY_CAPABILITIES`
//! names a directory (MIK-8044, `super::capability_dirs`).

use crate::cli::stdout::print;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mcp_gateway::cli::{
    ToolCommand,
    completion::{ShellTarget, generate_completion},
    invoke::{ToolCatalogue, execute_tool, resolve_args},
    output::{OutputFormat, print_tool_inspect, print_tool_list, print_tool_result},
};

use super::capability_dirs::{self, CapabilityDirs, NONE_FOUND};
use super::{CliExit, fail, usage};

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
    let dirs = capability_dirs::resolve(capabilities, config).map_err(|e| e.exit())?;
    let cat = capability_dirs::load(&dirs).await.map_err(|e| e.exit())?;
    Ok((cat, dirs))
}

/// Whether a catalogue read from the configured directories came back empty.
fn none_found(cat: &ToolCatalogue, dirs: &CapabilityDirs) -> bool {
    cat.all().is_empty() && matches!(dirs, CapabilityDirs::Configured(_))
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
            if none_found(&cat, &dirs) {
                eprintln!("{NONE_FOUND}.");
            }
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
        return capability_dirs::none_found_failure();
    }
    if let Some(cap) = cat.find(&tool) {
        print_tool_inspect(&cap.name, &cap.description, &cap.schema.input, format);
        ExitCode::SUCCESS
    } else {
        fail(
            CliExit::LocalFailure,
            &format!("Tool '{tool}' not found"),
            "Run 'mcp-gateway tool list' to see the available tools.",
        )
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
        return capability_dirs::none_found_failure();
    }
    // `--args` that is not JSON is a wrong invocation (exit 2); stdin that is not JSON and a malformed `key=value`
    // stay failures of the input (exit 1).
    if let Some(Err(e)) = args
        .as_deref()
        .map(serde_json::from_str::<serde_json::Value>)
    {
        return usage("tool invoke", &format!("--args is not valid JSON: {e}"));
    }
    // `key=value` text is typed by the tool's own input schema (MIK-7943).
    let kv_schema = catalogue.find(&tool).map(|cap| &cap.schema.input);
    let resolved = match resolve_args(args.as_deref(), &kv_args, true, kv_schema) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                CliExit::LocalFailure,
                &e.to_string(),
                "Pass the arguments as JSON on stdin, a JSON --args, or key=value pairs.",
            );
        }
    };
    match execute_tool(&catalogue, &tool, resolved).await {
        Ok(result) => {
            print_tool_result(&result, format);
            ExitCode::SUCCESS
        }
        Err(e) => fail(
            CliExit::LocalFailure,
            &e.to_string(),
            "Run 'mcp-gateway tool inspect' on the tool to see what it takes, then rerun.",
        ),
    }
}

async fn tool_completions(
    shell: clap_complete::Shell,
    capabilities: Option<PathBuf>,
    config: Option<&Path>,
) -> ExitCode {
    // A config that will not load stops completions as it stops the other
    // commands. A `-C` directory that cannot be read still yields a script,
    // as before, just without tool names.
    let dirs = match capability_dirs::resolve(capabilities, config) {
        Ok(dirs) => dirs,
        Err(e) => return e.exit(),
    };
    let tool_names: Vec<String> = match capability_dirs::load(&dirs).await {
        Ok(cat) => cat.all().iter().map(|c| c.name.clone()).collect(),
        Err(_) => Vec::new(),
    };
    let target = ShellTarget::from_shell(shell).unwrap_or(ShellTarget::Bash);
    let script = generate_completion(target, &tool_names);
    print!("{script}");
    ExitCode::SUCCESS
}
