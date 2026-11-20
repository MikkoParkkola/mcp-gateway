// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::path::PathBuf;

use clap::Subcommand;

use crate::cli::completion::CompletionShell;
use crate::cli::output::OutputFormat;

/// Tool CLI subcommands
///
/// All subcommands support `--format json|table|plain` for pipe-friendly output.
#[derive(Subcommand, Debug)]
pub enum ToolCommand {
    /// Call a registered tool with JSON arguments
    ///
    /// Arguments can be supplied as:
    /// - Individual `key=value` pairs: `invoke weather_current location=London`
    /// - JSON piped on stdin: `echo '{"location":"London"}' | mcp-gateway tool invoke weather_current`
    ///
    /// Multiple sources are merged; command-line keys override stdin.
    #[command(
        about = "Call a tool with JSON arguments",
        after_help = "Examples:\n  mcp-gateway tool invoke weather_current location=Oulu\n"
    )]
    Invoke {
        /// Tool name to invoke
        #[arg(required = true)]
        tool: String,

        /// Directory containing capability YAML definitions
        #[arg(short = 'C', hide = true, long, env = "MCP_GATEWAY_CAPABILITIES")]
        capabilities: Option<PathBuf>,

        /// JSON argument blob (merged with key=value pairs)
        #[arg(hide = true, short, long)]
        args: Option<String>,

        /// Additional key=value argument pairs (may be repeated)
        ///
        /// Values that look like JSON scalars (numbers, booleans, null,
        /// arrays, objects) are parsed as JSON; everything else is a string.
        #[arg(value_name = "KEY=VALUE")]
        kv_args: Vec<String>,

        /// Output format
        #[arg(short, long, default_value = "json", value_enum)]
        format: OutputFormat,
    },

    /// List tools from a local capability catalogue
    ///
    /// Reads the capability YAML files of the directories your gateway serves
    /// (the config's `capabilities.directories`; `./capabilities` with no
    /// config) and prints each tool with its description and authentication
    /// requirement. `-C` or `MCP_GATEWAY_CAPABILITIES` names another
    /// directory. `capabilities.enabled` does not change what is read.
    #[command(
        about = "List tools from a local capability catalogue",
        after_help = "Examples:\n  mcp-gateway tool list\n"
    )]
    List {
        /// Directory containing capability YAML definitions
        #[arg(short = 'C', hide = true, long, env = "MCP_GATEWAY_CAPABILITIES")]
        capabilities: Option<PathBuf>,

        /// Output format
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Show the input schema for a specific tool
    ///
    /// Prints the tool's description and its JSON Schema input definition,
    /// useful for discovering required/optional parameters before invoking.
    #[command(
        about = "Show a tool's input schema",
        after_help = "Examples:\n  mcp-gateway tool inspect weather_current\n"
    )]
    Inspect {
        /// Tool name to inspect
        #[arg(required = true)]
        tool: String,

        /// Directory containing capability YAML definitions
        #[arg(short = 'C', hide = true, long, env = "MCP_GATEWAY_CAPABILITIES")]
        capabilities: Option<PathBuf>,

        /// Output format
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Generate shell tab-completion scripts
    ///
    /// Outputs a completion script for the requested shell.  Tool names from
    /// the local capabilities directory are injected as completions for the
    /// `invoke` and `inspect` subcommands.
    ///
    /// # Install
    ///
    ///   mcp-gateway tool completions zsh > ~/.zsh/completions/_mcp-gateway
    ///   mcp-gateway tool completions bash >> ~/.bashrc
    ///   mcp-gateway tool completions fish > ~/.config/fish/completions/mcp-gateway.fish
    #[command(
        about = "Generate shell completions",
        after_help = "Examples:\n  mcp-gateway tool completions zsh\n"
    )]
    Completions {
        /// Target shell
        #[arg(required = true, value_enum)]
        shell: CompletionShell,

        /// Directory containing capability YAML definitions
        #[arg(short = 'C', hide = true, long, env = "MCP_GATEWAY_CAPABILITIES")]
        capabilities: Option<PathBuf>,
    },
}
