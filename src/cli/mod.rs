// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Command-line interface definitions for `mcp-gateway`.
//!
//! Defines the top-level [`Cli`] struct parsed by `clap` and the [`Command`] /
//! [`CapCommand`] / [`ToolCommand`] / [`TlsCommand`] subcommand enums.
//!
//! # CLI Bridge
//!
//! The `tool` subcommand exposes every registered capability tool as a
//! composable shell command:
//!
//! ```bash
//! # Invoke any tool directly
//! mcp-gateway tool invoke weather_current location=London
//!
//! # Pipe JSON args from stdin
//! echo '{"location":"Helsinki"}' | mcp-gateway tool invoke weather_current
//!
//! # List available tools
//! mcp-gateway tool list --format table
//!
//! # Inspect a tool's schema
//! mcp-gateway tool inspect yahoo_stock_quote
//!
//! # Generate shell completions
//! mcp-gateway tool completions zsh > ~/.zsh/completions/_mcp-gateway
//! ```

pub mod api;
pub mod audit_lookup;
mod command;
/// The leaf commands' output classes and the remote leaves on the shared error shape, enforced by its rows.
#[cfg(test)]
mod command_classes;
pub mod completion;
pub mod dashboard_link;
pub(crate) mod entry;
pub mod events;
pub mod identity;
pub mod invoke;
pub mod output;
pub mod redact;
mod setup;
pub mod skills;
pub(crate) mod stdout;
pub mod subcommands;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::cli::output::OutputFormat;

pub(crate) use command::Command;
pub use entry::run;
pub use identity::{IdentityCommand, IdentityGrantScopeArg, IdentityGrantsCommand};
pub use setup::SetupCommand;
pub use skills::SkillsCommand;
pub use subcommands::{
    AuditCommand, CapCommand, KubernetesCommand, ProtocolImportCommand, ProtocolImportKind,
    ProvenanceCommand, RankingCommand, RuntimeProviderArg, TlsCommand, TrustCommand,
    TrustLabCommand,
};

// ── Config-export CLI types ───────────────────────────────────────────────────
// Shared by the CLI parser and `commands/config_export.rs`.

/// Connection mode for the exported client config entry.
#[cfg(feature = "config-export")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConnectionMode {
    /// HTTP proxy mode: client connects to the running gateway's HTTP endpoint.
    Proxy,
    /// Stdio mode: client spawns `mcp-gateway serve --stdio` as a subprocess.
    Stdio,
    /// Auto-detect: probe the health endpoint first; fall back to stdio, then proxy.
    Auto,
}

/// Target AI client for config export.
#[cfg(feature = "config-export")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportTarget {
    /// Claude Code (`~/.claude.json`)
    ClaudeCode,
    /// Claude Desktop (platform-specific path)
    ClaudeDesktop,
    /// Cursor (`.cursor/mcp.json`, workspace-relative)
    Cursor,
    /// VS Code Copilot (`.vscode/mcp.json`, workspace-relative)
    VsCodeCopilot,
    /// Windsurf (`~/.codeium/windsurf/mcp_config.json`)
    Windsurf,
    /// Cline (`.cline/mcp_servers.json`, workspace-relative)
    Cline,
    /// Zed (platform-specific: Zed's own config directory)
    Zed,
    /// Generic: write to stdout
    Generic,
    /// All supported clients
    All,
}

/// Starter configuration profile for `mcp-gateway init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InitProfile {
    /// Self-contained local developer setup with zero-key sample capabilities.
    Local,
    /// Minimal skeleton config for operators who want to add everything manually.
    Minimal,
}

impl std::fmt::Display for InitProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Local => "local",
            Self::Minimal => "minimal",
        })
    }
}

/// Universal MCP Gateway - single-port multiplexing for MCP servers and REST APIs
///
/// Aggregates multiple MCP backends and REST capability definitions behind one
/// endpoint. Meta-MCP mode (default) exposes a compact discovery + operations
/// surface so AI clients only load the tools they actually need instead of
/// preloading every backend schema into the prompt.
///
/// Run without a subcommand to start the gateway server.
#[derive(Parser, Debug)]
#[command(name = "mcp-gateway")]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Path to the gateway configuration file (YAML)
    #[arg(short, long, env = "MCP_GATEWAY_CONFIG", global = true)]
    pub config: Option<PathBuf>,

    /// Port the gateway listens on (overrides config file)
    #[arg(short, long, env = "MCP_GATEWAY_PORT")]
    pub port: Option<u16>,

    /// Host address to bind to (overrides config file)
    #[arg(hide = true, long, env = "MCP_GATEWAY_HOST")]
    pub host: Option<String>,

    /// Minimum log level: trace, debug, info, warn, or error
    #[arg(
        long,
        default_value = "info",
        env = "MCP_GATEWAY_LOG_LEVEL",
        global = true
    )]
    pub log_level: String,

    /// Log output format: "text" for human-readable, "json" for structured
    #[arg(hide = true, long, env = "MCP_GATEWAY_LOG_FORMAT", global = true)]
    pub log_format: Option<String>,

    /// Disable Meta-MCP mode and expose all tools directly
    #[arg(hide = true, long)]
    pub no_meta_mcp: bool,

    /// RFC-0060 U1 measurement window (`record` turns it on). The operator's
    /// instrument for their own deployment, so hidden from `--help`
    /// (MIK-8783); it replaces the retired `server.protocol_revision_window`.
    #[arg(
        long,
        hide = true,
        value_enum,
        env = "MCP_GATEWAY_PROTOCOL_REVISION_WINDOW"
    )]
    pub protocol_revision_window: Option<crate::config::ProtocolRevisionWindow>,

    /// Subcommand to run (defaults to server mode when omitted)
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

/// Offline administration of the personal-account custody store.
///
/// Every subcommand here is offline and explicit: nothing starts the gateway,
/// the custody worker or an HTTP client, and no account record is read, written
/// or migrated. The configuration is selected with the global `--config PATH`
/// rather than a second `--config` of this subcommand's own, so the path the
/// store is initialized from is the same path `serve` would later open; a
/// duplicate flag could name one file here and another there.
#[derive(Subcommand, Debug)]
pub enum AccountsCommand {
    /// Create a fresh empty account authority for the configured roots.
    ///
    /// Requires `accounts` in the selected config, requires both configured
    /// roots to be empty, and refuses rather than replacing, merging or
    /// migrating existing custody state. The store it creates has zero records
    /// by construction.
    #[command(
        name = "init-store",
        about = "Create an empty personal-account store from --config (offline)"
    )]
    InitStore,
    /// Migrate one 3.x OAuth credential into the per-principal store.
    ///
    /// Offline and explicit. It opens an EXISTING store and never creates one,
    /// reads one 3.x credential file, and performs one guarded write. The 3.x
    /// file is never modified, renamed or deleted, so a refusal leaves the
    /// deployment exactly where it started.
    ///
    /// Arguments rather than a config block on purpose: a migration runs once,
    /// and a config block for a one-time operation is a standing instruction
    /// for something that has already happened.
    #[command(
        name = "migrate-credentials",
        about = "Migrate one 3.x OAuth credential into the account store (offline)"
    )]
    MigrateCredentials {
        /// The `accounts.descriptors` map key to migrate into.
        #[arg(long = "descriptor-id", value_name = "ID")]
        descriptor_id: String,
        /// The authorization server that issued the 3.x credential.
        ///
        /// Asserted, never defaulted from the descriptor: a 3.x record carries
        /// no issuer, and silently adopting the destination's would re-home a
        /// credential to a server that never issued it. It must equal the
        /// descriptor's issuer, or the credential belongs elsewhere and the
        /// answer is re-authorization rather than migration.
        #[arg(long = "legacy-issuer", value_name = "URL")]
        legacy_issuer: String,
        /// The 3.x backend registry name, if this backend was renamed since.
        ///
        /// Derived from the descriptor id when absent. Only a rename needs it:
        /// the 3.x file is hashed over the name the backend had then, and
        /// nothing in the tree records a former name.
        #[arg(long = "legacy-backend-name", value_name = "NAME")]
        legacy_backend_name: Option<String>,
    },
}

/// Runtime-substrate subcommands (feature `runtime-substrate`).
#[cfg(feature = "runtime-substrate")]
#[derive(Subcommand, Debug)]
pub enum RuntimeCommand {
    /// Compile a sandbox descriptor to its substrate bundle (gVisor OCI or
    /// Apple VM-spec), running schema + security preflight first.
    #[command(about = "Compile a sandbox descriptor (YAML/JSON) to a substrate bundle")]
    Compile {
        /// Path to the descriptor file (YAML or JSON).
        #[arg(value_name = "DESCRIPTOR")]
        descriptor: std::path::PathBuf,

        /// Compile for BOTH substrates and report cross-substrate divergence.
        #[arg(long, default_value_t = false)]
        both: bool,
    },
}

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
    #[command(about = "Call a tool with JSON arguments")]
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
    #[command(about = "List tools from a local capability catalogue")]
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
    #[command(about = "Show a tool's input schema")]
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
    #[command(about = "Generate shell completions")]
    Completions {
        /// Target shell
        #[arg(required = true, value_enum)]
        shell: Shell,

        /// Directory containing capability YAML definitions
        #[arg(short = 'C', hide = true, long, env = "MCP_GATEWAY_CAPABILITIES")]
        capabilities: Option<PathBuf>,
    },
}
