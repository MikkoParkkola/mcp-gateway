// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway setup` subcommands.

use std::path::PathBuf;

use clap::Subcommand;

#[cfg(feature = "config-export")]
use super::{ConnectionMode, ExportTarget};

/// Setup subcommands: interactive import wizard or config export.
#[derive(Subcommand, Debug)]
pub enum SetupCommand {
    /// Interactive setup wizard — scan AI clients and import MCP servers
    ///
    /// Scans Claude Desktop, Claude Code, Cursor, Zed, Continue.dev, Codex and
    /// running processes for existing MCP servers, lets you pick which ones to
    /// import into the gateway config, and optionally writes the gateway entry
    /// back into each AI client so they point at the gateway instead.
    #[command(about = "Interactive setup wizard — import existing MCP servers")]
    Wizard {
        /// Skip all interactive prompts and import every discovered server
        #[arg(long)]
        yes: bool,

        /// Path to write (or update) the gateway configuration file
        #[arg(short, long, default_value = "gateway.yaml")]
        output: PathBuf,

        /// Also write the gateway URL into each detected AI client config
        #[arg(long)]
        configure_client: bool,

        /// Rewrite the whole file when the change cannot keep its comments
        /// (the comments are lost); without it such a write is refused
        #[arg(long)]
        force: bool,
    },

    /// Export gateway.yaml as client-native MCP config files
    ///
    /// Generates JSON config entries for AI clients (Claude Code, Cursor, VS Code
    /// Copilot, Windsurf, Cline, Zed, Claude Desktop) from the single gateway.yaml.
    /// Supports HTTP proxy and stdio subprocess modes with auto-detection.
    ///
    /// # Examples
    ///
    /// ```bash
    /// # Export to all detected clients (auto-detect mode)
    /// mcp-gateway setup export --target all
    ///
    /// # Export only for Claude Code in stdio mode
    /// mcp-gateway setup export --target claude-code --mode stdio
    ///
    /// # Export in proxy mode with custom entry name
    /// mcp-gateway setup export --target all --mode proxy --name my-gateway
    ///
    /// # Watch for config changes and auto-regenerate all client configs
    /// mcp-gateway setup export --target all --watch
    ///
    /// # Dry-run: show what would be written without writing
    /// mcp-gateway setup export --target all --dry-run
    /// ```
    #[cfg(feature = "config-export")]
    #[command(about = "Generate client-specific MCP config files from gateway.yaml")]
    Export {
        /// Target client(s) to export for
        #[arg(short, long, default_value = "all", value_enum)]
        target: ExportTarget,

        /// Connection mode: proxy (HTTP URL), stdio (subprocess), or auto-detect
        #[arg(short, long, default_value = "auto", value_enum)]
        mode: ConnectionMode,

        /// Name for the gateway entry in client configs
        #[arg(short, long, default_value = "gateway")]
        name: String,

        /// Watch gateway.yaml for changes and auto-regenerate all client configs
        #[arg(short, long)]
        watch: bool,

        /// Show what would be written without actually writing anything
        #[arg(long)]
        dry_run: bool,

        /// Restore a client config from a backup created by this command
        #[arg(long, value_name = "BACKUP")]
        rollback: Option<PathBuf>,

        /// Gateway config file to read
        #[arg(short, long, default_value = "gateway.yaml")]
        config: PathBuf,
    },
}
