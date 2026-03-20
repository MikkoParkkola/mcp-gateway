//! CLI definition for `mcp-gateway skills generate`.
//!
//! Generates agent skill bundles from loaded capability YAML files and
//! optionally installs them into standard agent discovery paths.
//!
//! # Examples
//!
//! ```bash
//! # Generate all capabilities into ./skills/
//! mcp-gateway skills generate
//!
//! # Only capabilities for the "linear" backend
//! mcp-gateway skills generate --server linear
//!
//! # Only the "productivity" category
//! mcp-gateway skills generate --category productivity
//!
//! # Custom output directory + auto-install into agent paths
//! mcp-gateway skills generate --out-dir /tmp/skills --install
//! ```

use std::path::PathBuf;

use clap::Subcommand;

/// Skills management subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum SkillsCommand {
    /// Generate agent skill bundles from loaded capability definitions
    ///
    /// Reads all YAML capabilities from the capabilities directory (or the path
    /// configured in `gateway.yaml`) and renders them as Markdown skill bundles
    /// that AI agents can load with the `loadSkill` convention.
    ///
    /// # Output layout
    ///
    /// ```text
    /// <out-dir>/
    ///   mcp-gateway-<category>/
    ///     SKILL.md                ← category index (YAML front-matter + table)
    ///     commands/<name>.md      ← per-capability reference
    ///     crust.json              ← ownership marker
    /// ```
    #[command(about = "Generate agent skill bundles from capability definitions")]
    Generate {
        /// Capabilities directory to load from
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

        /// Only generate skills for capabilities whose name starts with this prefix
        /// (useful when multiple backends share the same capabilities directory)
        #[arg(long)]
        server: Option<String>,

        /// Only generate skills for capabilities in this category
        #[arg(long)]
        category: Option<String>,

        /// Output directory for generated skill bundles
        #[arg(long, default_value = "skills")]
        out_dir: PathBuf,

        /// Also install (symlink) generated skills into standard agent paths:
        /// .agents/skills/ and .claude/skills/ (relative to the current directory)
        #[arg(long)]
        install: bool,

        /// Print what would be generated without writing any files
        #[arg(long)]
        dry_run: bool,
    },
}
