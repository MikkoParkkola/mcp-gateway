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

    /// Import a SKILL.md file or directory into the local skill registry
    ///
    /// Accepts a path to a `SKILL.md` file, a skill directory (containing
    /// `SKILL.md`), or an `http(s)://` URL.  The parsed skill is added to
    /// the registry (default: `~/.mcp-gateway/skills.json`) so agents can
    /// discover it via `skills search` and inspect it via `skills show`.
    ///
    /// **Security**: imported skills are stored read-only.  No code in the
    /// SKILL.md body is executed — the gateway only surfaces the content
    /// for human/agent inspection.
    #[command(about = "Import a SKILL.md file into the registry")]
    Import {
        /// Path or URL to a SKILL.md file or a directory containing one
        #[arg(required = true)]
        source: String,

        /// Registry file path (defaults to ~/.mcp-gateway/skills.json)
        #[arg(long, env = "MCP_GATEWAY_SKILLS_REGISTRY")]
        registry: Option<PathBuf>,
    },

    /// List all skills in the local registry
    #[command(about = "List imported skills")]
    List {
        /// Registry file path (defaults to ~/.mcp-gateway/skills.json)
        #[arg(long, env = "MCP_GATEWAY_SKILLS_REGISTRY")]
        registry: Option<PathBuf>,
    },

    /// Search imported skills by name, description, keywords, or triggers
    #[command(about = "Search the imported skill registry")]
    Search {
        /// Free-text query (case-insensitive substring match)
        #[arg(required = true)]
        query: String,

        /// Registry file path (defaults to ~/.mcp-gateway/skills.json)
        #[arg(long, env = "MCP_GATEWAY_SKILLS_REGISTRY")]
        registry: Option<PathBuf>,
    },

    /// Show the full content of an imported skill
    #[command(about = "Show a single imported skill by name")]
    Show {
        /// Skill name (as reported by `skills list`)
        #[arg(required = true)]
        name: String,

        /// Registry file path (defaults to ~/.mcp-gateway/skills.json)
        #[arg(long, env = "MCP_GATEWAY_SKILLS_REGISTRY")]
        registry: Option<PathBuf>,
    },

    /// Remove a skill from the registry
    #[command(about = "Remove a skill from the registry")]
    Remove {
        /// Skill name to remove
        #[arg(required = true)]
        name: String,

        /// Registry file path (defaults to ~/.mcp-gateway/skills.json)
        #[arg(long, env = "MCP_GATEWAY_SKILLS_REGISTRY")]
        registry: Option<PathBuf>,
    },
}
