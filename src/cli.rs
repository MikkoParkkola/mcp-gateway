//! Command-line interface

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Universal MCP Gateway - Single-port multiplexing with Meta-MCP
#[derive(Parser, Debug)]
#[command(name = "mcp-gateway")]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Path to configuration file (YAML)
    #[arg(short, long, env = "MCP_GATEWAY_CONFIG", global = true)]
    pub config: Option<PathBuf>,

    /// Port to listen on
    #[arg(short, long, env = "MCP_GATEWAY_PORT")]
    pub port: Option<u16>,

    /// Host to bind to
    #[arg(long, env = "MCP_GATEWAY_HOST")]
    pub host: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(
        long,
        default_value = "info",
        env = "MCP_GATEWAY_LOG_LEVEL",
        global = true
    )]
    pub log_level: String,

    /// Log format (text, json)
    #[arg(long, env = "MCP_GATEWAY_LOG_FORMAT", global = true)]
    pub log_format: Option<String>,

    /// Disable Meta-MCP mode
    #[arg(long)]
    pub no_meta_mcp: bool,

    /// Subcommand (optional - defaults to server mode)
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the gateway server (default)
    Serve,

    /// Capability management commands
    #[command(subcommand)]
    Cap(CapCommand),

    /// Get gateway statistics
    Stats {
        /// Gateway URL
        #[arg(short, long, default_value = "http://127.0.0.1:39400")]
        url: String,

        /// Token price per million for cost calculations
        #[arg(short, long, default_value_t = 15.0)]
        price: f64,
    },
}

/// Capability subcommands
#[derive(Subcommand, Debug)]
pub enum CapCommand {
    /// Validate a capability definition
    Validate {
        /// Path to capability YAML file
        #[arg(required = true)]
        file: PathBuf,
    },

    /// List capabilities in a directory
    List {
        /// Directory containing capability definitions
        #[arg(default_value = "capabilities")]
        directory: PathBuf,
    },

    /// Convert `OpenAPI` spec to capabilities
    Import {
        /// Path to `OpenAPI` spec (YAML or JSON)
        #[arg(required = true)]
        spec: PathBuf,

        /// Output directory for generated capabilities
        #[arg(short, long, default_value = "capabilities")]
        output: PathBuf,

        /// Prefix for generated capability names
        #[arg(short, long)]
        prefix: Option<String>,

        /// Auth key reference (e.g., "`env:API_TOKEN`")
        #[arg(long)]
        auth_key: Option<String>,
    },

    /// Test a capability by executing it
    Test {
        /// Path to capability YAML file
        #[arg(required = true)]
        file: PathBuf,

        /// JSON arguments to pass to the capability
        #[arg(short, long, default_value = "{}")]
        args: String,
    },

    /// Discover existing MCP servers from configs and running processes
    Discover {
        /// Output format (table, json, yaml)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Write discovered servers to gateway config
        #[arg(long)]
        write_config: bool,

        /// Config file path to write to
        #[arg(long)]
        config_path: Option<PathBuf>,
    },

    /// Install a capability from the registry
    Install {
        /// Capability name
        #[arg(required = true)]
        name: String,

        /// Install from GitHub instead of local registry
        #[arg(long)]
        from_github: bool,

        /// GitHub repository (owner/repo)
        #[arg(long, default_value = "MikkoParkkola/mcp-gateway")]
        repo: String,

        /// GitHub branch
        #[arg(long, default_value = "main")]
        branch: String,

        /// Target directory
        #[arg(short, long, default_value = "capabilities")]
        output: PathBuf,
    },

    /// Search available capabilities in registry
    Search {
        /// Search query
        #[arg(required = true)]
        query: String,

        /// Capabilities directory path
        #[arg(short = 'c', long, default_value = "capabilities")]
        capabilities: PathBuf,
    },

    /// List all available capabilities in registry
    RegistryList {
        /// Capabilities directory path
        #[arg(short = 'c', long, default_value = "capabilities")]
        capabilities: PathBuf,
    },
}
