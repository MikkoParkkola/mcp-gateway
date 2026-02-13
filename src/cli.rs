//! Command-line interface definitions for `mcp-gateway`.
//!
//! Defines the top-level [`Cli`] struct parsed by `clap` and the [`Command`] /
//! [`CapCommand`] subcommand enums that drive the binary.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Universal MCP Gateway - single-port multiplexing for MCP servers and REST APIs
///
/// Aggregates multiple MCP backends and REST capability definitions behind one
/// endpoint.  Meta-MCP mode (default) exposes four dynamic discovery tools so AI
/// clients only load the tools they actually need, saving ~95% of context tokens.
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
    #[arg(long, env = "MCP_GATEWAY_HOST")]
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
    #[arg(long, env = "MCP_GATEWAY_LOG_FORMAT", global = true)]
    pub log_format: Option<String>,

    /// Disable Meta-MCP mode and expose all tools directly
    #[arg(long)]
    pub no_meta_mcp: bool,

    /// Subcommand to run (defaults to server mode when omitted)
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Top-level subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the gateway server (default when no subcommand is given)
    #[command(about = "Start the gateway server")]
    Serve,

    /// Manage capability definitions (validate, test, import, install)
    #[command(subcommand, about = "Capability management commands")]
    Cap(CapCommand),

    /// Generate a starter gateway.yaml with sensible defaults
    #[command(about = "Create a new gateway configuration file")]
    Init {
        /// File path to write the generated configuration to
        #[arg(short, long, default_value = "gateway.yaml")]
        output: PathBuf,

        /// Include example capability definitions and backend stubs
        #[arg(long, default_value = "true")]
        with_examples: bool,
    },

    /// Fetch live statistics from a running gateway instance
    #[command(about = "Show invocation counts, cache hits, and token savings")]
    Stats {
        /// Base URL of the running gateway (without /mcp suffix)
        #[arg(short, long, default_value = "http://127.0.0.1:39400")]
        url: String,

        /// Token price per million (USD) for estimated cost savings
        #[arg(short, long, default_value_t = 15.0)]
        price: f64,
    },
}

/// Capability management subcommands
#[derive(Subcommand, Debug)]
pub enum CapCommand {
    /// Check that a capability YAML file is well-formed and complete
    #[command(about = "Validate a capability definition file")]
    Validate {
        /// Path to the capability YAML file to validate
        #[arg(required = true)]
        file: PathBuf,
    },

    /// Show all capability definitions found in a directory tree
    #[command(about = "List capabilities in a directory")]
    List {
        /// Root directory to scan for capability YAML files
        #[arg(default_value = "capabilities")]
        directory: PathBuf,
    },

    /// Generate capability YAML files from an `OpenAPI` 3.x or Swagger 2.0 spec
    ///
    /// Reads the spec, creates one capability file per operation, and writes
    /// them to the output directory. Supports both YAML and JSON input.
    #[command(about = "Convert an OpenAPI spec into capability definitions")]
    Import {
        /// Path to the `OpenAPI` specification file (YAML or JSON)
        #[arg(required = true)]
        spec: PathBuf,

        /// Directory to write the generated capability files into
        #[arg(short, long, default_value = "capabilities")]
        output: PathBuf,

        /// String prepended to every generated capability name (e.g. "stripe")
        #[arg(short, long)]
        prefix: Option<String>,

        /// Default bearer-token credential reference for all generated capabilities (e.g. `env:API_TOKEN`)
        #[arg(long)]
        auth_key: Option<String>,
    },

    /// Execute a capability once and print the result (useful for debugging)
    #[command(about = "Test a capability by invoking it with sample arguments")]
    Test {
        /// Path to the capability YAML file to execute
        #[arg(required = true)]
        file: PathBuf,

        /// JSON object of arguments to pass to the capability
        #[arg(short, long, default_value = "{}")]
        args: String,
    },

    /// Scan local configs and running processes for MCP servers
    ///
    /// Checks Claude Desktop, VS Code, Cursor, Windsurf, ~/.config/mcp/,
    /// running MCP processes, and `MCP_SERVER_*` environment variables.
    #[command(about = "Auto-discover existing MCP servers on this machine")]
    Discover {
        /// Output format: "table" (human-readable), "json", or "yaml"
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Persist discovered servers into a gateway configuration file
        #[arg(long)]
        write_config: bool,

        /// Path for the generated config (default: mcp-gateway-discovered.yaml)
        #[arg(long)]
        config_path: Option<PathBuf>,
    },

    /// Download a capability from a GitHub repository into the local directory
    #[command(about = "Install a capability from the community registry")]
    Install {
        /// Name of the capability to install (e.g. `stock_quote`)
        #[arg(required = true)]
        name: String,

        /// Fetch from a remote GitHub repository instead of the local directory
        #[arg(long)]
        from_github: bool,

        /// GitHub repository in "owner/repo" format
        #[arg(long, default_value = "MikkoParkkola/mcp-gateway")]
        repo: String,

        /// Git branch to download from
        #[arg(long, default_value = "main")]
        branch: String,

        /// Local directory to save the downloaded capability into
        #[arg(short, long, default_value = "capabilities")]
        output: PathBuf,
    },

    /// Find capabilities by name, description, or tag
    #[command(about = "Search the capability registry")]
    Search {
        /// Text to match against capability names, descriptions, and tags
        #[arg(required = true)]
        query: String,

        /// Root directory containing capability definitions to index
        #[arg(short = 'c', long, default_value = "capabilities")]
        capabilities: PathBuf,
    },

    /// Display every capability in the registry with its description and auth status
    #[command(about = "List all capabilities in the registry")]
    RegistryList {
        /// Root directory containing capability definitions to index
        #[arg(short = 'c', long, default_value = "capabilities")]
        capabilities: PathBuf,
    },
}
