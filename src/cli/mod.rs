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

pub mod completion;
pub mod invoke;
pub mod output;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

use crate::cli::output::OutputFormat;

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

    /// Manage TLS certificates for mTLS authenticated tool access (RFC-0051)
    #[command(
        subcommand,
        about = "Certificate lifecycle management (init-ca, issue-server, issue-client)"
    )]
    Tls(TlsCommand),

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

    /// Lint capability YAMLs against agent-UX best practices
    ///
    /// Validates one or more capability files (or directories) against the
    /// full agent-UX rules engine (AX-001..AX-009) and reports issues with
    /// colored output. Supports JSON, SARIF, and auto-fix modes.
    #[command(about = "Validate capability definitions against agent-UX rules")]
    Validate {
        /// Files or directories to validate (YAML capabilities)
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Output format
        #[arg(short, long, default_value = "text", value_enum)]
        format: crate::validator::OutputFormat,

        /// Minimum severity to report
        #[arg(short, long, default_value = "info", value_enum)]
        severity: crate::validator::SeverityFilter,

        /// Auto-fix issues where possible (rewrites YAML in place)
        #[arg(long)]
        fix: bool,

        /// Disable colored output
        #[arg(long)]
        no_color: bool,
    },

    /// Invoke gateway tools directly from the shell without a running server
    ///
    /// Loads capabilities from the configured directory and exposes them as
    /// composable CLI commands.  Supports JSON args from stdin for piping:
    ///
    ///   `echo '{"location":"London"}' | mcp-gateway tool invoke weather_current`
    #[command(subcommand, about = "Invoke gateway tools directly from the CLI")]
    Tool(ToolCommand),

    /// Manage gateway plugins from the marketplace
    ///
    /// Search, install, uninstall, and list gateway plugins sourced from the
    /// remote plugin marketplace.
    #[command(subcommand, about = "Plugin marketplace management")]
    Plugin(PluginCommand),

    /// Interactive setup wizard — scan AI clients and import MCP servers
    ///
    /// Scans Claude Desktop, Claude Code, Cursor, Zed, Continue.dev, Codex and
    /// running processes for existing MCP servers, lets you pick which ones to
    /// import into the gateway config, and optionally writes the gateway entry
    /// back into each AI client so they point at the gateway instead.
    #[command(about = "Interactive setup wizard — import existing MCP servers")]
    Setup {
        /// Skip all interactive prompts and import every discovered server
        #[arg(long)]
        yes: bool,

        /// Path to write (or update) the gateway configuration file
        #[arg(short, long, default_value = "gateway.yaml")]
        output: PathBuf,

        /// Also write the gateway URL into each detected AI client config
        #[arg(long)]
        configure_client: bool,
    },

    /// Add an MCP backend to the gateway configuration
    ///
    /// If `name` matches a known server in the built-in registry the command
    /// uses its default `npx` command and env-var template — no flags needed.
    /// Pass `--command` or `--url` to add a completely custom server.
    #[command(about = "Add an MCP backend to gateway.yaml")]
    Add {
        /// Name for the new backend (used as the config key and registry lookup)
        name: String,

        /// Shell command to launch the server (stdio transport)
        #[arg(long)]
        command: Option<String>,

        /// HTTP URL for the server (HTTP/SSE transport)
        #[arg(long)]
        url: Option<String>,

        /// Human-readable description (defaults to registry description when available)
        #[arg(long)]
        description: Option<String>,

        /// Environment variable to inject, may be repeated (KEY=VALUE)
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env_vars: Vec<String>,

        /// Gateway config file to modify
        #[arg(short, long, default_value = "gateway.yaml")]
        config: PathBuf,
    },

    /// Remove an MCP backend from the gateway configuration
    #[command(about = "Remove an MCP backend from gateway.yaml")]
    Remove {
        /// Name of the backend to remove
        name: String,

        /// Gateway config file to modify
        #[arg(short, long, default_value = "gateway.yaml")]
        config: PathBuf,
    },

    /// Diagnose gateway and backend health
    ///
    /// Checks configuration, port availability, required env vars, HTTP
    /// reachability for HTTP backends, and whether any AI client is already
    /// pointed at the gateway.
    #[command(about = "Check gateway configuration and backend health")]
    Doctor {
        /// Attempt to auto-fix issues where possible (e.g. create missing dirs)
        #[arg(long)]
        fix: bool,

        /// Gateway config file to inspect (auto-detected when omitted)
        #[arg(short, long)]
        config: Option<PathBuf>,
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
    /// - A JSON blob via `--args '{"key": "value"}'`
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
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

        /// JSON argument blob (merged with key=value pairs)
        #[arg(short, long)]
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

    /// List all available tools with descriptions
    ///
    /// Scans the capabilities directory and prints each tool with its
    /// description and authentication requirement.
    #[command(about = "List all available tools")]
    List {
        /// Directory containing capability YAML definitions
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

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
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

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
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,
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

/// Plugin marketplace subcommands
///
/// Manages gateway plugins sourced from the remote marketplace at
/// `https://plugins.mcpgateway.io` (configurable via `marketplace.marketplace_url`).
///
/// # Examples
///
/// ```bash
/// # Search for Stripe-related plugins
/// mcp-gateway plugin search stripe
///
/// # Install a plugin
/// mcp-gateway plugin install stripe-payments
///
/// # List installed plugins
/// mcp-gateway plugin list
///
/// # Remove a plugin
/// mcp-gateway plugin uninstall stripe-payments
/// ```
#[derive(Subcommand, Debug)]
pub enum PluginCommand {
    /// Search the marketplace for plugins matching a query
    ///
    /// Queries the remote marketplace and prints matching plugin names,
    /// versions, and descriptions.
    #[command(about = "Search the plugin marketplace")]
    Search {
        /// Text to search for (matched against name, description, and tags)
        #[arg(required = true)]
        query: String,

        /// Marketplace base URL (overrides config `marketplace.marketplace_url`)
        #[arg(long, env = "MCP_GATEWAY_MARKETPLACE_URL")]
        marketplace_url: Option<String>,
    },

    /// Download and install a plugin from the marketplace
    ///
    /// Downloads the plugin manifest, verifies its SHA-256 checksum, and
    /// installs it into the local plugin directory.
    #[command(about = "Install a plugin from the marketplace")]
    Install {
        /// Plugin name to install (as listed by `plugin search`)
        #[arg(required = true)]
        name: String,

        /// Marketplace base URL (overrides config `marketplace.marketplace_url`)
        #[arg(long, env = "MCP_GATEWAY_MARKETPLACE_URL")]
        marketplace_url: Option<String>,

        /// Local directory to install plugins into (overrides config `marketplace.plugin_dir`)
        #[arg(long, env = "MCP_GATEWAY_PLUGIN_DIR")]
        plugin_dir: Option<std::path::PathBuf>,
    },

    /// Remove an installed plugin
    ///
    /// Deletes the plugin directory and removes it from the local registry.
    #[command(about = "Uninstall a plugin")]
    Uninstall {
        /// Plugin name to remove
        #[arg(required = true)]
        name: String,

        /// Local plugin directory (overrides config `marketplace.plugin_dir`)
        #[arg(long, env = "MCP_GATEWAY_PLUGIN_DIR")]
        plugin_dir: Option<std::path::PathBuf>,
    },

    /// List all locally installed plugins
    ///
    /// Scans the plugin directory and prints every installed plugin with its
    /// version and install path.
    #[command(about = "List installed plugins")]
    List {
        /// Local plugin directory (overrides config `marketplace.plugin_dir`)
        #[arg(long, env = "MCP_GATEWAY_PLUGIN_DIR")]
        plugin_dir: Option<std::path::PathBuf>,
    },
}

/// TLS certificate lifecycle subcommands (RFC-0051)
#[derive(Subcommand, Debug)]
pub enum TlsCommand {
    /// Generate a self-signed Root CA certificate and private key.
    ///
    /// Store the CA key offline (or in a vault). Use the CA cert as the
    /// `ca_cert` path in `gateway.yaml`.
    #[command(about = "Generate a Root CA certificate and key")]
    InitCa {
        /// Common Name for the CA certificate (e.g. "MCP Gateway Root CA")
        #[arg(long, default_value = "MCP Gateway Root CA")]
        cn: String,

        /// Validity period in days
        #[arg(long, default_value_t = 3650)]
        validity_days: u32,

        /// Directory to write `ca.crt` and `ca.key` into
        #[arg(short, long, default_value = "/etc/mcp-gateway/tls")]
        out: PathBuf,
    },

    /// Issue a server certificate signed by the CA.
    #[command(about = "Issue a server certificate (for the gateway)")]
    IssueServer {
        /// Path to the CA certificate file
        #[arg(long, default_value = "/etc/mcp-gateway/tls/ca.crt")]
        ca_cert: PathBuf,

        /// Path to the CA private key file
        #[arg(long, default_value = "/etc/mcp-gateway/tls/ca.key")]
        ca_key: PathBuf,

        /// Common Name (e.g. "gateway.company.com")
        #[arg(long)]
        cn: String,

        /// Comma-separated SAN DNS names (e.g. "gateway.company.com,localhost")
        #[arg(long, default_value = "")]
        san_dns: String,

        /// Validity period in days
        #[arg(long, default_value_t = 365)]
        validity_days: u32,

        /// Directory to write `server.crt` and `server.key`
        #[arg(short, long, default_value = "/etc/mcp-gateway/tls")]
        out: PathBuf,
    },

    /// Issue a client certificate for an agent, signed by the CA.
    #[command(about = "Issue a client certificate (for an agent)")]
    IssueClient {
        /// Path to the CA certificate file
        #[arg(long, default_value = "/etc/mcp-gateway/tls/ca.crt")]
        ca_cert: PathBuf,

        /// Path to the CA private key file
        #[arg(long, default_value = "/etc/mcp-gateway/tls/ca.key")]
        ca_key: PathBuf,

        /// Common Name for the client (e.g. "claude-code-agent")
        #[arg(long)]
        cn: String,

        /// Organisational Unit (e.g. "engineering")
        #[arg(long)]
        ou: Option<String>,

        /// SPIFFE URI SAN (e.g. `spiffe://company.com/agent/claude-code`)
        #[arg(long)]
        spiffe_uri: Option<String>,

        /// Validity period in days (default 1 day for short-lived certs)
        #[arg(long, default_value_t = 1)]
        validity_days: u32,

        /// Directory to write `<cn>.crt` and `<cn>.key`
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
    },
}
