//! Secondary subcommand enums for `mcp-gateway`.
//!
//! This module contains [`CapCommand`], [`PluginCommand`], [`TlsCommand`], and
//! [`TrustCommand`] — all extracted from `cli/mod.rs` to keep each file under
//! 800 lines.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use crate::cli::output::OutputFormat;

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

    /// Pin a capability YAML by computing and writing its SHA-256 hash.
    ///
    /// Rewrites the file in place, adding (or replacing) a top-level
    /// `sha256:` line. The loader will reject any future modification to
    /// the file that does not update the pin, defeating rug-pull attacks
    /// described in Invariant Labs' "Tool Poisoning Attacks" writeup.
    #[command(about = "Pin a capability YAML with its SHA-256 hash")]
    Pin {
        /// Path to the capability YAML file to pin
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
    ///
    /// Use `--shadow` for a passive `ShadowRadar` report of servers that are
    /// *not* already registered as backends in the gateway configuration. The
    /// report classifies ownership, transport exposure, trust status, data
    /// risk, recommended action, confidence, verification, and rollback. It
    /// never invokes discovered tools.
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

        /// Emit a passive `ShadowRadar` report for servers that are NOT
        /// registered in the gateway config.
        #[arg(long)]
        shadow: bool,

        /// Gateway config file to compare against when using --shadow.
        /// Defaults to `gateway.yaml` in the current directory.
        #[arg(long)]
        gateway_config: Option<PathBuf>,
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

    /// Probe a URL for an `OpenAPI` or GraphQL spec and generate capability files
    ///
    /// Runs SSRF validation, discovers the spec via parallel probing, converts
    /// it to capability YAML files, deduplicates against the output directory,
    /// and writes the results.
    #[cfg(feature = "discovery")]
    #[command(name = "import-url", about = "Import API capabilities from a URL")]
    ImportUrl {
        /// URL to probe for an API specification
        #[arg(required = true)]
        url: String,

        /// String prepended to every generated capability name (e.g. "stripe")
        #[arg(short, long)]
        prefix: Option<String>,

        /// Directory to write the generated capability files into
        #[arg(short, long, default_value = "capabilities")]
        output: PathBuf,

        /// Bearer token or credential reference for authenticated specs (e.g. `env:API_KEY`)
        #[arg(long)]
        auth: Option<String>,

        /// Maximum number of endpoints to generate capabilities for
        #[arg(long, default_value_t = 50)]
        max_endpoints: usize,

        /// Print what would be generated without writing any files
        #[arg(long)]
        dry_run: bool,

        /// Cost per API call in USD (annotated in generated capability metadata)
        #[arg(long)]
        cost_per_call: Option<f64>,
    },
}

/// Safe protocol import subcommands.
#[derive(Subcommand, Debug)]
pub enum ProtocolImportCommand {
    /// Preview disabled capability drafts from an API or MCP package source.
    #[command(about = "Preview disabled import drafts without writing or enabling tools")]
    Preview {
        /// Source format to import.
        #[arg(long, value_enum)]
        kind: ProtocolImportKind,

        /// Source file to preview.
        #[arg(required = true)]
        file: PathBuf,

        /// Source name used in generated plan metadata for OpenAPI/GraphQL.
        #[arg(long)]
        source_name: Option<String>,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,

        /// Context-integrity profile attached to generated draft policy defaults.
        #[arg(long, default_value = "imported_tool_baseline")]
        context_integrity_profile: String,
    },
}

/// Protocol source formats accepted by the safe import preview command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProtocolImportKind {
    /// `OpenAPI` 3.x or Swagger 2.0 file.
    #[value(name = "openapi", alias = "open-api")]
    OpenApi,
    /// GraphQL import specification file.
    Graphql,
    /// Postman collection JSON file.
    Postman,
    /// OCI MCP package metadata file.
    #[value(name = "oci-mcp-package", alias = "oci")]
    OciMcpPackage,
}

/// Kubernetes enterprise deployment commands.
#[derive(Subcommand, Debug)]
pub enum KubernetesCommand {
    /// Build a non-mutating reconcile plan from enterprise custom resources.
    #[command(about = "Plan Kubernetes enterprise reconciliation without mutating the cluster")]
    Plan {
        /// YAML file containing `Gateway`, `MCPServer`, `Policy`, `RuntimeProfile`, and `TrustCardReference` resources.
        #[arg(required = true)]
        resources: PathBuf,

        /// Target namespace.
        #[arg(short, long, default_value = "mcp-gateway")]
        namespace: String,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Run the deterministic controller-manager reconcile loop.
    #[command(about = "Run Kubernetes enterprise controller-manager reconciliation")]
    Controller {
        /// YAML file containing `Gateway`, `MCPServer`, `Policy`, `RuntimeProfile`, and `TrustCardReference` resources.
        #[arg(required = true)]
        resources: PathBuf,

        /// Target namespace.
        #[arg(short, long, default_value = "mcp-gateway")]
        namespace: String,

        /// Seconds between reconcile cycles.
        #[arg(long, default_value_t = 30)]
        interval_seconds: u64,

        /// Number of reconcile cycles to run when not watching continuously.
        #[arg(long, default_value_t = 1)]
        cycles: usize,

        /// Keep reconciling until the process is stopped.
        #[arg(long)]
        watch: bool,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Build a gated live-cluster apply command plan.
    #[command(
        name = "apply-plan",
        about = "Plan Kubernetes enterprise cluster apply commands with explicit mutation gates"
    )]
    ApplyPlan {
        /// YAML file containing `Gateway`, `MCPServer`, `Policy`, `RuntimeProfile`, and `TrustCardReference` resources.
        #[arg(required = true)]
        resources: PathBuf,

        /// Target namespace.
        #[arg(short, long, default_value = "mcp-gateway")]
        namespace: String,

        /// Enable mutating apply, evidence, verify, and rollback commands in the plan.
        #[arg(long)]
        approve_apply: bool,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },
}

/// `TrustCard` and CBOM advisory metadata commands.
#[derive(Subcommand, Debug)]
pub enum TrustCommand {
    /// Generate `TrustCard` and CBOM metadata from local capability YAML files.
    #[command(about = "Generate TrustCard metadata from local capabilities")]
    Generate {
        /// Directory containing capability YAML definitions.
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

        /// Output format.
        #[arg(short, long, default_value = "json", value_enum)]
        format: OutputFormat,

        /// Optional file path for machine JSON output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Inspect one generated `TrustCard` from the local capability catalogue.
    #[command(about = "Inspect a generated TrustCard for one capability")]
    Inspect {
        /// Capability/server name to inspect.
        #[arg(required = true)]
        name: String,

        /// Directory containing capability YAML definitions.
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Validate a `TrustCard` file or generated local capability `TrustCard`s.
    #[command(about = "Validate TrustCard metadata")]
    Validate {
        /// `TrustCard` JSON or YAML file to validate. If omitted, generated
        /// `TrustCard`s from --capabilities are validated.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Directory containing capability YAML definitions, used when --file
        /// is omitted.
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

        /// Return a non-zero exit code for warning findings, not only failures.
        #[arg(long)]
        strict: bool,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Evaluate generated `TrustCard`s with `CatalogTrustLab`.
    #[command(subcommand, about = "CatalogTrustLab advisory evaluation commands")]
    Lab(TrustLabCommand),
}

/// `CatalogTrustLab` evaluation commands.
#[derive(Subcommand, Debug)]
pub enum TrustLabCommand {
    /// Evaluate one or all local capability `TrustCard`s.
    #[command(about = "Evaluate generated TrustCards with CatalogTrustLab")]
    Evaluate {
        /// Optional capability/server name to evaluate. If omitted, every
        /// generated local `TrustCard` is evaluated.
        name: Option<String>,

        /// Directory containing capability YAML definitions.
        #[arg(
            short = 'C',
            long,
            default_value = "capabilities",
            env = "MCP_GATEWAY_CAPABILITIES"
        )]
        capabilities: PathBuf,

        /// Return non-zero when policy verdict is block. Default mode is
        /// advisory-only and records would-block evidence without failing.
        #[arg(long)]
        enforce: bool,

        /// Optional `TrustLab` baseline JSON/YAML file for schema-drift checks.
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Write the current generated tool schema digests as a baseline file.
        #[arg(long)]
        write_baseline: Option<PathBuf>,

        /// Managed local baseline registry directory. When --baseline is not
        /// set, the named baseline is loaded from this registry.
        #[arg(long)]
        baseline_registry: Option<PathBuf>,

        /// Create or update the named baseline inside --baseline-registry.
        #[arg(long)]
        update_baseline_registry: bool,

        /// JSON/YAML file with dry-run active fixture evidence. The CLI does
        /// not call a candidate server; it records which declared-safe fixtures
        /// would be eligible for isolated execution.
        #[arg(long)]
        active_fixtures: Option<PathBuf>,

        /// Baseline identifier used when --write-baseline is set.
        #[arg(long, default_value = "local-baseline")]
        baseline_id: String,

        /// Minimum score for policy allow.
        #[arg(long, default_value_t = 75)]
        minimum_score: u8,

        /// Minimum score for certification.
        #[arg(long, default_value_t = 90)]
        certification_score: u8,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
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

/// Transparency log audit subcommands
#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Verify the tamper-evidence hash chain of the transparency log
    #[command(about = "Verify the transparency log hash chain")]
    Verify {
        /// Path to the transparency log file
        /// (default: ~/.mcp-gateway/transparency/transparency.jsonl)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Show log entries for a specific session
    #[command(about = "Show transparency log entries for a session")]
    Show {
        /// Session ID to filter by
        #[arg(long, required = true)]
        session: String,

        /// Path to the transparency log file
        /// (default: ~/.mcp-gateway/transparency/transparency.jsonl)
        #[arg(long)]
        path: Option<PathBuf>,
    },
}
