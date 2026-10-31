// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Secondary subcommand enums for `mcp-gateway`.
//!
//! This module contains [`CapCommand`], [`TlsCommand`], and [`TrustCommand`]
//! — all extracted from `cli/mod.rs` to keep each file under
//! 800 lines.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use crate::cli::output::OutputFormat;

mod trust;
pub use trust::{
    AuditCommand, ProvenanceCommand, RuntimeProviderArg, TlsCommand, TrustCommand, TrustLabCommand,
};

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

        /// Rewrite the whole file when the change cannot be made in place
        /// (comments and layout are lost); without it such a write is refused
        #[arg(long)]
        force: bool,
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
        #[arg(short = 'C', long, default_value = "capabilities")]
        capabilities: PathBuf,
    },

    /// Display every capability in the registry with its description and auth status
    #[command(about = "List all capabilities in the registry")]
    RegistryList {
        /// Root directory containing capability definitions to index
        #[arg(short = 'C', long, default_value = "capabilities")]
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

    /// Write reviewed import drafts to an inactive draft directory.
    #[command(about = "Apply reversible import drafts to disk without enabling tools")]
    Apply {
        /// Source format to import.
        #[arg(long, value_enum)]
        kind: ProtocolImportKind,

        /// Source file to apply.
        #[arg(required = true)]
        file: PathBuf,

        /// Directory to write generated draft files into.
        #[arg(short, long, default_value = "capability-drafts")]
        output: PathBuf,

        /// Source name used in generated plan metadata for OpenAPI/GraphQL.
        #[arg(long)]
        source_name: Option<String>,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,

        /// Context-integrity profile attached to generated draft policy defaults.
        #[arg(long, default_value = "imported_tool_baseline")]
        context_integrity_profile: String,

        /// Overwrite existing draft files and manifest.
        #[arg(long)]
        force: bool,
    },
}

/// Adaptive ranking evaluation subcommands.
#[derive(Subcommand, Debug)]
pub enum RankingCommand {
    /// Evaluate deterministic offline ranking fixtures.
    #[command(about = "Evaluate adaptive ranking against a fixture corpus")]
    Eval {
        /// JSON file containing a fixture array or an object with a cases array.
        #[arg(required = true)]
        file: PathBuf,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
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

        /// Keep reconciling until stopped; `--format json` prints one JSON line per cycle.
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

        /// Execute enabled non-rollback commands after building the reviewed plan.
        #[arg(long)]
        execute: bool,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::{
        Cli, Command, ProtocolImportCommand, ProtocolImportKind, RankingCommand,
        output::OutputFormat,
    };

    fn parse_args(args: &[&str]) -> Result<Cli, clap::Error> {
        let mut raw_args = Vec::with_capacity(args.len() + 1);
        raw_args.push("mcp-gateway");
        raw_args.extend(args.iter().copied());
        Cli::try_parse_from(raw_args)
    }

    #[test]
    fn import_apply_parses_inactive_output_dir_and_force() {
        let cli = parse_args(&[
            "import",
            "apply",
            "--kind",
            "openapi",
            "fixtures/openapi.yaml",
            "--output",
            "capability-drafts/review",
            "--source-name",
            "users-api",
            "--format",
            "plain",
            "--force",
        ])
        .unwrap();

        match cli.command {
            Some(Command::Import(ProtocolImportCommand::Apply {
                kind,
                file,
                output,
                source_name,
                format,
                force,
                ..
            })) => {
                assert_eq!(kind, ProtocolImportKind::OpenApi);
                assert_eq!(file, std::path::PathBuf::from("fixtures/openapi.yaml"));
                assert_eq!(output, std::path::PathBuf::from("capability-drafts/review"));
                assert_eq!(source_name.as_deref(), Some("users-api"));
                assert_eq!(format, OutputFormat::Plain);
                assert!(force);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ranking_eval_parses_fixture_path_and_format() {
        let cli = parse_args(&[
            "ranking",
            "eval",
            "fixtures/ranking-eval.json",
            "--format",
            "json",
        ])
        .unwrap();

        match cli.command {
            Some(Command::Ranking(RankingCommand::Eval { file, format })) => {
                assert_eq!(file, std::path::PathBuf::from("fixtures/ranking-eval.json"));
                assert_eq!(format, OutputFormat::Json);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
