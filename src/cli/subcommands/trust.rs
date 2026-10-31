// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Trust, TLS, audit and provenance subcommand enums, with the runtime
//! provider argument the trust lab takes. Moved from `subcommands.rs` for the
//! file-size ceiling.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use crate::cli::output::OutputFormat;

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

        /// JSON/YAML file with active fixture evidence. By default the CLI
        /// records dry-run eligibility only and does not call a candidate
        /// server.
        #[arg(long)]
        active_fixtures: Option<PathBuf>,

        /// Execute declared-safe active fixtures through the local capability
        /// executor. Requires --active-fixtures and an isolated fixture spec.
        #[arg(long, requires = "active_fixtures")]
        execute_active_fixtures: bool,

        /// Attach `RuntimeProvider` planning evidence for active fixture
        /// execution. This does not provision the runtime yet.
        #[arg(long, value_enum, requires = "active_fixtures")]
        runtime_provider_plan: Option<RuntimeProviderArg>,

        /// Container image reference used when planning Docker or Podman
        /// active fixture execution.
        #[arg(long, requires = "runtime_provider_plan")]
        runtime_image: Option<String>,

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

/// Runtime provider families exposed by `TrustLab` planning flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RuntimeProviderArg {
    /// Existing direct local process path.
    LocalProcess,
    /// Docker container runtime.
    Docker,
    /// Podman container runtime.
    Podman,
    /// Linux systemd user service runtime.
    Systemd,
    /// macOS launchd runtime.
    Launchd,
    /// Kubernetes workload runtime.
    Kubernetes,
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

        /// Comma-separated SANs; an IP literal becomes an IP SAN (e.g. `gw.example,localhost,127.0.0.1,::1`)
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
        /// Path to the log (default: ~/.mcp-gateway/transparency/transparency.jsonl)
        #[arg(long)]
        path: Option<PathBuf>,
        /// A copied set: a missing `.hwm` only warns (tail completeness unchecked)
        #[arg(long)]
        archive: bool,
        /// An off-host copy of `<log>.hwm`: the log must still hold the
        /// record it names (a wiped, rolled-back or replaced log fails)
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// Check an Activity export (NDJSON) offline instead of the log: its
        /// manifest signature and the digest of its rows
        #[arg(long, conflicts_with_all = ["path", "archive", "anchor"])]
        export: Option<PathBuf>,
        /// The public key to check `--export` against, as `provenance
        /// public-key` prints it (default: this gateway's configured key)
        #[arg(long, requires = "export")]
        jwk: Option<PathBuf>,
    },

    /// Show log entries for a specific session
    #[command(about = "Show transparency log entries for a session")]
    Show {
        /// Session ID to filter by
        #[arg(long, required = true)]
        session: String,
        /// Path to the log (default: ~/.mcp-gateway/transparency/transparency.jsonl)
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

/// Public provenance key export and verification commands.
///
/// The configuration comes from the global `--config` (`-c`,
/// `MCP_GATEWAY_CONFIG`), as for every other 4.0 subcommand — this enum
/// defines no `--config` of its own.
#[derive(Subcommand, Debug)]
pub enum ProvenanceCommand {
    /// Export the gateway's public provenance key as JWK.
    #[command(about = "Export the public provenance key")]
    PublicKey,

    /// Verify a signed provenance receipt against trusted public keys.
    #[command(about = "Verify a signed provenance receipt")]
    Verify {
        /// JSON file holding the trusted public keys (one JWK or a JWKS).
        #[arg(long)]
        trust: PathBuf,

        /// Receipt to verify: a `SignedResultProvenance` or a full stamped result.
        receipt: PathBuf,

        /// Tool result the receipt binds to.
        #[arg(long)]
        result: Option<PathBuf>,

        /// Accept a receipt that carries a result digest when no result is
        /// given (`--result` absent); only its signature is checked.
        #[arg(long)]
        signature_only: bool,

        /// Accept a receipt that carries no result digest at all, so no
        /// result can ever be checked against it.
        #[arg(long)]
        accept_unbound: bool,
    },
}
