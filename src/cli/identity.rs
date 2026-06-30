//! Identity and local grant administration CLI definitions.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use crate::cli::output::OutputFormat;

/// Identity administration subcommands.
#[derive(Subcommand, Debug)]
pub enum IdentityCommand {
    /// Manage local identity-grant rows for personal capabilities.
    #[command(subcommand, about = "Manage local identity grants")]
    Grants(IdentityGrantsCommand),
}

/// Local identity-grant file subcommands.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum IdentityGrantsCommand {
    /// List local grant rows.
    #[command(about = "List local identity grants")]
    List {
        /// Local JSON or YAML grant file.
        #[arg(long, default_value = "~/.mcp-gateway/identity-grants.yaml")]
        file: PathBuf,

        /// Show only grants that are not expired or revoked.
        #[arg(long)]
        active_only: bool,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Append or replace one local grant row.
    #[command(about = "Add a local identity grant")]
    Grant {
        /// Local JSON or YAML grant file. Created when missing.
        #[arg(long, default_value = "~/.mcp-gateway/identity-grants.yaml")]
        file: PathBuf,

        /// Stable grant id.
        #[arg(long)]
        grant_id: String,

        /// Subject as AUTHORITY:SUBJECT. Use --subject-label for display text.
        #[arg(long)]
        subject: String,

        /// Optional subject display label.
        #[arg(long)]
        subject_label: Option<String>,

        /// Exact agent id allowed by this grant. Mutually exclusive with --any-agent.
        #[arg(long)]
        agent: Option<String>,

        /// Allow any agent acting for the subject.
        #[arg(long)]
        any_agent: bool,

        /// Capability id allowed by this grant.
        #[arg(long)]
        capability: String,

        /// Optional concrete tool name under the capability.
        #[arg(long)]
        tool: Option<String>,

        /// Granted action scope.
        #[arg(long, default_value = "execute", value_enum)]
        scope: IdentityGrantScopeArg,

        /// Owner subject as AUTHORITY:SUBJECT. Defaults to --subject.
        #[arg(long)]
        owner: Option<String>,

        /// Optional owner display label.
        #[arg(long)]
        owner_label: Option<String>,

        /// Absolute RFC3339 expiry timestamp, for example 2026-06-29T13:00:00Z.
        #[arg(long)]
        expires_at: Option<String>,

        /// Relative expiry in seconds from now. Mutually exclusive with --expires-at.
        #[arg(long)]
        ttl_seconds: Option<i64>,

        /// Provenance string recorded with the grant.
        #[arg(long, default_value = "mcp-gateway identity grants grant")]
        provenance: String,

        /// Operator-visible reason for the grant.
        #[arg(long)]
        reason: String,

        /// Replace an existing grant row with the same id.
        #[arg(long)]
        replace: bool,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },

    /// Mark one local grant row as revoked.
    #[command(about = "Revoke a local identity grant")]
    Revoke {
        /// Local JSON or YAML grant file.
        #[arg(long, default_value = "~/.mcp-gateway/identity-grants.yaml")]
        file: PathBuf,

        /// Grant id to revoke.
        #[arg(long)]
        grant_id: String,

        /// Absolute RFC3339 revocation timestamp. Defaults to now.
        #[arg(long)]
        revoked_at: Option<String>,

        /// Output format.
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
    },
}

/// CLI value for grant scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IdentityGrantScopeArg {
    /// Read-only operations.
    Read,
    /// Mutating operations.
    Write,
    /// Tool execution.
    Execute,
    /// Any operation.
    Any,
}
