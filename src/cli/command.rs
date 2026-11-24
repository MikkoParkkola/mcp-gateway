// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The top-level `Command` enum: one variant per `mcp-gateway` subcommand.

use std::path::PathBuf;

use clap::Subcommand;

#[cfg(feature = "runtime-substrate")]
use super::RuntimeCommand;
use super::identity::IdentityCommand;
use super::setup::SetupCommand;
use super::skills::SkillsCommand;
use super::subcommands::{
    AuditCommand, CapCommand, KubernetesCommand, ProtocolImportCommand, ProvenanceCommand,
    RankingCommand, TlsCommand, TrustCommand,
};
use super::{AccountsCommand, InitProfile, ToolCommand, api, dashboard_link, events};
use crate::cli::output::OutputFormat;

/// The value of an off switch read from a flag or its environment
/// variable: `false` only for "0" or "false" (trimmed, any case), `true`
/// for anything else, empty included. An off switch that is set at all is
/// read as on, so a misspelled value cannot silently re-enable what the
/// operator meant to turn off.
fn parse_off_switch(value: &str) -> bool {
    let value = value.trim();
    !(value == "0" || value.eq_ignore_ascii_case("false"))
}

/// Top-level subcommands
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Start the gateway server (default when no subcommand is given)
    #[command(about = "Start the gateway server")]
    Serve {
        /// Run in stdio mode: read JSON-RPC from stdin, write responses to stdout.
        ///
        /// Skips the HTTP listener and speaks MCP over newline-delimited JSON-RPC,
        /// making `mcp-gateway` directly usable as a Claude Code / MCP stdio server:
        ///
        ///   `mcp-gateway serve --stdio`
        ///
        /// or simply:
        ///
        ///   `echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}' | mcp-gateway serve --stdio`
        #[arg(long, default_value_t = false)]
        stdio: bool,
    },

    /// Manage capability definitions (validate, test, import, install)
    #[command(subcommand, about = "Capability management commands")]
    Cap(CapCommand),

    /// Preview safe protocol imports before writing or enabling generated tools
    #[command(
        subcommand,
        about = "Preview safe imports from API and MCP package sources"
    )]
    Import(ProtocolImportCommand),

    /// Plan enterprise Kubernetes reconciliation and validation.
    #[command(
        subcommand,
        hide = true,
        about = "Kubernetes enterprise deployment commands"
    )]
    Kubernetes(KubernetesCommand),

    /// Evaluate deterministic adaptive ranking fixtures.
    #[command(
        subcommand,
        hide = true,
        about = "Adaptive ranking evaluation commands"
    )]
    Ranking(RankingCommand),

    /// Manage TLS certificates for mTLS authenticated tool access (RFC-0051)
    #[command(
        subcommand,
        about = "Certificate lifecycle management (init-ca, issue-server, issue-client)"
    )]
    Tls(TlsCommand),

    /// Generate, inspect, and validate `TrustCard` and CBOM metadata.
    #[command(
        subcommand,
        hide = true,
        about = "TrustCard and CBOM metadata commands"
    )]
    Trust(TrustCommand),

    /// Export and verify public provenance keys
    #[command(subcommand, about = "Export and verify public provenance keys")]
    Provenance(ProvenanceCommand),

    /// Manage caller identity and local personal-capability grants.
    #[command(subcommand, about = "Identity and local grant administration")]
    Identity(IdentityCommand),

    /// Offline administration of the personal-account custody store.
    #[command(subcommand, about = "Personal account store administration (offline)")]
    Accounts(AccountsCommand),

    /// Print the `sha256:<hex>` digest of an API key read from stdin, for
    /// `auth.api_keys[].key_sha256`. Offline: reads no config, makes no call.
    #[command(
        name = "hash-key",
        about = "Digest an API key read from stdin (offline)"
    )]
    HashKey {
        /// Check the key against this digest instead: exit 0 on a match, 1 on
        /// a mismatch, 2 on a malformed digest.
        #[arg(long, value_name = "DIGEST")]
        verify: Option<String>,
        /// Print one JSON document on stdout (`key_sha256`); the `--verify` answer is its exit code
        #[arg(long, conflicts_with = "verify")]
        json: bool,
    },

    /// Generate a starter gateway.yaml with sensible defaults
    #[command(about = "Create a new gateway configuration file")]
    Init {
        /// File path to write the generated configuration to
        #[arg(short, long, default_value = "gateway.yaml")]
        output: PathBuf,

        /// Starter profile to generate
        #[arg(long, default_value = "local", value_enum)]
        profile: InitProfile,

        /// Include example capability definitions and backend stubs
        /// (on by default; `--with-examples=false` turns them off)
        #[arg(long, default_value_t = true, num_args = 0..=1, require_equals = true)]
        #[arg(default_missing_value = "true", action = clap::ArgAction::Set)]
        with_examples: bool,
    },

    /// Fetch live statistics from a running gateway instance
    #[command(about = "Show observed invocation counts and cache behavior")]
    Stats {
        /// Where to send the request; without a flag or `MCP_GATEWAY_URL`, the
        /// `server.host`/`server.port` of `--config` (the file `serve` binds
        /// to), else `http://127.0.0.1:39400`.
        #[command(flatten)]
        gateway: dashboard_link::GatewayArg,
        /// Print one JSON document on stdout instead of the text summary
        #[arg(long)]
        json: bool,
    },

    /// Print a fresh single-use dashboard link; reads `MCP_GATEWAY_TOKEN`.
    DashboardLink(dashboard_link::DashboardLinkArgs),
    /// Administer MCP Events: list and replay dead-lettered deliveries
    Events(events::EventsArgs),
    /// Send one request to a running gateway's admin API (`/ui/api/...`) and
    /// print its JSON; reads `MCP_GATEWAY_TOKEN`.
    Api(api::ApiArgs),

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
        format: crate::validator::ValidatorOutputFormat,

        /// Minimum severity to report
        #[arg(hide = true, short, long, default_value = "info", value_enum)]
        severity: crate::validator::SeverityFilter,

        /// Auto-fix issues where possible (rewrites YAML in place)
        #[arg(long)]
        fix: bool,

        /// Disable colored output. Hidden: colour already
        /// follows the terminal and `NO_COLOR`.
        #[arg(long, hide = true)]
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

    /// Generate agent skill bundles from capability definitions
    ///
    /// Converts loaded capability YAML files into Markdown skill bundles
    /// that AI agents can discover and load via the `loadSkill` convention.
    #[command(subcommand, about = "Generate agent skill bundles")]
    Skills(SkillsCommand),

    /// Setup wizard and config export — import MCP servers or export gateway config
    ///
    /// Two sub-modes:
    ///   `setup wizard`  — scan AI clients and import MCP servers into gateway.yaml
    ///   `setup export`  — write gateway config into AI client config files
    #[command(subcommand, about = "Setup wizard and config export")]
    Setup(SetupCommand),

    /// Add an MCP backend to the gateway configuration
    ///
    /// Compatible with `claude mcp add` and `codex mcp add` CLI conventions.
    /// If `name` matches a known server in the built-in registry,
    /// the command and env-var template are filled automatically.
    ///
    /// # Examples
    ///
    /// ```bash
    /// # From built-in registry (knows the npx command + required env vars):
    /// mcp-gateway add tavily
    ///
    /// # Stdio server with trailing command (claude/codex style):
    /// mcp-gateway add my-server -- npx -y @some/mcp-server --flag
    ///
    /// # Stdio server with an env var taken from this shell (values never go
    /// # on the command line, where process lists and history show them):
    /// export MY_TOKEN=...   # or set it in your shell profile
    /// mcp-gateway add -e MY_TOKEN my-server -- npx my-mcp-server
    ///
    /// # The same with values from a JSON file (`--env-file -` reads stdin):
    /// mcp-gateway add --env-file secrets.json my-server -- npx my-mcp-server
    ///
    /// # HTTP server:
    /// mcp-gateway add --url https://mcp.sentry.dev/mcp sentry
    ///
    /// # Both styles work:
    /// mcp-gateway add --command "npx -y tavily-mcp@0.2.22" tavily
    /// ```
    #[command(about = "Add an MCP backend to gateway.yaml (or the `--config` file)")]
    Add {
        /// Name for the new backend (used as the config key and registry lookup)
        name: String,

        /// HTTP URL for the server (streamable HTTP / SSE transport)
        #[arg(long)]
        url: Option<String>,

        /// Shell command as a single string (alternative to trailing `-- cmd args...`)
        #[arg(long)]
        command: Option<String>,

        /// Human-readable description (defaults to registry description when available)
        #[arg(long)]
        description: Option<String>,

        /// An environment variable to pass the server, by NAME; its value is
        /// read from this shell's environment. May be repeated. Values never
        /// go on the command line (process lists and shell history show them)
        #[arg(short = 'e', long = "env", value_name = "NAME")]
        env_vars: Vec<String>,

        /// A JSON object of environment variable names to values, from FILE
        /// or `-` for stdin (at most 64 KiB)
        #[arg(long = "env-file", value_name = "FILE")]
        env_file: Option<std::path::PathBuf>,

        /// Write this value into gateway.yaml as typed instead of storing it in
        /// the secret store; may be repeated (an env KEY, or header:NAME)
        #[arg(hide = true, long = "keep-as-text", value_name = "KEY")]
        keep_as_text: Vec<String>,

        /// Rewrite the whole file when the change cannot be made in place
        /// (comments and layout are lost); without it such a write is refused
        #[arg(long)]
        force: bool,

        /// Stdio command and arguments (after `--` separator, claude/codex style)
        #[arg(last = true)]
        trailing_command: Vec<String>,
    },

    /// Remove an MCP backend from the gateway configuration
    #[command(about = "Remove an MCP backend from gateway.yaml (or the `--config` file)")]
    Remove {
        /// Name of the backend to remove
        name: String,

        /// Rewrite the whole file when the change cannot be made in place
        /// (comments and layout are lost); without it such a write is refused
        #[arg(long)]
        force: bool,
    },

    /// List configured MCP backends
    #[command(about = "List the backends configured in gateway.yaml (or the `--config` file)")]
    List {
        /// Output as JSON (codex-compatible)
        #[arg(long)]
        json: bool,
        /// List the built-in server library instead: login, default state
        #[arg(long)]
        available: bool,
    },

    /// Get details about a specific MCP backend
    #[command(
        about = "Show details of a backend configured in gateway.yaml (or the `--config` file)"
    )]
    Get {
        /// Backend name to inspect
        name: String,
        /// Print one JSON document on stdout; values stay hidden as in the text form
        #[arg(long)]
        json: bool,
    },

    /// Diagnose gateway and backend health
    ///
    /// Checks configuration, port availability, required env vars, HTTP
    /// reachability for HTTP backends, and whether any AI client is already
    /// pointed at the gateway.
    ///
    /// With `--shadow`, skips the health checks and instead emits DLP/firewall
    /// regex rules for operator-side network detection of MCP traffic.  These
    /// are **heuristic guidance** for external tools (firewalls, SIEMs, proxies)
    /// — the gateway does not intercept arbitrary outbound traffic itself.
    ///
    /// # Examples
    ///
    /// ```bash
    /// # Emit shell-grep patterns (default)
    /// mcp-gateway doctor --shadow
    ///
    /// # Emit nginx http-context map snippet
    /// mcp-gateway doctor --shadow --shadow-format nginx
    ///
    /// # Emit YAML rule set for SIEM import
    /// mcp-gateway doctor --shadow --shadow-format yaml
    /// ```
    #[command(about = "Check gateway configuration and backend health")]
    Doctor {
        /// Attempt to auto-fix issues where possible (e.g. create missing dirs)
        #[arg(long)]
        fix: bool,

        /// Gateway config file to inspect (auto-detected when omitted)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output format for health checks
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,

        /// Emit operator-facing DLP/firewall regex rules for network-layer MCP
        /// detection instead of running the normal health checks.
        ///
        /// Rules are heuristic only — the gateway cannot intercept arbitrary
        /// outbound traffic.  Deploy the exported rules in your firewall, SIEM,
        /// or reverse proxy to detect unauthorised MCP sessions.
        #[arg(long)]
        shadow: bool,

        /// Output format for `--shadow` rule export: "grep", "nginx", or "yaml"
        #[arg(long, default_value = "grep", value_name = "FORMAT")]
        shadow_format: String,

        /// Start each stdio backend and complete `initialize`, reporting why one
        /// that dies first died (its exit status and stderr cause class). Runs the
        /// configured commands, with their side effects; off by default.
        #[arg(long)]
        start_stdio: bool,
        /// With `--start-stdio`: also show a failed start's masked stderr tail.
        #[arg(long, requires = "start_stdio")]
        show_stderr: bool,
        /// Skip the npm registry lookup. The lookup is on by default: for each stdio
        /// backend pinning an npm package from the gateway's own registry, doctor asks
        /// registry.npmjs.org whether that version is deprecated. Only package names
        /// from the gateway's own registry leave the machine (never your backend
        /// names, versions or settings), and npm sees this host's IP address.
        /// `security.posture: hardened` also skips it.
        /// This skips the gateway's own npm registry lookup; it does not stop npx or other servers started by --start-stdio from contacting npm, so air-gapped hosts should not use --start-stdio.
        /// The variable takes `0` or `false` to keep the lookup on; any other value skips it.
        #[arg(long, env = "MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK", num_args = 0..=1, default_missing_value = "true", default_value = "false", value_parser = |value: &str| Ok::<bool, std::convert::Infallible>(parse_off_switch(value)))]
        no_registry_check: bool,
    },

    /// Apply pending post-upgrade migrations and update the version stamp
    ///
    /// Reads `~/.mcp-gateway/version.stamp`, compares it to the current binary
    /// version, and runs any registered migrations. `gateway.yaml` is backed up
    /// to `gateway.yaml.bak.<old-version>` only when a migration will modify it;
    /// an upgrade that only prints notices leaves no backup, because it changed
    /// nothing to roll back to.
    ///
    /// This is called automatically at `serve` startup; run it manually after
    /// a Homebrew `brew upgrade` or other out-of-band binary swap.
    ///
    /// # Examples
    ///
    /// ```bash
    /// # Run interactively after upgrading
    /// mcp-gateway upgrade
    ///
    /// # Preview changes without writing anything
    /// mcp-gateway upgrade --dry-run
    /// ```
    #[command(about = "Apply post-upgrade migrations and update version stamp")]
    Upgrade {
        /// Show what would change without writing any files
        #[arg(long)]
        dry_run: bool,

        /// Suppress progress output; errors and breaking-change notices are
        /// still written to stderr (useful for Homebrew `post_install`)
        #[arg(hide = true, long, short)]
        quiet: bool,

        /// Override the data directory (default: ~/.mcp-gateway)
        #[arg(long, env = "MCP_GATEWAY_CONFIG_DIR")]
        data_dir: Option<PathBuf>,
    },

    /// Transparency log audit — verify chain integrity and query by session
    ///
    /// # Examples
    ///
    /// ```bash
    /// # Verify the full hash chain
    /// mcp-gateway audit verify
    ///
    /// # Show entries for a specific session
    /// mcp-gateway audit show --session sess-abc123
    /// ```
    #[command(subcommand, about = "Transparency log audit commands")]
    Audit(AuditCommand),

    /// Dual-substrate OCI runtime abstraction (B4-PLATFORM).
    #[cfg(feature = "runtime-substrate")]
    #[command(
        subcommand,
        hide = true,
        about = "Sandbox runtime substrate commands (opt-in)"
    )]
    Runtime(RuntimeCommand),
}
