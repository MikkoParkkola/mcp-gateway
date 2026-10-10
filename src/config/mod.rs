// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Configuration management.
//!
//! The top-level [`Config`] struct is loaded via figment (YAML + env vars).
//! Feature-specific types live in the [`features`] sub-module and are
//! re-exported here so callers use `crate::config::KeyServerConfig`, etc.

pub(crate) mod account_bindings;
mod account_refs;
mod backend_add;
mod backend_config;
mod backend_debug;
mod backend_ownership;
mod backend_transport;
mod config_file;
mod env_overlay;
mod features;
mod flagged_tools;
mod input_schema;
pub(crate) mod log_once;
mod meta_mcp_config;
mod pattern_grammar;
mod remote_provenance_posture;
mod secret_file;
mod secret_ref;
mod server_config;
mod strict_keys;
mod validation;
mod ws_backend;

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    time::Duration,
};

use figment::{
    Figment, Metadata, Profile, Provider,
    value::{Dict, Map, Tag, Value},
};
use serde::{Deserialize, Serialize};

use crate::mtls::MtlsConfig;
use crate::routing_profile::RoutingProfileConfig;
use crate::security::{posture, verify_remote_server_provenance};
use crate::{Error, Result};
pub(crate) use backend_transport::transport_key_for;
use config_file::ConfigFile;

pub use env_overlay::{EnvOverlay, Evaluated, HomeResolver, LiveEnv, ResolvedEnvFiles, SystemHome};
use env_overlay::{SecretFileDigests, SecretRefsRead, digest};
pub use input_schema::InputSchemaEnforcement;
use secret_ref::SecretRef;
pub(crate) use secret_ref::is_template_syntax;

// New items (F18): the one mode-checked read for files outside `config`.
#[cfg(windows)]
pub(crate) use secret_file::Protects;
pub(crate) use secret_file::{CheckedFile, read_checked_bytes, read_checked_file};

// Re-export all feature config types so external code needs only `crate::config::Foo`.
pub use features::{
    AgentAuthConfig, AgentDefinitionConfig, AgentIdentityConfig, ApiKeyConfig, ApiKeyKind,
    AuthConfig, CacheConfig, CapabilityConfig, CapabilityErrorBudgetSection, ChainEmit, ChainMode,
    CircuitBreakerConfig, CodeModeConfig, ContextIntegrityConfig, ContextIntegrityPresetConfig,
    DEFAULT_MAX_WORKERS, DashboardSessionConfig, ErrorBudgetSection, FailsafeConfig, FileRoots,
    HealthCheckConfig, IdempotencyConfig, IdempotencyReadOnlyTool, IdentityGrantsConfig,
    KeyServerConfig, KeyServerOidcConfig, KeyServerPolicyConfig, KeyServerProviderConfig,
    PlaybooksConfig, PolicyMatchConfig, PolicyScopesConfig, ProcessCommand, ProcessExecution,
    RateLimitConfig, RemoteServerSigningConfig, ResponseContractConfig, RetryConfig,
    RuntimeAvailabilityConfig, RuntimeConfig, RuntimeProfileConfig, SecurityConfig,
    SignatureChainConfig, StreamingConfig, TasksConfig, ToolContractConfig, WebhookConfig,
    api_key_digest_spec,
};
pub use features::{
    EventsConfig, EventsRateLimit, EventsScheduleConfig, EventsSourcesConfig, EventsWatchConfig,
};
pub(crate) use features::{api_key_expired_now, parse_api_key_digest, parse_cidr};

// Personal-account custody DTO only — not the rest of `personal_accounts`.
pub use crate::personal_accounts::config::{AccountsConfig, AccountsLimits};

/// A YAML null (an empty section) as the type's default.
fn null_as_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

// ── Root config ───────────────────────────────────────────────────────────────

/// Top-level gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    /// Environment files to load before processing config.
    /// Paths support ~ expansion. Loaded in order, later files override earlier.
    #[serde(default)]
    pub env_files: Vec<String>,
    /// Server configuration.
    pub server: ServerConfig,
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// Meta-MCP configuration.
    pub meta_mcp: MetaMcpConfig,
    /// Streaming configuration (for real-time notifications).
    pub streaming: StreamingConfig,
    /// Failsafe configuration.
    pub failsafe: FailsafeConfig,
    /// Error-budget / kill-switch thresholds (GH #475).
    pub error_budget: ErrorBudgetSection,
    /// Backend configurations. An empty `backends:` section, which is what a
    /// section with every entry commented out reads as, is no backends rather
    /// than a load error (MIK-8299).
    #[serde(deserialize_with = "null_as_default")]
    pub backends: HashMap<String, BackendConfig>,
    /// Capability configuration (direct REST API integration).
    pub capabilities: CapabilityConfig,
    /// Cache configuration.
    pub cache: CacheConfig,
    /// Operator-owned read-only exceptions to execution admission.
    pub idempotency: IdempotencyConfig,
    /// Playbook configuration.
    pub playbooks: PlaybooksConfig,
    /// Security policy configuration.
    pub security: SecurityConfig,
    /// Webhook receiver configuration.
    pub webhooks: WebhookConfig,
    /// Routing profiles for session-scoped tool access control.
    #[serde(default)]
    pub routing_profiles: HashMap<String, RoutingProfileConfig>,
    /// Name of the routing profile applied to new sessions.
    #[serde(default = "default_routing_profile")]
    pub default_routing_profile: String,
    /// Code Mode configuration (search+execute pattern).
    #[serde(default)]
    pub code_mode: CodeModeConfig,
    /// Mutual TLS configuration for transport-layer certificate authentication.
    #[serde(default)]
    pub mtls: MtlsConfig,
    /// Key Server — OIDC identity to temporary scoped API keys.
    #[serde(default)]
    pub key_server: KeyServerConfig,
    /// Agent Auth — OAuth 2.0 agent-scoped tool permissions.
    #[serde(default)]
    pub agent_auth: AgentAuthConfig,
    /// `RuntimeProvider` planning and isolation profiles.
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Enterprise control-plane governance (identity-to-role mapping, MIK-6688).
    #[serde(default)]
    pub control_plane: crate::control_plane::ControlPlaneConfig,
    /// Cost governance — per-tool budget enforcement and alerting.
    #[cfg(feature = "cost-governance")]
    #[serde(default)]
    pub cost_governance: crate::cost_accounting::config::CostGovernanceConfig,
    /// Durable tasks extension: store directory, worker cap, record limits.
    #[serde(default)]
    pub tasks: TasksConfig,
    /// MCP Events (MIK-7630): webhook-delivered event subscriptions.
    pub events: EventsConfig,
    /// Optional managed personal-account custody. Omitted enables none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<AccountsConfig>,
}

fn default_routing_profile() -> String {
    "default".to_string()
}

fn default_prompts_resources_fetch_timeout() -> Duration {
    Duration::from_secs(10)
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct EnvFileConfig {
    env_files: Vec<String>,
}

/// How a malformed env file is treated during evaluation.
///
/// An enum rather than a bool so the call site says which behaviour it wants
/// without the reader opening the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tolerance {
    /// Warn and carry on — what [`Config::load`] has always done.
    Warn,
    /// Refuse the load, for callers that can decline to start.
    Fail,
}

/// Figment provider reading `MCP_GATEWAY_*` from the overlay, then the process
/// environment.
///
/// Replaces `Env::prefixed(..)`, which reads the process environment only and
/// would therefore ignore every assignment made by an env file that is no
/// longer exported into the process.
struct OverlayEnv<'a> {
    overlay: &'a EnvOverlay,
}

impl<'a> OverlayEnv<'a> {
    const PREFIX: &'static str = "MCP_GATEWAY_";

    fn new(overlay: &'a EnvOverlay) -> Self {
        Self { overlay }
    }

    /// The variables the provider sees: `base` overlaid with the env files.
    ///
    /// `base` is the process environment as `OsString` pairs, converted the way
    /// `Env` converts them. Reading it through `std::env::vars` instead would
    /// panic the process on a single non-UTF-8 variable belonging to someone
    /// else, which is a startup failure `Env` never had.
    fn merged_vars<I>(&self, base: I) -> std::collections::BTreeMap<String, String>
    where
        I: Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut merged: std::collections::BTreeMap<String, String> = base
            .filter(|(key, _)| !key.is_empty())
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        // Process environment first so an env-file assignment wins, which is
        // the precedence `EnvOverlay::resolve` states.
        merged.extend(self.overlay.effective_vars());
        merged
    }

    /// Places `value` at the path `parts` names, creating dictionaries on the
    /// way down — the nesting `__` in a key stands for.
    fn insert_nested(dict: &mut Dict, parts: &[String], value: String) {
        match parts {
            [] => {}
            [leaf] => {
                // Parsed, not stored as a string: `Env` reads `9090` as a
                // number and `[a, b]` as a list, and `Figment::extract` does
                // not coerce a string into either. Inserting the raw string
                // would fail every non-string field an operator can override.
                dict.insert(leaf.clone(), value.parse().expect("infallible"));
            }
            [head, tail @ ..] => {
                let entry = dict
                    .entry(head.clone())
                    .or_insert_with(|| Value::Dict(Tag::Default, Dict::new()));
                let mut inner = match entry {
                    Value::Dict(_, existing) => std::mem::take(existing),
                    _ => Dict::new(),
                };
                Self::insert_nested(&mut inner, tail, value);
                *entry = Value::Dict(Tag::Default, inner);
            }
        }
    }
}

impl Provider for OverlayEnv<'_> {
    fn metadata(&self) -> Metadata {
        Metadata::named("environment variable(s)")
    }

    fn data(&self) -> figment::Result<Map<Profile, Dict>> {
        let mut dict = Dict::new();
        for (key, value) in self.merged_vars(std::env::vars_os()) {
            let Some(rest) = key.strip_prefix(Self::PREFIX) else {
                continue;
            };
            let parts: Vec<String> = rest.split("__").map(str::to_lowercase).collect();
            if parts.iter().any(String::is_empty) {
                continue;
            }
            Self::insert_nested(&mut dict, &parts, value);
        }
        backend_transport::refuse_backend_url(&dict).map_err(figment::Error::from)?;
        Ok(Profile::Default.collect(dict))
    }
}

/// Whether a load substitutes the environment into the config it returns.
///
/// A config destined for a rewrite must stay [`Expansion::Literal`]: the write
/// path serialises the whole struct, so a substituted secret becomes a
/// plaintext secret on disk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expansion {
    /// Resolve `env:` references and expand `${VAR}` patterns.
    Resolve,
    /// Leave every reference exactly as the file spells it.
    Literal,
}

impl Config {
    /// Candidate config file locations searched when `--config` is not specified.
    ///
    /// Checked in order; the first existing file wins.
    const FALLBACK_PATHS: &'static [&'static str] = &[
        "gateway.yaml",
        "config.yaml",
        // XDG / home-relative entries are generated at runtime by
        // [`Config::fallback_config_path`].
    ];

    /// Discover the config file to load when none is explicitly provided.
    ///
    /// Search order:
    /// 1. `./gateway.yaml`
    /// 2. `./config.yaml`
    /// 3. `~/.config/mcp-gateway/gateway.yaml`
    /// 4. `/etc/mcp-gateway/gateway.yaml`
    ///
    /// Returns `None` if none of the candidates exist (caller uses defaults).
    #[must_use]
    pub fn fallback_config_path() -> Option<PathBuf> {
        // Static relative candidates
        for candidate in Self::FALLBACK_PATHS {
            let p = PathBuf::from(candidate);
            if p.exists() {
                tracing::debug!("Auto-discovered config: {}", p.display());
                return Some(p);
            }
        }

        // Home-relative candidate
        if let Some(home) = crate::home_dir::home_dir() {
            let p = home.join(".config/mcp-gateway/gateway.yaml");
            if p.exists() {
                tracing::debug!("Auto-discovered config: {}", p.display());
                return Some(p);
            }
        }

        // System-wide candidate
        let system = PathBuf::from("/etc/mcp-gateway/gateway.yaml");
        if system.exists() {
            tracing::debug!("Auto-discovered config: {}", system.display());
            return Some(system);
        }

        None
    }

    /// Load configuration from file and environment.
    ///
    /// When `path` is `None`, the loader checks common locations in order
    /// (see [`Config::fallback_config_path`]).  If no file is found anywhere,
    /// it falls back to compiled-in defaults plus environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if an explicit `path` is supplied but does not exist,
    /// or if the config file cannot be parsed.
    /// Select the config file and prove it is readable before any load.
    ///
    /// Shared by every entry point so that "no such file" and "cannot read it"
    /// stay one diagnostic rather than one per loader.
    fn prepare(path: Option<&Path>) -> Result<Option<ConfigFile>> {
        // Resolve the config file: explicit path takes priority; otherwise
        // search well-known fallback locations.
        let resolved: Option<PathBuf> = match path {
            Some(p) => {
                if !p.exists() {
                    return Err(Error::Config(format!(
                        "Config file not found: {}",
                        p.display()
                    )));
                }
                Some(p.to_path_buf())
            }
            None => Self::fallback_config_path(),
        };

        if let Some(config_path) = resolved.as_deref()
            && let Err(error) = std::fs::File::open(config_path)
        {
            let detail = match error.kind() {
                #[cfg(unix)]
                std::io::ErrorKind::PermissionDenied => {
                    "The current process must be able to read the file itself: an owner-only file (mode 600 or 400) is readable only by its owner, so it must be owned by the process user (a mode 000 file, or a root-owned mode 600 file read by a non-root process, is refused here; `chmod 600` it or `chown` it to that user), or the process must run as root. Every containing directory must permit traversal. The official container runs as UID/GID 1001; create an owner-only deployment copy before transferring it with `install -m 600 <source> <deployment-copy>` and `chown 1001:1001 <deployment-copy>`; the owner must be that user or root. Do not make a credential-bearing config world-readable."
                }
                #[cfg(not(unix))]
                std::io::ErrorKind::PermissionDenied => {
                    "The current process needs read access to the selected config; grant it narrowly through the platform ACL. Do not make a credential-bearing config readable by unrelated users."
                }
                _ => {
                    "The selected config must be readable by the current process and must still exist after path selection."
                }
            };
            return Err(Error::Config(format!(
                "Cannot read config file {}: {error}. {detail}",
                config_path.display()
            )));
        }

        // Read once, through the handle the mode check ran on; every later
        // stage parses these bytes rather than reopening the path.
        resolved.map(ConfigFile::read).transpose()
    }

    /// Load the config, warning on (rather than refusing) a malformed env file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the file is missing, unreadable or does
    /// not parse, and [`Error::ConfigValidation`] when it parses but is invalid.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let resolved = Self::prepare(path)?;
        Ok(Self::evaluate(
            resolved.as_ref(),
            &SystemHome,
            Tolerance::Warn,
            Expansion::Resolve,
        )?
        .config)
    }

    /// Load the config exactly as it is written, leaving `env:` references and
    /// `${VAR}` patterns unexpanded.
    ///
    /// Every read-modify-write of the config file goes through this. A loader
    /// that resolves secrets in memory turns the next write into a plaintext
    /// dump of every credential the file merely referenced, because the whole
    /// struct is serialised back.
    ///
    /// # Errors
    ///
    /// As [`Config::load`].
    pub fn load_literal(path: Option<&Path>) -> Result<Self> {
        let resolved = Self::prepare(path)?;
        Ok(Self::evaluate(
            resolved.as_ref(),
            &SystemHome,
            Tolerance::Warn,
            Expansion::Literal,
        )?
        .config)
    }

    /// The overlay this config's own `env_files` produce.
    ///
    /// Lets a config that was never evaluated — one built in memory, or loaded
    /// literally — still be validated against the environment it declares.
    #[must_use]
    pub fn env_overlay(&self) -> EnvOverlay {
        let mut overlay = EnvOverlay::none();
        for entry in &self.env_files {
            let resolved = Self::expand_home(entry, &overlay, &SystemHome);
            overlay.apply_file_tolerant(&resolved);
        }
        overlay
    }

    /// Load a config together with the environment it was evaluated against.
    ///
    /// The fallible sibling of [`Config::load`]: a malformed env file is an
    /// error here, where the caller can refuse to start, rather than a warning
    /// that leaves the gateway running against half an env file.
    pub fn load_evaluated(path: Option<&Path>) -> Result<Evaluated> {
        Self::load_evaluated_with_home(path, &SystemHome)
    }

    /// As [`Config::load_evaluated`], with `~` resolved through `home`.
    pub fn load_evaluated_with_home(
        path: Option<&Path>,
        home: &dyn HomeResolver,
    ) -> Result<Evaluated> {
        let resolved = Self::prepare(path)?;
        Self::evaluate(resolved.as_ref(), home, Tolerance::Fail, Expansion::Resolve)
            .inspect(Evaluated::log_env_files)
    }

    /// Re-evaluate against env files the running process already recorded.
    ///
    /// Takes `env_paths` rather than the config's raw `env_files` spellings on
    /// purpose: `~` resolved once, at startup, and a reload that resolved again
    /// could silently open a different file. The overlay is built from those
    /// files alone — nothing carries over from the overlay it replaces, so a
    /// deleted assignment stops resolving when the reload lands.
    pub(crate) fn load_with_overlay(
        path: Option<&Path>,
        env_paths: &ResolvedEnvFiles,
    ) -> Result<Evaluated> {
        let resolved = Self::prepare(path)?;
        let overlay = EnvOverlay::from_paths_checked(env_paths.as_paths())?;
        Self::finish(
            resolved.as_ref(),
            overlay,
            env_paths.clone(),
            Expansion::Resolve,
        )
    }

    /// Resolve `~` and apply env files in sequence, then build the config.
    ///
    /// Sequential by construction: each entry is applied to the overlay before
    /// the next entry's `~` is expanded, so a `HOME` assignment in one file
    /// moves where the next file is looked for. Resolving the whole list up
    /// front would agree with itself and read a file nothing watches.
    fn evaluate(
        path: Option<&ConfigFile>,
        home: &dyn HomeResolver,
        tolerance: Tolerance,
        expansion: Expansion,
    ) -> Result<Evaluated> {
        let spec: EnvFileConfig = Self::figment(path, &EnvOverlay::none())
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;

        let mut overlay = EnvOverlay::none();
        let mut paths = Vec::with_capacity(spec.env_files.len());
        let tilde = spec.env_files.iter().any(|e| e.starts_with('~'));
        for entry in &spec.env_files {
            let resolved = Self::expand_home(entry, &overlay, home);
            match tolerance {
                Tolerance::Fail => overlay.apply_file(&resolved)?,
                Tolerance::Warn => overlay.apply_file_tolerant(&resolved),
            }
            paths.push(resolved);
        }
        Self::finish(
            path,
            overlay,
            ResolvedEnvFiles::new(paths, tilde),
            expansion,
        )
    }

    /// Substitutes a leading `~` with the home in force at this point in the
    /// sequence. A home that cannot be determined leaves the entry verbatim,
    /// which then simply does not exist and is skipped.
    fn expand_home(entry: &str, so_far: &EnvOverlay, home: &dyn HomeResolver) -> PathBuf {
        let Some(rest) = entry.strip_prefix('~') else {
            return PathBuf::from(entry);
        };
        match home.home_dir(so_far) {
            Some(dir) => PathBuf::from(format!("{}{rest}", dir.display())),
            None => PathBuf::from(entry),
        }
    }

    fn finish(
        path: Option<&ConfigFile>,
        mut overlay: EnvOverlay,
        env_paths: ResolvedEnvFiles,
        expansion: Expansion,
    ) -> Result<Evaluated> {
        // Both entry points funnel through here, so the refusal lives here
        // rather than at each of them: startup accepted a cross-file
        // substitution silently for as long as only the reload path checked.
        //
        // `dotenvy` expands a reference against the process environment and the
        // keys already read from the same file. Nothing writes the process
        // environment now, so a reference to a key another env file defines
        // expands to nothing and the value is lost without an edit.
        if let Some((path, key)) = overlay.substitution_naming_owned_key() {
            return Err(Error::Config(format!(
                "Refusing to load config: env file {} substitutes {key}, a key only another \
                 env file defines. Each env file is expanded on its own, so that reference is \
                 resolved from the process environment, which the gateway does not write: it \
                 would expand to nothing and the value would be lost without an edit. Inline \
                 the value, or move the assignment into this same file above the reference.",
                path.display()
            )));
        }

        let figment = match expansion {
            Expansion::Resolve => Self::figment(path, &overlay),
            // A rewrite path round-trips the FILE. Merging `MCP_GATEWAY_*`
            // here would materialise onto the struct a value nothing spells in
            // YAML, and the next write would persist it: the same defect as a
            // resolved secret, arriving through the prefix rather than through
            // `env:`.
            Expansion::Literal => Self::yaml(path),
        };
        let mut config: Self = figment
            .extract()
            .map_err(|e| Error::Config(e.to_string()))?;
        // Before any validation, so a misspelt key is reported rather than the
        // validation error its absence causes.
        strict_keys::refuse_unrecognised_keys(path, &figment)?;
        // After the file-only strict check: this catches a pair the env makes.
        backend_transport::refuse_two_transports(&figment)?;
        // ORDER MATTERS, AND IT DID NOT BEFORE.
        //
        // `expand_env_vars` below INLINES `auth.bearer_token` and
        // `auth.api_keys[].key_sha256`, so the structural alias check inside
        // `validate_with_env` would compare an adapter's `env:SHARED` reference
        // against plaintext and never match (silent with a DISABLED store).
        // Running it here, before any inlining, is the only point on this path
        // where BOTH sides are still references. The call inside
        // `validate_with_env` stays for callers that never inline; re-running a
        // text-only check costs nothing.
        // The API key digest check sits here for the same reason: an `env:`
        // variable holding plaintext must be refused by NAME, before inlining.
        config.auth.validate_api_key_material(&overlay)?;
        {
            let gateway_credentials = config.gateway_credentials();
            crate::personal_accounts::config::validate_adapter_gateway_reference_separation(
                config.accounts.as_ref(),
                &gateway_credentials,
            )
            .map_err(|error| Error::ConfigValidation(error.to_string()))?;
        }
        let (mut secret_refs, mut files) = match expansion {
            Expansion::Resolve => {
                let refs = config.expand_env_vars(&overlay)?;
                posture::resolve(&mut config, posture::FirewallBuild::CURRENT)?;
                config.security.message_signing =
                    config.security.message_signing.resolve_with_env(&overlay)?;
                let chain = &mut config.security.signature_chain;
                SignatureChainConfig::resolve_section(chain, &overlay)?;
                refs
            }
            Expansion::Literal => (BTreeSet::new(), SecretFileDigests::new()),
        };
        config.validate_with_env(&overlay)?;
        // Account secrets are recorded only once the block has passed
        // validation, and not at all when nothing will read them (#2248).
        if expansion == Expansion::Resolve {
            let (names, account_files) = config.record_account_refs();
            secret_refs.extend(names);
            files.extend(account_files);
            overlay.record_secret_files(files);
        }
        Ok(Evaluated {
            config,
            overlay: std::sync::Arc::new(overlay),
            env_paths,
            secret_refs,
        })
    }

    /// The config file alone, with no environment layered over it.
    fn yaml(path: Option<&ConfigFile>) -> Figment {
        let mut figment = Figment::new();
        if let Some(path) = path {
            figment = figment.merge(path);
        }
        figment
    }

    fn figment(path: Option<&ConfigFile>, overlay: &EnvOverlay) -> Figment {
        Self::yaml(path).merge(OverlayEnv::new(overlay))
    }

    /// Expand `${VAR}` and `${VAR:-default}` patterns in config values.
    ///
    /// An unset variable with no default is refused (C4) for enabled backends
    /// and `capabilities.directories`. A disabled backend keeps its text
    /// verbatim: auth validation skips it too, and enabling it goes through
    /// reload, which runs this again.
    fn expand_env_vars(&mut self, overlay: &EnvOverlay) -> Result<SecretRefsRead> {
        // Every unresolved reference in one error: fixing them one restart at a
        // time is the experience this replaces.
        let mut unresolved = Vec::new();
        let mut expand = |field: String, value: &mut String| match secret_ref::expand_field(
            &field, value, overlay,
        ) {
            Ok(expanded) => *value = expanded,
            Err(message) => unresolved.push(message),
        };
        for (name, backend) in self.backends.iter_mut().filter(|(_, b)| b.enabled) {
            for (key, value) in &mut backend.headers {
                expand(format!("backends.{name}.headers.{key}"), value);
            }
            for (key, value) in &mut backend.env {
                expand(format!("backends.{name}.env.{key}"), value);
            }
        }
        for (i, dir) in self.capabilities.directories.iter_mut().enumerate() {
            expand(format!("capabilities.directories[{i}]"), dir);
        }
        if !unresolved.is_empty() {
            // The env: secrets are checked later, in validation; report them
            // here too so one load names every unresolved reference.
            unresolved.extend(self.required_reference_errors(overlay));
            return Err(Self::unresolved_error(&unresolved, overlay));
        }

        Ok(self.resolve_secret_refs(overlay))
    }

    /// Substitute `env:NAME` secret references with the value the overlay holds.
    ///
    /// Done here, once, rather than at each holder's construction: an env file
    /// no longer reaches the process environment, so a holder built from a bare
    /// `AuthConfig` has nothing to look the name up in. Resolving at evaluation
    /// time also makes the startup-only nature of these secrets explicit — the
    /// value a holder captured is the value the file held when the process
    /// started, and a reload cannot revise it.
    ///
    /// A reference that does not resolve (unset or empty) is left verbatim.
    /// `validate_with_env` reports it, which is a better diagnostic than a
    /// silently empty secret.
    fn resolve_secret_refs(&mut self, overlay: &EnvOverlay) -> SecretRefsRead {
        let mut seen = BTreeSet::new();
        let mut files = SecretFileDigests::new();
        // Records the reference and returns the value it resolves to. A file is
        // read once: the digest reload compares is of the bytes substituted.
        let mut record = |slot: &str, seen: &mut BTreeSet<String>| match SecretRef::parse(slot) {
            SecretRef::Env(name) => {
                seen.insert(name.to_string());
                SecretRef::Env(name).resolve("", overlay).ok()
            }
            SecretRef::File(path) => {
                let value = secret_ref::read_file_ref("", path).ok();
                files.insert(path.to_path_buf(), value.as_deref().map(digest));
                value
            }
            SecretRef::Literal(_) => None,
        };
        // A literal stays as written; an empty one is `validate_with_env`'s to
        // report, like an unresolved reference left verbatim.
        let mut subst = |slot: &mut String, seen: &mut BTreeSet<String>| {
            if let Some(value) = record(slot, seen) {
                *slot = value;
            }
        };

        if let Some(token) = self.auth.bearer_token.as_mut() {
            subst(token, &mut seen);
        }
        for key in &mut self.auth.api_keys {
            if let Some(digest) = key.key_sha256.as_mut() {
                subst(digest, &mut seen);
            }
        }
        for agent in &mut self.agent_auth.agents {
            if let Some(secret) = agent.hs256_secret.as_mut() {
                subst(secret, &mut seen);
            }
        }
        if let Some(token) = self.key_server.admin_token.as_mut() {
            subst(token, &mut seen);
        }
        // Names and digests only: `resolve_metrics_token` reads the reference
        // itself, so the spelling stays. Without this a rotated token was
        // never reported and the route kept the one it was built with (#2251).
        if let Some(token) = &self.server.metrics_token {
            let _names_only = record(token, &mut seen);
        }
        (seen, files)
    }

    /// Get enabled backends only.
    pub fn enabled_backends(&self) -> impl Iterator<Item = (&String, &BackendConfig)> {
        self.backends.iter().filter(|(_, b)| b.enabled)
    }
}

fn remote_transport_identity(transport: &TransportConfig) -> Option<(&'static str, &str)> {
    match transport {
        TransportConfig::Http { http_url, .. } => Some((transport.transport_type(), http_url)),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url, .. } => Some((transport.transport_type(), a2a_url)),
        TransportConfig::WebSocket { ws_url, .. } => Some((transport.transport_type(), ws_url)),
        TransportConfig::Stdio { .. } => None,
    }
}

pub use backend_config::{BackendConfig, OAuthConfig, TransportConfig};
use backend_config::{default_token_refresh_buffer, default_true};
pub use meta_mcp_config::{MetaMcpConfig, SurfacedToolConfig};
pub use server_config::{CleartextHttp, IdempotencyKeyMode, ServerConfig};

// ── humantime_serde ───────────────────────────────────────────────────────────

/// Custom humantime serde module for `Duration`.
pub mod humantime_serde;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod backend_url_tests;
#[cfg(test)]
mod secret_file_ref_tests;
#[cfg(test)]
mod secret_ref_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "cwe532_debug_redaction_tests.rs"]
mod cwe532_debug_redaction;

#[cfg(test)]
#[path = "cleartext_credential_guard_tests.rs"]
mod cleartext_credential_guard;

#[cfg(test)]
#[path = "account_custody_tests.rs"]
mod account_custody_tests;

#[cfg(test)]
#[path = "account_secret_order_tests.rs"]
mod account_secret_order_tests;

#[cfg(test)]
#[path = "account_consumer_config_tests.rs"]
mod account_consumer_config_tests;

#[cfg(test)]
#[path = "descriptor_config_tests.rs"]
mod descriptor_config_tests;
