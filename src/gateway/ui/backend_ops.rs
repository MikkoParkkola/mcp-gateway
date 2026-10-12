// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reusable backend management operations for both CLI and HTTP handlers.
//!
//! This module extracts the core add/remove/update/list logic from the CLI
//! commands into pure functions that operate on `&mut Config` and return
//! `Result<T, String>` instead of `ExitCode`.  The CLI commands delegate here;
//! future HTTP handlers can call the same functions directly.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use crate::config_persistence::load_config_or_default;
#[allow(deprecated)] // the deprecated writer stays reachable by name until 5.0
pub use crate::config_persistence::write_config;
use crate::{
    config::{BackendConfig, Config, TransportConfig},
    registry::server_registry,
};

// ── Public data types ─────────────────────────────────────────────────────────

/// Structured summary of a single backend, safe to serialise as JSON.
///
/// "Safe" is the point of this type, not a description of it. Every field is a
/// name, a count or a scrubbed URL — with ONE deliberate exception: `description`
/// is operator-authored display text and is reproduced verbatim, because a list
/// of backends without it is unusable. An operator who puts a credential in a
/// description defeats this type, and no code here can tell that text apart from
/// the label it is meant to be. Everything else is redacted. Before
/// 2026-08-22 this carried `command: Option<String>`, `url: Option<String>` and
/// `env: HashMap<String, String>` verbatim from the config, so `get` and
/// `list --json` printed API keys in the clear — reproduced on `0373dca0` with
/// five canary secrets, all five visible (MIK-7221).
///
/// Adding a field that holds a configured value re-opens that. If a caller needs
/// one, it should read the config directly and take responsibility, rather than
/// widening a type whose contract is that it can be pasted into a bug report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendInfo {
    /// Backend key in the config map.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Transport kind: `"stdio"` or `"http"`.
    pub transport: String,
    /// Whether the backend is enabled.
    pub enabled: bool,
    /// Presence-only command summary (stdio only); arguments are never exposed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<BackendCommandInfo>,
    /// URL (http only), reduced to its ORIGIN. The path goes too — a webhook URL
    /// carries its whole secret there. See `redact_url_for_diagnostics`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Sorted environment-variable names; values are never exposed.
    pub env: Vec<String>,
    /// Sorted configured-header names; values are never exposed.
    pub headers: Vec<String>,
    /// Seconds of idleness after which the gateway stops this backend, or
    /// `None` when it is never stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_when_idle_for_secs: Option<u64>,
    /// Whether this backend can be stopped when idle at all. False for a backend
    /// reached over a URL the gateway did not start: it can close the connection
    /// but cannot stop the server. The panel should hide or disable the control
    /// rather than let an operator set something that will be refused.
    pub can_stop_when_idle: bool,
}

/// Secret-safe summary of a configured stdio command.
///
/// A command line is a common hiding place for a credential
/// (`some-server --api-key sk-…`), so the executable is reported and the
/// arguments are counted, never shown.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendCommandInfo {
    /// Parsed executable token.
    pub executable: String,
    /// Number of configured arguments, whose values are redacted.
    pub argument_count: usize,
}

/// Partial update applied by [`update_backend`].
///
/// `None` fields are left unchanged.
#[derive(Debug, Clone, Default)]
pub struct BackendUpdate {
    /// New description (replaces existing when `Some`).
    pub description: Option<String>,
    /// Replace the entire env map (merged when `Some`).
    pub env: Option<HashMap<String, String>>,
    /// Enable or disable the backend.
    pub enabled: Option<bool>,
    /// Replace the transport (overrides existing when `Some`).
    pub transport: Option<TransportConfig>,
    /// Stop this backend when it has been idle this long, or clear the setting.
    ///
    /// Double `Option` on purpose: the outer layer distinguishes "the panel did
    /// not send this field" (leave it alone) from "the panel sent it" (apply),
    /// and the inner one carries `None` to mean "never stop". Collapsing them
    /// would make the setting impossible to turn off once enabled.
    pub stop_when_idle_for: Option<Option<Duration>>,
}

// ── Core operations ───────────────────────────────────────────────────────────

/// Add a resolved backend to the in-memory config.
///
/// Returns what the caller should tell the user (why it was added disabled),
/// one line each; empty when there is nothing to say.
///
/// # Errors
///
/// `Err(String)` when `name` already exists in `config.backends`.
pub fn add_backend(
    config: &mut Config,
    name: &str,
    resolved: ResolvedBackend,
) -> Result<Vec<String>, String> {
    if config.backends.contains_key(name) {
        return Err(format!("Backend '{name}' already exists. Remove it first."));
    }
    let mut backend = resolved.backend;
    let mut notes = Vec::new();
    if let Some(entry) = resolved.entry {
        if let server_registry::Reach::Arbitrary { reason } = entry.reach
            && !entry.reach_allows_on()
        {
            notes.push(format!("Added disabled. {reason}"));
        }
        // The registry path takes no arguments, and the command does not
        // start without them (MIK-7816).
        if let server_registry::Setup::NeedsArgs { hint } = entry.setup {
            backend.enabled = false;
            notes.push(format!(
                "Added disabled. Append {hint} to its command, then set `enabled: true`."
            ));
        }
        if entry.auth == server_registry::Auth::OAuth {
            notes.push(
                "Logs in through your browser on first use. On a multi-user gateway the \
                 stored token is refused to other users unless oauth.shared_account is true."
                    .to_string(),
            );
        }
    }
    if let Some(entry) = resolved.entry {
        // The child environment is cleared, so an optional variable the gateway
        // itself holds (process env or env_files) reaches the server only when
        // named. Forward it when set and non-empty; leave it out otherwise, so
        // an unset one neither blocks enabling nor reaches the child empty.
        let overlay = config.env_overlay();
        for var in entry.optional_env {
            if overlay.resolve(var).is_some_and(|v| !v.is_empty()) {
                backend
                    .env
                    .entry((*var).to_string())
                    .or_insert_with(|| format!("${{{var}}}"));
            }
        }
    }
    if backend.enabled {
        // The loader refuses an enabled backend whose reference resolves to
        // nothing (C4); writing one would break the next start.
        let unresolved = backend.unresolved_references(name, &config.env_overlay());
        if !unresolved.is_empty() {
            backend.enabled = false;
            notes.push(
                "Added disabled until these resolve; set them in the environment or an \
                 env_files entry, then set `enabled: true`:"
                    .to_string(),
            );
            notes.extend(unresolved);
        }
    }
    config.backends.insert(name.to_string(), backend);
    Ok(notes)
}

/// Remove a backend from the in-memory config.
///
/// # Errors
///
/// `Err(String)` when no backend with `name` exists.
pub fn remove_backend(config: &mut Config, name: &str) -> Result<(), String> {
    if config.backends.remove(name).is_none() {
        return Err(format!("Backend '{name}' not found."));
    }
    Ok(())
}

/// Apply a partial update to an existing backend.
///
/// Only fields set to `Some` in `update` are written; others are untouched.
///
/// # Errors
///
/// `Err(String)` when no backend with `name` exists.
pub fn update_backend(
    config: &mut Config,
    name: &str,
    update: BackendUpdate,
) -> Result<(), String> {
    let overlay = config.env_overlay();
    let slot = config
        .backends
        .get_mut(name)
        .ok_or_else(|| format!("Backend '{name}' not found."))?;
    // Applied to a copy: a refused update leaves the config untouched.
    let mut backend = slot.clone();

    if let Some(desc) = update.description {
        backend.description = desc;
    }
    if let Some(env) = update.env {
        backend.env = env;
    }
    if let Some(enabled) = update.enabled {
        backend.enabled = enabled;
    }
    if let Some(transport) = update.transport {
        backend.transport = transport;
    }
    if let Some(idle) = update.stop_when_idle_for {
        // Refuse rather than silently drop. The panel is a place operators trust
        // to tell them what is in effect; accepting a setting the gateway cannot
        // honour is how `idle_timeout` came to sit on 24 backends doing nothing.
        if idle.is_some() && !matches!(backend.transport, TransportConfig::Stdio { .. }) {
            return Err(format!(
                "Backend '{name}' is reached over a URL the gateway did not start, so the \
                 gateway cannot stop it. 'Stop when idle' is available only for backends the \
                 gateway launches itself (those with a command)."
            ));
        }
        backend.stop_when_idle_for = idle;
    }

    // Same rule as `add_backend`, after every field is applied: an enabled
    // backend with an unresolved reference makes the next load fail (C4), so
    // the update is refused and the caller writes nothing.
    if backend.enabled {
        let unresolved = backend.unresolved_references(name, &overlay);
        if !unresolved.is_empty() {
            return Err(format!(
                "Backend '{name}' cannot be enabled with unresolved references: {}",
                unresolved.join("; ")
            ));
        }
    }

    *slot = backend;
    Ok(())
}

/// Return structured info for all backends in alphabetical order.
pub fn list_backends(config: &Config) -> Vec<BackendInfo> {
    let mut names: Vec<&String> = config.backends.keys().collect();
    names.sort();
    names
        .into_iter()
        .map(|n| backend_to_info(n, &config.backends[n]))
        .collect()
}

/// Return structured info for a single backend.
///
/// # Errors
///
/// `Err(String)` when no backend with `name` exists.
pub fn get_backend(config: &Config, name: &str) -> Result<BackendInfo, String> {
    config
        .backends
        .get(name)
        .map(|b| backend_to_info(name, b))
        .ok_or_else(|| format!("Backend '{name}' not found."))
}

// ── Transport resolution ──────────────────────────────────────────────────────

/// A backend ready to insert, and the registry entry it came from, if any.
#[derive(Clone)]
pub struct ResolvedBackend {
    /// The whole backend `add` writes.
    pub backend: BackendConfig,
    /// The registry entry it was built from; `None` for `--command`/`--url`.
    pub entry: Option<&'static server_registry::RegistryEntry>,
}

/// Build the backend `add` writes, from explicit flags or the built-in registry.
///
/// Priority: explicit `cmd` > explicit `url` > registry lookup by `name`.
/// `env` holds the user's `KEY=VALUE` pairs.
///
/// # Errors
///
/// Returns `Err` when none of the sources can satisfy the request (a name the
/// registry does not know, with no explicit `cmd` or `url`).
pub fn resolve_backend<S: std::hash::BuildHasher>(
    name: &str,
    cmd: Option<&str>,
    url: Option<&str>,
    desc: Option<&str>,
    env: HashMap<String, String, S>,
) -> Result<ResolvedBackend, String> {
    // Collect into a standard HashMap so it matches BackendConfig.env's field type.
    let env: HashMap<String, String> = env.into_iter().collect();
    let plain = |transport, description: &str| ResolvedBackend {
        backend: BackendConfig {
            description: description.to_string(),
            enabled: true,
            transport,
            env: env.clone(),
            ..Default::default()
        },
        entry: None,
    };

    // Explicit command takes priority.
    if let Some(command) = cmd {
        let transport = TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        };
        return Ok(plain(transport, desc.unwrap_or("")));
    }

    // Explicit URL.
    if let Some(url) = url {
        return Ok(plain(TransportConfig::for_url(url), desc.unwrap_or("")));
    }

    // Registry lookup.
    if let Some(entry) = server_registry::lookup(name) {
        return Ok(ResolvedBackend {
            backend: registry_backend(entry, desc, env),
            entry: Some(entry),
        });
    }

    Err(format!(
        "'{name}' is not in the built-in registry. Provide --command or --url."
    ))
}

/// The backend a registry entry describes, with the user's `-e` values.
///
/// Stdio: each required variable becomes `${NAME}` in `env` (the child
/// environment is cleared, so nothing else would reach it) unless `-e` gave a
/// value. HTTP: an OAuth entry gets an enabled `oauth:` stanza, so the existing
/// backend OAuth flow runs; a header entry gets its template, with a `-e`
/// value substituted in place because `headers` expand from the overlay, never
/// from `backend.env`. Enabled unless its reach is arbitrary; readiness of the
/// references is decided later, in [`add_backend`], against the target config.
fn registry_backend(
    entry: &server_registry::RegistryEntry,
    desc: Option<&str>,
    mut env: HashMap<String, String>,
) -> BackendConfig {
    use server_registry::{Auth, HttpFlavor, Transport};

    // An empty `-e VAR=` for a required variable is no value: the reference
    // stays, so the unresolved check in `add_backend` sees it (MIK-7816).
    env.retain(|key, value| !(value.is_empty() && entry.required_env.contains(&key.as_str())));

    let mut backend = BackendConfig {
        description: desc.unwrap_or(entry.description).to_string(),
        enabled: entry.reach_allows_on(),
        ..Default::default()
    };
    match entry.transport {
        Transport::Stdio => {
            backend.transport = TransportConfig::Stdio {
                command: entry.command.to_string(),
                cwd: None,
                protocol_version: None,
            };
            for var in entry.required_env {
                env.entry((*var).to_string())
                    .or_insert_with(|| format!("${{{var}}}"));
            }
            backend.env = env;
        }
        Transport::Http {
            default_url,
            flavor,
        } => {
            backend.transport = TransportConfig::Http {
                http_url: default_url.to_string(),
                streamable_http: Some(flavor == HttpFlavor::Streamable),
                protocol_version: None,
            };
            match entry.auth {
                Auth::OAuth => backend.oauth = Some(crate::config::OAuthConfig::default()),
                Auth::Header { name, value } => {
                    let mut value = value.to_string();
                    for var in entry.required_env {
                        if let Some(given) = env.remove(*var) {
                            value = value.replace(&format!("${{{var}}}"), &given);
                        }
                    }
                    backend.headers.insert(name.to_string(), value);
                }
                Auth::None | Auth::EnvVars => {}
            }
            backend.env = env;
        }
    }
    backend
}

/// Transport and description only, for tests that check routing.
#[cfg(test)]
pub(crate) fn resolve_parts(
    name: &str,
    cmd: Option<&str>,
    url: Option<&str>,
    desc: Option<&str>,
) -> Result<(TransportConfig, String), String> {
    resolve_backend(name, cmd, url, desc, HashMap::new())
        .map(|resolved| (resolved.backend.transport, resolved.backend.description))
}

// ── Env-var parsing ───────────────────────────────────────────────────────────

/// Parse a slice of `KEY=VALUE` strings into a `HashMap`.
///
/// The split uses the *first* `=` so values may contain `=` characters.
///
/// # Errors
///
/// Returns `Err` when any element does not contain `=`.
pub fn parse_env_vars(env_vars: &[String]) -> Result<HashMap<String, String>, String> {
    env_vars
        .iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("Invalid env value '{kv}': expected KEY=VALUE"))
        })
        .collect()
}

// ── OpenAPI import ────────────────────────────────────────────────────────────

/// Import an `OpenAPI` spec from a file path and return the generated capability YAML strings.
///
/// Each returned tuple is `(capability_name, yaml_content)`.
///
/// # Errors
///
/// Returns `Err` when the spec cannot be parsed or converted.
pub fn import_openapi_from_file(
    spec_path: &str,
    prefix: Option<&str>,
    auth_key: Option<String>,
) -> Result<Vec<(String, String)>, String> {
    use crate::capability::{AuthTemplate, OpenApiConverter};

    let mut converter = OpenApiConverter::new();
    if let Some(p) = prefix {
        converter = converter.with_prefix(p);
    }
    if let Some(key) = auth_key {
        converter = converter.with_default_auth(AuthTemplate {
            auth_type: "bearer".to_string(),
            key,
            description: "API authentication".to_string(),
        });
    }

    let caps = converter
        .convert_file(spec_path)
        .map_err(|e| format!("Failed to convert OpenAPI spec: {e}"))?;

    caps.into_iter()
        .map(|cap| {
            serde_yaml::to_string(&cap)
                .map(|yaml| (cap.name.clone(), yaml))
                .map_err(|e| format!("Failed to serialize capability '{}': {e}", cap.name))
        })
        .collect()
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn backend_to_info(name: &str, backend: &BackendConfig) -> BackendInfo {
    let (transport_kind, command, url) = match &backend.transport {
        TransportConfig::Stdio { command, .. } => {
            ("stdio".to_string(), Some(summarize_command(command)), None)
        }
        TransportConfig::Http { http_url, .. } => (
            "http".to_string(),
            None,
            Some(sanitize_backend_url(http_url)),
        ),
        TransportConfig::WebSocket { ws_url, .. } => (
            "websocket".to_string(),
            None,
            Some(sanitize_backend_url(ws_url)),
        ),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url, .. } => {
            ("a2a".to_string(), None, Some(sanitize_backend_url(a2a_url)))
        }
    };

    let can_stop_when_idle = matches!(backend.transport, TransportConfig::Stdio { .. });

    // Names only, sorted. Sorting is not cosmetic: it makes the output stable
    // between runs, so a diff of two `list --json` runs shows a configuration
    // change rather than HashMap iteration order.
    let mut env: Vec<String> = backend.env.keys().cloned().collect();
    env.sort();
    let mut headers: Vec<String> = backend.headers.keys().cloned().collect();
    headers.sort();

    BackendInfo {
        name: name.to_string(),
        description: backend.description.clone(),
        transport: transport_kind,
        enabled: backend.enabled,
        stop_when_idle_for_secs: backend.stop_when_idle_for.map(|d| d.as_secs()),
        can_stop_when_idle,
        command,
        url,
        env,
        headers,
    }
}

/// Executable plus argument count. Argument values are never returned.
fn summarize_command(command: &str) -> BackendCommandInfo {
    match crate::transport::split_command(command) {
        Some(parts) if !parts.is_empty() => BackendCommandInfo {
            executable: parts[0].clone(),
            argument_count: parts.len().saturating_sub(1),
        },
        // Unparseable input is reported as such rather than echoed. Echoing the
        // raw string on the error path is the classic way a redaction is undone:
        // an attacker-shaped command that fails to lex would print in full.
        _ => BackendCommandInfo {
            executable: "<invalid-command>".to_string(),
            argument_count: 0,
        },
    }
}

/// Reduce a URL to its origin before it is printed or serialised.
///
/// One line, because the rule and its reasoning live in
/// [`crate::security::sanitize::redact_url_for_diagnostics`]. The operator loses
/// the endpoint path for a backend they configured themselves; that cost is
/// accepted there, once, rather than argued in two places.
fn sanitize_backend_url(raw: &str) -> String {
    crate::security::sanitize::redact_url_for_diagnostics(raw)
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
#[path = "backend_ops_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "backend_add_tests.rs"]
mod backend_add_tests;
