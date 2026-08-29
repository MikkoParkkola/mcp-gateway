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

pub use crate::config_persistence::{load_config_or_default, write_config};
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

/// Add a new backend to the in-memory config.
///
/// Returns `Err` if a backend with `name` already exists.
///
/// # Errors
///
/// `Err(String)` when `name` already exists in `config.backends`.
pub fn add_backend<S: std::hash::BuildHasher>(
    config: &mut Config,
    name: &str,
    transport: TransportConfig,
    description: String,
    env: HashMap<String, String, S>,
) -> Result<(), String> {
    if config.backends.contains_key(name) {
        return Err(format!("Backend '{name}' already exists. Remove it first."));
    }

    // Collect into a standard HashMap so it matches BackendConfig.env's field type.
    let env: HashMap<String, String> = env.into_iter().collect();

    let backend = BackendConfig {
        description,
        enabled: true,
        transport,
        env,
        ..Default::default()
    };

    config.backends.insert(name.to_string(), backend);
    Ok(())
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
    let backend = config
        .backends
        .get_mut(name)
        .ok_or_else(|| format!("Backend '{name}' not found."))?;

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

/// Determine transport and description from explicit flags or the built-in registry.
///
/// Priority: explicit `cmd` > explicit `url` > registry lookup by `name`.
///
/// # Errors
///
/// Returns `Err` when none of the sources can satisfy the request (unknown name
/// without an explicit `cmd` or `url`).
pub fn resolve_transport(
    name: &str,
    cmd: Option<&str>,
    url: Option<&str>,
    desc: Option<&str>,
) -> Result<(TransportConfig, String), String> {
    // Explicit command takes priority.
    if let Some(command) = cmd {
        return Ok((
            TransportConfig::Stdio {
                command: command.to_string(),
                cwd: None,
                protocol_version: None,
            },
            desc.unwrap_or("").to_string(),
        ));
    }

    // Explicit URL.
    if let Some(http_url) = url {
        return Ok((
            TransportConfig::Http {
                http_url: http_url.to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            desc.unwrap_or("").to_string(),
        ));
    }

    // Registry lookup.
    if let Some(entry) = server_registry::lookup(name) {
        let transport = match entry.transport {
            server_registry::Transport::Stdio => TransportConfig::Stdio {
                command: entry.command.to_string(),
                cwd: None,
                protocol_version: None,
            },
            server_registry::Transport::Http { default_url } => TransportConfig::Http {
                http_url: default_url.to_string(),
                streamable_http: false,
                protocol_version: None,
            },
        };
        return Ok((transport, desc.unwrap_or(entry.description).to_string()));
    }

    Err(format!(
        "'{name}' is not in the built-in registry. Provide --command or --url."
    ))
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
    match shlex::split(command) {
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
mod tests {
    use super::*;

    fn empty_config() -> Config {
        Config::default()
    }

    fn stdio_transport(cmd: &str) -> TransportConfig {
        TransportConfig::Stdio {
            command: cmd.to_string(),
            cwd: None,
            protocol_version: None,
        }
    }

    fn http_transport(url: &str) -> TransportConfig {
        TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        }
    }

    // ── add_backend ───────────────────────────────────────────────────────────

    #[test]
    fn add_backend_inserts_entry() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "my-server",
            stdio_transport("node server.js"),
            "My server".to_string(),
            HashMap::new(),
        )
        .unwrap();

        let b = cfg.backends.get("my-server").unwrap();
        assert_eq!(b.description, "My server");
        assert!(b.enabled);
        match &b.transport {
            TransportConfig::Stdio { command, .. } => assert_eq!(command, "node server.js"),
            TransportConfig::Http { .. } => panic!("expected Stdio"),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => panic!("expected Stdio"),
        }
    }

    #[test]
    fn add_backend_duplicate_returns_error() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "dup",
            stdio_transport("cmd"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let err = add_backend(
            &mut cfg,
            "dup",
            stdio_transport("cmd"),
            String::new(),
            HashMap::new(),
        )
        .unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn add_backend_stores_env_vars() {
        let mut cfg = empty_config();
        let env = HashMap::from([("API_KEY".to_string(), "secret".to_string())]);
        add_backend(&mut cfg, "svc", stdio_transport("cmd"), String::new(), env).unwrap();

        assert_eq!(
            cfg.backends["svc"].env.get("API_KEY").map(String::as_str),
            Some("secret")
        );
    }

    // ── remove_backend ────────────────────────────────────────────────────────

    #[test]
    fn remove_backend_deletes_existing() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "to-remove",
            stdio_transport("cmd"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        remove_backend(&mut cfg, "to-remove").unwrap();
        assert!(!cfg.backends.contains_key("to-remove"));
    }

    #[test]
    fn remove_backend_missing_returns_error() {
        let mut cfg = empty_config();
        let err = remove_backend(&mut cfg, "ghost").unwrap_err();
        assert!(err.contains("not found"));
    }

    // ── update_backend ────────────────────────────────────────────────────────

    #[test]
    fn update_backend_changes_description() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "svc",
            stdio_transport("cmd"),
            "old desc".to_string(),
            HashMap::new(),
        )
        .unwrap();

        update_backend(
            &mut cfg,
            "svc",
            BackendUpdate {
                description: Some("new desc".to_string()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(cfg.backends["svc"].description, "new desc");
    }

    #[test]
    fn update_backend_partial_leaves_other_fields_intact() {
        let mut cfg = empty_config();
        let env = HashMap::from([("K".to_string(), "V".to_string())]);
        add_backend(
            &mut cfg,
            "svc",
            stdio_transport("original-cmd"),
            "desc".to_string(),
            env,
        )
        .unwrap();

        update_backend(
            &mut cfg,
            "svc",
            BackendUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

        let b = &cfg.backends["svc"];
        assert!(!b.enabled);
        assert_eq!(b.description, "desc"); // unchanged
        assert_eq!(b.env.get("K").map(String::as_str), Some("V")); // unchanged
    }

    #[test]
    fn update_backend_missing_returns_error() {
        let mut cfg = empty_config();
        let err = update_backend(&mut cfg, "ghost", BackendUpdate::default()).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn update_backend_replaces_transport() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "svc",
            stdio_transport("old"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        update_backend(
            &mut cfg,
            "svc",
            BackendUpdate {
                transport: Some(http_transport("http://localhost:9000")),
                ..Default::default()
            },
        )
        .unwrap();

        match &cfg.backends["svc"].transport {
            TransportConfig::Http { http_url, .. } => {
                assert_eq!(http_url, "http://localhost:9000");
            }
            TransportConfig::Stdio { .. } => panic!("expected Http after update"),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => panic!("expected Http after update"),
        }
    }

    // ── list_backends ─────────────────────────────────────────────────────────

    #[test]
    fn list_backends_returns_sorted_names() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "zebra",
            stdio_transport("z"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();
        add_backend(
            &mut cfg,
            "alpha",
            stdio_transport("a"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let list = list_backends(&cfg);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "zebra");
    }

    #[test]
    fn list_backends_empty_config_returns_empty_vec() {
        let cfg = empty_config();
        assert!(list_backends(&cfg).is_empty());
    }

    #[test]
    fn list_backends_http_transport_sets_url_field() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "remote",
            http_transport("https://api.example.com/mcp"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let info = &list_backends(&cfg)[0];
        assert_eq!(info.transport, "http");
        // Origin only. The path is dropped because a webhook-style URL keeps its
        // whole secret there (MIK-7221).
        assert_eq!(info.url.as_deref(), Some("https://api.example.com"));
        assert!(info.command.is_none());
    }

    #[test]
    fn list_backends_stdio_transport_sets_command_field() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "local",
            stdio_transport("npx my-server"),
            String::new(),
            HashMap::new(),
        )
        .unwrap();

        let info = &list_backends(&cfg)[0];
        assert_eq!(info.transport, "stdio");
        // The executable is reported; the arguments are counted, never shown.
        // This assertion used to read `Some("npx my-server")` — the whole command
        // string, which is where an `--api-key` would have been (MIK-7221).
        let command = info.command.as_ref().expect("stdio backend has a command");
        assert_eq!(command.executable, "npx");
        assert_eq!(command.argument_count, 1);
        assert!(info.url.is_none());
    }

    // ── get_backend ───────────────────────────────────────────────────────────

    #[test]
    fn get_backend_returns_info_for_known_name() {
        let mut cfg = empty_config();
        add_backend(
            &mut cfg,
            "known",
            stdio_transport("cmd"),
            "description".to_string(),
            HashMap::new(),
        )
        .unwrap();

        let info = get_backend(&cfg, "known").unwrap();
        assert_eq!(info.name, "known");
        assert_eq!(info.description, "description");
    }

    #[test]
    fn get_backend_missing_returns_error() {
        let cfg = empty_config();
        let err = get_backend(&cfg, "missing").unwrap_err();
        assert!(err.contains("not found"));
    }

    // ── resolve_transport ─────────────────────────────────────────────────────

    #[test]
    fn resolve_transport_explicit_command_takes_priority() {
        let (transport, _) = resolve_transport("tavily", Some("my-cmd"), None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => assert_eq!(command, "my-cmd"),
            TransportConfig::Http { .. } => panic!("expected Stdio"),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => panic!("expected Stdio"),
        }
    }

    #[test]
    fn resolve_transport_explicit_url() {
        let (transport, _) =
            resolve_transport("custom", None, Some("http://localhost:9000"), None).unwrap();
        match transport {
            TransportConfig::Http { http_url, .. } => assert_eq!(http_url, "http://localhost:9000"),
            TransportConfig::Stdio { .. } => panic!("expected Http"),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => panic!("expected Http"),
        }
    }

    #[test]
    fn resolve_transport_registry_lookup_for_known_name() {
        let (transport, description) = resolve_transport("tavily", None, None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => {
                assert!(command.contains("tavily"));
            }
            TransportConfig::Http { .. } => panic!("expected Stdio for tavily"),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => panic!("expected Stdio for tavily"),
        }
        assert!(!description.is_empty());
    }

    #[test]
    fn resolve_transport_unknown_name_without_flags_returns_error() {
        let result = resolve_transport("totally-unknown-server-xyz", None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_transport_desc_override_applies_for_registry_entry() {
        let (_, description) =
            resolve_transport("tavily", None, None, Some("my custom desc")).unwrap();
        assert_eq!(description, "my custom desc");
    }

    // ── parse_env_vars ────────────────────────────────────────────────────────

    #[test]
    fn parse_env_vars_valid_pairs_returns_map() {
        let vars = vec!["KEY=value".to_string(), "FOO=bar".to_string()];
        let map = parse_env_vars(&vars).unwrap();
        assert_eq!(map["KEY"], "value");
        assert_eq!(map["FOO"], "bar");
    }

    #[test]
    fn parse_env_vars_value_contains_equals_keeps_full_value() {
        let vars = vec!["URL=http://host:80/path?a=b".to_string()];
        let map = parse_env_vars(&vars).unwrap();
        assert_eq!(map["URL"], "http://host:80/path?a=b");
    }

    #[test]
    fn parse_env_vars_missing_equals_returns_error() {
        let vars = vec!["NOEQUALS".to_string()];
        assert!(parse_env_vars(&vars).is_err());
    }

    #[test]
    fn parse_env_vars_empty_slice_returns_empty_map() {
        let map = parse_env_vars(&[]).unwrap();
        assert!(map.is_empty());
    }

    // ── backend_to_info (via list/get) ────────────────────────────────────────

    #[test]
    fn backend_info_serializes_to_json() {
        let mut cfg = empty_config();
        let env = HashMap::from([("TOKEN".to_string(), "abc".to_string())]);
        add_backend(
            &mut cfg,
            "svc",
            http_transport("https://svc.example.com"),
            "A service".to_string(),
            env,
        )
        .unwrap();

        let info = get_backend(&cfg, "svc").unwrap();
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"svc\""));
        assert!(json.contains("\"transport\":\"http\""));
        assert!(json.contains("\"enabled\":true"));
        // The name is reported, the value never is. This assertion used to read
        // `json.contains("\"TOKEN\":\"abc\"")` — it asserted the leak, and passed
        // for as long as the leak existed (MIK-7221).
        assert!(json.contains("\"TOKEN\""), "the variable NAME is reported");
        assert!(
            !json.contains("abc"),
            "the VALUE must never be serialised: {json}"
        );
        // command should not appear for http transport
        assert!(!json.contains("\"command\""));
    }
}

#[cfg(test)]
mod stop_when_idle_ui_tests {
    use super::*;

    fn stdio_backend() -> BackendConfig {
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "echo hi".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..BackendConfig::default()
        }
    }

    fn http_backend() -> BackendConfig {
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "http://127.0.0.1:39400/mcp".to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            ..BackendConfig::default()
        }
    }

    fn config_with(name: &str, backend: BackendConfig) -> Config {
        let mut c = Config::default();
        c.backends.insert(name.to_string(), backend);
        c
    }

    // GW.IDLE.10 - settable from the panel on a backend the gateway starts.
    #[test]
    fn panel_can_set_and_clear_stop_when_idle_on_an_owned_backend() {
        let mut config = config_with("owned", stdio_backend());

        update_backend(
            &mut config,
            "owned",
            BackendUpdate {
                stop_when_idle_for: Some(Some(Duration::from_secs(300))),
                ..Default::default()
            },
        )
        .expect("an owned backend may opt in");
        assert_eq!(
            config.backends["owned"].stop_when_idle_for,
            Some(Duration::from_secs(300))
        );

        // And it must be switchable back off, or the panel is a one-way door.
        update_backend(
            &mut config,
            "owned",
            BackendUpdate {
                stop_when_idle_for: Some(None),
                ..Default::default()
            },
        )
        .expect("clearing must be possible");
        assert_eq!(config.backends["owned"].stop_when_idle_for, None);
    }

    // The panel must refuse, not silently drop. Silently dropping is exactly how
    // `idle_timeout` came to sit on 24 backends doing nothing.
    #[test]
    fn panel_refuses_stop_when_idle_on_a_backend_the_gateway_does_not_start() {
        let mut config = config_with("external", http_backend());

        let err = update_backend(
            &mut config,
            "external",
            BackendUpdate {
                stop_when_idle_for: Some(Some(Duration::from_secs(300))),
                ..Default::default()
            },
        )
        .expect_err("the gateway cannot stop a process it did not start");

        assert!(err.contains("external"), "must name the backend: {err}");
        assert_eq!(
            config.backends["external"].stop_when_idle_for, None,
            "a refused update must not partially apply"
        );
    }

    // An omitted field must leave the existing setting alone.
    #[test]
    fn an_unrelated_panel_edit_does_not_disturb_the_setting() {
        let mut config = config_with("owned", stdio_backend());
        config.backends.get_mut("owned").unwrap().stop_when_idle_for =
            Some(Duration::from_secs(600));

        update_backend(
            &mut config,
            "owned",
            BackendUpdate {
                description: Some("renamed".to_string()),
                ..Default::default()
            },
        )
        .expect("update");

        assert_eq!(
            config.backends["owned"].stop_when_idle_for,
            Some(Duration::from_secs(600)),
            "editing the description must not silently clear an unrelated setting"
        );
    }

    // The panel needs to know whether to offer the control at all.
    #[test]
    fn backend_info_reports_whether_the_control_is_offerable() {
        let owned = config_with("owned", stdio_backend());
        let external = config_with("external", http_backend());

        assert!(
            get_backend(&owned, "owned")
                .expect("info")
                .can_stop_when_idle,
            "a gateway-started backend can be stopped"
        );
        assert!(
            !get_backend(&external, "external")
                .expect("info")
                .can_stop_when_idle,
            "the panel must hide the control for a backend the gateway did not start"
        );
    }
}
