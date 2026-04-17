//! Reusable backend management operations for both CLI and HTTP handlers.
//!
//! This module extracts the core add/remove/update/list logic from the CLI
//! commands into pure functions that operate on `&mut Config` and return
//! `Result<T, String>` instead of `ExitCode`.  The CLI commands delegate here;
//! future HTTP handlers can call the same functions directly.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use crate::config_persistence::{load_config_or_default, write_config};
use crate::{
    config::{BackendConfig, Config, TransportConfig},
    registry::server_registry,
};

// ── Public data types ─────────────────────────────────────────────────────────

/// Structured summary of a single backend, safe to serialise as JSON.
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
    /// Command (stdio only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// URL (http only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Environment variables.
    pub env: HashMap<String, String>,
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
            ("stdio".to_string(), Some(command.clone()), None)
        }
        TransportConfig::Http { http_url, .. } => {
            ("http".to_string(), None, Some(http_url.clone()))
        }
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url, .. } => ("a2a".to_string(), None, Some(a2a_url.clone())),
    };

    BackendInfo {
        name: name.to_string(),
        description: backend.description.clone(),
        transport: transport_kind,
        enabled: backend.enabled,
        command,
        url,
        env: backend.env.clone(),
    }
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
        assert_eq!(info.url.as_deref(), Some("https://api.example.com/mcp"));
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
        assert_eq!(info.command.as_deref(), Some("npx my-server"));
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
        assert!(json.contains("\"TOKEN\":\"abc\""));
        // command should not appear for http transport
        assert!(!json.contains("\"command\""));
    }
}
