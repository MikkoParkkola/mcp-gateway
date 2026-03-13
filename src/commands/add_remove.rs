//! Implementation of `mcp-gateway add` and `mcp-gateway remove`.
//!
//! `add` creates a new backend entry in gateway.yaml, optionally bootstrapped
//! from the built-in server registry.  `remove` deletes an existing entry.

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use mcp_gateway::{
    config::{BackendConfig, Config, TransportConfig},
    registry::server_registry,
};

// ── add ───────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway add`.
///
/// # Arguments
///
/// * `name` – backend key (also used for registry lookup)
/// * `cmd` – explicit stdio command (overrides registry)
/// * `url` – explicit HTTP URL (overrides registry)
/// * `desc` – description (overrides registry)
/// * `env_vars` – `KEY=VALUE` strings injected as environment variables
/// * `config` – path to the gateway config file
pub async fn run_add_command(
    name: &str,
    cmd: Option<&str>,
    url: Option<&str>,
    desc: Option<&str>,
    env_vars: &[String],
    config: &Path,
) -> ExitCode {
    // ── Resolve transport ──────────────────────────────────────────────────
    let (transport, description) = match resolve_transport(name, cmd, url, desc) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // ── Build env map ──────────────────────────────────────────────────────
    let env = match parse_env_vars(env_vars) {
        Ok(e) => e,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // ── Load config ────────────────────────────────────────────────────────
    let mut gateway_config = load_config(config);

    if gateway_config.backends.contains_key(name) {
        eprintln!(
            "Error: Backend '{}' already exists in {}. Remove it first.",
            name,
            config.display()
        );
        return ExitCode::FAILURE;
    }

    // ── Insert backend ─────────────────────────────────────────────────────
    let backend = BackendConfig {
        description: description.clone(),
        enabled: true,
        transport: transport.clone(),
        env: env.clone(),
        ..Default::default()
    };

    gateway_config.backends.insert(name.to_string(), backend);

    // ── Write config ───────────────────────────────────────────────────────
    if let Err(e) = write_config(config, &gateway_config) {
        eprintln!("Error: Failed to write {}: {e}", config.display());
        return ExitCode::FAILURE;
    }

    // ── Report ─────────────────────────────────────────────────────────────
    let transport_label = match &transport {
        TransportConfig::Stdio { .. } => "stdio",
        TransportConfig::Http { .. } => "http",
    };
    println!("Added '{}' ({transport_label}).", name);

    if let Some(entry) = server_registry::lookup(name) {
        report_env_status(entry.required_env, &env);
    }

    ExitCode::SUCCESS
}

/// Determine transport and description from explicit flags or registry.
fn resolve_transport(
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
        "'{}' is not in the built-in registry. Provide --command or --url.",
        name
    ))
}

/// Parse a slice of `KEY=VALUE` strings into a `HashMap`.
fn parse_env_vars(env_vars: &[String]) -> Result<HashMap<String, String>, String> {
    env_vars
        .iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("Invalid --env value '{kv}': expected KEY=VALUE"))
        })
        .collect()
}

/// Print which required env vars are set and which are missing.
fn report_env_status(required: &[&str], provided_env: &HashMap<String, String>) {
    for key in required {
        let set_in_env = std::env::var(key).is_ok();
        let set_in_config = provided_env.contains_key(*key);
        let status = if set_in_env || set_in_config {
            "set"
        } else {
            "NOT SET"
        };
        println!("  Required: {key} {status}");
    }
}

// ── remove ────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway remove`.
pub fn run_remove_command(name: &str, config: &Path) -> ExitCode {
    let mut gateway_config = load_config(config);

    if gateway_config.backends.remove(name).is_none() {
        eprintln!(
            "Error: Backend '{}' not found in {}.",
            name,
            config.display()
        );
        return ExitCode::FAILURE;
    }

    if let Err(e) = write_config(config, &gateway_config) {
        eprintln!("Error: Failed to write {}: {e}", config.display());
        return ExitCode::FAILURE;
    }

    println!("Removed '{name}'.");
    ExitCode::SUCCESS
}

// ── list ─────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway list`.
pub fn run_list_command(json: bool, config: &Path) -> ExitCode {
    let gateway_config = load_config(config);

    if gateway_config.backends.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("No backends configured in {}.", config.display());
        }
        return ExitCode::SUCCESS;
    }

    if json {
        let entries: Vec<serde_json::Value> = gateway_config
            .backends
            .iter()
            .map(|(name, backend)| {
                serde_json::json!({
                    "name": name,
                    "transport": format_transport(&backend.transport),
                    "description": &backend.description,
                    "enabled": backend.enabled,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_default()
        );
    } else {
        println!(
            "{} backend(s) in {}:\n",
            gateway_config.backends.len(),
            config.display()
        );
        let mut names: Vec<_> = gateway_config.backends.keys().collect();
        names.sort();
        for name in names {
            let backend = &gateway_config.backends[name];
            let transport = format_transport(&backend.transport);
            let desc = if backend.description.is_empty() {
                "(no description)"
            } else {
                &backend.description
            };
            let enabled = if backend.enabled { "" } else { " [disabled]" };
            println!("  {name} ({transport}){enabled}");
            println!("    {desc}");
        }
    }
    ExitCode::SUCCESS
}

// ── get ──────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway get`.
pub fn run_get_command(name: &str, config: &Path) -> ExitCode {
    let gateway_config = load_config(config);

    let Some(backend) = gateway_config.backends.get(name) else {
        eprintln!(
            "Error: Backend '{}' not found in {}.",
            name,
            config.display()
        );
        return ExitCode::FAILURE;
    };

    println!("Name:        {name}");
    println!("Transport:   {}", format_transport(&backend.transport));
    println!(
        "Description: {}",
        if backend.description.is_empty() { "(none)" } else { &backend.description }
    );
    println!("Enabled:     {}", backend.enabled);

    match &backend.transport {
        TransportConfig::Stdio { command, .. } => {
            println!("Command:     {command}");
        }
        TransportConfig::Http { http_url, .. } => {
            println!("URL:         {http_url}");
        }
    }

    if !backend.env.is_empty() {
        println!("Environment:");
        for (k, v) in &backend.env {
            println!("  {k}={v}");
        }
    }

    ExitCode::SUCCESS
}

fn format_transport(t: &TransportConfig) -> &'static str {
    match t {
        TransportConfig::Stdio { .. } => "stdio",
        TransportConfig::Http { .. } => "http",
    }
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

fn load_config(path: &Path) -> Config {
    if path.exists() {
        Config::load(Some(path)).unwrap_or_else(|e| {
            eprintln!("Warning: Could not load config ({e}); using defaults.");
            Config::default()
        })
    } else {
        Config::default()
    }
}

fn write_config(path: &Path, config: &Config) -> Result<(), String> {
    let yaml =
        serde_yaml::to_string(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    std::fs::write(path, yaml).map_err(|e| e.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_config() -> (TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        (dir, path)
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

    // ── resolve_transport ─────────────────────────────────────────────────────

    #[test]
    fn resolve_transport_explicit_command_takes_priority() {
        let (transport, _) = resolve_transport("tavily", Some("my-cmd"), None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => assert_eq!(command, "my-cmd"),
            _ => panic!("expected Stdio"),
        }
    }

    #[test]
    fn resolve_transport_explicit_url() {
        let (transport, _) =
            resolve_transport("custom", None, Some("http://localhost:9000"), None).unwrap();
        match transport {
            TransportConfig::Http { http_url, .. } => {
                assert_eq!(http_url, "http://localhost:9000");
            }
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn resolve_transport_registry_lookup_for_known_name() {
        let (transport, description) = resolve_transport("tavily", None, None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => {
                assert!(command.contains("tavily"), "command should contain tavily");
            }
            _ => panic!("expected Stdio for tavily"),
        }
        assert!(
            !description.is_empty(),
            "registry description must not be empty"
        );
    }

    #[test]
    fn resolve_transport_unknown_name_without_flags_returns_error() {
        let result = resolve_transport("totally-unknown-server-xyz", None, None, None);
        assert!(result.is_err());
    }

    // ── add round-trip ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn add_then_remove_round_trip() {
        // GIVEN: a temp config file
        let (_dir, path) = temp_config();

        // WHEN: adding a backend by registry name
        let code = run_add_command("tavily", None, None, None, &[], &path).await;
        assert_eq!(code, ExitCode::SUCCESS, "add should succeed");

        // THEN: it appears in the config
        let config = Config::load(Some(&path)).unwrap();
        assert!(
            config.backends.contains_key("tavily"),
            "tavily must be present"
        );

        // WHEN: removing it
        let code = run_remove_command("tavily", &path);
        assert_eq!(code, ExitCode::SUCCESS, "remove should succeed");

        // THEN: it is gone
        let config = Config::load(Some(&path)).unwrap();
        assert!(
            !config.backends.contains_key("tavily"),
            "tavily must be gone"
        );
    }

    #[tokio::test]
    async fn add_custom_command_backend() {
        // GIVEN: a temp config
        let (_dir, path) = temp_config();

        // WHEN: adding with an explicit --command
        let code = run_add_command(
            "my-server",
            Some("node /home/user/my-server.js"),
            None,
            Some("My custom server"),
            &["API_KEY=secret123".to_string()],
            &path,
        )
        .await;
        assert_eq!(code, ExitCode::SUCCESS);

        // THEN: the backend has correct fields
        let config = Config::load(Some(&path)).unwrap();
        let backend = config.backends.get("my-server").unwrap();
        assert_eq!(backend.description, "My custom server");
        assert_eq!(
            backend.env.get("API_KEY").map(String::as_str),
            Some("secret123")
        );
    }

    #[tokio::test]
    async fn add_duplicate_returns_failure() {
        // GIVEN: a config that already has "tavily"
        let (_dir, path) = temp_config();
        run_add_command("tavily", None, None, None, &[], &path).await;

        // WHEN: adding again
        let code = run_add_command("tavily", None, None, None, &[], &path).await;

        // THEN: failure
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[test]
    fn remove_nonexistent_backend_returns_failure() {
        let (_dir, path) = temp_config();
        let code = run_remove_command("does-not-exist", &path);
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn add_http_url_backend() {
        // GIVEN: a temp config
        let (_dir, path) = temp_config();

        // WHEN: adding an HTTP backend
        let code = run_add_command(
            "context7",
            None,
            Some("https://mcp.context7.com/mcp"),
            None,
            &[],
            &path,
        )
        .await;
        assert_eq!(code, ExitCode::SUCCESS);

        // THEN: transport is Http
        let config = Config::load(Some(&path)).unwrap();
        let backend = config.backends.get("context7").unwrap();
        match &backend.transport {
            TransportConfig::Http { http_url, .. } => {
                assert_eq!(http_url, "https://mcp.context7.com/mcp");
            }
            _ => panic!("expected Http transport"),
        }
    }
}
