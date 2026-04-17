//! Implementation of `mcp-gateway add` and `mcp-gateway remove`.
//!
//! `add` creates a new backend entry in gateway.yaml, optionally bootstrapped
//! from the built-in server registry.  `remove` deletes an existing entry.
//!
//! All core logic is delegated to [`mcp_gateway::gateway::ui::backend_ops`],
//! which provides `Result<T>` functions usable from both CLI and HTTP handlers.

use std::path::Path;
use std::process::ExitCode;

use mcp_gateway::{
    config::TransportConfig,
    gateway::ui::backend_ops::{
        self, BackendUpdate, add_backend, get_backend, list_backends, parse_env_vars,
        remove_backend, resolve_transport, update_backend, write_config,
    },
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
    let mut gateway_config = backend_ops::load_config_or_default(config);

    // ── Insert backend ─────────────────────────────────────────────────────
    if let Err(msg) = add_backend(
        &mut gateway_config,
        name,
        transport.clone(),
        description,
        env.clone(),
    ) {
        eprintln!("Error: {msg} (in {})", config.display());
        return ExitCode::FAILURE;
    }

    // ── Write config ───────────────────────────────────────────────────────
    if let Err(e) = write_config(config, &gateway_config) {
        eprintln!("Error: Failed to write {}: {e}", config.display());
        return ExitCode::FAILURE;
    }

    // ── Report ─────────────────────────────────────────────────────────────
    let transport_label = match &transport {
        TransportConfig::Stdio { .. } => "stdio",
        TransportConfig::Http { .. } => "http",
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { .. } => "a2a",
    };
    println!("Added '{name}' ({transport_label}).");

    if let Some(entry) = server_registry::lookup(name) {
        report_env_status(entry.required_env, &env);
    }

    ExitCode::SUCCESS
}

/// Print which required env vars are set and which are missing.
fn report_env_status(required: &[&str], provided_env: &std::collections::HashMap<String, String>) {
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
    let mut gateway_config = backend_ops::load_config_or_default(config);

    if let Err(msg) = remove_backend(&mut gateway_config, name) {
        eprintln!("Error: {msg} (in {})", config.display());
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
    let gateway_config = backend_ops::load_config_or_default(config);

    if gateway_config.backends.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("No backends configured in {}.", config.display());
        }
        return ExitCode::SUCCESS;
    }

    let backends = list_backends(&gateway_config);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&backends).unwrap_or_default()
        );
    } else {
        println!("{} backend(s) in {}:\n", backends.len(), config.display());
        for info in &backends {
            let desc = if info.description.is_empty() {
                "(no description)"
            } else {
                &info.description
            };
            let enabled = if info.enabled { "" } else { " [disabled]" };
            println!("  {} ({}){enabled}", info.name, info.transport);
            println!("    {desc}");
        }
    }
    ExitCode::SUCCESS
}

// ── get ──────────────────────────────────────────────────────────────────────

/// Run `mcp-gateway get`.
pub fn run_get_command(name: &str, config: &Path) -> ExitCode {
    let gateway_config = backend_ops::load_config_or_default(config);

    let info = match get_backend(&gateway_config, name) {
        Ok(i) => i,
        Err(msg) => {
            eprintln!("Error: {msg} (in {})", config.display());
            return ExitCode::FAILURE;
        }
    };

    println!("Name:        {name}");
    println!("Transport:   {}", info.transport);
    println!(
        "Description: {}",
        if info.description.is_empty() {
            "(none)"
        } else {
            &info.description
        }
    );
    println!("Enabled:     {}", info.enabled);

    if let Some(cmd) = &info.command {
        println!("Command:     {cmd}");
    }
    if let Some(url) = &info.url {
        println!("URL:         {url}");
    }

    if !info.env.is_empty() {
        println!("Environment:");
        for (k, v) in &info.env {
            println!("  {k}={v}");
        }
    }

    ExitCode::SUCCESS
}

// ── update (used by HTTP handler, not yet wired to a CLI verb) ────────────────

/// Run a programmatic partial update on a backend (no `ExitCode` wrapper).
///
/// Exposed here so the CLI layer has a thin wrapper if needed later.
/// Will be called from HTTP handlers in Task 1.2.
#[allow(dead_code)]
pub fn run_update_backend(name: &str, update: BackendUpdate, config: &Path) -> Result<(), String> {
    let mut gateway_config = backend_ops::load_config_or_default(config);
    update_backend(&mut gateway_config, name, update)?;
    write_config(config, &gateway_config)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::config::{Config, TransportConfig};
    use tempfile::TempDir;

    fn temp_config() -> (TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        (dir, path)
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
            TransportConfig::Stdio { .. } => panic!("expected Http transport"),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => panic!("expected Http transport"),
        }
    }

    // ── get command ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_existing_backend_returns_success() {
        let (_dir, path) = temp_config();
        run_add_command("tavily", None, None, None, &[], &path).await;
        let code = run_get_command("tavily", &path);
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn get_missing_backend_returns_failure() {
        let (_dir, path) = temp_config();
        let code = run_get_command("ghost", &path);
        assert_eq!(code, ExitCode::FAILURE);
    }

    // ── list command ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_returns_success_when_empty() {
        let (_dir, path) = temp_config();
        let code = run_list_command(false, &path);
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn list_json_returns_success_with_backends() {
        let (_dir, path) = temp_config();
        run_add_command("tavily", None, None, None, &[], &path).await;
        let code = run_list_command(true, &path);
        assert_eq!(code, ExitCode::SUCCESS);
    }

    // ── run_update_backend ────────────────────────────────────────────────────

    #[tokio::test]
    async fn update_existing_backend_succeeds() {
        let (_dir, path) = temp_config();
        run_add_command("tavily", None, None, None, &[], &path).await;

        let result = run_update_backend(
            "tavily",
            BackendUpdate {
                description: Some("updated desc".to_string()),
                ..Default::default()
            },
            &path,
        );
        assert!(result.is_ok());

        let config = Config::load(Some(&path)).unwrap();
        assert_eq!(config.backends["tavily"].description, "updated desc");
    }

    #[test]
    fn update_missing_backend_returns_error() {
        let (_dir, path) = temp_config();
        let result = run_update_backend("ghost", BackendUpdate::default(), &path);
        assert!(result.is_err());
    }
}
