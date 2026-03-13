//! CLI command handlers for `mcp-gateway plugin` subcommands.
//!
//! Each function corresponds to a [`PluginCommand`] variant and returns an
//! [`ExitCode`] for the process.  Marketplace URL and plugin-dir resolution
//! follows this priority order (highest to lowest):
//!
//! 1. CLI `--marketplace-url` / `--plugin-dir` flag
//! 2. Config file `marketplace.marketplace_url` / `marketplace.plugin_dir`
//! 3. Built-in defaults (`https://plugins.mcpgateway.io`, `~/.mcp-gateway/plugins`)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mcp_gateway::{
    config::{Config, MarketplaceConfig},
    registry::marketplace::{InstalledPlugin, MarketplaceClient, PluginRegistry},
};

// ── Public entry point ────────────────────────────────────────────────────────

/// Run a `plugin` subcommand.
///
/// Loads config from `config_path` (or uses defaults when `None`) and
/// dispatches to the appropriate handler.
pub async fn run_plugin_search(
    query: &str,
    marketplace_url: Option<&str>,
    config: &Config,
) -> ExitCode {
    let url = resolve_marketplace_url(marketplace_url, &config.marketplace);
    let cache_dir = resolved_plugin_dir(None, &config.marketplace);
    let client = match MarketplaceClient::new(url, &cache_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: failed to create marketplace client: {e}");
            return ExitCode::FAILURE;
        }
    };

    match client.search(query).await {
        Ok(results) if results.is_empty() => {
            println!("No plugins found matching '{query}'.");
            ExitCode::SUCCESS
        }
        Ok(results) => {
            println!("{} plugin(s) found:", results.len());
            for m in &results {
                println!("  {} v{}  —  {}", m.name, m.version, m.description);
                println!(
                    "    author: {}  capabilities: {}",
                    m.author,
                    m.capabilities.join(", ")
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: marketplace search failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Install a plugin by name from the marketplace.
pub async fn run_plugin_install(
    name: &str,
    marketplace_url: Option<&str>,
    plugin_dir: Option<&Path>,
    config: &Config,
) -> ExitCode {
    let url = resolve_marketplace_url(marketplace_url, &config.marketplace);
    let dir = plugin_dir.map_or_else(
        || resolved_plugin_dir(None, &config.marketplace),
        Path::to_path_buf,
    );

    let client = match MarketplaceClient::new(url, &dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: failed to create marketplace client: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("Installing plugin '{name}' from {url} ...");

    match client.install(name, &dir).await {
        Ok(plugin) => {
            if let Err(e) = persist_to_registry(&plugin, &dir) {
                eprintln!("Warning: plugin installed but registry update failed: {e}");
            }
            println!(
                "Installed: {} v{}",
                plugin.manifest.name, plugin.manifest.version
            );
            println!("  path:     {}", plugin.install_path.display());
            println!("  caps:     {}", plugin.manifest.capabilities.join(", "));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: installation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Remove an installed plugin.
pub async fn run_plugin_uninstall(
    name: &str,
    plugin_dir: Option<&Path>,
    config: &Config,
) -> ExitCode {
    let dir = plugin_dir.map_or_else(
        || resolved_plugin_dir(None, &config.marketplace),
        Path::to_path_buf,
    );

    match MarketplaceClient::uninstall(name, &dir) {
        Ok(()) => {
            // Also remove from persistent registry if it exists.
            if let Ok(mut reg) = PluginRegistry::open(&dir) {
                let _ = reg.deregister(name);
            }
            println!("Uninstalled plugin '{name}'.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// List installed plugins.
pub fn run_plugin_list(plugin_dir: Option<&Path>, config: &Config) -> ExitCode {
    let dir = plugin_dir.map_or_else(
        || resolved_plugin_dir(None, &config.marketplace),
        Path::to_path_buf,
    );

    match MarketplaceClient::list_installed(&dir) {
        Ok(plugins) if plugins.is_empty() => {
            println!("No plugins installed in {}.", dir.display());
            ExitCode::SUCCESS
        }
        Ok(plugins) => {
            println!(
                "{} plugin(s) installed in {}:",
                plugins.len(),
                dir.display()
            );
            print_plugin_table(&plugins);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: failed to read plugin directory: {e}");
            ExitCode::FAILURE
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Choose the effective marketplace URL: CLI flag > config > default.
fn resolve_marketplace_url<'a>(cli: Option<&'a str>, cfg: &'a MarketplaceConfig) -> &'a str {
    cli.unwrap_or(cfg.marketplace_url.as_str())
}

/// Resolve and expand the plugin directory path.
///
/// Priority: explicit `cli` arg > config `marketplace.plugin_dir` > default.
pub fn resolved_plugin_dir(cli: Option<&Path>, cfg: &MarketplaceConfig) -> PathBuf {
    let raw = cli.map_or_else(
        || cfg.plugin_dir.clone(),
        |p| p.to_string_lossy().into_owned(),
    );
    expand_tilde(&raw)
}

/// Expand a leading `~` to the user home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest)
    } else if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
    } else {
        PathBuf::from(path)
    }
}

/// Write an installed plugin into the local `PluginRegistry`.
fn persist_to_registry(plugin: &InstalledPlugin, plugin_dir: &Path) -> mcp_gateway::Result<()> {
    let mut reg = PluginRegistry::open(plugin_dir)?;
    reg.register(plugin.clone())
}

/// Print a compact table of installed plugins.
fn print_plugin_table(plugins: &[InstalledPlugin]) {
    for p in plugins {
        println!(
            "  {:<30} v{:<10}  {}",
            p.manifest.name,
            p.manifest.version,
            p.install_path.display()
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::config::Config;

    fn default_config() -> Config {
        Config::default()
    }

    // ── resolve_marketplace_url ───────────────────────────────────────────────

    #[test]
    fn resolve_marketplace_url_uses_cli_flag_over_config() {
        // GIVEN: a config with one URL and a CLI override
        let cfg = default_config();
        // WHEN: a CLI override is provided
        let result = resolve_marketplace_url(Some("https://custom.example.com"), &cfg.marketplace);
        // THEN: the CLI value wins
        assert_eq!(result, "https://custom.example.com");
    }

    #[test]
    fn resolve_marketplace_url_falls_back_to_config() {
        // GIVEN: no CLI override
        let cfg = default_config();
        // WHEN: CLI arg is None
        let result = resolve_marketplace_url(None, &cfg.marketplace);
        // THEN: config value is returned
        assert_eq!(result, "https://plugins.mcpgateway.io");
    }

    // ── resolved_plugin_dir ───────────────────────────────────────────────────

    #[test]
    fn resolved_plugin_dir_uses_cli_path_when_provided() {
        // GIVEN: a CLI --plugin-dir value
        let cfg = default_config();
        let cli_path = PathBuf::from("/tmp/my-plugins");
        // WHEN: resolving the plugin dir
        let result = resolved_plugin_dir(Some(&cli_path), &cfg.marketplace);
        // THEN: the CLI path is returned verbatim
        assert_eq!(result, PathBuf::from("/tmp/my-plugins"));
    }

    #[test]
    fn resolved_plugin_dir_expands_tilde_from_config() {
        // GIVEN: default config (plugin_dir = "~/.mcp-gateway/plugins")
        let cfg = default_config();
        // WHEN: resolving without a CLI override
        let result = resolved_plugin_dir(None, &cfg.marketplace);
        // THEN: ~ is expanded (must not start with '~' in the result)
        let s = result.to_string_lossy();
        assert!(!s.starts_with('~'), "tilde should be expanded; got: {s}");
    }

    #[test]
    fn resolved_plugin_dir_absolute_path_unchanged() {
        // GIVEN: a config with an absolute plugin_dir
        let mut cfg = default_config();
        cfg.marketplace.plugin_dir = "/var/lib/mcp-gateway/plugins".to_string();
        // WHEN: resolving without a CLI override
        let result = resolved_plugin_dir(None, &cfg.marketplace);
        // THEN: absolute path returned unchanged
        assert_eq!(result, PathBuf::from("/var/lib/mcp-gateway/plugins"));
    }

    // ── expand_tilde ─────────────────────────────────────────────────────────

    #[test]
    fn expand_tilde_bare_tilde_returns_home() {
        // GIVEN: exactly "~"
        let result = expand_tilde("~");
        // THEN: resolves to a non-empty path (home dir or ".")
        assert!(!result.as_os_str().is_empty());
    }

    #[test]
    fn expand_tilde_no_tilde_returns_path_unchanged() {
        // GIVEN: a path without tilde
        let result = expand_tilde("/etc/config");
        // THEN: unchanged
        assert_eq!(result, PathBuf::from("/etc/config"));
    }

    #[test]
    fn expand_tilde_tilde_slash_appends_to_home() {
        // GIVEN: "~/foo/bar"
        let result = expand_tilde("~/foo/bar");
        // THEN: path ends with "foo/bar" and starts with the home directory
        let s = result.to_string_lossy();
        assert!(s.ends_with("foo/bar"), "got: {s}");
        assert!(!s.starts_with('~'), "tilde should be gone; got: {s}");
    }

    // ── MarketplaceConfig defaults ────────────────────────────────────────────

    #[test]
    fn marketplace_config_has_expected_defaults() {
        // GIVEN: a default MarketplaceConfig
        let cfg = MarketplaceConfig::default();
        // THEN: URL and plugin_dir have the documented defaults
        assert_eq!(cfg.marketplace_url, "https://plugins.mcpgateway.io");
        assert_eq!(cfg.plugin_dir, "~/.mcp-gateway/plugins");
    }

    #[test]
    fn default_config_marketplace_is_default_marketplace_config() {
        // GIVEN: the top-level Config default
        let cfg = Config::default();
        // THEN: marketplace sub-config has default values
        assert_eq!(
            cfg.marketplace.marketplace_url,
            "https://plugins.mcpgateway.io"
        );
    }
}
