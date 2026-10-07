// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Configuration file scanner for MCP servers

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use tracing::debug;

use crate::config::TransportConfig;
use crate::home_dir::home_dir;
use crate::{Error, Result};
#[cfg(not(target_os = "macos"))]
use dirs::config_dir;

use super::{DiscoveredServer, DiscoverySource, ServerMetadata};

/// Scans config files for MCP server definitions
#[derive(Default)]
pub struct ConfigScanner {
    /// The environment the gateway resolves against, when one has been
    /// published. `None` keeps the process environment as the only source,
    /// which is what a scanner built without one has always read.
    env: Option<Arc<crate::config::LiveEnv>>,
}

impl ConfigScanner {
    /// Create new config scanner
    #[must_use]
    pub fn new() -> Self {
        Self { env: None }
    }

    /// Resolve the environment scan against the live environment.
    ///
    /// Consuming builder rather than a constructor argument, matching the other
    /// consumers of `LiveEnv`: every existing call site keeps working, and the
    /// one that has an environment says so.
    #[must_use]
    pub fn with_env(mut self, env: Arc<crate::config::LiveEnv>) -> Self {
        self.env = Some(env);
        self
    }

    /// Scan all known config locations
    ///
    /// # Errors
    ///
    /// Returns an error if a critical scanning operation fails.
    pub async fn scan_all(&self) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        // Scan Claude Desktop config
        if let Ok(mut s) = self.scan_claude_desktop().await {
            servers.append(&mut s);
        }

        // Scan Claude Code CLI config
        if let Ok(mut s) = self.scan_claude_code().await {
            servers.append(&mut s);
        }

        // Scan VS Code config
        if let Ok(mut s) = self.scan_vscode().await {
            servers.append(&mut s);
        }

        // Scan Cursor standalone mcp.json
        if let Ok(mut s) = self.scan_cursor_mcp_json().await {
            servers.append(&mut s);
        }

        // Scan Windsurf config
        if let Ok(mut s) = self.scan_windsurf().await {
            servers.append(&mut s);
        }

        // Scan Zed editor
        if let Ok(mut s) = self.scan_zed().await {
            servers.append(&mut s);
        }

        // Scan Continue.dev
        if let Ok(mut s) = self.scan_continue().await {
            servers.append(&mut s);
        }

        // Scan OpenAI Codex CLI
        if let Ok(mut s) = self.scan_codex().await {
            servers.append(&mut s);
        }

        // Scan generic MCP config directory
        if let Ok(mut s) = self.scan_mcp_config_dir().await {
            servers.append(&mut s);
        }

        // Scan environment variables
        if let Ok(mut s) = self.scan_environment() {
            servers.append(&mut s);
        }

        Ok(servers)
    }

    /// Scan Claude Desktop configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be read or parsed.
    pub async fn scan_claude_desktop(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::claude_desktop_config_path()?;
        if !config_path.exists() {
            debug!(
                "Claude Desktop config not found at {}",
                config_path.display()
            );
            return Ok(Vec::new());
        }

        debug!(
            "Scanning Claude Desktop config at {}",
            config_path.display()
        );
        self.parse_claude_config(&config_path, DiscoverySource::ClaudeDesktop)
            .await
    }

    /// Scan VS Code/Cursor MCP configuration
    ///
    /// # Errors
    ///
    /// Returns an error if a config file exists but cannot be read or parsed.
    pub async fn scan_vscode(&self) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        // VS Code settings
        if let Ok(vscode_path) = Self::vscode_config_path()
            && vscode_path.exists()
        {
            debug!("Scanning VS Code config at {}", vscode_path.display());
            if let Ok(mut vs_servers) = self
                .parse_vscode_config(&vscode_path, DiscoverySource::VsCode)
                .await
            {
                servers.append(&mut vs_servers);
            }
        }

        // Cursor settings (similar format)
        if let Ok(cursor_path) = Self::cursor_config_path()
            && cursor_path.exists()
        {
            debug!("Scanning Cursor config at {}", cursor_path.display());
            if let Ok(mut cursor_servers) = self
                .parse_vscode_config(&cursor_path, DiscoverySource::VsCode)
                .await
            {
                servers.append(&mut cursor_servers);
            }
        }

        Ok(servers)
    }

    /// Scan Windsurf MCP configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be read or parsed.
    pub async fn scan_windsurf(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::windsurf_config_path()?;
        if !config_path.exists() {
            debug!("Windsurf config not found at {}", config_path.display());
            return Ok(Vec::new());
        }

        debug!("Scanning Windsurf config at {}", config_path.display());
        self.parse_claude_config(&config_path, DiscoverySource::Windsurf)
            .await
    }

    /// Scan ~/.config/mcp/*.json files
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be read.
    pub async fn scan_mcp_config_dir(&self) -> Result<Vec<DiscoveredServer>> {
        let mcp_dir = Self::mcp_config_dir()?;
        if !mcp_dir.exists() {
            debug!("MCP config directory not found at {}", mcp_dir.display());
            return Ok(Vec::new());
        }

        let mut servers = Vec::new();
        let entries = tokio::fs::read_dir(&mcp_dir)
            .await
            .map_err(|e| Error::Config(format!("Failed to read MCP config dir: {e}")))?;

        let mut entries = entries;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| Error::Config(format!("Failed to read dir entry: {e}")))?
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                debug!("Scanning MCP config file: {}", path.display());
                if let Ok(mut config_servers) = self
                    .parse_claude_config(&path, DiscoverySource::McpConfig)
                    .await
                {
                    servers.append(&mut config_servers);
                }
            }
        }

        Ok(servers)
    }

    /// Scan environment variables for MCP_* patterns
    ///
    /// # Errors
    ///
    /// This function currently does not return errors but maintains the `Result`
    /// type for consistency with other scanning methods.
    pub fn scan_environment(&self) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        // Process environment first so an env-file assignment wins, which is
        // the precedence `EnvOverlay::resolve` states. Merged rather than
        // substituted: an overlay carries only its own files' assignments, so
        // reading it alone would stop discovering shell-exported endpoints.
        let mut merged: std::collections::BTreeMap<String, String> = env::vars().collect();
        if let Some(env) = &self.env {
            merged.extend(env.get().effective_vars());
        }

        // Look for MCP_SERVER_* environment variables
        for (key, value) in merged {
            if key.starts_with("MCP_SERVER_") && key.ends_with("_URL") {
                // Extract server name from MCP_SERVER_NAME_URL
                let name = key
                    .strip_prefix("MCP_SERVER_")
                    .and_then(|s| s.strip_suffix("_URL"))
                    .unwrap_or("unknown")
                    .to_lowercase()
                    .replace('_', "-");

                // The variable name, never its value: an endpoint URL carries
                // userinfo and query-string tokens often enough that logging it
                // writes a credential into the log because discovery ran.
                debug!("Found MCP server in environment: {name} (from {key})");

                servers.push(DiscoveredServer::new(
                    name.clone(),
                    format!("MCP server from environment variable {key}"),
                    DiscoverySource::Environment,
                    TransportConfig::for_url(&value),
                    ServerMetadata {
                        config_path: None,
                        pid: None,
                        port: None,
                        command: None,
                        working_dir: None,
                    },
                ));
            }
        }

        Ok(servers)
    }

    /// Parse Claude Desktop format config (also used by Windsurf)
    async fn parse_claude_config(
        &self,
        path: &Path,
        source: DiscoverySource,
    ) -> Result<Vec<DiscoveredServer>> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| Error::Config(format!("Failed to read config: {e}")))?;

        let config: Value = serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse JSON: {e}")))?;

        let mut servers = Vec::new();

        // Claude Desktop format: { "mcpServers": { "name": { "command": "...", ... } } }
        if let Some(mcp_servers) = config.get("mcpServers").and_then(|v| v.as_object()) {
            for (name, server_config) in mcp_servers {
                if let Some(server) = Self::parse_server_config(name, server_config, &source, path)
                {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Parse VS Code format config
    async fn parse_vscode_config(
        &self,
        path: &Path,
        source: DiscoverySource,
    ) -> Result<Vec<DiscoveredServer>> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| Error::Config(format!("Failed to read config: {e}")))?;

        // VS Code and Cursor write settings.json as JSONC.
        let config: Value = super::jsonc::strip_jsonc(&content)
            .ok_or_else(|| Error::Config("Unterminated comment or string in settings".into()))
            .and_then(|text| {
                serde_json::from_str(&text)
                    .map_err(|e| Error::Config(format!("Failed to parse JSON: {e}")))
            })?;

        let mut servers = Vec::new();

        // VS Code user settings: { "mcp": { "servers": { "<name>": {...} } } }.
        // Siblings such as `mcp.inputs` are not servers.
        if let Some(mcp_config) = config.pointer("/mcp/servers").and_then(Value::as_object) {
            for (name, server_config) in mcp_config {
                if let Some(server) = Self::parse_server_config(name, server_config, &source, path)
                {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Parse one client server entry (`command`/`args`/`env`/`cwd`, or
    /// `url`/`headers`); see [`super::client_entry`].
    fn parse_server_config(
        name: &str,
        config: &Value,
        source: &DiscoverySource,
        config_path: &Path,
    ) -> Option<DiscoveredServer> {
        super::client_entry::parse(name, config, source, config_path)
    }

    // ── New AI client scanners ─────────────────────────────────────────────

    /// Scan Claude Code CLI configuration (`~/.claude.json`).
    ///
    /// Format: `{ "mcpServers": { "<name>": { "command": "...", "args": [...], "env": {...} } } }`
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub async fn scan_claude_code(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::claude_code_config_path()?;
        if !config_path.exists() {
            debug!("Claude Code config not found at {}", config_path.display());
            return Ok(Vec::new());
        }
        debug!("Scanning Claude Code config at {}", config_path.display());
        self.parse_claude_config(&config_path, DiscoverySource::ClaudeCode)
            .await
    }

    /// Scan Cursor's standalone MCP config (`~/.cursor/mcp.json`).
    ///
    /// Same `mcpServers` format as Claude Desktop.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub async fn scan_cursor_mcp_json(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::cursor_mcp_json_path()?;
        if !config_path.exists() {
            debug!("Cursor mcp.json not found at {}", config_path.display());
            return Ok(Vec::new());
        }
        debug!("Scanning Cursor mcp.json at {}", config_path.display());
        self.parse_claude_config(&config_path, DiscoverySource::Cursor)
            .await
    }

    /// Scan Zed editor configuration (Zed's config directory, see
    /// [`Self::zed_config_path`]).
    ///
    /// Format: `{ "context_servers": { "<name>": { "command": "...", "args": [...] } } }`,
    /// or `{ "url": "..." }` for an HTTP server.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub async fn scan_zed(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::zed_config_path()?;
        if !config_path.exists() {
            debug!("Zed config not found at {}", config_path.display());
            return Ok(Vec::new());
        }
        debug!("Scanning Zed config at {}", config_path.display());
        self.parse_zed_config(&config_path).await
    }

    /// Scan Continue.dev configuration (`~/.continue/config.json`).
    ///
    /// Format: `{ "mcpServers": [ { "name": "...", "command": "...", "args": [...] } ] }`
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub async fn scan_continue(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::continue_config_path()?;
        if !config_path.exists() {
            debug!("Continue.dev config not found at {}", config_path.display());
            return Ok(Vec::new());
        }
        debug!("Scanning Continue.dev config at {}", config_path.display());
        self.parse_continue_config(&config_path).await
    }

    /// Scan `OpenAI` Codex CLI configuration (`~/.codex/config.json`).
    ///
    /// Format: `{ "mcpServers": { "<name>": { "command": "...", "args": [...] } } }`
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub async fn scan_codex(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::codex_config_path()?;
        if !config_path.exists() {
            debug!("Codex config not found at {}", config_path.display());
            return Ok(Vec::new());
        }
        debug!("Scanning Codex config at {}", config_path.display());
        self.parse_claude_config(&config_path, DiscoverySource::Codex)
            .await
    }

    // ── Zed-specific parser ────────────────────────────────────────────────

    /// Parse Zed `settings.json` — `context_servers` key.
    async fn parse_zed_config(&self, path: &Path) -> Result<Vec<DiscoveredServer>> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| Error::Config(format!("Failed to read Zed config: {e}")))?;

        // Zed's settings are JSONC: comments and trailing commas are allowed.
        let config: Value = super::jsonc::strip_jsonc(&content)
            .ok_or_else(|| Error::Config("Unterminated comment or string in Zed config".into()))
            .and_then(|text| {
                serde_json::from_str(&text)
                    .map_err(|e| Error::Config(format!("Failed to parse Zed config JSON: {e}")))
            })?;

        let Some(context_servers) = config.get("context_servers").and_then(|v| v.as_object())
        else {
            return Ok(Vec::new());
        };

        let mut servers = Vec::new();
        for (name, server_config) in context_servers {
            if let Some(server) = Self::parse_zed_server(name, server_config, path) {
                servers.push(server);
            }
        }
        Ok(servers)
    }

    /// Parse a single Zed context-server entry.
    ///
    /// Zed's entries are flat, the same shape as an `mcpServers` entry:
    /// `{"command": "<path>", "args": [...]}` for stdio or `{"url": ...}` for
    /// HTTP (zed-industries/zed @ 1a28cff4,
    /// `crates/settings_content/src/project.rs:517-615`). An extension entry
    /// has neither and is not imported.
    fn parse_zed_server(
        name: &str,
        config: &Value,
        config_path: &Path,
    ) -> Option<DiscoveredServer> {
        let flat =
            config.get("command").is_some_and(Value::is_string) || config.get("url").is_some();
        if !flat {
            return None;
        }
        Self::parse_server_config(name, config, &DiscoverySource::Zed, config_path)
    }

    // ── Continue.dev-specific parser ───────────────────────────────────────

    /// Parse Continue.dev `config.json` — `mcpServers` array or object.
    async fn parse_continue_config(&self, path: &Path) -> Result<Vec<DiscoveredServer>> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| Error::Config(format!("Failed to read Continue.dev config: {e}")))?;

        let config: Value = serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse Continue.dev config JSON: {e}")))?;

        let mut servers = Vec::new();

        // Continue.dev supports both array format (list of server objects) and
        // object format (name-keyed map), depending on version.
        match config.get("mcpServers") {
            Some(Value::Array(arr)) => {
                for entry in arr {
                    if let Some(name) = entry.get("name").and_then(|v| v.as_str())
                        && let Some(server) =
                            Self::parse_server_config(name, entry, &DiscoverySource::Continue, path)
                    {
                        servers.push(server);
                    }
                }
            }
            Some(Value::Object(map)) => {
                for (name, server_config) in map {
                    if let Some(server) = Self::parse_server_config(
                        name,
                        server_config,
                        &DiscoverySource::Continue,
                        path,
                    ) {
                        servers.push(server);
                    }
                }
            }
            _ => {}
        }

        Ok(servers)
    }

    // ── New path helpers ───────────────────────────────────────────────────

    /// Get Claude Code CLI config path (`~/.claude.json`).
    fn claude_code_config_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;
        Ok(home.join(".claude.json"))
    }

    /// Get Cursor standalone mcp.json path (`~/.cursor/mcp.json`).
    fn cursor_mcp_json_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;
        Ok(home.join(".cursor/mcp.json"))
    }

    /// Get Zed settings path: `~/.config/zed/settings.json` on macOS, the OS
    /// config directory joined with `zed` (Linux) or `Zed` elsewhere.
    fn zed_config_path() -> Result<PathBuf> {
        let home = || {
            home_dir()
                .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))
        };

        // Zed's `config_dir()` (zed-industries/zed @ 1a28cff4,
        // `crates/paths/src/paths.rs:133-152`): `~/.config/zed` on macOS, the
        // OS config dir elsewhere. ponytail: Zed's Flatpak override
        // (`FLATPAK_XDG_CONFIG_HOME`) is not followed; add it if a Flatpak user
        // reports a miss.
        // The home directory is needed only where the OS config dir is not
        // known (and always on macOS).
        #[cfg(target_os = "macos")]
        let path = home()?.join(".config/zed/settings.json");
        #[cfg(target_os = "linux")]
        let path = match config_dir() {
            Some(dir) => dir,
            None => home()?.join(".config"),
        }
        .join("zed/settings.json");
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let path = match config_dir() {
            Some(dir) => dir,
            None => home()?.join(".config"),
        }
        .join("Zed/settings.json");

        Ok(path)
    }

    /// Get Continue.dev config path (`~/.continue/config.json`).
    fn continue_config_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;
        Ok(home.join(".continue/config.json"))
    }

    /// Get `OpenAI` Codex CLI config path (`~/.codex/config.json`).
    fn codex_config_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;
        Ok(home.join(".codex/config.json"))
    }

    /// Get Claude Desktop config path
    fn claude_desktop_config_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;

        #[cfg(target_os = "macos")]
        let path = home.join("Library/Application Support/Claude/claude_desktop_config.json");

        #[cfg(target_os = "linux")]
        let path = home.join(".config/Claude/claude_desktop_config.json");

        #[cfg(target_os = "windows")]
        let path = home.join("AppData/Roaming/Claude/claude_desktop_config.json");

        Ok(path)
    }

    /// Get VS Code settings path
    fn vscode_config_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;

        #[cfg(target_os = "macos")]
        let path = home.join("Library/Application Support/Code/User/settings.json");

        #[cfg(target_os = "linux")]
        let path = home.join(".config/Code/User/settings.json");

        #[cfg(target_os = "windows")]
        let path = home.join("AppData/Roaming/Code/User/settings.json");

        Ok(path)
    }

    /// Get Cursor settings path
    fn cursor_config_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;

        #[cfg(target_os = "macos")]
        let path = home.join("Library/Application Support/Cursor/User/settings.json");

        #[cfg(target_os = "linux")]
        let path = home.join(".config/Cursor/User/settings.json");

        #[cfg(target_os = "windows")]
        let path = home.join("AppData/Roaming/Cursor/User/settings.json");

        Ok(path)
    }

    /// Get Windsurf config path
    fn windsurf_config_path() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;

        #[cfg(target_os = "macos")]
        let path = home.join("Library/Application Support/Windsurf/windsurf_config.json");

        #[cfg(target_os = "linux")]
        let path = home.join(".config/Windsurf/windsurf_config.json");

        #[cfg(target_os = "windows")]
        let path = home.join("AppData/Roaming/Windsurf/windsurf_config.json");

        Ok(path)
    }

    /// Get generic MCP config directory
    fn mcp_config_dir() -> Result<PathBuf> {
        let home = home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;

        Ok(home.join(".config/mcp"))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn discovered_url(servers: &[DiscoveredServer], name: &str) -> Option<String> {
        servers
            .iter()
            .find(|s| s.name == name)
            .map(|s| match &s.transport {
                TransportConfig::Http { http_url, .. } => http_url.clone(),
                other => {
                    panic!("environment discovery must produce an HTTP transport, got {other:?}")
                }
            })
    }

    #[test]
    fn an_env_file_endpoint_reaches_the_environment_scan() {
        // The scan enumerated the process environment, which cannot see a value
        // an env file assigns once env files load into an overlay instead of
        // being applied to the process.
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");
        crate::gateway::test_helpers::write_owner_only(
            &env_file,
            "MCP_SERVER_ROTATED_URL=http://127.0.0.1:9931\n",
        )
        .unwrap();
        let overlay = Arc::new(crate::config::EnvOverlay::from_paths(&[env_file]));
        let env = Arc::new(crate::config::LiveEnv::new(
            Arc::clone(&overlay),
            crate::config::ResolvedEnvFiles::default(),
        ));

        let bare = ConfigScanner::new().scan_environment().unwrap();
        assert!(
            discovered_url(&bare, "rotated").is_none(),
            "the value exists only in the env file, so a process-only scan must not see it"
        );

        let scanner = ConfigScanner::new().with_env(Arc::clone(&env));
        assert_eq!(
            discovered_url(&scanner.scan_environment().unwrap(), "rotated").as_deref(),
            Some("http://127.0.0.1:9931"),
            "the env-file endpoint must be discoverable"
        );

        // A reload that drops the assignment must reach a scanner built before it.
        env.set(Arc::new(crate::config::EnvOverlay::none()));
        assert!(
            discovered_url(&scanner.scan_environment().unwrap(), "rotated").is_none(),
            "a reload that clears the assignment must be visible to the next scan"
        );

        assert!(std::env::var("MCP_SERVER_ROTATED_URL").is_err());
    }
}

#[cfg(test)]
#[path = "config_scanner_ws_tests.rs"]
mod ws_tests;

#[cfg(test)]
#[path = "config_scanner_zed_tests.rs"]
mod zed_tests;

#[cfg(test)]
#[path = "config_scanner_vscode_tests.rs"]
mod vscode_tests;

#[cfg(test)]
#[path = "config_scanner_entry_tests.rs"]
mod entry_tests;
