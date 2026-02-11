//! Configuration file scanner for MCP servers

use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tracing::{debug, warn};

use crate::config::TransportConfig;
use crate::{Error, Result};

use super::{DiscoveredServer, DiscoverySource, ServerMetadata};

/// Scans config files for MCP server definitions
pub struct ConfigScanner;

impl ConfigScanner {
    /// Create new config scanner
    pub fn new() -> Self {
        Self
    }

    /// Scan all known config locations
    pub async fn scan_all(&self) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        // Scan Claude Desktop config
        if let Ok(mut claude_servers) = self.scan_claude_desktop().await {
            servers.append(&mut claude_servers);
        }

        // Scan VS Code config
        if let Ok(mut vscode_servers) = self.scan_vscode().await {
            servers.append(&mut vscode_servers);
        }

        // Scan Windsurf config
        if let Ok(mut windsurf_servers) = self.scan_windsurf().await {
            servers.append(&mut windsurf_servers);
        }

        // Scan generic MCP config directory
        if let Ok(mut mcp_servers) = self.scan_mcp_config_dir().await {
            servers.append(&mut mcp_servers);
        }

        // Scan environment variables
        if let Ok(mut env_servers) = self.scan_environment().await {
            servers.append(&mut env_servers);
        }

        Ok(servers)
    }

    /// Scan Claude Desktop configuration
    pub async fn scan_claude_desktop(&self) -> Result<Vec<DiscoveredServer>> {
        let config_path = Self::claude_desktop_config_path()?;
        if !config_path.exists() {
            debug!("Claude Desktop config not found at {}", config_path.display());
            return Ok(Vec::new());
        }

        debug!("Scanning Claude Desktop config at {}", config_path.display());
        self.parse_claude_config(&config_path, DiscoverySource::ClaudeDesktop)
            .await
    }

    /// Scan VS Code/Cursor MCP configuration
    pub async fn scan_vscode(&self) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        // VS Code settings
        if let Ok(vscode_path) = Self::vscode_config_path() {
            if vscode_path.exists() {
                debug!("Scanning VS Code config at {}", vscode_path.display());
                if let Ok(mut vs_servers) = self
                    .parse_vscode_config(&vscode_path, DiscoverySource::VsCode)
                    .await
                {
                    servers.append(&mut vs_servers);
                }
            }
        }

        // Cursor settings (similar format)
        if let Ok(cursor_path) = Self::cursor_config_path() {
            if cursor_path.exists() {
                debug!("Scanning Cursor config at {}", cursor_path.display());
                if let Ok(mut cursor_servers) = self
                    .parse_vscode_config(&cursor_path, DiscoverySource::VsCode)
                    .await
                {
                    servers.append(&mut cursor_servers);
                }
            }
        }

        Ok(servers)
    }

    /// Scan Windsurf MCP configuration
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
    pub async fn scan_mcp_config_dir(&self) -> Result<Vec<DiscoveredServer>> {
        let mcp_dir = Self::mcp_config_dir()?;
        if !mcp_dir.exists() {
            debug!("MCP config directory not found at {}", mcp_dir.display());
            return Ok(Vec::new());
        }

        let mut servers = Vec::new();
        let entries = tokio::fs::read_dir(&mcp_dir).await.map_err(|e| {
            Error::Config(format!("Failed to read MCP config dir: {e}"))
        })?;

        let mut entries = entries;
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            Error::Config(format!("Failed to read dir entry: {e}"))
        })? {
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
    pub async fn scan_environment(&self) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        // Look for MCP_SERVER_* environment variables
        for (key, value) in env::vars() {
            if key.starts_with("MCP_SERVER_") && key.ends_with("_URL") {
                // Extract server name from MCP_SERVER_NAME_URL
                let name = key
                    .strip_prefix("MCP_SERVER_")
                    .and_then(|s| s.strip_suffix("_URL"))
                    .unwrap_or("unknown")
                    .to_lowercase()
                    .replace('_', "-");

                debug!("Found MCP server in environment: {name} = {value}");

                servers.push(DiscoveredServer {
                    name: name.clone(),
                    description: format!("MCP server from environment variable {key}"),
                    source: DiscoverySource::Environment,
                    transport: TransportConfig::Http {
                        http_url: value,
                        streamable_http: false,
                        protocol_version: None,
                    },
                    metadata: ServerMetadata {
                        config_path: None,
                        pid: None,
                        port: None,
                        command: None,
                        working_dir: None,
                    },
                });
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
                if let Some(server) = self.parse_server_config(name, server_config, &source, path) {
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

        let config: Value = serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse JSON: {e}")))?;

        let mut servers = Vec::new();

        // VS Code might have MCP config under various keys
        if let Some(mcp_config) = config.get("mcp").and_then(|v| v.as_object()) {
            for (name, server_config) in mcp_config {
                if let Some(server) = self.parse_server_config(name, server_config, &source, path) {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Parse individual server config
    fn parse_server_config(
        &self,
        name: &str,
        config: &Value,
        source: &DiscoverySource,
        config_path: &Path,
    ) -> Option<DiscoveredServer> {
        // Extract command (stdio transport)
        if let Some(command) = config.get("command").and_then(|v| v.as_str()) {
            let args = config
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let full_command = if args.is_empty() {
                command.to_string()
            } else {
                format!("{} {}", command, args.join(" "))
            };

            let working_dir = config
                .get("cwd")
                .and_then(|v| v.as_str())
                .map(PathBuf::from);

            return Some(DiscoveredServer {
                name: name.to_string(),
                description: format!("MCP server from {:?}", source),
                source: source.clone(),
                transport: TransportConfig::Stdio {
                    command: full_command.clone(),
                    cwd: working_dir.as_ref().map(|p| p.to_string_lossy().into_owned()),
                },
                metadata: ServerMetadata {
                    config_path: Some(config_path.to_path_buf()),
                    pid: None,
                    port: None,
                    command: Some(full_command),
                    working_dir,
                },
            });
        }

        // Extract URL (HTTP transport)
        if let Some(url) = config.get("url").and_then(|v| v.as_str()) {
            return Some(DiscoveredServer {
                name: name.to_string(),
                description: format!("MCP server from {:?}", source),
                source: source.clone(),
                transport: TransportConfig::Http {
                    http_url: url.to_string(),
                    streamable_http: false,
                    protocol_version: None,
                },
                metadata: ServerMetadata {
                    config_path: Some(config_path.to_path_buf()),
                    pid: None,
                    port: Self::extract_port_from_url(url),
                    command: None,
                    working_dir: None,
                },
            });
        }

        warn!("Unsupported server config format for {name}");
        None
    }

    /// Extract port number from URL
    fn extract_port_from_url(url: &str) -> Option<u16> {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.port())
    }

    /// Get Claude Desktop config path
    fn claude_desktop_config_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
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
        let home = dirs::home_dir()
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
        let home = dirs::home_dir()
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
        let home = dirs::home_dir()
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
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Config("Could not determine home directory".to_string()))?;

        Ok(home.join(".config/mcp"))
    }
}

impl Default for ConfigScanner {
    fn default() -> Self {
        Self::new()
    }
}
