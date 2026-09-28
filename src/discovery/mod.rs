// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MCP Server Auto-Discovery
//!
//! Scans for existing MCP server configurations in common locations
//! and running MCP server processes to enable zero-config integration.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::Result;
use crate::config::{BackendConfig, TransportConfig};

mod client_entry;
pub mod config_scanner;
mod jsonc;
pub mod process_scanner;
mod secret_map;
pub mod shadow;

pub use secret_map::{REDACTED, SecretMap};

use config_scanner::ConfigScanner;
use process_scanner::ProcessScanner;

/// Discovered MCP server
///
/// `#[non_exhaustive]` since 4.0: build one with [`DiscoveredServer::new`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DiscoveredServer {
    /// Suggested name for the backend
    pub name: String,
    /// Server description
    pub description: String,
    /// Source of discovery
    pub source: DiscoverySource,
    /// Transport configuration
    pub transport: TransportConfig,
    /// Additional metadata
    pub metadata: ServerMetadata,
    /// Environment the client passes a stdio server. Values are secrets:
    /// see [`SecretMap`].
    #[serde(default, skip_serializing_if = "SecretMap::is_empty")]
    pub env: SecretMap,
    /// Headers the client sends an HTTP server. Values are secrets: see
    /// [`SecretMap`].
    #[serde(default, skip_serializing_if = "SecretMap::is_empty")]
    pub headers: SecretMap,
}

/// Source of discovery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Claude Desktop config
    ClaudeDesktop,
    /// Claude Code CLI config (~/.claude.json)
    ClaudeCode,
    /// VS Code/Cursor MCP config (settings.json `mcp.servers` key)
    VsCode,
    /// Cursor standalone mcp.json (~/.cursor/mcp.json)
    Cursor,
    /// Windsurf MCP config
    Windsurf,
    /// Zed editor `context_servers` config
    Zed,
    /// Continue.dev mcpServers config
    Continue,
    /// `OpenAI` Codex CLI config
    Codex,
    /// Generic MCP config in ~/.config/mcp/
    McpConfig,
    /// Running process
    RunningProcess,
    /// Environment variable
    Environment,
}

/// Server metadata from discovery
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerMetadata {
    /// Original config file path
    pub config_path: Option<PathBuf>,
    /// Process ID if running
    pub pid: Option<u32>,
    /// Port number if detected
    pub port: Option<u16>,
    /// Command if stdio
    pub command: Option<String>,
    /// Working directory
    pub working_dir: Option<PathBuf>,
}

impl DiscoveredServer {
    /// A discovered server with no environment and no headers.
    #[must_use]
    pub fn new(
        name: String,
        description: String,
        source: DiscoverySource,
        transport: TransportConfig,
        metadata: ServerMetadata,
    ) -> Self {
        Self {
            name,
            description,
            source,
            transport,
            metadata,
            env: SecretMap::default(),
            headers: SecretMap::default(),
        }
    }

    /// Convert to backend config, values included: this is what the
    /// owner-only config writer persists. `BackendConfig` is the gateway.yaml
    /// schema, so its `Serialize` carries `env`/`headers` values as it does
    /// for every hand-written backend; its `Debug` shows counts only.
    #[must_use]
    pub fn to_backend_config(&self) -> BackendConfig {
        // The one path that sees env and header values: the backend the
        // config writer persists owner-only.
        BackendConfig {
            description: self.description.clone(),
            enabled: true,
            transport: self.transport.clone(),
            env: self.env.expose().clone().into_iter().collect(),
            headers: self.headers.expose().clone().into_iter().collect(),
            ..Default::default()
        }
    }

    /// Clone with argv and credential-bearing URLs replaced. Same serde shape
    /// as the live server, so JSON and YAML discovery output stay compatible.
    #[must_use]
    pub fn redacted_for_diagnostics(&self) -> Self {
        use crate::security::{diagnostic_url, summarize_stdio_command};
        let mut redacted = self.clone();
        match &mut redacted.transport {
            TransportConfig::Stdio { command, .. } => {
                *command = summarize_stdio_command(command);
            }
            TransportConfig::Http { http_url: url, .. }
            | TransportConfig::WebSocket { ws_url: url, .. } => {
                *url = diagnostic_url(url);
            }
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => {
                *a2a_url = diagnostic_url(a2a_url);
            }
        }
        if let Some(command) = redacted.metadata.command.as_mut() {
            *command = summarize_stdio_command(command);
        }
        redacted
    }

    /// Operator-facing JSON: the redacted clone, never argv or secrets.
    #[must_use]
    pub fn diagnostic_value(&self) -> serde_json::Value {
        serde_json::to_value(self.redacted_for_diagnostics()).unwrap_or(serde_json::Value::Null)
    }
}

/// MCP Auto-Discovery orchestrator
pub struct AutoDiscovery {
    config_scanner: ConfigScanner,
    process_scanner: ProcessScanner,
}

impl AutoDiscovery {
    /// Create new auto-discovery instance
    #[must_use]
    pub fn new() -> Self {
        Self {
            config_scanner: ConfigScanner::new(),
            process_scanner: ProcessScanner::new(),
        }
    }

    /// Resolve the environment scan against the live environment.
    ///
    /// Without one the scan reads the process environment alone, which is what
    /// an instance built without an environment has always done.
    #[must_use]
    pub fn with_env(mut self, env: std::sync::Arc<crate::config::LiveEnv>) -> Self {
        self.config_scanner = self.config_scanner.with_env(env);
        self
    }

    /// Discover all MCP servers from all sources
    ///
    /// # Errors
    ///
    /// Returns an error if both config and process scanning fail entirely.
    pub async fn discover_all(&self) -> Result<Vec<DiscoveredServer>> {
        let mut servers = Vec::new();

        // Scan config files (includes all known AI clients)
        debug!("Scanning config files for MCP servers");
        match self.config_scanner.scan_all().await {
            Ok(mut config_servers) => servers.append(&mut config_servers),
            Err(e) => {
                tracing::warn!("Config scan failed: {e}");
            }
        }

        // Scan running processes
        debug!("Scanning running processes for MCP servers");
        match self.process_scanner.scan().await {
            Ok(mut process_servers) => servers.append(&mut process_servers),
            Err(e) => {
                tracing::warn!("Process scan failed: {e}");
            }
        }

        // Deduplicate by name (prefer config over process)
        let mut unique_servers: Vec<DiscoveredServer> = Vec::new();
        for server in servers {
            if !unique_servers.iter().any(|s| s.name == server.name) {
                unique_servers.push(server);
            }
        }

        Ok(unique_servers)
    }

    /// Discover from specific source
    ///
    /// # Errors
    ///
    /// Returns an error if the specified source scan fails.
    pub async fn discover_from_source(
        &self,
        source: DiscoverySource,
    ) -> Result<Vec<DiscoveredServer>> {
        match source {
            DiscoverySource::ClaudeDesktop => self.config_scanner.scan_claude_desktop().await,
            DiscoverySource::ClaudeCode => self.config_scanner.scan_claude_code().await,
            DiscoverySource::VsCode => self.config_scanner.scan_vscode().await,
            DiscoverySource::Cursor => self.config_scanner.scan_cursor_mcp_json().await,
            DiscoverySource::Windsurf => self.config_scanner.scan_windsurf().await,
            DiscoverySource::Zed => self.config_scanner.scan_zed().await,
            DiscoverySource::Continue => self.config_scanner.scan_continue().await,
            DiscoverySource::Codex => self.config_scanner.scan_codex().await,
            DiscoverySource::McpConfig => self.config_scanner.scan_mcp_config_dir().await,
            DiscoverySource::RunningProcess => self.process_scanner.scan().await,
            DiscoverySource::Environment => self.config_scanner.scan_environment(),
        }
    }
}

impl Default for AutoDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "secret_flow_tests.rs"]
mod secret_flow_tests;

#[cfg(test)]
mod yaml_redaction_tests {
    use super::*;

    const CANARY: &str = "SENTINEL_SWEEP_7222";

    #[test]
    fn yaml_of_redacted_server_keeps_schema_and_drops_canary() {
        let server = DiscoveredServer::new(
            "leaky".into(),
            "d".into(),
            DiscoverySource::Environment,
            TransportConfig::Stdio {
                command: format!("node --token {CANARY} server.js"),
                cwd: None,
                protocol_version: None,
            },
            ServerMetadata {
                command: Some(format!("node --token {CANARY}")),
                ..ServerMetadata::default()
            },
        );
        let yaml = serde_yaml::to_string(&server.redacted_for_diagnostics()).expect("yaml");
        assert!(!yaml.contains(CANARY), "{yaml}");
        assert!(yaml.contains("command:"), "{yaml}");
        let raw = serde_yaml::to_string(&server).expect("raw");
        assert!(
            raw.contains(CANARY),
            "fixture is only useful if raw YAML would leak"
        );
    }
}
