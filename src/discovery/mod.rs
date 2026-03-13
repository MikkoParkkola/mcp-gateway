//! MCP Server Auto-Discovery
//!
//! Scans for existing MCP server configurations in common locations
//! and running MCP server processes to enable zero-config integration.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::Result;
use crate::config::{BackendConfig, TransportConfig};

pub mod config_scanner;
pub mod process_scanner;

use config_scanner::ConfigScanner;
use process_scanner::ProcessScanner;

/// Discovered MCP server
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Source of discovery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Claude Desktop config
    ClaudeDesktop,
    /// Claude Code CLI config (~/.claude.json)
    ClaudeCode,
    /// VS Code/Cursor MCP config (settings.json `mcp` key)
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
    /// Convert to backend config
    #[must_use]
    pub fn to_backend_config(&self) -> BackendConfig {
        BackendConfig {
            description: self.description.clone(),
            enabled: true,
            transport: self.transport.clone(),
            ..Default::default()
        }
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
